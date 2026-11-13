package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/jackc/pgx/v5/pgconn"
)

// isFKViolation reports whether err is a Postgres foreign-key violation (SQLSTATE
// 23503) — e.g. an activity insert whose exploration_id has no parent row.
func isFKViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// dropReason classifies why an activity write was dropped, so the log can be
// grouped/analysed by cause rather than by raw error text.
func dropReason(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503":
			return "fk_violation(23503,父exploration不存在)"
		case "23505":
			return "unique_violation(23505)"
		default:
			return "pg_error(" + pgErr.Code + ")"
		}
	}
	return "write_error"
}

// bumpDrop increments and returns the running count of dropped (unpersistable)
// activity records for a task. Concurrent planner + worker emits race here, so the
// counter is an atomic behind sync.Map. The count in the log shows loss scale at a
// glance instead of forcing a grep-and-count.
func (e *Engine) bumpDrop(taskID string) int64 {
	v, _ := e.dropCnt.LoadOrStore(taskID, new(int64))
	return atomic.AddInt64(v.(*int64), 1)
}

// preview collapses newlines and trims s to a short rune-safe snippet for one-line
// log output (avoids dumping a multi-KB summary/detail into the log).
func preview(s string, n int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// model_error（provider/API 故障：LLM 层瞬时重试耗尽，或流已开始后中途断流）
// 收场的 work 不是「试过没做完」也不是真失败，而是外部抖动。默认把它当永久
// blocked 会白丢一条意图，所以这里对该终态额外重跑几次，每次之间退避一下，给
// provider 恢复的时间；重试期间若被暂停/终止/取消则立即让位给对应分支处理。
const (
	modelErrorRetries      = 2               // model_error 收场后额外重试的次数
	modelErrorRetryBackoff = 3 * time.Second // 每次重试前的退避
	workControlWaitTimeout = 30 * time.Second
)

var errWorkControlConflict = errors.New("work control conflict")

// retryableWorkerModelError excludes errors already handled by the task router.
// In particular, a quota error after partial streaming advances the task cursor
// for the next LLM call but must not replay this whole intent on the backup.
func retryableWorkerModelError(reason harness.TerminalReason, err error) bool {
	return reason == harness.ReasonModelError && !isTaskLLMRuntimeError(err)
}

// Engine drives the event-driven exploration loop with real LLM agents
// (docs §4.3/§4.4): on component/exploration-graph change (debounced) it wakes the
// planner, which reads the route, queries components, judges goals and emits intents;
// N concurrent work agents claim intents and execute them. There is no
// simulation mode — an LLM provider is required. The planner/worker can be
// (re)installed at runtime (LLM configured from the UI); the loops always run
// but idle until an LLM is set.
type Engine struct {
	m        *Manager
	debounce time.Duration

	bc *Broadcaster // live activity pub/sub (SSE)

	started  sync.Map // taskID -> bool, so Run is idempotent per task
	lastAct  sync.Map // taskID -> int64 unix, last planner/worker activity (heartbeat)
	llmCalls sync.Map // taskID -> *int64, actual planner/worker/main-agent LLM calls
	paused   sync.Map // taskID -> bool, user-paused (planner + workers idle but loops alive)
	deleting sync.Map // taskID -> bool, delete barrier (no new task-owned writes)
	dropCnt  sync.Map // taskID -> *int64, running count of dropped (unpersistable) activity records

	// deleteMu makes installing the delete barrier atomic with registering a new
	// task operation. Once BeginDelete returns, every admitted writer is reflected
	// in inflight and every later writer is rejected.
	deleteMu sync.RWMutex

	// Every long-lived task goroutine (planner, workers and deadline coordinator)
	// runs under one task-scoped context. Successful deletion cancels that context,
	// waits for all goroutines, then releases every task-level Engine reference.
	runtimeMu sync.Mutex
	runtimes  map[string]*taskRuntime

	// per-task execution context: each planner.Plan / worker.Execute runs under it,
	// so pausing can CANCEL an in-flight run (not just skip the next one). Recreated
	// on resume since cancelling is one-shot. Every cancellation carries a named
	// cause so the activity trace can identify the initiating control path.
	execMu     sync.Mutex
	execCancel map[string]context.CancelCauseFunc
	execCtx    map[string]context.Context

	// Per-work control lets the planner kill a worker and lets the UI pause/cancel
	// one intent without pausing the whole task. The done channel closes only after
	// runWorkerStep has stopped writing and committed its final state.
	workMu sync.Mutex
	work   map[int64]*workExecution

	// steerBox queues planner course-corrections for a running work (keyed by intent
	// id). The worker's PreToolUse hook drains it before its next tool call and hands
	// the message to the model (blocking that call) so it re-plans — no kill needed.
	steerMu  sync.Mutex
	steerBox map[int64][]string

	// 漏洞判重审计（批次）：待审集合、静默窗口计时器与运行标记；resolveAud 由
	// server 注入（按任务解析 auditor，复用该任务的 LLM 链与 transcript）。
	auditMu     sync.Mutex
	auditQ      map[string]*auditQueue
	auditRecent map[string]map[int64]time.Time // taskID -> findingID -> 上次批次完成时间（120s 去抖）
	resolveAud  func(t *Task) *agent.Auditor

	plannerRound sync.Map // taskID -> int, planner round counter (for UI round separators)

	// 任务级超时(见 docs/任务级超时与收尾设计.md):
	settling     sync.Map // taskID -> bool, 任务已进入收尾时序(停止派/领新意图)
	deadline     sync.Map // taskID -> int64 unix, 绝对截止时刻(首次运行时盖章;0/缺省=不限)
	stamped      sync.Map // taskID -> bool, first_run_at 是否已盖章(本进程内只盖一次)
	inflight     sync.Map // taskID -> *int64, 在跑的 planner.Plan + worker.Execute 计数(用于 drain)
	coordStarted sync.Map // taskID -> bool, deadline 协调器是否已启动(Run/reload 去重)

	// resolve returns a task's dedicated planner/worker (wired by the server as the
	// authoritative task-router). nil,nil means this task is deliberately unavailable
	// (for example an exhausted failover chain) — there is no global-pair fallback.
	resolve              func(t *Task) (*agent.Planner, *agent.Worker)
	resolveAuthoritative bool
	// readiness reports whether a global LLM provider is configured — the signal behind
	// Ready()/the llm_configured indicator. Wired once at startup; nil → not ready.
	readiness func() bool
}

type taskRuntime struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type workExecution struct {
	cancel context.CancelCauseFunc
	done   chan error
	action string // user action: pause | cancel
}

// nextPlannerRound returns the next planner round number for a task (1-based).
func (e *Engine) nextPlannerRound(taskID string) int {
	v, _ := e.plannerRound.LoadOrStore(taskID, 0)
	n := v.(int) + 1
	e.plannerRound.Store(taskID, n)
	return n
}

// Pause stops a task: marks it paused AND cancels any in-flight planner/worker run
// for it (a long worker.Execute would otherwise keep going until it finishes).
func (e *Engine) Pause(taskID string, cause error) {
	e.paused.Store(taskID, true)
	e.cancelExec(taskID, cause)
}

// BeginDelete installs an execution barrier before task data/files are removed.
// The temporary pause is not a user pause. The server serializes this transition
// with lifecycle admission and tells AbortDelete whether the persisted task is
// paused/queued if cleanup fails.
func (e *Engine) BeginDelete(taskID string) bool {
	e.deleteMu.Lock()
	if _, loaded := e.deleting.LoadOrStore(taskID, true); loaded {
		e.deleteMu.Unlock()
		return false
	}
	e.paused.Store(taskID, true)
	e.deleteMu.Unlock()
	e.cancelExec(taskID, agent.AbortTaskDeleted)
	e.forgetAuditQueue(taskID) // 任务要删了：判重队列直接清掉，别再起批
	return true
}

// forgetAuditQueue 丢弃某任务的判重队列（任务删除时调用；不写库，行本身会被删）。
func (e *Engine) forgetAuditQueue(key string) {
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	if q := e.auditQ[key]; q != nil {
		if q.timer != nil {
			q.timer.Stop()
		}
		delete(e.auditQ, key)
	}
	delete(e.auditRecent, key)
}

func (e *Engine) AbortDelete(taskID string, keepPaused bool) {
	e.deleteMu.Lock()
	if !e.IsDeleting(taskID) {
		e.deleteMu.Unlock()
		return
	}
	e.deleting.Delete(taskID)
	if !keepPaused {
		e.paused.Delete(taskID)
	}
	e.deleteMu.Unlock()
	if !keepPaused && e.m != nil {
		if t, ok := e.m.Task(taskID); ok {
			t.Notify()
		}
	}
}

func (e *Engine) IsDeleting(taskID string) bool {
	_, ok := e.deleting.Load(taskID)
	return ok
}

// registerTaskRoutines reserves count goroutines in the task runtime. Callers
// hold deleteMu for reading so StopTask cannot race WaitGroup.Add with Wait.
func (e *Engine) registerTaskRoutines(parent context.Context, taskID string, count int) *taskRuntime {
	e.runtimeMu.Lock()
	defer e.runtimeMu.Unlock()
	rt := e.runtimes[taskID]
	if rt == nil {
		ctx, cancel := context.WithCancel(parent)
		rt = &taskRuntime{ctx: ctx, cancel: cancel}
		e.runtimes[taskID] = rt
	}
	rt.wg.Add(count)
	return rt
}

func runTaskRoutine(rt *taskRuntime, fn func(context.Context)) {
	go func() {
		defer rt.wg.Done()
		fn(rt.ctx)
	}()
}

// StopTask permanently stops every long-lived goroutine and removes all Engine
// state for a successfully deleted task. The delete barrier remains installed
// until cleanup finishes, so no new task operation can race the teardown.
func (e *Engine) StopTask(taskID string) {
	e.deleteMu.Lock()
	e.deleting.Store(taskID, true)
	e.deleteMu.Unlock()

	e.cancelExec(taskID, agent.AbortTaskDeleted)
	e.runtimeMu.Lock()
	rt := e.runtimes[taskID]
	if rt != nil {
		rt.cancel()
	}
	e.runtimeMu.Unlock()
	if rt != nil {
		rt.wg.Wait()
	}

	e.execMu.Lock()
	if cancel := e.execCancel[taskID]; cancel != nil {
		cancel(agent.AbortTaskDeleted)
	}
	delete(e.execCancel, taskID)
	delete(e.execCtx, taskID)
	e.execMu.Unlock()

	e.runtimeMu.Lock()
	if e.runtimes[taskID] == rt {
		delete(e.runtimes, taskID)
	}
	e.runtimeMu.Unlock()

	e.started.Delete(taskID)
	e.lastAct.Delete(taskID)
	e.llmCalls.Delete(taskID)
	e.paused.Delete(taskID)
	e.dropCnt.Delete(taskID)
	e.plannerRound.Delete(taskID)
	e.settling.Delete(taskID)
	e.deadline.Delete(taskID)
	e.stamped.Delete(taskID)
	e.inflight.Delete(taskID)
	e.coordStarted.Delete(taskID)
	e.deleteMu.Lock()
	e.deleting.Delete(taskID)
	e.deleteMu.Unlock()
}

// cancelExec cancels a task's current per-task exec context (any in-flight
// planner.Plan / worker.Execute), if present. Shared by Pause and the settle
// sequence's hard-drain backstop.
func (e *Engine) cancelExec(taskID string, cause error) {
	e.execMu.Lock()
	if cancel := e.execCancel[taskID]; cancel != nil {
		cancel(cause)
	}
	e.execMu.Unlock()
}

// Resume un-pauses a task and nudges a fresh planning round. The next exec under
// it gets a fresh (uncancelled) context.
func (e *Engine) Resume(t *Task) {
	// BeginDelete owns the pause barrier once deletion starts. A concurrent
	// resume must never clear it and let a planner/worker re-enter while cleanup
	// is waiting for task operations to drain.
	if t == nil {
		return
	}
	e.deleteMu.RLock()
	defer e.deleteMu.RUnlock()
	if e.IsDeleting(t.ID) {
		return
	}
	e.paused.Delete(t.ID)
	t.Notify()
}

// execContextFor returns a live per-task context derived from parent, recreating
// it if a prior pause cancelled it.
func (e *Engine) execContextFor(parent context.Context, taskID string) context.Context {
	e.execMu.Lock()
	defer e.execMu.Unlock()
	if e.IsPaused(taskID) {
		// never hand out a live context while paused (guards the claim→Execute race)
		c, cancel := context.WithCancelCause(parent)
		cancel(agent.AbortPausedRaceGuard)
		return c
	}
	if c := e.execCtx[taskID]; c != nil && c.Err() == nil {
		return c
	}
	c, cancel := context.WithCancelCause(parent)
	e.execCtx[taskID] = c
	e.execCancel[taskID] = cancel
	return c
}

// IsPaused reports whether a task is user-paused.
func (e *Engine) IsPaused(taskID string) bool {
	v, ok := e.paused.Load(taskID)
	return ok && v.(bool)
}

// Started reports whether the engine loops are running for a task.
func (e *Engine) Started(taskID string) bool {
	_, ok := e.started.Load(taskID)
	return ok
}

// LastActivity returns the unix time of the last planner/worker activity for a
// task (0 if none yet).
func (e *Engine) LastActivity(taskID string) int64 {
	if v, ok := e.lastAct.Load(taskID); ok {
		return v.(int64)
	}
	return 0
}

// BeginLLMCall/EndLLMCall track actual provider calls separately from the
// scheduler's task-operation counter. A task can have live loops while all of
// them are waiting for a trigger; that state must remain idle in the UI.
func (e *Engine) BeginLLMCall(taskID string) {
	v, _ := e.llmCalls.LoadOrStore(taskID, new(int64))
	atomic.AddInt64(v.(*int64), 1)
}

func (e *Engine) EndLLMCall(taskID string) {
	if v, ok := e.llmCalls.Load(taskID); ok {
		p := v.(*int64)
		if atomic.AddInt64(p, -1) <= 0 {
			atomic.StoreInt64(p, 0)
		}
	}
}

func (e *Engine) ActiveLLMCalls(taskID string) int64 {
	if v, ok := e.llmCalls.Load(taskID); ok {
		return atomic.LoadInt64(v.(*int64))
	}
	return 0
}

func (e *Engine) touch(taskID string) { e.lastAct.Store(taskID, time.Now().Unix()) }

func NewEngine(m *Manager) *Engine {
	return &Engine{m: m, debounce: 800 * time.Millisecond, bc: NewBroadcaster(),
		execCancel: map[string]context.CancelCauseFunc{}, execCtx: map[string]context.Context{},
		work: map[int64]*workExecution{}, steerBox: map[int64][]string{},
		runtimes: map[string]*taskRuntime{}}
}

// registerWork records the cancel for the work currently running intentID.
func (e *Engine) registerWork(intentID int64, cancel context.CancelCauseFunc) {
	e.workMu.Lock()
	e.work[intentID] = &workExecution{cancel: cancel, done: make(chan error, 1)}
	e.workMu.Unlock()
}

// detachWork removes the live control handle once Execute has returned. complete
// must be called after the final intent state write so a waiting cancel handler can
// safely delete the worker's blackboard output without racing a late write.
func (e *Engine) detachWork(intentID int64) (action string, complete func(error)) {
	e.workMu.Lock()
	run := e.work[intentID]
	if run != nil {
		delete(e.work, intentID)
		action = run.action
		run.cancel(agent.AbortWorkFinished) // release resources (no-op if already cancelled)
	}
	e.workMu.Unlock()
	e.steerMu.Lock()
	delete(e.steerBox, intentID) // drop any undelivered steering for a finished work
	e.steerMu.Unlock()
	if run == nil {
		return action, func(error) {}
	}
	return action, func(err error) { run.done <- err }
}

// ControlWork requests a user-visible pause or cancellation and waits until the
// worker has fully stopped writing. Cancellation cleanup is performed by the API
// handler after this returns; pause state is committed by runWorkerStep itself.
func (e *Engine) ControlWork(ctx context.Context, intentID int64, action string) error {
	if action != "pause" && action != "cancel" {
		return fmt.Errorf("unsupported work action %q", action)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e.workMu.Lock()
	run := e.work[intentID]
	if run == nil {
		e.workMu.Unlock()
		return fmt.Errorf("%w: 意图 %d 当前没有运行中的 work（可能已结束或未被领取）", errWorkControlConflict, intentID)
	}
	if run.action != "" {
		e.workMu.Unlock()
		return fmt.Errorf("%w: 意图 %d 正在执行 %s 操作", errWorkControlConflict, intentID, run.action)
	}
	run.action = action
	done := run.done
	cause := error(agent.AbortWorkPausedByUser)
	if action == "cancel" {
		cause = agent.AbortWorkCancelledByUser
	}
	run.cancel(cause)
	e.workMu.Unlock()

	timer := time.NewTimer(workControlWaitTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		e.releaseWorkControl(intentID, run, action)
		return fmt.Errorf("等待意图 %d %s 收尾: %w", intentID, action, ctx.Err())
	case <-timer.C:
		e.releaseWorkControl(intentID, run, action)
		return fmt.Errorf("等待意图 %d %s 收尾: %w", intentID, action, context.DeadlineExceeded)
	}
}

// releaseWorkControl drops only this caller's reservation after its wait is
// cancelled. The work context stays cancelled; runWorkerStep recognizes the
// named cancellation cause and settles the intent into the recoverable paused
// state even if the HTTP caller has gone away.
func (e *Engine) releaseWorkControl(intentID int64, run *workExecution, action string) {
	e.workMu.Lock()
	if current := e.work[intentID]; current == run && current.action == action {
		current.action = ""
	}
	e.workMu.Unlock()
}

func transitionIntentState(store *db.ExplorationStore, intentID int64, expected, state string) error {
	changed, err := store.CompareAndSetIntentState(intentID, expected, state)
	if err != nil {
		return err
	}
	if !changed {
		return fmt.Errorf("%w: 意图 %d 不再是 %s 状态", db.ErrIntentStateConflict, intentID, expected)
	}
	return nil
}

// SteerWork queues a mid-run course-correction for the work running intentID (the
// planner's steer_work tool). The worker delivers it before its next tool call and
// re-plans — no kill. Errors if no work is currently running that intent.
func (e *Engine) SteerWork(intentID int64, msg string) error {
	if strings.TrimSpace(msg) == "" {
		return fmt.Errorf("纠偏消息不能为空")
	}
	e.workMu.Lock()
	running := e.work[intentID] != nil
	e.workMu.Unlock()
	if !running {
		return fmt.Errorf("意图 %d 当前没有运行中的 work（可能已结束或未被领取）", intentID)
	}
	e.steerMu.Lock()
	e.steerBox[intentID] = append(e.steerBox[intentID], msg)
	e.steerMu.Unlock()
	return nil
}

// drainSteer pops the oldest queued steering message for intentID (FIFO), if any.
func (e *Engine) drainSteer(intentID int64) (string, bool) {
	e.steerMu.Lock()
	defer e.steerMu.Unlock()
	q := e.steerBox[intentID]
	if len(q) == 0 {
		return "", false
	}
	msg := q[0]
	if len(q) == 1 {
		delete(e.steerBox, intentID)
	} else {
		e.steerBox[intentID] = q[1:]
	}
	return msg, true
}

// steerHooks wraps the guard's hook runner so the planner can steer a running work:
// before each tool call it drains a queued course-correction (if any) and blocks the
// call, handing the message back to the model — which re-plans its next step instead
// of running the tool. No queued message → the guard behaves exactly as before.
// 它同时负责「空转回合」的续跑，见 Stop。
type steerHooks struct {
	inner harness.HookRunner
	drain func() (string, bool)
	// nudges 是本条意图已注入的空转续跑次数，上限 limit。指针:harness 持有的是
	// steerHooks 的值拷贝，计数必须共享同一份。
	nudges *atomic.Int64
	// limit 是空转续跑的次数上限，由 Engine.emptyTurnNudgeLimit() 从「空响应重试
	// 次数」解析而来。<=0 = 不介入(用户显式关掉了这层)。
	limit int
	// label 形如 "worker-1 · #42"，只用于日志。
	label string
	// expWrote 读库判断本意图的经验是否已写入（nil = 不做经验校验）。读不到时返回
	// true（fail-open）：数据库抖动不该把一条正常结束的意图打成未完成。
	expWrote func() bool
	// expNudges 是「经验未写」提醒的已注入次数，上限 expLimit；同样是共享指针。
	expNudges *atomic.Int64
	expLimit  int
}

// 空转回合(只有思考、既无正文也无工具调用)续跑次数的默认值，与 SDK 空响应重试的
// 内置默认(norma/llm/openai.go 的 emptyResponseRetries)保持一致——两层共用同一个
// 旋钮，不配置时的行为也该对齐。解析见 Engine.emptyTurnNudgeLimit。
//
// 注意这个数是「一条意图的总量」，不是「连续几次」:harness 自身的 stopHookActive
// 已经限死了连续空转只推一次——推完那一轮若还是空转，Stop 钩子不会再被调到，run 直接
// 收场;只有真正发生过一次工具回合，配额才刷新(norma/harness/query.go:534)。所以这个
// 闸挡的是「工具 → 空转 → 推 → 工具 → 空转」这种病态循环，别让它把意图预算耗光。
const defaultEmptyTurnNudges = 2

// experienceNudgesLimit 是「经验未写」提醒在一条意图内的注入上限（C2）。harness 的
// stopHookActive 保证推一次之后必须隔一个工具回合才会再推，所以这里只是总配额：
// 推完两次还不写，就放行收场，交给落终态时的 C4 校验判 blocked。
const experienceNudgesLimit = 2

// emptyTurnNudge 是空转回合注入的续跑指令。
//
// 这种回合在 harness 眼里是一次自然结束(stop_reason=end_turn 且无 tool_use)，五层
// LLM 重试一层都不适用——它不是错误，是模型「想完了但没动手」。SDK 的空响应重试也
// 够不着:它以「有没有 yield 过事件」判空，而思考增量本身就是事件(norma/llm/openai.go
// 的 SEThinkingDelta)，所以 thinking-only 不算空。何况那层是原样重发整个 prompt，
// 对这种由上下文形状决定的空转，重发只会让模型再想一遍。这里换成追加一条指令，让它
// 带着已经产出的思考继续，输入变了才有理由给出不同的行为。
const emptyTurnNudge = "【空转提醒】你上一轮只输出了思考过程，既没有给出正文回复，也没有调用任何工具，" +
	"这一轮等于没有产出。请直接执行你刚才想好的下一步：要么调用工具，要么给出结论文字。不要重复思考。"

// isThinkingOnlyTurn reports whether the latest assistant turn produced neither
// text nor a tool call — i.e. the model spent the whole round thinking.
func isThinkingOnlyTurn(messages []llm.Message) bool {
	for i := len(messages) - 1; i >= 0; i-- {
		m := messages[i]
		if m.Role != llm.RoleAssistant {
			continue
		}
		return strings.TrimSpace(m.Text()) == "" && len(m.ToolUses()) == 0
	}
	return false
}

func (h steerHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if msg, ok := h.drain(); ok {
		return true, "【规划者实时纠偏】" + msg +
			"\n（这是规划者对本意图的即时指令；本次工具调用未执行，请据此调整下一步。若与你当前打算冲突，以此为准。）", nil
	}
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (h steerHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

// Stop 在 guard 原有语义之上补一层「空转回合」续跑:模型只输出了思考、既没给正文
// 也没调工具时，harness 会把它当成自然结束并以空 summary 收场(query.go 的
// ReasonCompleted + asst.Text())，一条本来还没做完的意图就这样断在半路。此时注入
// 一条续跑指令，让模型带着已有思考接着走。
func (h steerHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	var (
		prevent  bool
		blocking []string
		msg      string
	)
	if h.inner != nil {
		prevent, blocking, msg = h.inner.Stop(ctx, messages)
	}
	// inner 已经决定硬停、或已经要注入自己的续跑消息 → 尊重它，不再叠加。
	if prevent || len(blocking) > 0 {
		return prevent, blocking, msg
	}
	// 经验校验（C2）：模型要收场了，但【本轮】还没写经验 → 叫回来写。
	// 顺序上让"空转续跑"先来（见下）：只思考没产出时催它写经验，只会让它给没做完的活
	// 写个占位经验，反而把意图判成完成。所以这里只在"这一轮确实有正文产出"时才拦。
	if !isThinkingOnlyTurn(messages) && h.expWrote != nil && h.expNudges != nil && h.expLimit > 0 && !h.expWrote() {
		n := h.expNudges.Add(1)
		if n <= int64(h.expLimit) {
			log.Printf("[work %s] 本轮未写经验，注入提醒 (%d/%d)", h.label, n, h.expLimit)
			return false, []string{agent.ExperienceReminder}, ""
		}
		log.Printf("[work %s] 经验提醒已达上限 %d，放行收场", h.label, h.expLimit)
		return prevent, blocking, msg
	}
	// limit<=0 = 用户把「空响应重试次数」配成了 -1，即显式关掉这层。
	if h.nudges == nil || h.limit <= 0 || !isThinkingOnlyTurn(messages) {
		return prevent, blocking, msg
	}
	n := h.nudges.Add(1)
	if n > int64(h.limit) {
		log.Printf("[work %s] 空转回合(仅思考、无正文无工具)已达续跑上限 %d，放行收场", h.label, h.limit)
		return prevent, blocking, msg
	}
	log.Printf("[work %s] 空转回合(仅思考、无正文无工具)，注入续跑指令 (%d/%d)", h.label, n, h.limit)
	return false, []string{emptyTurnNudge}, ""
}

// KillWork cancels the in-flight work running intentID (planner's kill_work tool).
// The work's agent-core session honors ctx cancellation and aborts promptly.
func (e *Engine) KillWork(intentID int64) error {
	e.workMu.Lock()
	run := e.work[intentID]
	e.workMu.Unlock()
	if run == nil {
		return fmt.Errorf("意图 %d 当前没有运行中的 work（可能已结束或未被领取）", intentID)
	}
	run.cancel(agent.AbortKilledByPlanner)
	return nil
}

// Broadcaster exposes the engine's live activity pub/sub (used by the SSE handler).
func (e *Engine) Broadcaster() *Broadcaster { return e.bc }

// emitActivity persists one captured step AND fans it out to live subscribers,
// from a single point so storage and the SSE stream never diverge.
func (e *Engine) emitActivity(t *Task, r db.Activity) db.Activity {
	id, err := e.appendActivity(t, r)
	if err != nil {
		// NO LONGER SILENT: dropping a record breaks command↔result pairing in the
		// trace — a tool_use whose tool_result was lost shows as "执行中" forever, and
		// a lost 'result'/'round' record leaves the session with no summary ("无总结").
		// Everything needed to分析根因 goes into ONE error-level line: reason class,
		// summary preview, running drop count for this task, and — on the FK case — a
		// live probe of WHY the parent exploration is unreachable.
		n := e.bumpDrop(t.ID)
		diag := ""
		// On the FK-parent failure (23503) probe the live DB so the log records WHY the
		// exploration is unreachable (row gone / wrong expID) instead of just that it is.
		if isFKViolation(err) {
			storeID := t.Store.ID()
			if exists, refs, maxID, dErr := e.m.pg.ExplorationDiag(storeID); dErr != nil {
				diag = fmt.Sprintf(" | FK诊断查询失败(store.expID=%d task.ExpID=%d): %v", storeID, t.ExpID, dErr)
			} else {
				diag = fmt.Sprintf(" | FK诊断: store.expID=%d task.ExpID=%d exploration存在=%v 引用它的task数=%d MAX(exploration.id)=%d",
					storeID, t.ExpID, exists, refs, maxID)
			}
		}
		log.Printf("[activity] task %s 丢弃活动记录(该任务累计第 %d 条) worker=%s kind=%s tool=%s tuid=%s reason=%s summary=%q: %v%s",
			t.ID, n, r.Worker, r.Kind, r.Tool, r.ToolUseID, dropReason(err), preview(r.Summary, 80), err, diag)
		e.touch(t.ID)
		return r
	}
	r.ID = id
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	e.bc.Publish(t.ID, r)
	e.touch(t.ID)
	return r
}

// appendActivity persists one activity row, retrying briefly on write failure.
// Concurrent planner + worker inserts into the same exploration's activity log
// occasionally fail; a couple of quick retries recover most. Crucially, every
// failure is now LOGGED (it used to be swallowed by an `if err == nil`), so the
// underlying DB error is finally visible for diagnosis.
func (e *Engine) appendActivity(t *Task, r db.Activity) (int64, error) {
	var id int64
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if id, err = t.Store.AppendActivity(r); err == nil {
			if attempt > 1 {
				log.Printf("[activity] task %s 写入第 %d 次重试成功 (worker=%s kind=%s tool=%s)",
					t.ID, attempt, r.Worker, r.Kind, r.Tool)
			}
			return id, nil
		}
		log.Printf("[activity] task %s 写入失败 (第 %d/3 次, worker=%s kind=%s tool=%s expID=%d): %v",
			t.ID, attempt, r.Worker, r.Kind, r.Tool, t.Store.ID(), err)
		time.Sleep(time.Duration(attempt) * 25 * time.Millisecond)
	}
	return 0, err
}

// SetReadiness wires the global "an LLM provider is configured" predicate (read by
// Ready() / the llm_configured indicator). Called once at startup.
func (e *Engine) SetReadiness(fn func() bool) { e.readiness = fn }

// SetAgentResolver installs a per-task planner/worker resolver (wired by the server).
// Called once at startup before any task loop runs, so no lock is needed on reads.
func (e *Engine) SetAgentResolver(fn func(t *Task) (*agent.Planner, *agent.Worker)) {
	e.resolve = fn
	e.resolveAuthoritative = false
}

// SetAuthoritativeAgentResolver installs a resolver whose nil result must not
// fall through to the global provider. Task-level failover chains use this so a
// fully exhausted chain cannot silently bypass its configured boundary.
func (e *Engine) SetAuthoritativeAgentResolver(fn func(t *Task) (*agent.Planner, *agent.Worker)) {
	e.resolve = fn
	e.resolveAuthoritative = true
}

// snapshotFor returns the planner/worker a task should run on, from the task-router
// resolver. nil,nil means the task is deliberately unavailable (e.g. an exhausted
// failover chain); there is no global-pair fallback.
func (e *Engine) snapshotFor(t *Task) (*agent.Planner, *agent.Worker) {
	if e.resolve != nil {
		p, w := e.resolve(t)
		if (p != nil && w != nil) || e.resolveAuthoritative {
			return p, w
		}
	}
	return nil, nil
}

// Ready reports whether a global LLM provider is configured (via the readiness
// predicate wired at startup).
func (e *Engine) Ready() bool {
	return e.readiness != nil && e.readiness()
}

// ReadyFor reports whether a specific task can resolve a planner/worker pair.
// An explicit task profile chain can be runnable even when no global default
// provider is configured, so task status must not rely on Ready alone.
func (e *Engine) ReadyFor(t *Task) bool {
	p, w := e.snapshotFor(t)
	return p != nil && w != nil
}

// Run starts the planner loop + N worker loops for a task. The loops always run
// but no-op until an LLM is configured (so a task created while idle picks up
// automatically once LLM is set from the UI).
func (e *Engine) Run(ctx context.Context, t *Task) {
	workers := e.m.Workers()
	e.deleteMu.RLock()
	if e.IsDeleting(t.ID) {
		e.deleteMu.RUnlock()
		return
	}
	if _, loaded := e.started.LoadOrStore(t.ID, true); loaded {
		e.deleteMu.RUnlock()
		t.Notify() // already running — just nudge a planning round
		return
	}
	rt := e.registerTaskRoutines(ctx, t.ID, 1+workers)
	e.deleteMu.RUnlock()
	e.touch(t.ID)
	runTaskRoutine(rt, func(loopCtx context.Context) { e.plannerLoop(loopCtx, t) })
	for i := 0; i < workers; i++ {
		name := fmt.Sprintf("work#%d", i+1)
		runTaskRoutine(rt, func(loopCtx context.Context) { e.workerLoop(loopCtx, t, name) })
	}
	e.startDeadlineCoordinator(ctx, t) // 任务级超时定时器(仅 timeout>0;去重)
	// 仅在「完全没有活动意图(open+running)」时才 kick 首轮规划。带种子意图的任务:种子已
	// 是 open,或已被上面刚起的 worker 抢先 claim 成 running——两种都算「有活干」,一律跳过
	// 首轮 planner,worker 直接领种子意图开跑,跑完由 NotifyDone/心跳唤醒 planner。
	// ⚠️ 不能用 Frontier(只数 open):worker 领取(open→running)与本检查存在竞态,会误 kick。
	// 重启自动恢复时也可能只剩 running 意图,同样应跳过。
	if has, _ := t.Store.HasActiveIntent(); !has {
		t.Notify() // kick the first planning round (acted on once LLM is ready)
	}
}

// plannerHeartbeatInterval 解析任务的 planner 心跳间隔。db.CreateTask 已归一
// (低于 600 一律抬到 600);这里再兜一次底,防内存态异常值。
func plannerHeartbeatInterval(t *Task) time.Duration {
	sec := t.PlanHeartbeatSeconds
	if sec < db.MinPlanHeartbeatSeconds { // 下限=默认=600(10min)
		sec = db.MinPlanHeartbeatSeconds
	}
	return time.Duration(sec) * time.Second
}

// resetPlannerTimer 安全重臂一个可能已触发的 Timer(标准 Stop→drain→Reset 模式)。
func resetPlannerTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func (e *Engine) plannerLoop(ctx context.Context, t *Task) {
	interval := plannerHeartbeatInterval(t)
	// 心跳定时器在 loop 入口臂 = 从任务 start 计时:即使是跳过首轮 planner 的 seed 任务
	// (Run 里 frontier 非空不 kick 首轮)、这里一直阻塞,心跳也会在「任务 start + interval」
	// 触发第一轮规划。之后每次唤醒(边沿/心跳)都重臂 = 距上次任意规划触发的时长。
	heartbeat := time.NewTimer(interval)
	defer heartbeat.Stop()

	// firstLoop flags the task's first planning wake-up (in-memory, resets on process
	// restart). Plan() ANDs it with "the graph has no intent yet", so a restart can't
	// re-treat an already-explored task as a first round.
	firstLoop := true

	// runRound 跑一轮规划(含 debounce 合并 + 各 guard)。src 仅用于日志区分触发来源。
	runRound := func(src string) {
		// debounce: coalesce a burst of changes into one planning round
		timer := time.NewTimer(e.debounce)
	drain:
		for {
			select {
			case <-t.notify:
			case <-timer.C:
				break drain
			}
		}
		planner, _ := e.snapshotFor(t)
		if planner == nil {
			return // idle until LLM configured
		}
		if e.IsPaused(t.ID) {
			return // user-paused: don't plan
		}
		if e.IsDeleting(t.ID) {
			return
		}
		// terminal task (goals all met → done, or failed): the run is over. A
		// resume/nudge — e.g. auto-resume of the active task on restart — must NOT
		// re-plan (it would burn an LLM round and re-confirm a settled result).
		if isTerminalStatus(t.lifecycleSnapshot().Status) {
			return
		}
		// 任务级超时收尾中:丢弃普通唤醒——worker 收尾写回、Resume 的 Notify 都不再
		// 触发常规规划轮;终局那一轮由协调器(settleTask)直接驱动,不走这里。
		if e.isSettling(t.ID) {
			return
		}
		// goalless（人工直投）分支：任务已无 open 目标时 planner 不跑——跑了会重判
		// met→cancelExec 杀掉用户经主 agent 直投的意图。是否结束改由 frontier 决定：
		// 还有 open/running 意图 → 保持 running、静默等待；意图已全部跑干 → 落 done。
		// 整段纯 Go、不触发任何 LLM 调用，也不打规划轮 marker。
		if open, err := t.Store.HasOpenGoal(); err == nil && !open {
			t.drainTriggers() // 丢弃累积的 done/finding 触发，避免 goalless 长会话里无界增长
			if active, err := t.Store.HasActiveIntent(); err == nil && !active {
				// frontier 抽干且无在跑意图 → 收尾。用 Guarded 版做 CAS，避免踩到并发的
				// pause/delete/超时收尾的状态转换。
				if won, err := e.m.SetTaskStatusGuarded(t.ID, "done"); err != nil {
					log.Printf("[goalless] task %s 收尾落 done 失败: %v", t.ID, err)
				} else if won {
					e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
						Summary: "目标已全部达成，直投意图已执行完毕，任务结束"})
				}
			}
			return // goalless 分支永不进入 planner.Plan
		}
		if !e.beginTaskOperation(t.ID) {
			return
		}
		defer e.decInflight(t.ID)
		e.stampFirstRun(t) // 首次真正规划 → 盖 first_run_at + 算 deadline(仅带 timeout 的任务)
		e.touch(t.ID)
		emit := func(r db.Activity) { e.emitActivity(t, r) }
		ectx := e.clockCtx(e.execContextFor(ctx, t.ID), t, false) // cancellable by Pause; 带任务 deadline
		if ectx.Err() != nil || e.IsDeleting(t.ID) {
			return
		}
		log.Printf("[planner] task %s 规划中…(%s 触发)", t.ID, src)
		// round marker: each Plan() is one planner round; emit a boundary so the
		// UI can separate rounds in the transcript (kind='round').
		e.emitActivity(t, db.Activity{Worker: "planner", Kind: "round",
			Summary: fmt.Sprintf("第 %d 轮规划", e.nextPlannerRound(t.ID))})
		// what fired this round (worker done / finding; may be several — debounce
		// coalesces a burst; empty for time/heartbeat wakes).
		triggers := t.drainTriggers()
		taskIDInt, _ := strconv.ParseInt(t.ID, 10, 64)
		e.BeginLLMCall(t.ID)
		// 消费首轮名额：先取值再置 false，保证只有这一次唤醒能走首轮文案。
		firstPlan := firstLoop
		firstLoop = false
		met, reason, err := planner.Plan(ectx, taskIDInt, e.m.components, t.Store, t.Goal, firstPlan, triggers, emit)
		e.EndLLMCall(t.ID)
		switch {
		case err != nil && ectx.Err() == nil:
			log.Printf("[planner] task %s 规划出错: %v", t.ID, err)
		case met:
			log.Printf("[planner] task %s 判定目标达成: %s", t.ID, reason)
			// 所有目标达成 → 持久化任务状态为 done（前端 DTO 会优先展示该终态）。
			if err := e.m.SetTaskStatus(t.ID, "done"); err != nil {
				log.Printf("[planner] task %s 标记完成落库失败: %v", t.ID, err)
			}
			// 任务已判完成 → 立刻取消在跑的 worker：它们手头的意图跑出来也没意义了。
			// 下一轮 worker 循环撞终态门就不再领新意图;被取消的这批走下方"任务已完成"分支
			// 归为 stopped(而非 blocked)。
			e.cancelExec(t.ID, agent.AbortGoalMet)
		default:
			log.Printf("[planner] task %s 规划完成", t.ID)
		}
		e.touch(t.ID)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.notify:
			runRound("edge") // worker 结束 / finding / kill / resume / seed 首轮
		case <-heartbeat.C:
			// 周期兜底:死锁兜底 + 唤醒去监督飞行中的 worker(steer/kill) + 周期复查。
			runRound("heartbeat")
		}
		// 每次唤醒(边沿或心跳)后重臂心跳:任意规划触发都重算这段静置计时。
		resetPlannerTimer(heartbeat, interval)
	}
}

func (e *Engine) workerLoop(ctx context.Context, t *Task, name string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, worker := e.snapshotFor(t)
		if worker == nil {
			if sleepCtx(ctx, 1500*time.Millisecond) {
				return
			}
			continue
		}
		if e.IsPaused(t.ID) {
			if sleepCtx(ctx, 1000*time.Millisecond) {
				return
			}
			continue // user-paused: don't claim/execute intents
		}
		if e.IsDeleting(t.ID) {
			return
		}
		if e.isSettling(t.ID) {
			if sleepCtx(ctx, 1000*time.Millisecond) {
				return
			}
			continue // 任务超时收尾中:不再领新意图(在跑的自行收尾,协调器等其 drain)
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			if sleepCtx(ctx, 1000*time.Millisecond) {
				return
			}
			continue // 任务已终态(done/failed/timeout):停止领取遗留意图,别在完成后空跑 frontier
		}
		if !e.beginTaskOperation(t.ID) {
			return
		}
		claimed := e.runWorkerStep(ctx, t, name, worker)
		e.decInflight(t.ID)
		if !claimed && sleepCtx(ctx, 800*time.Millisecond) {
			return
		}
	}
}

// runWorkerStep claims one intent from the frontier and fully settles it via
// runIntent. Returns false when nothing was claimable. The pool worker loop is its
// only caller.
func (e *Engine) runWorkerStep(ctx context.Context, t *Task, name string, worker *agent.Worker) bool {
	intent := e.claimNext(t, name)
	if intent == nil {
		return false
	}
	log.Printf("[worker %s] task %s 领取意图 #%d", name, t.ID, intent.ID)
	return e.runIntent(ctx, t, name, worker, intent, "", "")
}

// runIntent executes and fully settles one already-claimed (state=running) intent.
// Both the pool worker loop (via runWorkerStep) and the human-message handler (via
// runDetachedIntent, a dedicated goroutine outside the worker pool) call it, so the
// execute/retry/state-write logic lives in exactly one place. A non-empty message
// is injected as this turn's input through ExecuteWithMessage; requestID keys the
// transcript marker that dedups re-injection across model_error retries. The caller
// must already hold one task-operation admission for the whole sequence so a delete
// cannot observe quiescence between the LLM return and the final DB writes.
func (e *Engine) runIntent(ctx context.Context, t *Task, name string, worker *agent.Worker, intent *db.Node, requestID, message string) bool {
	hasChatMessage := message != ""
	e.stampFirstRun(t) // 首次真正执行 → 盖 first_run_at + 算 deadline(仅带 timeout 的任务)
	e.touch(t.ID)
	emit := func(r db.Activity) { e.emitActivity(t, r) }
	ectx := e.clockCtx(e.execContextFor(ctx, t.ID), t, false) // cancellable by Pause; 带任务 deadline
	if ectx.Err() != nil || e.IsDeleting(t.ID) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "open"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d 领取后回退失败: %v", name, t.ID, intent.ID, err)
		}
		return true
	}
	// per-work child context so the planner's kill_work can stop just this work.
	workCtx, workCancel := context.WithCancelCause(ectx)
	e.registerWork(intent.ID, workCancel)
	// wrap the guard hooks so steer_work can inject a mid-run course-correction
	// for THIS intent (drained before the worker's next tool call).
	iid := intent.ID
	taskEmit := func(a db.Activity) {
		nid := iid
		a.NodeID, a.Worker = &nid, name
		emit(a)
	}
	label := fmt.Sprintf("%s · #%d", name, iid)
	workCtx = intercept.WithTaskContext(workCtx, t.ID, label, taskEmit)
	// 本轮开始的时刻：经验校验按「本轮有没有写」(experience_at >= runStart) 判定。
	// 必须在 worker.Execute 之前取，且只属于这一次 run——重跑要重新写经验。
	runStart := time.Now()
	// nudges 有意建在 model_error 重跑循环之外:空转续跑的上限是「这条意图」的总量，
	// 重跑一轮不该把额度清零重来。
	hooks := steerHooks{
		inner:  t.Guard.Hooks(),
		drain:  func() (string, bool) { return e.drainSteer(iid) },
		nudges: &atomic.Int64{},
		limit:  e.emptyTurnNudgeLimit(),
		label:  label,
		// C2 经验校验：模型要收场但【本轮】还没写经验 → 注入提醒把它叫回来写。
		// 判据是 experience_at >= runStart，不是"列里非空"——上一轮留下的旧经验不算数。
		// 读库失败按「已写」处理（fail-open）：一次 DB 抖动不该把正常收尾打成未完成；
		// 真正的兜底在后面落终态时的 C4 校验。
		expWrote: func() bool {
			ok, err := t.Store.IntentExperienceWrittenSince(iid, runStart)
			if err != nil {
				return true
			}
			return ok
		},
		expNudges: &atomic.Int64{},
		expLimit:  experienceNudgesLimit,
	}
	wTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
	e.BeginLLMCall(t.ID)
	var reason harness.TerminalReason
	var wrote agent.WriteCounts
	var err error
	if hasChatMessage {
		reason, wrote, err = worker.ExecuteWithMessage(workCtx, name, wTaskID, e.m.components, t.Store, intent, hooks, emit, t.NotifyFinding, requestID, message)
	} else {
		reason, wrote, err = worker.Execute(workCtx, name, wTaskID, e.m.components, t.Store, intent, hooks, emit, t.NotifyFinding)
	}
	e.EndLLMCall(t.ID)
	// model_error 收场 → 额外重跑几次（退避后再试）。仅在意图仍属本 work、任务
	// 未暂停/未终止/未取消【且未进入收尾】时重试；否则让位给对应分支处理(收尾期不
	// 再重试,避免退避挤占其他 worker 的优雅收尾窗口)。
	maxRetries, retryBackoff := e.modelErrorRetryPolicy()
	for attempt := 1; attempt <= maxRetries &&
		retryableWorkerModelError(reason, err) &&
		workCtx.Err() == nil && ectx.Err() == nil && !e.IsPaused(t.ID) && !e.isSettling(t.ID); attempt++ {
		log.Printf("[worker %s] task %s 意图 #%d model_error 收场，%v 后重试 (%d/%d)",
			name, t.ID, intent.ID, retryBackoff, attempt, maxRetries)
		if sleepCtx(workCtx, retryBackoff) {
			break // 退避期间被取消（终止/暂停）→ 交给下方分支处理
		}
		e.BeginLLMCall(t.ID)
		if hasChatMessage {
			reason, wrote, err = worker.ExecuteWithMessage(workCtx, name, wTaskID, e.m.components, t.Store, intent, hooks, emit, t.NotifyFinding, requestID, message)
		} else {
			reason, wrote, err = worker.Execute(workCtx, name, wTaskID, e.m.components, t.Store, intent, hooks, emit, t.NotifyFinding)
		}
		e.EndLLMCall(t.ID)
	}
	// Capture kill state before detachWork cancels workCtx. kill = this work's
	// ctx was cancelled (planner kill_work) while the TASK ctx kept running; a
	// pause cancels the task ctx (ectx) instead. Checking workCtx.Err() AFTER
	// unregister would always be true (unregister cancels it) → every completed
	// work would be wrongly marked stopped.
	workCause := context.Cause(workCtx)
	killed := workCtx.Err() != nil && ectx.Err() == nil
	action, completeWork := e.detachWork(intent.ID)
	// A caller may stop waiting and release its in-memory reservation before the
	// agent honors cancellation. The named context cause remains authoritative and
	// still settles the stopped run into a recoverable state.
	if action == "" {
		switch {
		case errors.Is(workCause, agent.AbortWorkPausedByUser):
			action = "pause"
		case errors.Is(workCause, agent.AbortWorkCancelledByUser):
			action = "cancel"
		}
	}
	var controlErr error
	defer func() { completeWork(controlErr) }()
	if action == "pause" {
		controlErr = transitionIntentState(t.Store, intent.ID, "running", "paused")
		if controlErr != nil {
			log.Printf("[worker %s] task %s 意图 #%d 暂停状态落库失败: %v", name, t.ID, intent.ID, controlErr)
			return true
		}
		log.Printf("[worker %s] task %s 意图 #%d 已暂停", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	if action == "cancel" {
		// Park the stopped run in paused before handing cleanup to the API. If the
		// request disconnects after cancellation, the intent remains recoverable and
		// a later cancel can finish cleanup instead of leaving a phantom running row.
		controlErr = transitionIntentState(t.Store, intent.ID, "running", "paused")
		if controlErr != nil {
			log.Printf("[worker %s] task %s 意图 #%d 取消栅栏落库失败: %v", name, t.ID, intent.ID, controlErr)
			return true
		}
		log.Printf("[worker %s] task %s 意图 #%d 已停止，等待取消清理", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	// if a pause cancelled this run mid-flight, return the intent to the frontier
	// so it is re-claimed on resume — the worker will resume the prior LLM
	// conversation from its transcript instead of restarting from scratch.
	if ectx.Err() != nil && taskExecutionPaused(context.Cause(ectx)) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "open"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d 任务暂停回退失败: %v", name, t.ID, intent.ID, err)
		}
		return true
	}
	// 任务超时收尾的硬兜底 cancel(非 pause、非 kill)取消了本 run → 归为 exhausted(已收尾),
	// 不要误标 blocked。此时 worker 通常已在 settlement 阶段把结果写回。
	if ectx.Err() != nil && e.isSettling(t.ID) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "exhausted"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d 超时收尾状态落库失败: %v", name, t.ID, intent.ID, err)
		}
		log.Printf("[worker %s] task %s 意图 #%d 因任务超时收尾结束(exhausted)，写回 %s", name, t.ID, intent.ID, wrote)
		e.touch(t.ID)
		return true
	}
	// 任务已判完成(done via 常规路径)→ 上面 cancelExec 取消了本 run。意图结果已无意义,
	// 标 stopped(不是 blocked),别污染已完成任务的意图状态。
	if ectx.Err() != nil && isTerminalStatus(e.m.TaskStatus(t.ID)) {
		if err := transitionIntentState(t.Store, intent.ID, "running", "stopped"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d 终态停止落库失败: %v", name, t.ID, intent.ID, err)
		}
		log.Printf("[worker %s] task %s 意图 #%d 因任务已完成而取消(stopped)", name, t.ID, intent.ID)
		e.touch(t.ID)
		return true
	}
	// killed by the planner: mark stopped (don't write back results, don't auto-reclaim).
	if killed {
		if err := transitionIntentState(t.Store, intent.ID, "running", "stopped"); err != nil {
			log.Printf("[worker %s] task %s 意图 #%d planner 停止落库失败: %v", name, t.ID, intent.ID, err)
		}
		log.Printf("[worker %s] task %s 意图 #%d 被终止(stopped)", name, t.ID, intent.ID)
		e.touch(t.ID)
		t.Notify()
		return true
	}
	if err != nil {
		log.Printf("[worker %s] intent %d: %v", name, intent.ID, err)
	}
	// terminal分流：撞步数上限 ≠ 完成。max_turns→exhausted（规划者据此知道这个方向
	// 试过但没真正做完、需换角度，而非当成已覆盖永久跳过）；出错→blocked；正常→done。
	state := "done"
	switch {
	case err != nil:
		state = "blocked"
	case reason == harness.ReasonMaxTurns:
		state = "exhausted"
		log.Printf("[worker %s] intent %d 撞步数上限(exhausted)，本次写回 %s", name, intent.ID, wrote)
	case reason == harness.ReasonTimeout:
		state = "exhausted"
		log.Printf("[worker %s] intent %d 运行超时(exhausted)，收尾后写回 %s", name, intent.ID, wrote)
	}
	// C4 经验留痕：正常收尾但【本轮】没写经验 → 仍然判 done。成果（事实/漏洞）已经写回
	// 图里了，判成 blocked 只会让 planner 以为这条方向没做完、重复派活；C2/C3 也已经在
	// 同一会话里追问过两次。这里只在意图上留一条备注 blocked_reason=experience_missing，
	// 供审计/统计看，planner 侧刻意看不到它（compactIntents 只给非 done 输出该字段）。
	expMissing := false
	if state == "done" {
		if fresh, freshErr := t.Store.IntentExperienceWrittenSince(intent.ID, runStart); freshErr == nil && !fresh {
			expMissing = true
			log.Printf("[worker %s] task %s 意图 #%d 收尾但未写经验，只做留痕(done+experience_missing)，写回 %s", name, t.ID, intent.ID, wrote)
		}
	}
	if state == "blocked" && isTaskLLMChainExhausted(err) {
		_ = t.Store.SetIntentBlockedReason(intent.ID, db.IntentBlockedLLMQuota)
	} else {
		if stateErr := transitionIntentState(t.Store, intent.ID, "running", state); stateErr != nil {
			log.Printf("[worker %s] task %s 意图 #%d 终态 %s 落库失败: %v", name, t.ID, intent.ID, state, stateErr)
		}
		if expMissing {
			_ = t.Store.MarkIntentNote(intent.ID, db.IntentNoteExperienceMissing)
		}
	}
	log.Printf("[worker %s] task %s 意图 #%d 结束: %s (写回 %s)", name, t.ID, intent.ID, state, wrote)
	e.touch(t.ID)
	t.NotifyDone(intent.ID) // results changed the graph -> wake the planner (with the just-finished intent id)
	return true
}

// runDetachedIntent runs one paused intent OUTSIDE the worker pool in its own
// goroutine — the human-message path. It transitions the intent paused->running
// itself (never through 'open'), so the pool, which only claims 'open', can never
// race it; the "at most one run per intent" invariant still holds because winning
// the CAS is the sole entry and work[intentID] was cleared when the pause settled.
// Because it does not compete for a frontier slot, a user message continues the
// worker immediately even when all pool slots are busy (mirroring how the
// main-agent chat handler starts its run directly). The spawned goroutine owns one
// task-operation admission for the whole run and roots its context at ctx (pass the
// server root, never the HTTP request, so a disconnect cannot strand the run while
// task pause/delete/shutdown still stops it). Returns an error if the run could not
// be started; the intent is left untouched in that case.
func (e *Engine) runDetachedIntent(ctx context.Context, t *Task, intentID int64, requestID, message, agentMessage string) error {
	if !e.beginTaskOperation(t.ID) {
		return fmt.Errorf("task is being deleted")
	}
	release := true
	defer func() {
		if release {
			e.decInflight(t.ID)
		}
	}()
	_, worker := e.snapshotFor(t)
	if worker == nil {
		return fmt.Errorf("worker 尚未就绪")
	}
	node, err := t.Store.GetNode(intentID)
	if err != nil {
		return err
	}
	if node == nil || node.Kind != db.KindIntent {
		return fmt.Errorf("intent not found")
	}
	changed, err := t.Store.CompareAndSetIntentState(intentID, "paused", "running")
	if err != nil {
		return err
	}
	if !changed {
		return fmt.Errorf("%w: 意图不再是 paused 状态", db.ErrIntentStateConflict)
	}
	node.State, node.Owner = "running", "chat"
	// Record the human turn as a visible activity BEFORE the run starts, so it is
	// ordered ahead of any worker step and never appears without the run happening.
	// Keep the UI copy concise; ExecuteWithMessage writes the server-resolved
	// reference snapshot into the intent transcript as the LLM input.
	uid := intentID
	e.emitActivity(t, db.Activity{NodeID: &uid, Worker: "user", Kind: "user", Summary: message, Detail: message})
	release = false // ownership of the admission passes to the goroutine
	go func() {
		defer e.decInflight(t.ID)
		e.runIntent(ctx, t, "chat", worker, node, requestID, agentMessage)
	}()
	return nil
}

func taskExecutionPaused(cause error) bool {
	var abort *agent.AbortCause
	if !errors.As(cause, &abort) {
		return false
	}
	switch abort.Code {
	case "paused_by_user", "paused_by_orchestrator", "paused_on_reload", "paused_race_guard",
		"queued_for_admission", "llm_unavailable_queued", "task_deleted":
		return true
	default:
		return false
	}
}

func sleepCtx(ctx context.Context, d time.Duration) (done bool) {
	select {
	case <-ctx.Done():
		return true
	case <-time.After(d):
		return false
	}
}

func (e *Engine) claimNext(t *Task, name string) *db.Node {
	fr, _ := t.Store.Frontier(20)
	for _, in := range fr {
		if ok, _ := t.Store.ClaimIntent(in.ID, name); ok {
			return in
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 漏洞判重审计队列（批次）
// ---------------------------------------------------------------------------
//
// 模型：新漏洞入队 → 静默 10 秒或攒够 8 条就起一个批次会话 → 会话内可做多次合并。
// 同任务串行（一个批次跑完才起下一个），跨任务并行；人工触发跳过限速与静默窗口。

const (
	auditIdleWindow    = 10 * time.Second  // 静默窗口：这段时间没有新漏洞才开批
	auditBatchTrigger  = 8                 // 攒够这么多条提前开批
	auditBatchMax      = 40                // 单批上限（与角色提示词一致）
	auditPerMinute     = 3                 // 同任务每分钟最多几个批次（自动触发）
	auditDailyCap      = 200               // 同任务每天最多审计多少条漏洞（自动触发）
	auditBatchDailyCap = 60                // 同任务每天最多启动多少批次（自动触发）
	auditQueueCap      = 200               // 待审集合上限：超出只保留最新 200 条
	auditDedupeWindow  = 120 * time.Second // 同一漏洞两次入队的最小间隔（报告回写去抖）
	auditDisabledRetry = 5 * time.Minute   // 后台总开关关闭 / auditor 未就绪时的重试间隔
	auditMaxAttempts   = 2                 // 失败重试 1 次（首次 + 重试一次）
)

type auditQueue struct {
	ids         []int64
	seen        map[int64]bool
	force       map[int64]bool
	dirty       map[int64]bool
	source      string
	timer       *time.Timer
	running     bool
	starts      []time.Time
	day         string    // 批次数统计的归属日（YYYY-MM-DD）
	batches     int       // 当天已启动的批次数（只在自动触发路径上受限）
	holdUntil   time.Time // 到这个时间之前不再起批（放回队列重试时的退避）
	capNotice   string    // 每日上限提示的归属日：同一天只提示一次，避免每 5 分钟刷一条
	windowUntil time.Time // 静默窗口到期时间；零值表示没有窗口（可以立刻起批）
	// 注意：窗口只能由「入队」往后推，绝不能由 pump 自己重排定时器 —— pump 也是定时器回调，
	// 那样会永远重排、永远开不了批（历史 bug）。
	total       int // 本轮判重的目标总数（进度展示用）
	done        int // 已处理条数
	batchesDone int // 已完成批次数
}

// AuditProgress 是任务判重的进度快照，供页面展示「第 x/y 批，已处理 m/n 条」。
type AuditProgress struct {
	Pending      int  `json:"pending"`
	Running      bool `json:"running"`
	Done         int  `json:"done"`
	Total        int  `json:"total"`
	BatchesDone  int  `json:"batches_done"`
	BatchesTotal int  `json:"batches_total"`
	// WindowLeft 是静默窗口剩余秒数（0 表示没有待开批的窗口）。
	// 前端拿它做逐秒倒计时；窗口每被一次点击刷新，这个值就从 30 重新开始。
	WindowLeft int `json:"window_left"`
}

// SetAuditorResolver installs the per-task auditor resolver (wired by the server).
func (e *Engine) SetAuditorResolver(fn func(t *Task) *agent.Auditor) { e.resolveAud = fn }

func (e *Engine) taskByID(id string) *Task {
	e.m.mu.RLock()
	defer e.m.mu.RUnlock()
	return e.m.tasks[id]
}

// auditEnabled 是后台总开关（系统设置 finding_audit_enabled，默认开）。
func (e *Engine) auditEnabled() bool {
	if e.m == nil || e.m.pg == nil {
		return false
	}
	return e.m.pg.GetBool(settingFindingAuditEnabled, true)
}

// AuditEnabled 是对外暴露的总开关查询（人工触发接口用它给出明确报错）。
func (e *Engine) AuditEnabled() bool { return e.auditEnabled() }

// isManualAuditSource 判断来源是否人工触发（manual / manual_one / manual_task），
// 人工触发忽略限速与每日上限。
func isManualAuditSource(source string) bool {
	return source == "manual" || strings.HasPrefix(source, "manual_")
}

func auditStatusEligible(status string) bool {
	switch status {
	case db.FindingFalsePositive, db.FindingIgnored, db.FindingFixed, db.FindingResolved:
		return false
	}
	return true
}

// EnqueueAudit 把一个漏洞放进本任务的待审集合。force=true 表示人工/改动触发
// （忽略已审计标记）；120 秒内的重复触发会被推迟到窗口结束，避免报告回写造成双跑。
func (e *Engine) EnqueueAudit(taskID, findingID int64, source string, force bool) {
	if taskID <= 0 || findingID <= 0 {
		return
	}
	// 总开关关闭时仍然入队（不消耗模型、只是攒着），重新打开后 pump 会接着跑；
	// 人工触发由接口层直接 403，不会走到这里。
	key := strconv.FormatInt(taskID, 10)
	e.auditMu.Lock()
	if e.auditQ == nil {
		e.auditQ = map[string]*auditQueue{}
	}
	if e.auditRecent == nil {
		e.auditRecent = map[string]map[int64]time.Time{}
	}
	q := e.auditQ[key]
	if q == nil {
		q = &auditQueue{seen: map[int64]bool{}, force: map[int64]bool{}, dirty: map[int64]bool{}}
		e.auditQ[key] = q
	}
	if q.seen[findingID] {
		// 已经在队列里（或正在被当前批次处理）：只有强制触发才标 dirty，本批跑完补一轮。
		if force {
			q.dirty[findingID] = true
		}
		e.auditMu.Unlock()
		return
	}
	if !force {
		if last := e.auditRecent[key][findingID]; !last.IsZero() && time.Since(last) < auditDedupeWindow {
			wait := auditDedupeWindow - time.Since(last)
			e.auditMu.Unlock()
			time.AfterFunc(wait, func() { e.EnqueueAudit(taskID, findingID, source, false) })
			return
		}
	}
	// 新一轮判重（队列空且没有批次在跑）从 0 开始计数：doc §3.2 的「第 x/y 批，已处理 m/n 条」
	// 说的是本次触发的进度，不是历史累计。
	if !q.running && len(q.ids) == 0 {
		q.total, q.done, q.batchesDone = 0, 0, 0
	}
	q.ids = append(q.ids, findingID)
	q.seen[findingID] = true
	q.windowUntil = time.Now().Add(auditIdleWindow) // 新条目进来就刷新等待期
	if force {
		q.force[findingID] = true
	}
	if !isManualAuditSource(q.source) {
		q.source = source
	}
	if q.total < q.done+len(q.ids) {
		q.total = q.done + len(q.ids)
	}
	// 队列上限：超出只保留最新 200 条，丢掉最老的（记一条 activity 提示积压）。
	var dropped []int64
	if over := len(q.ids) - auditQueueCap; over > 0 {
		dropped = append(dropped, q.ids[:over]...)
		q.ids = append([]int64{}, q.ids[over:]...)
		for _, id := range dropped {
			delete(q.seen, id)
		}
	}
	e.auditMu.Unlock()

	if len(dropped) > 0 {
		if t := e.taskByID(key); t != nil {
			e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text", IsError: true,
				Summary: fmt.Sprintf("判重队列积压：待审超过 %d 条，丢弃最早的 %d 条（可人工重新触发）", auditQueueCap, len(dropped))})
		}
	}
	e.pumpAudit(key)
}

// EnqueueAuditBatch 一次性把一批漏洞放进队列，只在最后 pump 一次。
//
// 逐条调 EnqueueAudit 会有个坑：人工来源（manual_*）跳过静默窗口和「攒够 8 条」判断，
// 第一次入队就会把队列里那唯一 1 条取走起批 —— 整任务判重于是先跑一个 1 条的批次。
// 批量触发（整任务判重、人工整任务重审）必须走这里。
func (e *Engine) EnqueueAuditBatch(taskID int64, ids []int64, source string, force bool) {
	if len(ids) == 0 {
		return
	}
	key := strconv.FormatInt(taskID, 10)
	e.auditMu.Lock()
	if e.auditQ == nil {
		e.auditQ = map[string]*auditQueue{}
	}
	if e.auditRecent == nil {
		e.auditRecent = map[string]map[int64]time.Time{}
	}
	q := e.auditQ[key]
	if q == nil {
		q = &auditQueue{seen: map[int64]bool{}, force: map[int64]bool{}, dirty: map[int64]bool{}}
		e.auditQ[key] = q
	}
	// 新一轮判重（队列空且没有批次在跑）从 0 开始计数。
	if !q.running && len(q.ids) == 0 {
		q.total, q.done, q.batchesDone = 0, 0, 0
	}
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if q.seen[id] {
			// 已在队列里（或正在被本批处理）：批量触发是幂等的，不再标 dirty，
			// 否则连点两次「整任务判重」会让整批在跑完后被强制再审一轮（双倍 Token）。
			continue
		}
		if !force {
			if last := e.auditRecent[key][id]; !last.IsZero() && time.Since(last) < auditDedupeWindow {
				continue // 批量路径只做「跳过」，需要补审的用强制触发
			}
		}
		q.ids = append(q.ids, id)
		q.seen[id] = true
		q.windowUntil = time.Now().Add(auditIdleWindow) // 有新条目才刷新等待期
		if force {
			q.force[id] = true
		}
		if q.total < q.done+len(q.ids) {
			q.total = q.done + len(q.ids)
		}
	}
	if isManualAuditSource(source) || !isManualAuditSource(q.source) {
		q.source = source
	}
	var dropped []int64
	if over := len(q.ids) - auditQueueCap; over > 0 {
		dropped = append(dropped, q.ids[:over]...)
		q.ids = append([]int64{}, q.ids[over:]...)
		for _, id := range dropped {
			delete(q.seen, id)
			delete(q.force, id)
		}
	}
	e.auditMu.Unlock()

	if len(dropped) > 0 {
		if t := e.taskByID(key); t != nil {
			e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text", IsError: true,
				Summary: fmt.Sprintf("判重队列积压：待审超过 %d 条，丢弃最早的 %d 条（可人工重新触发）", auditQueueCap, len(dropped))})
		}
	}
	e.pumpAudit(key)
}

// pumpAudit 判断是否可以起批：总开关、同任务串行、静默/攒批/限速/每日上限。
func (e *Engine) pumpAudit(key string) {
	e.auditMu.Lock()
	q := e.auditQ[key]
	if q == nil || q.running || len(q.ids) == 0 {
		if q != nil && len(q.ids) == 0 && !q.running {
			q.windowUntil = time.Time{} // 队列空了就没有窗口，别让界面显示假倒计时
		}
		e.auditMu.Unlock()
		return
	}
	if !e.auditEnabled() {
		// 后台关掉了判重：队列保留，隔一段时间再看（重新打开后会接着跑）。
		if q.timer != nil {
			q.timer.Stop()
		}
		q.timer = time.AfterFunc(auditDisabledRetry, func() { e.pumpAudit(key) })
		e.auditMu.Unlock()
		return
	}
	// 退避窗口（auditor 未就绪 / 触顶 / 读库失败放回队列）：到期前不起批，
	// 否则 requeue 后立刻 pump 会形成无间隔忙循环。
	if now := time.Now(); !q.holdUntil.IsZero() && now.Before(q.holdUntil) {
		wait := time.Until(q.holdUntil)
		if q.timer != nil {
			q.timer.Stop()
		}
		q.timer = time.AfterFunc(wait, func() { e.pumpAudit(key) })
		e.auditMu.Unlock()
		return
	}
	manual := isManualAuditSource(q.source)
	// 静默窗口：窗口到期时间由「入队」维护（EnqueueAudit/EnqueueAuditBatch 把 windowUntil 推到 10 秒后），
	// 这里只判断「还没到期就继续等」。绝对不能在这里无条件重排定时器 —— 定时器回调也是 pumpAudit，
	// 那样会一直重排、永远走不到起批（曾经就是死循环，点一条判重 10 秒后一动不动）。
	// 攒够 8 条提前开批只对自动触发生效：人工触发（含整任务判重）一律等满静默窗口。
	if manual || len(q.ids) < auditBatchTrigger {
		if wait := time.Until(q.windowUntil); wait > 0 {
			if q.timer != nil {
				q.timer.Stop()
			}
			q.timer = time.AfterFunc(wait, func() { e.pumpAudit(key) })
			e.auditMu.Unlock()
			return
		}
	}
	q.windowUntil = time.Time{}
	now := time.Now()
	kept := q.starts[:0]
	for _, ts := range q.starts {
		if now.Sub(ts) < time.Minute {
			kept = append(kept, ts)
		}
	}
	q.starts = kept
	if !manual && len(q.starts) >= auditPerMinute {
		if q.timer != nil {
			q.timer.Stop()
		}
		q.timer = time.AfterFunc(time.Minute, func() { e.pumpAudit(key) })
		e.auditMu.Unlock()
		return
	}
	// 每日批次上限：自动触发超限就排队到明天，人工触发不受限。
	day := now.Format("2006-01-02")
	if q.day != day {
		q.day, q.batches = day, 0
	}
	if !manual && q.batches >= auditBatchDailyCap {
		if q.timer != nil {
			q.timer.Stop()
		}
		q.timer = time.AfterFunc(10*time.Minute, func() { e.pumpAudit(key) })
		e.auditMu.Unlock()
		return
	}
	take := q.ids
	if len(take) > auditBatchMax {
		take = take[:auditBatchMax]
	}
	q.ids = append([]int64{}, q.ids[len(take):]...)
	force := map[int64]bool{}
	for _, id := range take {
		delete(q.seen, id)
		if q.force[id] {
			force[id] = true
			delete(q.force, id)
		}
	}
	q.running = true
	q.starts = append(q.starts, now)
	q.batches++
	source := q.source
	q.source = ""
	e.auditMu.Unlock()

	ids := append([]int64{}, take...)
	go e.runAuditBatch(key, ids, source, force)
}

// requeueAuditFront 把一批没跑成的 id 放回队首（auditor 未就绪等可恢复情况），
// 隔一段时间再 pump，避免丢队列也避免空转。
func (e *Engine) requeueAuditFront(key string, ids []int64) {
	e.requeueAuditUntil(key, ids, time.Now().Add(auditDisabledRetry))
}

// requeueAuditUntil 是 requeueAuditFront 的带截止时间版本：每日上限触顶时顺延到次日 0 点，
// 而不是每 5 分钟回来一次（那样会一天刷几百条时间线）。
func (e *Engine) requeueAuditUntil(key string, ids []int64, until time.Time) {
	e.auditMu.Lock()
	q := e.auditQ[key]
	if q == nil {
		q = &auditQueue{seen: map[int64]bool{}, force: map[int64]bool{}, dirty: map[int64]bool{}}
		e.auditQ[key] = q
	}
	head := make([]int64, 0, len(ids)+len(q.ids))
	for _, id := range ids {
		if !q.seen[id] {
			q.seen[id] = true
			head = append(head, id)
		}
	}
	q.ids = append(head, q.ids...)
	if q.total < q.done+len(q.ids) {
		q.total = q.done + len(q.ids)
	}
	wait := time.Until(until)
	if wait < auditDisabledRetry {
		wait = auditDisabledRetry // 至少隔 5 分钟，避免同一时刻反复起批
	}
	q.holdUntil = time.Now().Add(wait)
	if q.timer != nil {
		q.timer.Stop()
	}
	q.timer = time.AfterFunc(wait, func() { e.pumpAudit(key) })
	e.auditMu.Unlock()
}

// markAuditSkipped 把队列里剩下的漏洞标成 skipped 并留痕（任务结束、积压超限等）。
func (e *Engine) markAuditSkipped(key, reason string) int {
	e.auditMu.Lock()
	q := e.auditQ[key]
	if q == nil {
		e.auditMu.Unlock()
		return 0
	}
	ids := append([]int64{}, q.ids...)
	q.ids = nil
	q.seen = map[int64]bool{}
	q.dirty = map[int64]bool{}
	q.force = map[int64]bool{}
	q.source = ""
	if q.timer != nil {
		q.timer.Stop()
		q.timer = nil
	}
	e.auditMu.Unlock()

	for _, id := range ids {
		_ = e.m.pg.MarkFindingSkipped(id)
	}
	if len(ids) > 0 {
		if t := e.taskByID(key); t != nil {
			e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text",
				Summary: fmt.Sprintf("%s：%d 条漏洞未审计，已标记 skipped", reason, len(ids)),
				Detail:  "可由人工在漏洞详情页点「重新判重」补审。"})
		}
	}
	return len(ids)
}

// recordAuditDone 记下这批漏洞的完成时间（120 秒去抖用）。
func (e *Engine) recordAuditDone(key string, ids []int64) {
	if len(ids) == 0 {
		return
	}
	e.auditMu.Lock()
	if e.auditRecent == nil {
		e.auditRecent = map[string]map[int64]time.Time{}
	}
	m := e.auditRecent[key]
	if m == nil {
		m = map[int64]time.Time{}
		e.auditRecent[key] = m
	}
	now := time.Now()
	for _, id := range ids {
		m[id] = now
	}
	// 防止长期运行后无界增长：超过 2000 条就整体重建。
	if len(m) > 2000 {
		cut := now.Add(-auditDedupeWindow)
		for id, ts := range m {
			if ts.Before(cut) {
				delete(m, id)
			}
		}
	}
	e.auditMu.Unlock()
}

// runAuditBatch 跑一个批次的审计会话，结束后自动 pump 下一批（含 dirty 补跑）。
func (e *Engine) runAuditBatch(key string, ids []int64, source string, force map[int64]bool) {
	requeued := false // 放回队首重试的批次不算「已处理」，避免进度虚高
	defer func() {
		e.auditMu.Lock()
		if q := e.auditQ[key]; q != nil {
			q.running = false
			if !requeued {
				q.done += len(ids)
				q.batchesDone++
			}
			if q.total < q.done {
				q.total = q.done
			}
			// dirty 的项重新入队，最多补跑一次（避免报告反复改写导致无限重审）。
			for id := range q.dirty {
				if !q.seen[id] {
					q.ids = append(q.ids, id)
					q.seen[id] = true
					if q.total < q.done+len(q.ids) {
						q.total = q.done + len(q.ids)
					}
				}
				delete(q.dirty, id)
			}
		}
		e.auditMu.Unlock()
		e.pumpAudit(key)
	}()

	t := e.taskByID(key)
	if t == nil || e.IsDeleting(key) || isTerminalStatus(t.lifecycleSnapshot().Status) {
		// 任务已终局/删除：不再起审计，队列剩余 + 本批这些一起标 skipped 并留痕。
		n := e.markAuditSkipped(key, "任务已结束")
		for _, id := range ids {
			_ = e.m.pg.MarkFindingSkipped(id)
		}
		requeued = true // 本批没有真的审，进度不算已处理
		log.Printf("[audit] task %s: 任务已结束，队列 %d 条 + 本批 %d 条标 skipped", key, n, len(ids))
		return
	}
	aud := e.resolveAuditor(t)
	if aud == nil {
		// 模型链路还没就绪：放回队首，稍后重试（不丢队列、不空转）。
		log.Printf("[audit] task %s: auditor 未就绪，%d 条稍后重试", key, len(ids))
		requeued = true
		e.requeueAuditFront(key, ids)
		return
	}
	taskIDInt, _ := strconv.ParseInt(key, 10, 64)
	rows, err := e.m.pg.FindingsByIDs(ids)
	if err != nil {
		log.Printf("[audit] task %s: 读取漏洞失败: %v", key, err)
		requeued = true
		e.requeueAuditFront(key, ids)
		return
	}
	meta, err := e.m.pg.FindingAuditMeta(ids)
	if err != nil {
		log.Printf("[audit] task %s: 读取审计状态失败: %v", key, err)
		requeued = true
		e.requeueAuditFront(key, ids)
		return
	}
	targets := make([]*db.DBFinding, 0, len(rows))
	skippedMerged := make([]int64, 0)
	skippedOther := make([]int64, 0)
	for _, f := range rows {
		m, ok := meta[f.ID]
		if !ok || m.Merged || m.TaskID != taskIDInt || !auditStatusEligible(m.Status) || (m.Audited && !force[f.ID]) {
			if ok && m.Merged {
				skippedMerged = append(skippedMerged, f.ID)
			} else {
				skippedOther = append(skippedOther, f.ID)
			}
			continue
		}
		targets = append(targets, f)
	}
	if len(skippedMerged) > 0 || len(skippedOther) > 0 {
		// 执行前过滤留痕：让时间线能解释「这条为什么没被审」。
		detail := ""
		if len(skippedMerged) > 0 {
			// 反查快照里记的旧 id → 新 id，文案对齐 doc §4.2 的「#283 已并入 #290」。
			into := e.m.pg.FindingIDsMergedInto(skippedMerged)
			parts := make([]string, 0, len(skippedMerged))
			for _, id := range skippedMerged {
				if nid, ok := into[id]; ok {
					parts = append(parts, fmt.Sprintf("#%d 已并入 #%d", id, nid))
				} else {
					parts = append(parts, fmt.Sprintf("#%d 已并入其他漏洞", id))
				}
			}
			detail += strings.Join(parts, "；") + "；"
		}
		if len(skippedOther) > 0 {
			detail += fmt.Sprintf("%s 状态不适格/已审计/已不在本任务；", formatAuditIDList(skippedOther))
		}
		e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text",
			Summary: "本批跳过 " + formatAuditIDList(append(append([]int64{}, skippedMerged...), skippedOther...)), Detail: detail})
	}
	if len(targets) == 0 {
		e.recordAuditDone(key, ids)
		return
	}
	if n, err := e.m.pg.CountAuditedToday(taskIDInt); err == nil && n+len(targets) > auditDailyCap && !isManualAuditSource(source) {
		day := time.Now().Format("2006-01-02")
		if e.takeAuditCapNotice(key, day) {
			// 同一天只写一条：否则每 5 分钟回来一次就会把时间线刷满。
			e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text",
				Summary: fmt.Sprintf("本轮触发跳过：今日已审计 %d 条（上限 %d），剩余 %d 条排队到明天", n, auditDailyCap, len(ids))})
		}
		requeued = true
		e.requeueAuditUntil(key, ids, nextAuditDayStart(time.Now()))
		return
	}
	// 人工触发留痕：记来源、涉及 id、改动前各自的 audited_at（doc §3.2）。
	if isManualAuditSource(source) {
		before := map[string]any{}
		for _, f := range targets {
			if m := meta[f.ID]; m.AuditedAt != nil {
				before[fmt.Sprintf("%d", f.ID)] = m.AuditedAt.Format(time.RFC3339)
			}
		}
		idx := e.AuditProgress(key)
		batchNo := idx.BatchesDone + 1
		batchTotal := idx.BatchesTotal
		if batchTotal < batchNo {
			batchTotal = batchNo
		}
		metaJSON, _ := json.Marshal(map[string]any{
			"source": source, "batch": batchNo, "batches_total": batchTotal, "ids": func() []int64 {
				out := make([]int64, 0, len(targets))
				for _, f := range targets {
					out = append(out, f.ID)
				}
				return out
			}(), "audited_at_before": before,
		})
		e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text", Tool: "request_finding_audit",
			Summary:  fmt.Sprintf("整任务判重：第 %d/%d 批，本批 %d 条（%s）", batchNo, batchTotal, len(targets), source),
			Detail:   "强制重审，忽略此前的审计结论。",
			Metadata: metaJSON})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	emit := func(r db.Activity) { e.emitActivity(t, r) }

	var res *agent.AuditBatchResult
	drained := false // 首次 attempt 已把这批全部合并掉（旧行都没了），重试时无目标
	for attempt := 1; attempt <= auditMaxAttempts; attempt++ {
		if attempt > 1 {
			// 上一次 attempt 可能已经合并掉一部分（旧行已删除）；把老清单再喂给模型，
			// 模型只会读到「不在范围内」，白烧一轮。重试前重新读库。
			if fresh := e.refreshAuditTargets(ids); fresh != nil {
				targets = fresh
			}
			if len(targets) == 0 {
				res, err, drained = &agent.AuditBatchResult{}, nil, true
				break
			}
		}
		res, err = aud.AuditBatch(ctx, taskIDInt, e.m.components, t.Store, targets, source, emit)
		if err == nil {
			break
		}
		log.Printf("[audit] task %s: 批次第 %d 次失败: %v", key, attempt, err)
		if attempt < auditMaxAttempts {
			e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text", IsError: true,
				Summary: "判重批次失败，重试一次：" + err.Error()})
		}
	}
	if err != nil {
		for _, f := range targets {
			_ = e.m.pg.MarkFindingAudited(f.ID, db.FindingAuditError)
		}
		e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text", IsError: true,
			Summary: "判重审计失败（已重试一次）：" + err.Error()})
		e.recordAuditDone(key, ids)
		return
	}
	e.recordAuditDone(key, ids)
	if drained {
		e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text",
			Summary: "判重审计完成：本批条目已在首次尝试中全部合并"})
		return
	}
	summary := fmt.Sprintf("判重审计完成：本批 %d 条，合并 %d 组，判不同 %d 条", len(targets), res.Merged, len(res.Distinct))
	if len(res.Uncovered) > 0 {
		summary += fmt.Sprintf("，待复核 %d 条", len(res.Uncovered))
	}
	e.emitActivity(t, db.Activity{Worker: "auditor", Kind: "text", Summary: summary})
	log.Printf("[audit] task %s: %s", key, summary)
}

// refreshAuditTargets 重读本批漏洞，并剔除已经被合并掉的旧行。
// 返回 nil 表示读库失败（调用方保留原清单）。
func (e *Engine) refreshAuditTargets(ids []int64) []*db.DBFinding {
	fresh, err := e.m.pg.FindingsByIDs(ids)
	if err != nil {
		log.Printf("[audit] 重试前重读漏洞失败: %v", err)
		return nil
	}
	meta, err := e.m.pg.FindingAuditMeta(ids)
	if err != nil {
		return fresh
	}
	out := make([]*db.DBFinding, 0, len(fresh))
	for _, f := range fresh {
		if m, ok := meta[f.ID]; ok && m.Merged {
			continue
		}
		out = append(out, f)
	}
	return out
}

// nextAuditDayStart 返回本地时区次日 0 点（每日上限触顶后顺延到这里）。
func nextAuditDayStart(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
}

// takeAuditCapNotice 判断「今天这条上限提示写过没有」：写过返回 false。
func (e *Engine) takeAuditCapNotice(key, day string) bool {
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	q := e.auditQ[key]
	if q == nil {
		return true
	}
	if q.capNotice == day {
		return false
	}
	q.capNotice = day
	return true
}

// formatAuditIDList 渲染「#1、#2」。
func formatAuditIDList(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, "#"+strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, "、")
}

// resolveAuditor 返回任务当前的审计角色（未注入或链路不可用时为 nil）。
func (e *Engine) resolveAuditor(t *Task) *agent.Auditor {
	if e.resolveAud == nil {
		return nil
	}
	return e.resolveAud(t)
}

// AuditProgress 返回某任务当前的判重进度（待审条数、是否在跑、已完成/总数、批次数）。
func (e *Engine) AuditProgress(taskID string) AuditProgress {
	e.auditMu.Lock()
	defer e.auditMu.Unlock()
	out := AuditProgress{}
	q := e.auditQ[taskID]
	if q == nil {
		return out
	}
	out.Pending = len(q.ids)
	out.Running = q.running
	out.Done = q.done
	out.Total = q.total
	out.BatchesDone = q.batchesDone
	out.BatchesTotal = (q.total + auditBatchMax - 1) / auditBatchMax
	if out.BatchesTotal < out.BatchesDone {
		out.BatchesTotal = out.BatchesDone
	}
	if !q.running && !q.windowUntil.IsZero() {
		left := time.Until(q.windowUntil)
		if left > 0 {
			out.WindowLeft = int((left + time.Second - 1) / time.Second) // 向上取整：29.2s 显示 30
		}
	}
	return out
}

// AuditStatus 保留旧的二元接口（pending/running），供既有调用点使用。
func (e *Engine) AuditStatus(taskID string) (pending int, running bool) {
	p := e.AuditProgress(taskID)
	return p.Pending, p.Running
}
