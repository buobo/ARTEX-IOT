package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/transcript"
)

// auditBatchState 记录一批审计的归位情况：哪些被合并、哪些判了不同。
// 工具的每次 consolidate_findings / keep_separate 都会更新它，收尾时用它做覆盖闸门。
type auditBatchState struct {
	mu       sync.Mutex
	mergedTo map[int64]int64 // 旧 id → 新 id
	distinct map[int64]bool
	merges   [][]int64
	reason   map[int64]string
	// targets 是本批必须归位的 id；read 是通过 audit_get_findings 真读过原文的 id。
	// keep_separate 只要求「读过」——considered 可以带本批之外的对照条目，
	// 覆盖闸门只按 targets 归位，对照不会让任何人被误记账。
	targets map[int64]bool
	read    map[int64]bool
}

func newAuditBatchState() *auditBatchState {
	return &auditBatchState{
		mergedTo: map[int64]int64{}, distinct: map[int64]bool{}, reason: map[int64]string{},
		targets: map[int64]bool{}, read: map[int64]bool{},
	}
}

// setTargets 登记本批必须归位的 id。
func (s *auditBatchState) setTargets(ids []int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		s.targets[id] = true
	}
}

// markRead 记录「这些 id 已经读过原文」。
func (s *auditBatchState) markRead(ids []int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		s.read[id] = true
	}
}

// unreadIn 返回 ids 里还没读过原文的那些（keep_separate 的前置校验）。
// 不校验「是否在本批 targets 内」：Agent 可以拿本批之外、已读过原文的漏洞做对照，
// 只判 targets 会白白拒掉合法用法；覆盖闸门仍只认 targets，对照条目不会被记账。
func (s *auditBatchState) unreadIn(ids []int64) []int64 {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var unread []int64
	for _, id := range ids {
		if !s.read[id] {
			unread = append(unread, id)
		}
	}
	return unread
}

// splitTargets 把 considered 拆成「本批目标」（会被记为 distinct）与「对照」（只写 activity）。
func (s *auditBatchState) splitTargets(ids []int64) (targets, context []int64) {
	if s == nil {
		return nil, ids
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if s.targets[id] {
			targets = append(targets, id)
		} else {
			context = append(context, id)
		}
	}
	return targets, context
}

// targetSnapshot 返回本批目标名单（排序后），只用于 activity 留痕。
func (s *auditBatchState) targetSnapshot() []int64 {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int64, 0, len(s.targets))
	for id := range s.targets {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *auditBatchState) markMerged(ids []int64, newID int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	group := append([]int64(nil), ids...)
	s.merges = append(s.merges, group)
	for _, id := range ids {
		s.mergedTo[id] = newID
	}
}

func (s *auditBatchState) markDistinct(ids []int64, reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		s.distinct[id] = true
		if reason != "" {
			s.reason[id] = reason
		}
	}
}

func (s *auditBatchState) merged(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.mergedTo[id]
	return ok
}

func (s *auditBatchState) covered(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.mergedTo[id]; ok {
		return true
	}
	return s.distinct[id]
}

// uncovered 返回还没归位的目标 id（既没被合并、也没被判不同）。
func (s *auditBatchState) uncovered(targets []int64) []int64 {
	out := make([]int64, 0)
	for _, id := range targets {
		if !s.covered(id) {
			out = append(out, id)
		}
	}
	return out
}

func (s *auditBatchState) mergeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.merges)
}

// Auditor 是漏洞判重审计角色：一个批次会话处理一批新漏洞，会话内可做多次合并。
type Auditor struct {
	pg             *db.DB
	prov           llm.Provider
	model          string
	tx             *transcript.Store
	window         int
	maxTurns       int
	maxDuration    time.Duration
	workDir        string
	nonStreamingFn func() bool
	maxTokensFn    func() int
}

// NewAuditor 构造审计角色。maxTurns=0 表示不限轮次。
func NewAuditor(pg *db.DB, prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Auditor {
	if maxTurns <= 0 {
		maxTurns = 12 // 批次默认上限：一次会话合几组，12 轮够用且能兜住跑飞
	}
	return &Auditor{pg: pg, prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, maxDuration: 300 * time.Second}
}

func (a *Auditor) SetNonStreaming(fn func() bool) { a.nonStreamingFn = fn }
func (a *Auditor) SetMaxTokens(fn func() int)     { a.maxTokensFn = fn }
func (a *Auditor) SetMaxDuration(d time.Duration) { a.maxDuration = d }

func (a *Auditor) nonStreaming() bool { return a.nonStreamingFn != nil && a.nonStreamingFn() }
func (a *Auditor) maxTokens() int {
	if a.maxTokensFn == nil {
		return 0
	}
	return a.maxTokensFn()
}

// AuditBatchResult 是一个批次的执行结果（供引擎写活动与统计）。
type AuditBatchResult struct {
	Targets   []int64
	Merges    [][]int64
	Merged    int
	Distinct  []int64
	Uncovered []int64
}

// AuditBatch 跑一个批次的审计会话。targets 是本批要归位的漏洞（已按 id 升序）。
// emit 收到每一步执行记录（worker 固定为 auditor）。
func (a *Auditor) AuditBatch(ctx context.Context, taskID int64, as *db.ComponentStore, ts *db.ExplorationStore,
	targets []*db.DBFinding, source string, emit func(db.Activity)) (*AuditBatchResult, error) {
	res := &AuditBatchResult{}
	if ts == nil || len(targets) == 0 {
		return res, nil
	}
	targetIDs := make([]int64, 0, len(targets))
	for _, f := range targets {
		targetIDs = append(targetIDs, f.ID)
		res.Targets = append(res.Targets, f.ID)
	}
	state := newAuditBatchState()
	state.setTargets(targetIDs)

	tsx := NewToolSet(ts, "auditor")
	tsx.SetTaskID(taskID)
	tsx.SetAuditDB(a.pg)
	tsx.SetAuditState(state)
	tsx.SetAuditSource(source)
	tsx.SetDataDir(a.workDir)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "auditor", tsx.AuditorTools())
	defer cleanup()

	taskDir := ensureRunDir(a.workDir, taskID, 0)
	ctx = intercept.WithReviewWorkingDirectory(ctx, taskDir)
	system, boundary := deferredSystem(auditorSystem(a.workDir), def)
	opts := agentcore.Options{
		Provider:        a.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		WorkingDir:      taskDir,
		ToolOutputDir:   cmdOutDir(taskDir),
		MaxTurns:        a.maxTurns,
		MaxDuration:     a.maxDuration,
		Compaction:      compactionConfig(a.window),
		Settlement:      wrapupSettlement("auditor", nil),
		NonStreaming:    a.nonStreaming(),
		MaxTokens:       a.maxTokens(),
	}
	if a.tx != nil {
		opts.Transcript = a.tx
		opts.SessionID = fmt.Sprintf("exp%d-audit-%d", ts.ID(), time.Now().UnixNano())
	}
	s := agentcore.NewSession(opts)
	defer s.Close()

	emitAll := func(r db.Activity) {
		if emit != nil {
			r.Worker = "auditor"
			emit(r)
		}
	}
	input := auditorInput(targets, source)
	if _, _, err := captureRunSession(ctx, s, input, emitAll); err != nil {
		return res, err
	}
	// 覆盖闸门：本批还有没归位的目标 → 同会话追问一次。
	if missing := state.uncovered(targetIDs); len(missing) > 0 {
		_, _, _ = captureRunSession(ctx, s, auditorCoverageReminder(missing), emitAll)
	}
	res.Merges = state.merges
	res.Merged = len(state.merges)
	uncovered := state.uncovered(targetIDs)
	res.Uncovered = uncovered
	for _, id := range targetIDs {
		switch {
		case state.merged(id): // 旧行已被删除，不需要标记
		case state.covered(id):
			res.Distinct = append(res.Distinct, id)
			_ = a.pg.MarkFindingAudited(id, db.FindingAuditDistinct)
		}
	}
	if len(uncovered) > 0 {
		meta, _ := json.Marshal(map[string]any{"uncovered": uncovered, "targets": targetIDs})
		_, _ = ts.AppendActivity(db.Activity{
			Worker: "auditor", Kind: "text",
			Summary:  "待人工复核：" + formatAuditIDs(uncovered) + " 本批没有归位",
			Detail:   "模型没有给出合并或判不同的结论；这些漏洞保持未审计状态，可由人工触发重审。",
			Metadata: meta,
		})
	}
	return res, nil
}

// auditorSystem 渲染审计角色的系统提示（可在 agent_prompts 后台覆盖）。
func auditorSystem(workDir string) string {
	return renderSystem("auditor", auditorDefaultTmpl, AuditVars{DataDir: workDir, Now: nowStr()})
}

// auditorInput 是本批的第一条 user 消息：本批要归位的漏洞 + 归位要求。
func auditorInput(targets []*db.DBFinding, source string) string {
	var b strings.Builder
	b.WriteString("本批需要归位的漏洞（")
	b.WriteString(fmt.Sprintf("%d 条", len(targets)))
	if source != "" {
		b.WriteString("，触发来源：" + source)
	}
	b.WriteString("）：\n")
	for _, f := range targets {
		inherited := ""
		if f.TaskID != nil {
			inherited = fmt.Sprintf("task#%d", *f.TaskID)
		}
		b.WriteString(fmt.Sprintf("- #%d [%s/%s] %s：%s\n", f.ID, f.VulnClass, f.Severity, inherited, oneLine(f.Summary, 160)))
	}
	b.WriteString("\n要求：先用 list_findings 拉本任务（含直接来源任务）全部漏洞，再用 audit_get_findings 读候选原文；")
	b.WriteString("把这批每一条都归位——并进某个重复组（consolidate_findings，一组一次，可以多次调用）或明确判不同（keep_separate）。")
	b.WriteString("合并要重写整合内容，报告必填。不要只看标题下结论，也不要漏掉本批的任何一条。")
	return b.String()
}

// auditorCoverageReminder 是覆盖闸门的一次追问文案。
func auditorCoverageReminder(missing []int64) string {
	return "以下漏洞还没有归位：" + formatAuditIDs(missing) +
		"。请对每一条给出结论：要么用 consolidate_findings 并入某个重复组，要么用 keep_separate 说明为什么不是重复。不要跳过。"
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	return truncateRunes(s, n)
}
