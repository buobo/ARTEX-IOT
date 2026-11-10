package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const FindingRetestAgentKey = "retester"

var ErrRetestNotRunning = errors.New("本次复测已结束或尚未开始，请从漏洞详情发起新的复测")

// FindingRetest is an immutable historical test once its conversation turn ends.
// Snapshot is only loaded for the agent, never sent with the history list.
type FindingRetest struct {
	ID             int64           `json:"id"`
	FindingID      int64           `json:"finding_id"`
	ConversationID *int64          `json:"conversation_id"`
	Status         string          `json:"status"`
	Verdict        string          `json:"verdict"`
	Notes          string          `json:"notes"`
	Snapshot       json.RawMessage `json:"snapshot,omitempty"`
	Summary        string          `json:"summary"`
	Evidence       string          `json:"evidence"`
	Error          string          `json:"error"`
	CreatedAt      time.Time       `json:"created_at"`
	StartedAt      *time.Time      `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at"`
	// 列表接口按需填充，不参与 retestCols 扫描。
	Recordings []*FindingRetestRecording `json:"recordings,omitempty"`
}

const retestCols = `id, finding_id, conversation_id, status, verdict, notes, summary, evidence, error, created_at, started_at, finished_at`

// ActiveFindingRetest is the small status payload polled by the findings list.
// Finding IDs use the same string representation as the findings API.
type ActiveFindingRetest struct {
	ID             int64                     `json:"id"`
	FindingID      int64                     `json:"finding_id,string"`
	ConversationID int64                     `json:"conversation_id"`
	Status         string                    `json:"status"`
	Recordings     []*FindingRetestRecording `json:"recordings,omitempty"`
}

func (d *DB) ListActiveFindingRetests(ctx context.Context) ([]ActiveFindingRetest, error) {
	rows, err := d.QueryContext(ctx, `SELECT id, finding_id, conversation_id, status FROM finding_retests
	WHERE status IN ('pending','running') AND conversation_id IS NOT NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ActiveFindingRetest{}
	for rows.Next() {
		var item ActiveFindingRetest
		if err := rows.Scan(&item.ID, &item.FindingID, &item.ConversationID, &item.Status); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanRetest(row interface{ Scan(...any) error }) (*FindingRetest, error) {
	r := &FindingRetest{}
	err := row.Scan(&r.ID, &r.FindingID, &r.ConversationID, &r.Status, &r.Verdict, &r.Notes,
		&r.Summary, &r.Evidence, &r.Error, &r.CreatedAt, &r.StartedAt, &r.FinishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// CreateFindingRetest atomically snapshots the source, creates its conversation
// and persists the first message. A finding row lock deduplicates simultaneous
// clicks across clients; an existing active run is returned without dispatching.
func (d *DB) CreateFindingRetest(ctx context.Context, findingID int64, notes string) (*FindingRetest, *Conversation, bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, false, err
	}
	defer tx.Rollback()
	var title string
	var snapshot []byte
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(NULLIF(f.name,''), NULLIF(f.vulnclass,''), '未分类'),
	jsonb_build_object('finding', to_jsonb(f),
	 'assets', COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM assets a WHERE f.asset_ids @> to_jsonb(ARRAY[a.id])), '[]'::jsonb),
	 'constraints', COALESCE((SELECT jsonb_agg(to_jsonb(c)) FROM task_constraints c JOIN tasks t ON t.exploration_id=c.exploration_id WHERE t.id=f.task_id), '[]'::jsonb))
	FROM findings f WHERE f.id=$1 FOR UPDATE OF f`, findingID).Scan(&title, &snapshot)
	if err != nil {
		return nil, nil, false, err
	}
	r, err := scanRetest(tx.QueryRowContext(ctx, `SELECT `+retestCols+` FROM finding_retests WHERE finding_id=$1 AND status IN ('pending','running')`, findingID))
	if err != nil {
		return nil, nil, false, err
	}
	if r != nil {
		return r, nil, false, nil
	}
	// Keep the title within the same limit as ordinary conversations.
	if runes := []rune(title); len(runes) > 100 {
		title = string(runes[:100])
	}
	c, err := scanConv(tx.QueryRowContext(ctx, `INSERT INTO conversations(agent_key,title) VALUES ($1,$2) RETURNING `+convCols,
		FindingRetestAgentKey, fmt.Sprintf("复测 #%d · %s", findingID, title)))
	if err != nil {
		return nil, nil, false, err
	}
	r, err = scanRetest(tx.QueryRowContext(ctx, `INSERT INTO finding_retests(finding_id,conversation_id,notes,snapshot) VALUES ($1,$2,$3,$4) RETURNING `+retestCols,
		findingID, c.ID, strings.TrimSpace(notes), snapshot))
	if err != nil {
		return nil, nil, false, err
	}
	msg := r.InitialMessage()
	_, err = tx.ExecContext(ctx, `INSERT INTO conversation_activities(conversation_id,worker,kind,summary,detail) VALUES ($1,$2,'user',$3,$4)`,
		c.ID, FindingRetestAgentKey, fmt.Sprintf("请复测漏洞 #%d", findingID), msg)
	if err != nil {
		return nil, nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, false, err
	}
	return r, &c, true, nil
}

// InitialMessage 是复测会话的首条用户消息：只给结论目标 + 录屏纪律，
// 漏洞证据由 get_finding_retest_context 按需拉取（避免把目标响应当指令灌进来）。
func (r *FindingRetest) InitialMessage() string {
	var b strings.Builder
	fmt.Fprintf(&b, "请复测漏洞 #%d。先调用 get_finding_retest_context 读取本会话关联的原始证据与约束，再执行针对性验证，验证没问题之后，再把验证步骤精简化进行录屏，最后调用 record_finding_retest_result 保存结论。", r.FindingID)
	b.WriteString(`

录屏要求（本次复测必须遵守）：
1. 验证通过后再开始录屏：调用 retest_recording(action=capabilities) 确认后端，再 action=start。证据是命令行就选 app=terminal，证据是界面状态就选 app=chrome。
2. 录屏内容按最小可复现原则：只保留复现该漏洞必需的关键步骤，不做冗余操作（不要全量扫描、不要重复试错、不要跑与结论无关的侦察）。
3. 复现命令尽量与漏洞报告中的操作相同或相近（同一条请求、同一条命令、同一组参数），只复现关键点；确有必要偏离时，在 evidence 里写明原因。
4. 开始复现前，先在同一录屏终端里做一次环境可达性检查（例如 ping、curl -I 或连接目标端口），让视频开头能看出目标环境可达、走的是同一条路径。
5. 关键节点用 retest_recording(action=mark, note=...) 标记（如"可达性确认""触发溢出""命令回显"），结束时 action=stop，并把返回的 path 与时间点写进 evidence 的「复测录屏」小节。`)
	if r.Notes != "" {
		b.WriteString("\n\n本次复测补充说明：\n" + r.Notes)
	}
	return b.String()
}

func (d *DB) ListFindingRetests(findingID int64) ([]*FindingRetest, error) {
	rows, err := d.Query(`SELECT `+retestCols+` FROM finding_retests WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FindingRetest{}
	for rows.Next() {
		r, err := scanRetest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) FindingRetestForConversation(ctx context.Context, conversationID int64) (*FindingRetest, error) {
	r, err := scanRetest(d.QueryRowContext(ctx, `SELECT `+retestCols+` FROM finding_retests WHERE conversation_id=$1`, conversationID))
	if err != nil || r == nil {
		return r, err
	}
	err = d.QueryRowContext(ctx, `SELECT snapshot FROM finding_retests WHERE id=$1`, r.ID).Scan(&r.Snapshot)
	return r, err
}

// FailPendingRetestForConversation seals a conversation's unfinished retest when
// the runner could not even load it — the retest ID is unknown on that path, so
// the conversation ID is the only handle. Without it a transient read error
// leaves the row 'pending' forever: the findings list keeps showing 复测中 and
// every later 发起复测 is deduped against a run that is not happening, with only
// a process restart (RecoverFindingRetests) able to clear it.
func (d *DB) FailPendingRetestForConversation(conversationID int64, reason string) error {
	_, err := d.Exec(`UPDATE finding_retests SET status='failed', error=$2, finished_at=now()
		WHERE conversation_id=$1 AND status IN ('pending','running')`, conversationID, reason)
	return err
}

func (d *DB) StartFindingRetest(ctx context.Context, id int64) (bool, error) {
	res, err := d.ExecContext(ctx, `UPDATE finding_retests SET status='running', started_at=now() WHERE id=$1 AND status='pending'`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RecordFindingRetestResult never accepts a finding ID: ownership comes from the
// runtime conversation. Identical retries are safe; a second verdict is refused.
func (d *DB) RecordFindingRetestResult(ctx context.Context, conversationID int64, verdict, summary, evidence string) error {
	if verdict != "reproduced" && verdict != "fixed" && verdict != "inconclusive" {
		return errors.New("verdict 必须为 reproduced / fixed / inconclusive")
	}
	summary, evidence = strings.TrimSpace(summary), strings.TrimSpace(evidence)
	if summary == "" || evidence == "" {
		return errors.New("summary 与 evidence 不能为空；无法确认时说明实际检查及阻塞原因")
	}
	if len(summary) > 16000 || len(evidence) > 128000 {
		return errors.New("复测结论过长（summary ≤ 16KB，evidence ≤ 128KB）")
	}
	res, err := d.ExecContext(ctx, `UPDATE finding_retests SET verdict=$2,summary=$3,evidence=$4
	WHERE conversation_id=$1 AND status='running' AND (verdict='' OR (verdict=$2 AND summary=$3 AND evidence=$4))`, conversationID, verdict, summary, evidence)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrRetestNotRunning
	}
	return nil
}

// FinishFindingRetest seals the result. Cancellation/failure takes precedence
// over a staged verdict so an interrupted test cannot appear successfully fixed.
// Only a newly completed fixed verdict updates triage, in the same transaction.
func (d *DB) FinishFindingRetest(id int64, status, reason string) error {
	if status != "completed" && status != "failed" && status != "stopped" {
		return errors.New("invalid terminal retest status")
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Lock the finding before the retest, matching creation and cascading deletion.
	var findingID int64
	err = tx.QueryRow(`SELECT f.id FROM findings f WHERE f.id=(SELECT finding_id FROM finding_retests WHERE id=$1) FOR UPDATE OF f`, id).Scan(&findingID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // Finding/retest already deleted.
	}
	if err != nil {
		return err
	}
	var finalStatus, verdict string
	err = tx.QueryRow(`UPDATE finding_retests SET
	status=CASE WHEN $2='completed' AND verdict='' THEN 'failed' ELSE $2 END,
	error=CASE WHEN $2='completed' AND verdict='' THEN 'Agent 未保存复测结论，请查看会话后重新复测' ELSE $3 END,
	finished_at=now() WHERE id=$1 AND status IN ('pending','running') RETURNING status,verdict`, id, status, reason).Scan(&finalStatus, &verdict)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // A replay must not overwrite a later manual triage decision.
	}
	if err != nil {
		return err
	}
	if finalStatus == "completed" && verdict == "fixed" {
		// 走带通知的版本，与人工在详情页改状态共用同一套语义。
		//
		// 此前这里是裸的 UPDATE：复测判「已修复」时状态确实变了，但配了
		// on_status_change 的渠道完全收不到推送——状态在界面上悄悄变了，
		// 运维要打开平台才知道。状态更新与推送事件必须一起落库，
		// SetFindingStatusTx 内部处理了「状态没变就不登记」等细节。
		// 用 context.Background()：本函数整条都是无 ctx 的旧风格（d.Begin()/
		// tx.QueryRow/tx.Exec），没有可传递的取消信号，硬加一个 ctx 参数会
		// 牵动 server 侧调用点与多处测试，超出本次改动的范围。
		if _, _, _, _, err := SetFindingStatusTx(context.Background(), tx, findingID, FindingFixed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) RecoverFindingRetests() error {
	_, err := d.Exec(`UPDATE finding_retests SET status='stopped', error='服务重启，复测已中断，请重新发起', finished_at=now() WHERE status IN ('pending','running')`)
	return err
}

// ---------------------------------------------------------------------------
// 复测录屏
// ---------------------------------------------------------------------------

// FindingRetestRecording 是一次复测的可视化证据。
// Path 是「任务相对路径」（recordings/<retest_id>/<id>.mp4），
// 不存绝对路径：任务归档/恢复/迁移后同一相对位置仍然有效。
type FindingRetestRecording struct {
	ID          int64           `json:"id"`
	RetestID    int64           `json:"retest_id"`
	TaskID      int64           `json:"task_id"`
	App         string          `json:"app"`
	Backend     string          `json:"backend"`
	Display     string          `json:"display,omitempty"`
	TmuxSession string          `json:"-"`
	Path        string          `json:"path"`
	Status      string          `json:"status"`
	Width       int             `json:"width"`
	Height      int             `json:"height"`
	FPS         int             `json:"fps"`
	ExecCount   int             `json:"exec_count"`
	Marks       json.RawMessage `json:"marks"`
	SHA256      string          `json:"sha256,omitempty"`
	StartedAt   time.Time       `json:"started_at"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	DurationMS  int64           `json:"duration_ms"`
	SizeBytes   int64           `json:"size_bytes"`
	Error       string          `json:"error"`
	// URL 由 server 填充（/api/finding-retest-recordings/<id>/stream），不落库。
	URL string `json:"url,omitempty"`
}

// recordingColsQualified 用于 JOIN 查询（与 recordingCols 顺序一致，避免 id 歧义）。
const recordingColsQualified = `r.id, r.retest_id, r.task_id, r.app, r.backend, r.display, r.tmux_session, r.path, r.status,
	r.width, r.height, r.fps, r.exec_count, r.marks, r.sha256, r.started_at, r.finished_at, r.duration_ms, r.size_bytes, r.error`

// recordingCols 只用于**单表**查询。任何 JOIN 都必须用 recordingColsQualified：
// 两张表都有 id/retest_id，裸列名会让 Postgres 报 42702 ambiguous。
const recordingCols = `id, retest_id, task_id, app, backend, display, tmux_session, path, status,
	width, height, fps, exec_count, marks, sha256, started_at, finished_at, duration_ms, size_bytes, error`

func scanRecording(row interface{ Scan(...any) error }) (*FindingRetestRecording, error) {
	r := &FindingRetestRecording{}
	var marks []byte
	err := row.Scan(&r.ID, &r.RetestID, &r.TaskID, &r.App, &r.Backend, &r.Display, &r.TmuxSession, &r.Path,
		&r.Status, &r.Width, &r.Height, &r.FPS, &r.ExecCount, &marks, &r.SHA256,
		&r.StartedAt, &r.FinishedAt, &r.DurationMS, &r.SizeBytes, &r.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(marks) == 0 {
		marks = []byte("[]")
	}
	r.Marks = marks
	return r, nil
}

// CreateRetestRecording 先落 DB 行再起进程：进程失败时也有 id 可标记 failed，
// 唯一索引保证同一复测同时只有一条活跃录制。
func (d *DB) CreateRetestRecording(ctx context.Context, retestID, taskID int64, app string) (*FindingRetestRecording, error) {
	r, err := scanRecording(d.QueryRowContext(ctx, `INSERT INTO finding_retest_recordings(retest_id,task_id,app)
VALUES ($1,$2,$3) RETURNING `+recordingCols, retestID, taskID, app))
	if err != nil && strings.Contains(err.Error(), "idx_retest_recordings_active") {
		return nil, errors.New("本次复测已有录制进行中")
	}
	return r, err
}

func (d *DB) SetRetestRecordingLive(ctx context.Context, id int64, display, session, path string, width, height, fps int) error {
	res, err := d.ExecContext(ctx, `UPDATE finding_retest_recordings
SET status='recording', display=$2, tmux_session=$3, path=$4, width=$5, height=$6, fps=$7
WHERE id=$1 AND status='starting'`, id, display, session, path, width, height, fps)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("录制启动状态已变化，请重试")
	}
	return nil
}

func (d *DB) SetRetestRecordingStopping(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `UPDATE finding_retest_recordings SET status='stopping' WHERE id=$1 AND status='recording'`, id)
	return err
}

func (d *DB) FailRetestRecording(ctx context.Context, id int64, reason string) error {
	_, err := d.ExecContext(ctx, `UPDATE finding_retest_recordings
SET status='failed', error=$2, finished_at=now() WHERE id=$1 AND status IN ('starting','recording','stopping')`, id, reason)
	return err
}

func (d *DB) FinishRetestRecording(ctx context.Context, id int64, status string, durationMS, sizeBytes int64, sha, errNote string) error {
	if status != "completed" && status != "interrupted" && status != "failed" {
		return errors.New("invalid terminal recording status")
	}
	_, err := d.ExecContext(ctx, `UPDATE finding_retest_recordings
SET status=$2, duration_ms=$3, size_bytes=$4, sha256=$5,
    error=CASE WHEN $6 <> '' THEN $6 ELSE error END, finished_at=now()
WHERE id=$1 AND status IN ('starting','recording','stopping')`, id, status, durationMS, sizeBytes, sha, errNote)
	return err
}

func (d *DB) IncRetestRecordingExec(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `UPDATE finding_retest_recordings SET exec_count=exec_count+1 WHERE id=$1`, id)
	return err
}

func (d *DB) AddRetestRecordingMark(ctx context.Context, id int64, offsetS float64, note string) error {
	if note == "" {
		return errors.New("mark 需要 note")
	}
	if len([]rune(note)) > 500 {
		return errors.New("mark note 最多 500 个字符")
	}
	// jsonb_build_object 的参数类型是 any，不给 $n 显式类型时 Postgres
	// 无法推断（SQLSTATE 42P18），语句会在解析阶段失败——marks 就一直为空。
	_, err := d.ExecContext(ctx, `UPDATE finding_retest_recordings
SET marks = marks || jsonb_build_array(jsonb_build_object('offset_s',$2::float8,'note',$3::text))
WHERE id=$1`, id, offsetS, note)
	return err
}

func (d *DB) ActiveRetestRecording(ctx context.Context, retestID int64) (*FindingRetestRecording, error) {
	return scanRecording(d.QueryRowContext(ctx, `SELECT `+recordingCols+` FROM finding_retest_recordings
WHERE retest_id=$1 AND status IN ('starting','recording','stopping') ORDER BY id DESC LIMIT 1`, retestID))
}

func (d *DB) ActiveRetestRecordingForConversation(ctx context.Context, conversationID int64) (*FindingRetestRecording, error) {
	return scanRecording(d.QueryRowContext(ctx, `SELECT `+recordingCols+` FROM finding_retest_recordings r
JOIN finding_retests t ON t.id=r.retest_id
WHERE t.conversation_id=$1 AND r.status IN ('starting','recording','stopping') ORDER BY r.id DESC LIMIT 1`, conversationID))
}

func (d *DB) RetestRecordingByID(ctx context.Context, id int64) (*FindingRetestRecording, error) {
	return scanRecording(d.QueryRowContext(ctx, `SELECT `+recordingCols+` FROM finding_retest_recordings WHERE id=$1`, id))
}

// RetestRecordingsForFinding 供复测列表一次性带出历史录屏，避免 N+1。
func (d *DB) RetestRecordingsForFinding(ctx context.Context, findingID int64) (map[int64][]*FindingRetestRecording, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+recordingColsQualified+` FROM finding_retest_recordings r
JOIN finding_retests t ON t.id=r.retest_id
WHERE t.finding_id=$1 ORDER BY r.id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectRecordings(rows)
}

// RetestRecordingsForRetests 按复测 id 批量取录屏（活跃列表用，避免 N+1）。
func (d *DB) RetestRecordingsForRetests(ctx context.Context, retestIDs []int64) (map[int64][]*FindingRetestRecording, error) {
	if len(retestIDs) == 0 {
		return map[int64][]*FindingRetestRecording{}, nil
	}
	rows, err := d.QueryContext(ctx, `SELECT `+recordingColsQualified+` FROM finding_retest_recordings r
WHERE r.retest_id = ANY($1::bigint[]) ORDER BY r.id DESC`, retestIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectRecordings(rows)
}

func collectRecordings(rows *sql.Rows) (map[int64][]*FindingRetestRecording, error) {
	out := map[int64][]*FindingRetestRecording{}
	for rows.Next() {
		r, err := scanRecording(rows)
		if err != nil {
			return nil, err
		}
		out[r.RetestID] = append(out[r.RetestID], r)
	}
	return out, rows.Err()
}

// RecoverRetestRecordings 在服务启动时封口上一进程遗留的录制。
// 返回这些行供调用方清理残留进程（tmux 会话 / Xvfb）。
func (d *DB) RecoverRetestRecordings() ([]*FindingRetestRecording, error) {
	rows, err := d.Query(`SELECT ` + recordingCols + ` FROM finding_retest_recordings
WHERE status IN ('starting','recording','stopping') ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var out []*FindingRetestRecording
	for rows.Next() {
		r, err := scanRecording(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if _, err := d.Exec(`UPDATE finding_retest_recordings
SET status='interrupted', error='服务重启，录制已中断', finished_at=now()
WHERE status IN ('starting','recording','stopping')`); err != nil {
		return nil, err
	}
	// 已落盘的半截 mp4 仍算证据，尽量保留并回报大小。
	for _, r := range out {
		r.Status = "interrupted"
		r.Error = "服务重启，录制已中断"
	}
	return out, nil
}

// InterruptRetestRecording 封口一条进程已不在的录制（崩溃/重启/归档前收尾）。
func (d *DB) InterruptRetestRecording(ctx context.Context, id int64, reason string) error {
	_, err := d.ExecContext(ctx, `UPDATE finding_retest_recordings
SET status='interrupted', error=$2, finished_at=now()
WHERE id=$1 AND status IN ('starting','recording','stopping')`, id, reason)
	return err
}

// ActiveRecordingsForTask 返回某任务下所有仍在进行的录制，
// 附带所属复测会话 id（用于命中进程内句柄）。归档前用它做强制收尾。
func (d *DB) ActiveRecordingsForTask(ctx context.Context, taskID int64) ([]*FindingRetestRecording, []int64, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+recordingColsQualified+`, COALESCE(t.conversation_id,0)
FROM finding_retest_recordings r JOIN finding_retests t ON t.id=r.retest_id
WHERE r.task_id=$1 AND r.status IN ('starting','recording','stopping') ORDER BY r.id`, taskID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var recs []*FindingRetestRecording
	var convs []int64
	for rows.Next() {
		r := &FindingRetestRecording{}
		var marks []byte
		var convID int64
		if err := rows.Scan(&r.ID, &r.RetestID, &r.TaskID, &r.App, &r.Backend, &r.Display, &r.TmuxSession, &r.Path,
			&r.Status, &r.Width, &r.Height, &r.FPS, &r.ExecCount, &marks, &r.SHA256,
			&r.StartedAt, &r.FinishedAt, &r.DurationMS, &r.SizeBytes, &r.Error, &convID); err != nil {
			return nil, nil, err
		}
		if len(marks) == 0 {
			marks = []byte("[]")
		}
		r.Marks = marks
		recs = append(recs, r)
		convs = append(convs, convID)
	}
	return recs, convs, rows.Err()
}

// TaskArchiveState 返回任务最新归档状态（无记录则为空），
// 供录屏播放接口在文件已随任务归档时给出明确提示而不是 404。
func (d *DB) TaskArchiveState(taskID int64) (string, error) {
	var state string
	err := d.QueryRow(`SELECT state FROM task_archives WHERE task_id=$1 ORDER BY id DESC LIMIT 1`, taskID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return state, err
}
