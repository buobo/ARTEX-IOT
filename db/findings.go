package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DBFinding is a row in the standalone findings table. It persists across task
// deletion unless the caller explicitly requests related finding cleanup.
type DBFinding struct {
	TrafficCount          int
	EvidenceVersion       int64
	ReportEvidenceVersion int64
	TrafficBindings       []FindingTrafficBinding // populated only for export

	// PocFiles 是这条漏洞的 PoC 文件名（poc/ 下的单层名）。
	PocFiles []string

	ID              int64
	TaskID          *int64
	NodeID          *int64
	VulnClass       string
	Name            string // 漏洞名称(可读标题);为空时前端回退展示 VulnClass
	Severity        string
	Summary         string
	Evidence        string
	Worker          string
	ComponentIDs    []int64
	Status          string
	Report          string // 详细报告(Markdown);仅 GetFinding 填充,列表查询不带
	CreatedAt       time.Time
	TaskDescription string // populated via LEFT JOIN on tasks

	// 审计列：仅 GetFinding 填充。MergedFrom 是本行由哪几条旧漏洞整合而来（一维平表）。
	MergedFrom  []FindingSnapshot
	AuditedAt   *time.Time
	AuditResult string
}

// Finding triage states (findings.status).
const (
	FindingPending       = "pending"        // 待处理
	FindingInProgress    = "in_progress"    // 处理中
	FindingConfirmed     = "confirmed"      // 已确认(真实漏洞,未修复)
	FindingResolved      = "resolved"       // 已处理
	FindingFixed         = "fixed"          // 已修复
	FindingFalsePositive = "false_positive" // 误报
	FindingIgnored       = "ignored"        // 忽略
	FindingDuplicate     = "duplicate"      // 重复
	FindingRiskAccepted  = "risk_accepted"  // 风险接受
)

// ValidFindingStatus reports whether s is a known triage state.
func ValidFindingStatus(s string) bool {
	switch s {
	case FindingPending, FindingInProgress, FindingConfirmed, FindingResolved, FindingFixed,
		FindingFalsePositive, FindingIgnored, FindingDuplicate, FindingRiskAccepted:
		return true
	}
	return false
}

// Finding severity levels (findings.severity).
const (
	SeverityCritical = "critical" // 严重
	SeverityHigh     = "high"     // 高
	SeverityMedium   = "medium"   // 中
	SeverityLow      = "low"      // 低
)

// ValidSeverity reports whether s is a known severity level.
func ValidSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	}
	return false
}

// AddFinding inserts a finding into the standalone findings table. taskID and
// nodeID may be 0 (stored as NULL). name may be "" (frontend falls back to
// vulnclass). Returns the new finding id.
func (d *DB) AddFinding(taskID, nodeID int64, vulnclass, name, severity, summary, evidence, worker string, componentIDs []int64) (int64, error) {
	aidsJSON, _ := json.Marshal(componentIDs)
	if componentIDs == nil {
		aidsJSON = []byte("[]")
	}
	var tid, nid *int64
	if taskID > 0 {
		tid = &taskID
	}
	if nodeID > 0 {
		nid = &nodeID
	}
	var id int64
	err := d.QueryRow(
		`INSERT INTO findings (task_id, node_id, vulnclass, name, severity, summary, evidence, worker, component_ids)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		tid, nid, vulnclass, name, severity, summary, evidence, worker, string(aidsJSON),
	).Scan(&id)
	return id, err
}

// findingSelectCols is the column list (with task_description join) every finding
// list query selects, so scanFinding stays in sync across callers.
const findingSelectCols = `f.id, f.task_id, f.node_id, f.vulnclass, COALESCE(f.name, ''), f.severity, f.summary,
	       f.evidence, f.worker, f.component_ids, COALESCE(f.poc_files, '[]'::jsonb), COALESCE(f.status, 'pending'), f.created_at,
	       COALESCE(t.description, '') AS task_description, f.evidence_version, f.report_evidence_version,
 (SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=f.id)`

// scanFindings materializes rows selected via findingSelectCols.
func scanFindings(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*DBFinding, error) {
	var out []*DBFinding
	for rows.Next() {
		f := &DBFinding{}
		var aidsJSON, pocJSON string
		if err := rows.Scan(&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Name, &f.Severity,
			&f.Summary, &f.Evidence, &f.Worker, &aidsJSON, &pocJSON, &f.Status, &f.CreatedAt, &f.TaskDescription, &f.EvidenceVersion, &f.ReportEvidenceVersion, &f.TrafficCount); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(aidsJSON), &f.ComponentIDs)
		_ = json.Unmarshal([]byte(pocJSON), &f.PocFiles)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListFindings returns all findings (newest first), joined with task description.
// Kept for the dashboard's summary; the paginated 发现 page uses ListFindingsPage.
func (d *DB) ListFindings(limit int) ([]*DBFinding, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := d.Query(`
		SELECT `+findingSelectCols+`
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id
		ORDER BY f.created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// FindingFilter narrows a paginated findings query. Empty-string fields mean "no
// filter on that column". Sort is "severity" (severity desc, then newest) or
// anything else (newest first).
type FindingFilter struct {
	Severity  string // high | medium | low
	Status    string // pending | false_positive | ignored | resolved
	VulnClass string
	TaskID    string // 任务 id(字符串形式;空/非法 = 不按任务筛选)
	Query     string // 名称/类型/摘要/证据/报告正文的模糊检索关键词
	Sort      string // "severity" | "time"
	// ComponentScope 是组件树的节点 key（组件类型名 / component:<id> / __none__），
	// 选中一个节点等于选中它的整棵子树。空 = 不按组件筛选。
	ComponentScope string

	// 下面三个由 applyComponentScope 从 ComponentScope 解析而来,调用方不用设置。
	componentIDs  []int64 // 子树里所有资产 id
	componentNone bool    // 只要「未关联资产」的发现
	componentMiss bool    // 选中的节点在当前筛选下不存在 → 结果恒空
}

// FindingUnassignedTask is the task filter sentinel for findings whose task is
// absent. That includes rows created without a task and rows retained after their
// originating task was deleted (the findings FK is ON DELETE SET NULL).
const FindingUnassignedTask = "__unassigned__"

// where builds the WHERE clause (shared by the page and count queries) plus its
// positional args. All values are parameterized; Query also escapes ILIKE
// wildcards so user input is always matched literally.
func (f FindingFilter) where() (string, []any) {
	var conds []string
	var args []any
	add := func(col, val string) {
		if val == "" {
			return
		}
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("f.%s = $%d", col, len(args)))
	}
	add("severity", f.Severity)
	add("status", f.Status)
	add("vulnclass", f.VulnClass)
	// task_id 是 bigint 列,按整数比较(不能走上面的文本 add);空/非法值忽略。
	if f.TaskID == FindingUnassignedTask {
		conds = append(conds, "(f.task_id IS NULL OR t.id IS NULL)")
	} else if tid, err := strconv.ParseInt(f.TaskID, 10, 64); err == nil && tid > 0 {
		args = append(args, tid)
		conds = append(conds, fmt.Sprintf("f.task_id = $%d", len(args)))
	}
	// 资产筛选:component_ids 是 jsonb 数组,@> ANY(...) 能走 idx_findings_component_ids。
	switch {
	case f.componentMiss:
		conds = append(conds, "FALSE")
	case f.componentNone:
		// 「未关联资产」= component_ids 为空,或者里面的 id 一个都不在 components 表里
		// (资产已被删除)。两类都进资产树的未关联桶,这里必须同样收下,否则桶上
		// 的计数会大于点开后能查到的条数。
		conds = append(conds, `(
			jsonb_array_length(COALESCE(f.component_ids, '[]'::jsonb)) = 0
			OR NOT EXISTS (
				SELECT 1 FROM jsonb_array_elements_text(f.component_ids) e(v)
				JOIN components a ON a.id = e.v::bigint
			)
		)`)
	case len(f.componentIDs) > 0:
		args = append(args, componentIDContainments(f.componentIDs))
		conds = append(conds, fmt.Sprintf("f.component_ids @> ANY($%d::jsonb[])", len(args)))
	}
	if query := strings.TrimSpace(f.Query); query != "" {
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(query)
		args = append(args, "%"+escaped+"%")
		placeholder := fmt.Sprintf("$%d", len(args))
		conds = append(conds, fmt.Sprintf(`(
			COALESCE(f.name, '') ILIKE %s ESCAPE '\' OR
			f.vulnclass ILIKE %s ESCAPE '\' OR
			f.summary ILIKE %s ESCAPE '\' OR
			f.evidence ILIKE %s ESCAPE '\' OR
			COALESCE(f.report, '') ILIKE %s ESCAPE '\'
		)`, placeholder, placeholder, placeholder, placeholder, placeholder))
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListFindingsPage returns one page of findings matching the filter, plus the
// total count of matching rows (for the frontend pager). page is 1-based.
func (d *DB) ListFindingsPage(f FindingFilter, page, pageSize int) ([]*DBFinding, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	f, err := d.applyComponentScope(f)
	if err != nil {
		return nil, 0, err
	}
	where, args := f.where()

	var total int
	if err := d.QueryRow(`SELECT COUNT(*) FROM findings f LEFT JOIN tasks t ON f.task_id=t.id`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	// Avoid overflowing (page-1)*pageSize for an arbitrarily large page number.
	// Once the requested page is beyond the exact count, no data query is needed.
	if total == 0 || page > (total-1)/pageSize+1 {
		return []*DBFinding{}, total, nil
	}

	order := "f.created_at DESC, f.id DESC"
	if f.Sort == "severity" {
		// critical > high > medium > low > 其它, then newest first.
		order = `CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, f.created_at DESC, f.id DESC`
	}
	pageArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	q := fmt.Sprintf(`
		SELECT %s
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d`, findingSelectCols, where, order, len(args)+1, len(args)+2)
	rows, err := d.Query(q, pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out, err := scanFindings(rows)
	return out, total, err
}

// FindingGroup is one task-level bucket in the global findings view. TaskID is
// nil for both findings that never had a task and findings retained after task
// deletion; those records intentionally share one "unassigned/deleted" bucket.
type FindingGroup struct {
	TaskID          *int64    `json:"task_id"`
	TaskName        string    `json:"task_name"` // 可选任务名称;空=未命名
	TaskDescription string    `json:"task_description"`
	TaskStatus      string    `json:"task_status"`
	Count           int       `json:"count"`
	Critical        int       `json:"critical"`
	High            int       `json:"high"`
	Medium          int       `json:"medium"`
	Low             int       `json:"low"`
	LastFoundAt     time.Time `json:"last_found_at"`
}

// ListFindingGroups returns a page of task groups matching the same filters as
// ListFindingsPage. The group count and finding count are independent totals so
// clients can page groups without losing the exact export/selection count.
func (d *DB) ListFindingGroups(f FindingFilter, page, pageSize int) ([]FindingGroup, int, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}
	f, err := d.applyComponentScope(f)
	if err != nil {
		return nil, 0, 0, err
	}
	where, args := f.where()
	grouped := ` FROM findings f LEFT JOIN tasks t ON f.task_id=t.id` + where +
		` GROUP BY t.id, t.name, t.description, t.status, t.paused, t.queued`

	var groupTotal, findingTotal int
	countQuery := `SELECT COUNT(*), COALESCE(SUM(finding_count),0) FROM (` +
		`SELECT COUNT(*) AS finding_count` + grouped + `) grouped_findings`
	if err := d.QueryRow(countQuery, args...).Scan(&groupTotal, &findingTotal); err != nil {
		return nil, 0, 0, err
	}
	if groupTotal == 0 || page > (groupTotal-1)/pageSize+1 {
		return []FindingGroup{}, groupTotal, findingTotal, nil
	}

	order := "MAX(f.created_at) DESC, t.id DESC NULLS LAST"
	if f.Sort == "severity" {
		order = `MAX(CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) DESC, MAX(f.created_at) DESC, t.id DESC NULLS LAST`
	}
	pageArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	query := fmt.Sprintf(`SELECT t.id, COALESCE(t.name,''), COALESCE(t.description,''), COALESCE(
		CASE
			WHEN t.status IN ('done','failed','timeout') THEN t.status
			WHEN t.queued THEN 'queued'
			WHEN t.paused THEN 'paused'
			ELSE t.status
		END, ''),
		COUNT(*),
		COUNT(*) FILTER (WHERE f.severity='critical'),
		COUNT(*) FILTER (WHERE f.severity='high'),
		COUNT(*) FILTER (WHERE f.severity='medium'),
		COUNT(*) FILTER (WHERE f.severity='low'),
		MAX(f.created_at)%s
		ORDER BY %s LIMIT $%d OFFSET $%d`, grouped, order, len(args)+1, len(args)+2)
	rows, err := d.Query(query, pageArgs...)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	groups := []FindingGroup{}
	for rows.Next() {
		var group FindingGroup
		var taskID sql.NullInt64
		if err := rows.Scan(&taskID, &group.TaskName, &group.TaskDescription, &group.TaskStatus, &group.Count,
			&group.Critical, &group.High, &group.Medium, &group.Low, &group.LastFoundAt); err != nil {
			return nil, 0, 0, err
		}
		if taskID.Valid {
			id := taskID.Int64
			group.TaskID = &id
		}
		groups = append(groups, group)
	}
	return groups, groupTotal, findingTotal, rows.Err()
}

// ErrFindingOriginUnavailable means a retained finding no longer has a live
// owning task and finding node from which a follow-up intent can be derived.
var ErrFindingOriginUnavailable = errors.New("finding origin is no longer available")

// AddFindingFollowUpIntent atomically creates a priority-10 human intent from a
// live finding node, copies that finding's component anchors, records the
// finding --derived_from--> intent lineage edge, and persists its audit activity.
// The returned activity is the committed row and can be broadcast as-is without
// calling AppendActivity again.
func (s *ExplorationStore) AddFindingFollowUpIntent(findingID, findingNodeID int64, description string, audit Activity) (int64, Activity, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, Activity{}, err
	}
	defer tx.Rollback()

	var liveNodeID int64
	err = tx.QueryRow(`SELECT n.id
		FROM findings f
		JOIN tasks t ON t.id=f.task_id
		JOIN exploration_nodes n ON n.id=f.node_id AND n.exploration_id=t.exploration_id
		WHERE f.id=$1 AND f.node_id=$2 AND t.exploration_id=$3 AND n.kind='finding'
		FOR SHARE OF f, t, n`, findingID, findingNodeID, s.expID).Scan(&liveNodeID)
	if err == sql.ErrNoRows {
		return 0, Activity{}, ErrFindingOriginUnavailable
	}
	if err != nil {
		return 0, Activity{}, err
	}

	anchors := []int64{}
	anchorRows, err := tx.Query(`SELECT component_id FROM exploration_anchors WHERE node_id=$1 ORDER BY component_id`, liveNodeID)
	if err != nil {
		return 0, Activity{}, err
	}
	for anchorRows.Next() {
		var componentID int64
		if err := anchorRows.Scan(&componentID); err != nil {
			anchorRows.Close()
			return 0, Activity{}, err
		}
		anchors = append(anchors, componentID)
	}
	if err := anchorRows.Err(); err != nil {
		anchorRows.Close()
		return 0, Activity{}, err
	}
	if err := anchorRows.Close(); err != nil {
		return 0, Activity{}, err
	}

	payload := map[string]any{
		"summary":                description,
		"source_finding_id":      findingID,
		"source_finding_node_id": liveNodeID,
	}
	if len(anchors) > 0 {
		payload["component_ids"] = anchors
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, Activity{}, err
	}
	var intentID int64
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
		VALUES ($1,'intent',$2,10,'open','human') RETURNING id`, s.expID, raw).Scan(&intentID); err != nil {
		return 0, Activity{}, err
	}
	if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,component_id)
		SELECT $1, component_id FROM exploration_anchors WHERE node_id=$2
		ON CONFLICT DO NOTHING`, intentID, liveNodeID); err != nil {
		return 0, Activity{}, err
	}
	if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
		VALUES ($1,$2,$3,$4)`, s.expID, liveNodeID, RelDerivedFrom, intentID); err != nil {
		return 0, Activity{}, err
	}

	audit.NodeID = &intentID
	if summary := strings.TrimSpace(audit.Summary); summary != "" {
		audit.Summary = fmt.Sprintf("%s #%d", summary, intentID)
	} else {
		audit.Summary = ""
	}
	metadata := audit.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	if err := tx.QueryRow(`
INSERT INTO activity(exploration_id, node_id, worker, kind, tool, tool_use_id, is_error, summary, detail, metadata, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),$7,NULLIF($8,''),NULLIF($9,''),$10,$11,$12,$13,$14)
RETURNING id, created_at`, s.expID, audit.NodeID, utf8Clean(audit.Worker), utf8Clean(audit.Kind), utf8Clean(audit.Tool), utf8Clean(audit.ToolUseID), audit.IsError,
		utf8Clean(audit.Summary), utf8Clean(audit.Detail), metadata, audit.InputTokens, audit.OutputTokens, audit.CacheReadTokens, audit.CacheWriteTokens).
		Scan(&audit.ID, &audit.CreatedAt); err != nil {
		return 0, Activity{}, err
	}
	audit.Metadata = metadata
	if err := tx.Commit(); err != nil {
		return 0, Activity{}, err
	}
	return intentID, audit, nil
}

// ListFindingsForExport returns findings for the 发现 page 导出功能，携带完整
// report 字段、不分页。ids 非空时按这批 finding id 精确导出(勾选导出),忽略
// filter;ids 为空时按 filter 导出(导出当前筛选/全部)。结果按严重等级降序、
// 再按时间倒序,与「导出汇总报告」的分组顺序一致。
func (d *DB) ListFindingsForExport(f FindingFilter, ids []int64) ([]*DBFinding, error) {
	const order = `ORDER BY CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, f.created_at DESC`
	cols := findingSelectCols + `, COALESCE(f.report, '')`

	var q string
	var args []any
	if len(ids) > 0 {
		ph := make([]string, len(ids))
		for i, id := range ids {
			ph[i] = fmt.Sprintf("$%d", i+1)
			args = append(args, id)
		}
		q = `SELECT ` + cols + `
			FROM findings f
			LEFT JOIN tasks t ON f.task_id = t.id
			WHERE f.id IN (` + strings.Join(ph, ",") + `)
			` + order
	} else {
		scoped, err := d.applyComponentScope(f)
		if err != nil {
			return nil, err
		}
		where, wargs := scoped.where()
		q = `SELECT ` + cols + `
			FROM findings f
			LEFT JOIN tasks t ON f.task_id = t.id` + where + `
			` + order
		args = wargs
	}

	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*DBFinding
	for rows.Next() {
		f := &DBFinding{}
		var aidsJSON, pocJSON string
		if err := rows.Scan(&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Name, &f.Severity,
			&f.Summary, &f.Evidence, &f.Worker, &aidsJSON, &pocJSON, &f.Status, &f.CreatedAt,
			&f.TaskDescription, &f.EvidenceVersion, &f.ReportEvidenceVersion, &f.TrafficCount, &f.Report); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(aidsJSON), &f.ComponentIDs)
		_ = json.Unmarshal([]byte(pocJSON), &f.PocFiles)
		out = append(out, f)
	}
	return out, rows.Err()
}

// FindingStats is the whole-table aggregate powering the 发现 page's stat cards
// and vuln-class filter — computed server-side so it stays exact regardless of
// pagination.
type FindingStats struct {
	Total       int                 `json:"total"`
	Pending     int                 `json:"pending"`
	Critical    int                 `json:"critical"`
	High        int                 `json:"high"`
	Medium      int                 `json:"medium"`
	Low         int                 `json:"low"`
	VulnClasses []string            `json:"vulnclasses"`
	Tasks       []FindingTaskOption `json:"tasks"` // 有漏洞的任务(供「按任务」下拉)
}

// FindingTaskOption is one entry in the 发现 page's 任务 filter: a task that has at
// least one finding, with its description and finding count. Description is empty when
// the task has since been deleted (finding rows persist), so the frontend falls back to
// the id.
type FindingTaskOption struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"` // 可选任务名称;空=未命名
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// FindingStats returns whole-table counts (by severity + pending) and the sorted
// set of distinct vuln classes.
func (d *DB) FindingStats() (*FindingStats, error) {
	st := &FindingStats{VulnClasses: []string{}, Tasks: []FindingTaskOption{}}
	err := d.QueryRow(`SELECT
		COUNT(*),
		COUNT(*) FILTER (WHERE status = 'pending'),
		COUNT(*) FILTER (WHERE severity = 'critical'),
		COUNT(*) FILTER (WHERE severity = 'high'),
		COUNT(*) FILTER (WHERE severity = 'medium'),
		COUNT(*) FILTER (WHERE severity = 'low')
		FROM findings`).Scan(&st.Total, &st.Pending, &st.Critical, &st.High, &st.Medium, &st.Low)
	if err != nil {
		return nil, err
	}
	rows, err := d.Query(`SELECT DISTINCT vulnclass FROM findings WHERE vulnclass <> '' ORDER BY vulnclass`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var vc string
		if err := rows.Scan(&vc); err != nil {
			return nil, err
		}
		st.VulnClasses = append(st.VulnClasses, vc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 任务下拉:有漏洞的任务,带描述(任务删除后为空,前端回退 id)和条数,最新有漏洞的排前。
	trows, err := d.Query(`SELECT f.task_id, COALESCE(t.name, ''), COALESCE(t.description, ''), COUNT(*)
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id
		WHERE f.task_id IS NOT NULL
		GROUP BY f.task_id, t.name, t.description
		ORDER BY MAX(f.created_at) DESC`)
	if err != nil {
		return nil, err
	}
	defer trows.Close()
	for trows.Next() {
		var opt FindingTaskOption
		if err := trows.Scan(&opt.ID, &opt.Name, &opt.Description, &opt.Count); err != nil {
			return nil, err
		}
		st.Tasks = append(st.Tasks, opt)
	}
	if err := trows.Err(); err != nil {
		return nil, err
	}
	archived, err := d.archivedTaskAggregates()
	if err != nil {
		return nil, err
	}
	vulnclasses := make(map[string]bool, len(st.VulnClasses))
	for _, vulnclass := range st.VulnClasses {
		vulnclasses[vulnclass] = true
	}
	for _, aggregate := range archived {
		cold := aggregate.FindingStats
		st.Total += cold.Total
		st.Pending += cold.Pending
		st.Critical += cold.Critical
		st.High += cold.High
		st.Medium += cold.Medium
		st.Low += cold.Low
		for _, vulnclass := range cold.VulnClasses {
			if vulnclass != "" {
				vulnclasses[vulnclass] = true
			}
		}
	}
	st.VulnClasses = st.VulnClasses[:0]
	for vulnclass := range vulnclasses {
		st.VulnClasses = append(st.VulnClasses, vulnclass)
	}
	sort.Strings(st.VulnClasses)
	return st, nil
}

// GetFinding returns a single finding row (with task_description joined and the
// full Markdown report), or nil when no row has that id. Unlike the list queries
// it also selects `report` — that column is only needed on the detail page.
func (d *DB) GetFinding(id int64) (*DBFinding, error) {
	f := &DBFinding{}
	var aidsJSON, pocJSON string
	err := d.QueryRow(`SELECT `+findingSelectCols+`, COALESCE(f.report, ''),
			f.audited_at, COALESCE(f.audit_result, '')
		FROM findings f
		LEFT JOIN tasks t ON f.task_id = t.id
		WHERE f.id = $1`, id).Scan(
		&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Name, &f.Severity,
		&f.Summary, &f.Evidence, &f.Worker, &aidsJSON, &pocJSON, &f.Status, &f.CreatedAt,
		&f.TaskDescription, &f.EvidenceVersion, &f.ReportEvidenceVersion, &f.TrafficCount, &f.Report,
		&f.AuditedAt, &f.AuditResult)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(aidsJSON), &f.ComponentIDs)
	_ = json.Unmarshal([]byte(pocJSON), &f.PocFiles)
	return f, nil
}

// FindingMergeHistory 只给详情页用：取这条漏洞的合并前快照（merged_from）。
// 快照含旧行完整证据与报告，可能到 MB 级，所以不放进通用 GetFinding（流量面板/复测列表/
// chat 提及都是热路径，每次都解析它没必要）。
func (d *DB) FindingMergeHistory(id int64) ([]FindingSnapshot, error) {
	if id <= 0 {
		return nil, nil
	}
	var raw string
	err := d.QueryRow(`SELECT COALESCE(merged_from, '[]'::jsonb) FROM findings WHERE id=$1`, id).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []FindingSnapshot
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out, nil
}

// FindingIDsMergedInto 反查「旧编号并入了哪条新漏洞」，只用于审计留痕文案
// （doc §4.2「#283 未审计：已被并入 #290」）。快照里存了旧行的 id，可以直接反查，
// 不需要单独建映射表。
func (d *DB) FindingIDsMergedInto(oldIDs []int64) map[int64]int64 {
	out := map[int64]int64{}
	for _, id := range dedupeSortedIDs(oldIDs) {
		var newID int64
		err := d.QueryRow(`SELECT id FROM findings WHERE merged_from @> $1::jsonb ORDER BY id LIMIT 1`,
			fmt.Sprintf(`[{"id":%d}]`, id)).Scan(&newID)
		if err == nil {
			out[id] = newID
		}
	}
	return out
}

// DeleteFinding removes a finding entirely: the standalone findings row and its
// originating exploration node (kind='finding'), so it disappears from the findings
// list, the per-task 发现 Tab, and the exploration graph alike. Deleting the node
// cascades its edges + node_components and nulls any activity referencing it. Returns
// rows affected (0 = no finding with that id).
func (d *DB) DeleteFinding(id int64) (n int64, err error) {
	err = d.WithEvidenceTx(context.Background(), func(tx *sql.Tx) error {
		if err := LockFindingEvidenceTx(tx, id, nil); err != nil {
			if errors.Is(err, ErrFindingNotFound) {
				return nil
			}
			return err
		}
		var nodeID sql.NullInt64
		if err := tx.QueryRow(`DELETE FROM findings WHERE id=$1 RETURNING node_id`, id).Scan(&nodeID); err != nil {
			return err
		}
		if nodeID.Valid {
			if _, err := tx.Exec(`DELETE FROM exploration_nodes WHERE id=$1 AND kind='finding'`, nodeID.Int64); err != nil {
				return err
			}
		}
		n = 1
		return nil
	})
	return
}

// DeleteFindingsByTask removes all findings rows of a task. The originating
// exploration finding nodes are cascade-deleted separately when the task's
// exploration subgraph is dropped. Returns rows deleted.
func (d *DB) DeleteFindingsByTask(taskID int64) (int64, error) {
	res, err := d.Exec(`DELETE FROM findings WHERE task_id=$1`, taskID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetFindingStatus updates one finding's triage state. Returns rows affected.
//
// 底层 setter：只改状态、不登记推送事件。生产代码改状态请走
// SetFindingStatusWithNotify —— 直接调本函数会让「状态变更推送」静默失效。
// 保留它是为了让不关心通知的用例（参数校验、复测流程）能单独驱动状态。
func (d *DB) SetFindingStatus(id int64, status string) (int64, error) {
	res, err := d.Exec(`UPDATE findings SET status=$1 WHERE id=$2`, status, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetFindingReportByNodeID sets the Markdown report on the standalone finding row
// whose node_id matches — report_finding returns that node id, so an agent tool
// can address the finding it just created. Returns rows affected (0 when no row).
func (d *DB) SetFindingReportByNodeID(nodeID int64, report string) (int64, error) {
	return d.SetFindingReportVersionByNodeID(context.Background(), nodeID, report, nil)
}

// setFindingCol updates one text column on the standalone finding row AND mirrors
// the new value into the originating exploration node's payload under jsonKey, so the
// per-task 发现 Tab (which reads the node payload, not this table) stays in sync.
// Returns rows affected (0 when no finding has that id); the node sync is best-effort.
// col and jsonKey MUST be trusted constants (they are interpolated into SQL) — never
// pass user input.
func (d *DB) setFindingCol(id int64, col, jsonKey, val string) (int64, error) {
	var nodeID *int64
	err := d.QueryRow(`UPDATE findings SET `+col+`=$1 WHERE id=$2 RETURNING node_id`, val, id).Scan(&nodeID)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if nodeID != nil {
		_, _ = d.Exec(`UPDATE exploration_nodes
			SET payload = jsonb_set(payload, '{`+jsonKey+`}', to_jsonb($1::text))
			WHERE id = $2`, val, *nodeID)
	}
	return 1, nil
}

// SetFindingSeverity updates one finding's severity (+ node payload sync). Returns
// rows affected (0 when no finding has that id).
func (d *DB) SetFindingSeverity(id int64, severity string) (int64, error) {
	return d.setFindingCol(id, "severity", "severity", severity)
}

// SetFindingName updates one finding's 漏洞名称 (+ node payload sync). Empty name is
// allowed — the frontend falls back to the vuln class for display.
func (d *DB) SetFindingName(id int64, name string) (int64, error) {
	return d.setFindingCol(id, "name", "name", name)
}

// SetFindingVulnClass updates one finding's 漏洞类别 (+ node payload sync).
func (d *DB) SetFindingVulnClass(id int64, vulnclass string) (int64, error) {
	return d.setFindingCol(id, "vulnclass", "vulnclass", vulnclass)
}

// FindingMeta is the standalone-row data (id, triage state, anchored components) the
// per-task view grafts onto its exploration-node findings.
type FindingMeta struct {
	TrafficCount int

	ID           int64
	Status       string
	ComponentIDs []int64
}

// FindingMetaByNodeID maps a task's finding node ids to their standalone-row
// metadata (status + anchored component ids) via the component store, so callers holding
// only an ComponentStore (e.g. the agent ToolSet) can reach it without a raw *DB.
func (a *ComponentStore) FindingMetaByNodeID(taskID int64) (map[int64]FindingMeta, error) {
	return a.db.FindingMetaByNodeID(taskID)
}

// FindingMetaByNodeID maps a task's finding node ids to their standalone-row
// metadata, so the per-task view (which reads exploration nodes) can show and
// edit the same status — and the same anchored components — as the global 发现 page.
func (d *DB) FindingMetaByNodeID(taskID int64) (map[int64]FindingMeta, error) {
	out := map[int64]FindingMeta{}
	if taskID <= 0 {
		return out, nil
	}
	rows, err := d.Query(`SELECT node_id, id, COALESCE(status,'pending'), component_ids, (SELECT count(*) FROM finding_traffic_bindings b WHERE b.finding_id=findings.id) FROM findings
		WHERE task_id=$1 AND node_id IS NOT NULL`, taskID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var nid int64
		var m FindingMeta
		var aidsJSON string
		if err := rows.Scan(&nid, &m.ID, &m.Status, &aidsJSON, &m.TrafficCount); err != nil {
			return out, err
		}
		_ = json.Unmarshal([]byte(aidsJSON), &m.ComponentIDs)
		out[nid] = m
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// 漏洞判重审计（auditor）：把 N 条重复漏洞整合成一条
// ---------------------------------------------------------------------------

// 审计结论（findings.audit_result）。
const (
	FindingAuditMerged   = "merged"   // 这一行是被合并出来的产物
	FindingAuditDistinct = "distinct" // 判为不同漏洞，原样保留
	FindingAuditError    = "error"    // 审计失败（模型/超时），未改业务数据
	FindingAuditSkipped  = "skipped"  // 未审就放弃（任务结束 / 队列积压超限）
)

// 长文本上限：与 finding_retests 的既有校验保持一致（summary ≤ 16KB、evidence ≤ 128KB）；
// 报告按 evidence 同一档处理（≤ 128KB）。
const (
	MaxFindingSummaryBytes  = 16000
	MaxFindingEvidenceBytes = 128000
	MaxFindingReportBytes   = 128000
	MaxFindingMergeGroup    = 10 // 一次合并最多几条
	// MaxFindingMergeGroupsPerBatch 是一次审计会话（一个批次）最多合并几组，
	// 防止一次会话把半个任务的漏洞都合掉。
	MaxFindingMergeGroupsPerBatch = 10
)

// FindingSnapshot 是合并前的旧行快照，写进新行的 merged_from（一维平表，不嵌套）。
type FindingSnapshot struct {
	ID           int64     `json:"id"`
	TaskID       *int64    `json:"task_id,omitempty"`
	NodeID       *int64    `json:"node_id,omitempty"`
	Worker       string    `json:"worker"`
	CreatedAt    time.Time `json:"created_at"`
	VulnClass    string    `json:"vulnclass"`
	Name         string    `json:"name"`
	Severity     string    `json:"severity"`
	Summary      string    `json:"summary"`
	Evidence     string    `json:"evidence"`
	Report       string    `json:"report"`
	ComponentIDs []int64   `json:"component_ids"`
	PocFiles     []string  `json:"poc_files"`
	Status       string    `json:"status"`
}

// FindingAuditMerge 是一次「把 N 条旧漏洞整合成一条」的写库请求。
type FindingAuditMerge struct {
	TaskID        int64   // 新行归属任务（当前批次所属任务）
	ExplorationID int64   // 该任务的探索图
	FindingIDs    []int64 // 要合并的旧行（2..MaxFindingMergeGroup）
	VulnClass     string
	Name          string
	Severity      string
	Summary       string
	Evidence      string
	Report        string
	Status        string // 空 = 按旧行继承 confirmed > in_progress > pending
	ComponentIDs  []int64
	PocFiles      []string
	Reason        string
	Operator      string // auditor / manual
	Group         int    // 本批次内的第几组（用于 activity 文案「第 N 组」；0=不标）
	Source        string // 触发来源（finding / manual_one / edit_evidence…），只进 activity metadata
}

// FindingAuditMergeResult 是合并结果。
type FindingAuditMergeResult struct {
	NewFindingID    int64   `json:"new_id"`
	NewNodeID       int64   `json:"new_node_id"`
	Deleted         []int64 `json:"deleted"`
	TrafficBindings int     `json:"traffic_bindings"`
	Retests         int     `json:"retests"`
	SourceTasks     []int64 `json:"source_tasks,omitempty"`
}

func sqlIn(start, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "$%d", start+i)
	}
	return b.String()
}

func dedupeSortedIDs(in []int64) []int64 {
	seen := map[int64]bool{}
	out := make([]int64, 0, len(in))
	for _, id := range in {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type auditOldRow struct {
	id         int64
	taskID     *int64
	nodeID     *int64
	vulnClass  string
	name       string
	severity   string
	summary    string
	evidence   string
	worker     string
	components []int64
	pocFiles   []string
	status     string
	report     string
	mergedFrom []FindingSnapshot
	createdAt  time.Time
}

// FindingsByIDs 按 finding id 批量取原文（含 report），按 id 升序返回；
// 不存在的 id 直接跳过，由调用方按返回的 id 集合判断缺了谁。
func (d *DB) FindingsByIDs(ids []int64) ([]*DBFinding, error) {
	out := make([]*DBFinding, 0, len(ids))
	for _, id := range dedupeSortedIDs(ids) {
		f, err := d.GetFinding(id)
		if err != nil {
			return nil, err
		}
		if f == nil {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// MarkFindingSkipped 把「还没审过」的行标成 skipped；已有结论（distinct/merged/error）的不动，
// 避免任务终局把之前的判重结论覆盖掉。
func (d *DB) MarkFindingSkipped(id int64) error {
	if id <= 0 {
		return nil
	}
	_, err := d.Exec(`UPDATE findings SET audited_at=now(), audit_result=$2
		WHERE id=$1 AND audited_at IS NULL`, id, FindingAuditSkipped)
	return err
}

// MarkFindingAudited 记一条归位结论（merged 由合并事务自己写）。
func (d *DB) MarkFindingAudited(id int64, result string) error {
	if id <= 0 || result == "" {
		return nil
	}
	_, err := d.Exec(`UPDATE findings SET audited_at=now(), audit_result=$2 WHERE id=$1`, id, result)
	return err
}

// ConsolidateFindings 在一个短事务里完成一次合并：
// 锁旧行 → 校验范围/状态/复测冲突/并集 → 建新节点 → 插新行 → 搬子表 → 存快照 → 删旧行与旧节点 → 留痕。
//
// 顺序不能改：子表（流量证据、复测历史）是 ON DELETE CASCADE，必须先搬后删。
func (d *DB) ConsolidateFindings(ctx context.Context, in FindingAuditMerge) (*FindingAuditMergeResult, error) {
	ids := dedupeSortedIDs(in.FindingIDs)
	if len(ids) < 2 {
		return nil, errors.New("合并至少需要两条漏洞")
	}
	if len(ids) > MaxFindingMergeGroup {
		return nil, fmt.Errorf("一次最多合并 %d 条（收到 %d 条）", MaxFindingMergeGroup, len(ids))
	}
	if in.TaskID <= 0 || in.ExplorationID <= 0 {
		return nil, errors.New("合并缺少任务上下文")
	}
	if strings.TrimSpace(in.Report) == "" {
		return nil, errors.New("合并后的报告(report)不能为空")
	}
	if len(in.Report) > MaxFindingReportBytes {
		return nil, fmt.Errorf("合并后的报告过长（report ≤ 128KB，当前 %d 字节）", len(in.Report))
	}
	if len(in.Summary) > MaxFindingSummaryBytes {
		return nil, fmt.Errorf("摘要过长（summary ≤ 16KB，当前 %d 字节）", len(in.Summary))
	}
	if len(in.Evidence) > MaxFindingEvidenceBytes {
		return nil, fmt.Errorf("证据过长（evidence ≤ 128KB，当前 %d 字节）", len(in.Evidence))
	}
	if in.Status != "" && !ValidFindingStatus(in.Status) {
		return nil, fmt.Errorf("未知的漏洞状态 %q", in.Status)
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// 允许范围：本任务 + 它的直接来源任务（与 list_findings 的可见范围一致）。
	allowed := map[int64]bool{in.TaskID: true}
	// 与 list_findings 的可见范围保持一致：软删除的来源任务不参与（DirectSourceStores 同样过滤）。
	srcRows, err := tx.Query(`SELECT relation.source_task_id FROM task_relations relation
		JOIN tasks source ON source.id=relation.source_task_id AND source.deleted_at IS NULL
		WHERE relation.task_id=$1`, in.TaskID)
	if err != nil {
		return nil, err
	}
	for srcRows.Next() {
		var id int64
		if err := srcRows.Scan(&id); err != nil {
			srcRows.Close()
			return nil, err
		}
		allowed[id] = true
	}
	srcRows.Close()

	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := tx.Query(`SELECT id, task_id, node_id, vulnclass, COALESCE(name,''), severity, summary, evidence, worker,
		component_ids, COALESCE(poc_files,'[]'::jsonb), COALESCE(status,'pending'), COALESCE(report,''),
		COALESCE(merged_from,'[]'::jsonb), created_at
		FROM findings WHERE id IN (`+sqlIn(1, len(ids))+`) ORDER BY id FOR UPDATE`, args...)
	if err != nil {
		return nil, err
	}
	old := make([]auditOldRow, 0, len(ids))
	for rows.Next() {
		var r auditOldRow
		var compJSON, pocJSON, mergedJSON string
		if err := rows.Scan(&r.id, &r.taskID, &r.nodeID, &r.vulnClass, &r.name, &r.severity, &r.summary,
			&r.evidence, &r.worker, &compJSON, &pocJSON, &r.status, &r.report, &mergedJSON, &r.createdAt); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal([]byte(compJSON), &r.components)
		_ = json.Unmarshal([]byte(pocJSON), &r.pocFiles)
		if strings.TrimSpace(mergedJSON) != "" && mergedJSON != "[]" {
			_ = json.Unmarshal([]byte(mergedJSON), &r.mergedFrom)
		}
		old = append(old, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(old) != len(ids) {
		found := map[int64]bool{}
		for _, r := range old {
			found[r.id] = true
		}
		missing := make([]string, 0)
		for _, id := range ids {
			if !found[id] {
				missing = append(missing, fmt.Sprintf("#%d", id))
			}
		}
		return nil, fmt.Errorf("%s 已不存在，可能已被合并；请重新 list_findings 后再合并", strings.Join(missing, "、"))
	}

	// 范围、状态、并集校验。
	compUnion := map[int64]bool{}
	pocUnion := map[string]bool{}
	oldNodeIDs := make([]int64, 0, len(old))
	sourceTasks := map[int64]bool{}
	statusRank := 0
	for _, r := range old {
		if r.taskID == nil || !allowed[*r.taskID] {
			return nil, fmt.Errorf("#%d 不在本任务范围内（只能合并本任务或直接来源任务的漏洞）", r.id)
		}
		switch r.status {
		case FindingFalsePositive, FindingIgnored, FindingFixed, FindingResolved:
			return nil, fmt.Errorf("#%d 的状态是 %s，不能参与合并；请只合并仍在处理中的漏洞", r.id, r.status)
		}
		switch r.status {
		case FindingConfirmed:
			if statusRank < 3 {
				statusRank = 3
			}
		case FindingInProgress:
			if statusRank < 2 {
				statusRank = 2
			}
		default:
			if statusRank < 1 {
				statusRank = 1
			}
		}
		for _, c := range r.components {
			compUnion[c] = true
		}
		for _, f := range r.pocFiles {
			pocUnion[f] = true
		}
		if r.nodeID != nil && *r.nodeID > 0 {
			oldNodeIDs = append(oldNodeIDs, *r.nodeID)
		}
		if *r.taskID != in.TaskID {
			sourceTasks[*r.taskID] = true
		}
	}
	for _, c := range in.ComponentIDs {
		if !compUnion[c] {
			return nil, fmt.Errorf("组件 %d 不在这些漏洞原有的组件里；合并不能新增组件", c)
		}
	}
	for _, f := range in.PocFiles {
		if !pocUnion[f] {
			return nil, fmt.Errorf("PoC 文件 %q 不在这些漏洞原有的 PoC 里；合并不能新增 PoC", f)
		}
	}

	// 复测冲突：同一组里只允许一条进行中的复测（partial unique index 的硬约束）。
	retestRows, err := tx.Query(`SELECT finding_id FROM finding_retests WHERE finding_id IN (`+sqlIn(1, len(ids))+`) AND status IN ('pending','running')`, args...)
	if err != nil {
		return nil, err
	}
	activeRetests := map[int64]bool{}
	for retestRows.Next() {
		var id int64
		if err := retestRows.Scan(&id); err != nil {
			retestRows.Close()
			return nil, err
		}
		activeRetests[id] = true
	}
	retestRows.Close()
	if len(activeRetests) > 1 {
		list := make([]string, 0, len(activeRetests))
		for _, id := range ids {
			if activeRetests[id] {
				list = append(list, fmt.Sprintf("#%d", id))
			}
		}
		return nil, fmt.Errorf("%s 都有进行中的复测，合并会与「每条漏洞只允许一条进行中复测」冲突；请等复测结束或先停掉其中一条", strings.Join(list, "、"))
	}

	// 快照：旧行自身 + 它之前已摊平的 merged_from，全部平铺进新行（永远一维）。
	snapshots := make([]FindingSnapshot, 0, len(old))
	for _, r := range old {
		snapshots = append(snapshots, r.mergedFrom...)
		snapshots = append(snapshots, FindingSnapshot{
			ID: r.id, TaskID: r.taskID, NodeID: r.nodeID, Worker: r.worker, CreatedAt: r.createdAt,
			VulnClass: r.vulnClass, Name: r.name, Severity: r.severity, Summary: r.summary,
			Evidence: r.evidence, Report: r.report, ComponentIDs: r.components, PocFiles: r.pocFiles, Status: r.status,
		})
	}
	snapshotJSON, err := json.Marshal(snapshots)
	if err != nil {
		return nil, err
	}

	// 新节点：任务发现页读的是 exploration_nodes，不建节点会出现「漏洞库一条、发现页两条」。
	payload, err := json.Marshal(map[string]any{
		"vulnclass": in.VulnClass, "name": in.Name, "severity": in.Severity, "summary": in.Summary,
		"evidence": map[string]any{"by": in.Operator, "poc": in.Evidence},
	})
	if err != nil {
		return nil, err
	}
	res := &FindingAuditMergeResult{Deleted: ids}
	// 新节点的父意图：组内最早那条漏洞节点由哪个 intent yields 过来。
	var intentID int64
	if len(oldNodeIDs) > 0 {
		nodeArgs := make([]any, len(oldNodeIDs))
		for i, id := range oldNodeIDs {
			nodeArgs[i] = id
		}
		_ = tx.QueryRow(`SELECT src_id FROM exploration_edges WHERE dst_id IN (`+sqlIn(1, len(oldNodeIDs))+`)
			AND rel=$`+fmt.Sprint(len(oldNodeIDs)+1)+` ORDER BY src_id LIMIT 1`,
			append(nodeArgs, RelYields)...).Scan(&intentID)
	}
	// 省略 component_ids / poc_files 时取组内并集：它们是「并集子集」的合法值，
	// 但空集会让新行丢掉组件关联（组件视图/覆盖统计里这条就没了），所以缺省取并集。
	components := in.ComponentIDs
	if components == nil {
		components = make([]int64, 0, len(compUnion))
		for c := range compUnion {
			components = append(components, c)
		}
		sort.Slice(components, func(i, j int) bool { return components[i] < components[j] })
	}
	pocFiles := in.PocFiles
	if pocFiles == nil {
		pocFiles = make([]string, 0, len(pocUnion))
		for f := range pocUnion {
			pocFiles = append(pocFiles, f)
		}
		sort.Strings(pocFiles)
	}
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
		VALUES($1,'finding',$2,9,'confirmed',$3) RETURNING id`, in.ExplorationID, string(payload), in.Operator).Scan(&res.NewNodeID); err != nil {
		return nil, err
	}
	for _, c := range components {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id,component_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, res.NewNodeID, c); err != nil {
			return nil, err
		}
	}
	if intentID > 0 {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			in.ExplorationID, intentID, RelYields, res.NewNodeID); err != nil {
			return nil, err
		}
	}

	// 新行：内容来自模型整合稿；report 必填；evidence_version=0（新证据、新报告）。
	status := in.Status
	if status == "" {
		switch statusRank {
		case 3:
			status = FindingConfirmed
		case 2:
			status = FindingInProgress
		default:
			status = FindingPending
		}
	}
	compJSON, _ := json.Marshal(components)
	pocJSON, _ := json.Marshal(pocFiles)
	if err := tx.QueryRow(`INSERT INTO findings(task_id,node_id,vulnclass,name,severity,summary,evidence,worker,
		component_ids,poc_files,status,report,merged_from,audited_at,audit_result)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now(),$14) RETURNING id`,
		in.TaskID, res.NewNodeID, in.VulnClass, in.Name, in.Severity, in.Summary, in.Evidence, in.Operator,
		string(compJSON), string(pocJSON), status, in.Report, string(snapshotJSON), FindingAuditMerged).Scan(&res.NewFindingID); err != nil {
		return nil, err
	}

	// 搬子表：同一份抓包可能同时绑在组内多条漏洞上，而表上有 UNIQUE(finding_id, snapshot_id)，
	// 直接改指会整组回滚。先按 snapshot_id 去重（保留 position/id 最小的那条，等价于 ON CONFLICT
	// DO NOTHING 但保留最早绑定），再统一改指，最后重排 position。
	if _, err := tx.Exec(`DELETE FROM finding_traffic_bindings a USING finding_traffic_bindings b
		WHERE a.finding_id IN (`+sqlIn(1, len(ids))+`) AND b.finding_id IN (`+sqlIn(1, len(ids))+`)
		  AND a.snapshot_id=b.snapshot_id AND (a.position, a.id) > (b.position, b.id)`,
		args...); err != nil { // 两处 sqlIn 用同一组 $1..$n 占位符，参数只传一份
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE finding_traffic_bindings SET finding_id=$1 WHERE finding_id IN (`+sqlIn(2, len(ids))+`)`,
		append([]any{res.NewFindingID}, args...)...); err != nil {
		return nil, err
	}
	if bindRows, err := tx.Query(`SELECT id FROM finding_traffic_bindings WHERE finding_id=$1 ORDER BY position, id`, res.NewFindingID); err == nil {
		bindIDs := []int64{}
		for bindRows.Next() {
			var id int64
			if err := bindRows.Scan(&id); err == nil {
				bindIDs = append(bindIDs, id)
			}
		}
		bindRows.Close()
		for i, id := range bindIDs {
			if _, err := tx.Exec(`UPDATE finding_traffic_bindings SET position=$1 WHERE id=$2`, i+1, id); err != nil {
				return nil, err
			}
		}
		res.TrafficBindings = len(bindIDs)
	}
	if retestRes, err := tx.Exec(`UPDATE finding_retests SET finding_id=$1 WHERE finding_id IN (`+sqlIn(2, len(ids))+`)`,
		append([]any{res.NewFindingID}, args...)...); err != nil {
		return nil, err
	} else if n, err := retestRes.RowsAffected(); err == nil {
		res.Retests = int(n)
	}

	// 删旧行（带任务条件），行数必须对得上。
	delArgs := append([]any{}, args...)
	delRes, err := tx.Exec(`DELETE FROM findings WHERE id IN (`+sqlIn(1, len(ids))+`)`, delArgs...)
	if err != nil {
		return nil, err
	}
	if n, err := delRes.RowsAffected(); err != nil || int(n) != len(ids) {
		return nil, fmt.Errorf("删除旧漏洞时行数不符（期望 %d，实际 %v），已回滚", len(ids), n)
	}

	// 删旧节点：只删属于允许任务探索图的那批。
	if len(oldNodeIDs) > 0 {
		allowedIDs := make([]int64, 0, len(allowed))
		for id := range allowed {
			allowedIDs = append(allowedIDs, id)
		}
		expArgs := make([]any, 0, len(allowedIDs))
		for _, id := range allowedIDs {
			expArgs = append(expArgs, id)
		}
		expIDs := make([]any, 0, len(allowedIDs))
		taskExp, err := tx.Query(`SELECT exploration_id FROM tasks WHERE id IN (`+sqlIn(1, len(allowedIDs))+`)`, expArgs...)
		if err != nil {
			return nil, err
		}
		for taskExp.Next() {
			var e int64
			if err := taskExp.Scan(&e); err == nil {
				expIDs = append(expIDs, e)
			}
		}
		taskExp.Close()
		if len(expIDs) > 0 {
			nodeDelArgs := make([]any, 0, len(oldNodeIDs)+len(expIDs))
			for _, id := range oldNodeIDs {
				nodeDelArgs = append(nodeDelArgs, id)
			}
			for _, e := range expIDs {
				nodeDelArgs = append(nodeDelArgs, e)
			}
			if _, err := tx.Exec(`DELETE FROM exploration_nodes WHERE id IN (`+sqlIn(1, len(oldNodeIDs))+`)
				AND exploration_id IN (`+sqlIn(len(oldNodeIDs)+1, len(expIDs))+`)`, nodeDelArgs...); err != nil {
				return nil, err
			}
		}
	}

	// 留痕：当前任务一条；被合并了来源任务条目的，在来源任务也留一条。
	meta, _ := json.Marshal(map[string]any{
		"old_ids": ids, "new_id": res.NewFindingID, "reason": in.Reason, "operator": in.Operator,
		"source_tasks": sourceTasks, "source": in.Source, "group": in.Group,
	})
	summary := fmt.Sprintf("漏洞整合：%s → #%d", formatFindingIDs(ids), res.NewFindingID)
	if in.Group > 0 {
		summary = fmt.Sprintf("漏洞整合（第 %d 组）：%s → #%d", in.Group, formatFindingIDs(ids), res.NewFindingID)
	}
	if err := appendAuditActivity(tx, in.ExplorationID, summary, in.Reason, meta); err != nil {
		return nil, err
	}
	for tid := range sourceTasks {
		res.SourceTasks = append(res.SourceTasks, tid)
		var expID int64
		if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1`, tid).Scan(&expID); err == nil && expID > 0 {
			_ = appendAuditActivity(tx, expID,
				fmt.Sprintf("漏洞 %s 已并入任务 #%d 的 #%d", formatFindingIDs(ids), in.TaskID, res.NewFindingID), in.Reason, meta)
		}
	}
	sort.Slice(res.SourceTasks, func(i, j int) bool { return res.SourceTasks[i] < res.SourceTasks[j] })
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

func formatFindingIDs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("#%d", id))
	}
	return strings.Join(parts, " + ")
}

// appendAuditActivity 在给定探索图里写一条 auditor 活动（事务内）。
func appendAuditActivity(tx *sql.Tx, expID int64, summary, detail string, metadata []byte) error {
	if expID <= 0 {
		return nil
	}
	if len(metadata) == 0 {
		metadata = []byte("{}")
	}
	_, err := tx.Exec(`INSERT INTO activity(exploration_id, node_id, worker, kind, tool, tool_use_id, is_error, summary, detail, metadata, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, main_seg)
		VALUES ($1,NULL,'auditor','text',NULL,NULL,false,$2,NULLIF($3,''),$4,0,0,0,0,0)`, expID, summary, detail, string(metadata))
	return err
}

// FindingAuditMeta 是判重队列需要的最小状态：是否已审计、是否合并产物、当前状态与归属任务。
type FindingAuditMeta struct {
	ID        int64
	TaskID    int64
	Status    string
	Audited   bool
	AuditedAt *time.Time
	Merged    bool
}

// FindingAuditMeta 批量读取上述状态（不改共享的 findingSelectCols，避免影响其它查询）。
func (d *DB) FindingAuditMeta(ids []int64) (map[int64]FindingAuditMeta, error) {
	out := map[int64]FindingAuditMeta{}
	ids = dedupeSortedIDs(ids)
	if len(ids) == 0 {
		return out, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := d.Query(`SELECT id, COALESCE(task_id,0), COALESCE(status,'pending'),
		audited_at IS NOT NULL, merged_from IS NOT NULL, audited_at
		FROM findings WHERE id IN (`+sqlIn(1, len(ids))+`)`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var m FindingAuditMeta
		if err := rows.Scan(&m.ID, &m.TaskID, &m.Status, &m.Audited, &m.Merged, &m.AuditedAt); err != nil {
			return out, err
		}
		out[m.ID] = m
	}
	return out, rows.Err()
}

// ActiveFindingIDs 返回本任务可以参与判重的漏洞（排除合并产物与已人工结案的状态），按 id 升序。
func (d *DB) ActiveFindingIDs(taskID int64) ([]int64, error) {
	if taskID <= 0 {
		return nil, nil
	}
	rows, err := d.Query(`SELECT id FROM findings WHERE task_id=$1 AND merged_from IS NULL
		AND COALESCE(status,'pending') NOT IN ('false_positive','ignored','fixed','resolved')
		ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CountAuditedToday 返回本任务今天已经审计过的漏洞数（用于每日上限）。
func (d *DB) CountAuditedToday(taskID int64) (int, error) {
	var n int
	// 合并产物不算「参与审计」（它本身是被审出来的结果），否则合并多的任务额度消耗飞快。
	err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND audited_at >= date_trunc('day', now())
		AND COALESCE(audit_result,'') <> $2`, taskID, FindingAuditMerged).Scan(&n)
	return n, err
}
