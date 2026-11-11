package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// =====================================================================
// 组件表
// =====================================================================
//
// components 由原 components 表改造而来：一行 = 固件里的一个软件实体。
// 复用系统既有语义字段：type 组件类型、component_name 组件名、port/open_ports
// 监听端口、technologies 相关库、task_ids 任务归属、status 复用
// pending/running/completed/ignored 四个状态词。

// ComponentKind* 是 type 列的合法取值（与 schema.sql 的 CHECK 一致）。
var ComponentKinds = []string{"web", "mqtt", "ros", "ssh", "telnet", "upnp", "onvif", "rtsp", "ftp", "other"}

// ComponentStatuses 是 status 列的合法取值：与 tasks/findings 的状态词保持一致。
var ComponentStatuses = []string{"pending", "running", "completed", "ignored"}

// Component is a row in the components table.
type Component struct {
	ID             int64    `json:"id"`
	Type           string   `json:"type"`
	CompanyID      *int64   `json:"company_id,omitempty"`
	TaskIDs        []int64  `json:"task_ids"`
	ComponentName  string   `json:"component_name"`
	Version        string   `json:"version,omitempty"`
	Vendor         string   `json:"vendor,omitempty"`
	BinaryPath     string   `json:"binary_path,omitempty"`
	ConfigPath     string   `json:"config_path,omitempty"`
	StartedBy      string   `json:"started_by,omitempty"`
	FirmwareSha256 string   `json:"firmware_sha256,omitempty"`
	Port           *int     `json:"port,omitempty"`
	OpenPorts      []PortService `json:"open_ports,omitempty"`
	Technologies   []string `json:"technologies,omitempty"`
	Status         string   `json:"status"`
	Notes          string   `json:"notes,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
	LastSeen       string   `json:"last_seen"`

	// 任务维度来源（task_component_links），仅按任务查询时填充。
	TaskSource        string `json:"task_source,omitempty"`
	TaskSourceSummary string `json:"task_source_summary,omitempty"`
	TaskSourceNodeID  *int64 `json:"task_source_node_id,omitempty"`
}

// PortService is one entry in open_ports: {"port":22,"service":"ssh"}.
type PortService struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// ComponentInput is one item accepted by insert_components.
type ComponentInput struct {
	Type           string   `json:"type"`
	Name           string   `json:"component_name"`
	Version        string   `json:"version"`
	Vendor         string   `json:"vendor"`
	BinaryPath     string   `json:"binary_path"`
	ConfigPath     string   `json:"config_path"`
	StartedBy      string   `json:"started_by"`
	FirmwareSha256 string   `json:"firmware_sha256"`
	Port           int      `json:"port"`
	OpenPorts      []PortService `json:"open_ports"`
	Technologies   []string `json:"technologies"`
	Notes          string   `json:"notes"`
	Status         string   `json:"status"`
}

// ComponentFilter narrows ListComponents.
type ComponentFilter struct {
	Type          string // 组件类型（精确）
	NameContains  string // 组件名模糊
	Status        string // 状态（精确）
	TaskID        int64  // >0 时只看该任务
	Limit, Offset int
}

// TypeStat 是按组件类型汇总的挖掘进度。
type TypeStat struct {
	Type      string `json:"type"`
	Total     int    `json:"total"`     // 不含 ignored
	Pending   int    `json:"pending"`
	Running   int    `json:"running"`
	Completed int    `json:"completed"`
	Ignored   int    `json:"ignored"`
}

// ErrComponentInvalid 表示组件输入不合法。
var ErrComponentInvalid = errors.New("组件输入不合法")

// querier 是 *DB 与 *sql.Tx 的公共子集，便于同一份 SQL 在事务内外复用。
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

// ComponentStore operates on the components table.
type ComponentStore struct {
	db      *DB
	company *CompanyStore
	tx      *sql.Tx
}

// Components returns the component store.
func (d *DB) Components() *ComponentStore {
	return &ComponentStore{db: d, company: d.Companies()}
}

// Companies returns the company store associated with this component store.
func (s *ComponentStore) Companies() *CompanyStore { return s.company }

// q 在执行带事务的写入时返回事务对象，否则返回库连接。
func (s *ComponentStore) q() querier {
	if s.tx != nil {
		return s.tx
	}
	return s.db
}

func componentCols() string {
	return `id, type, company_id, array_to_json(task_ids)::text,
       component_name, COALESCE(version,''), COALESCE(vendor,''),
       COALESCE(binary_path,''), COALESCE(config_path,''), COALESCE(started_by,''),
       COALESCE(firmware_sha256,''), port, array_to_json(open_ports)::text,
       array_to_json(technologies)::text, status, COALESCE(notes,''),
       extra, last_seen::text`
}

// scanComponent 扫描 componentCols() 的列。
func scanComponent(sc interface{ Scan(...any) error }) (*Component, error) {
	var (
		c          Component
		taskIDs    string
		openPorts  string
		techs      string
		extra      []byte
	)
	if err := sc.Scan(&c.ID, &c.Type, &c.CompanyID, &taskIDs, &c.ComponentName,
		&c.Version, &c.Vendor, &c.BinaryPath, &c.ConfigPath, &c.StartedBy,
		&c.FirmwareSha256, &c.Port, &openPorts, &techs, &c.Status, &c.Notes,
		&extra, &c.LastSeen); err != nil {
		return nil, err
	}
	c.TaskIDs = parseIDArray(taskIDs)
	c.OpenPorts = parsePortServices(openPorts)
	c.Technologies = parseStringArray(techs)
	if len(extra) > 0 {
		_ = json.Unmarshal(extra, &c.Extra)
	}
	return &c, nil
}

func scanComponents(rows *sql.Rows) ([]*Component, error) {
	defer rows.Close()
	var out []*Component
	for rows.Next() {
		c, err := scanComponent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func parseIDArray(s string) []int64 {
	if s == "" || s == "null" {
		return nil
	}
	var ids []int64
	if err := json.Unmarshal([]byte(s), &ids); err != nil {
		return nil
	}
	return ids
}

func parseStringArray(s string) []string {
	if s == "" || s == "null" {
		return nil
	}
	var v []string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}

func parsePortServices(s string) []PortService {
	if s == "" || s == "null" {
		return nil
	}
	var v []PortService
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}

func marshalStringArray(items []string) string {
	if len(items) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(items)
	return string(b)
}

func marshalPortServices(items []PortService) string {
	if len(items) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(items)
	return string(b)
}

// normalizeKind 校验组件类型，空值落 other。
func normalizeKind(typ string) (string, bool) {
	t := strings.ToLower(strings.TrimSpace(typ))
	if t == "" {
		return "other", true
	}
	for _, k := range ComponentKinds {
		if t == k {
			return t, true
		}
	}
	return "", false
}

// normalizeComponentStatus 校验状态词，空值落 pending。
func normalizeComponentStatus(st string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(st))
	if v == "" {
		return "pending", true
	}
	for _, s := range ComponentStatuses {
		if v == s {
			return v, true
		}
	}
	return "", false
}

// UpsertComponents 批量登记组件。唯一键 (firmware_sha256,type,component_name,version)：
// 已存在则补齐缺失字段（版本/二进制/启动脚本），不覆盖已有值。
// 返回新增数、更新数、对应的组件 id（与 items 顺序一致）。
func (s *ComponentStore) UpsertComponents(taskIDs []int64, items []ComponentInput) (inserted, updated int, ids []int64, err error) {
	if len(items) == 0 {
		return 0, 0, nil, fmt.Errorf("%w: 至少 1 个组件", ErrComponentInvalid)
	}
	for i := range items {
		kind, ok := normalizeKind(items[i].Type)
		if !ok {
			return 0, 0, nil, fmt.Errorf("%w: 第 %d 条 type=%q 不在 %v 内",
				ErrComponentInvalid, i+1, items[i].Type, ComponentKinds)
		}
		items[i].Type = kind
		if strings.TrimSpace(items[i].Name) == "" {
			return 0, 0, nil, fmt.Errorf("%w: 第 %d 条缺 component_name", ErrComponentInvalid, i+1)
		}
		st, ok := normalizeComponentStatus(items[i].Status)
		if !ok {
			return 0, 0, nil, fmt.Errorf("%w: 第 %d 条 status=%q 不在 %v 内",
				ErrComponentInvalid, i+1, items[i].Status, ComponentStatuses)
		}
		items[i].Status = st
	}

	q := s.q()
	// nil 切片会被驱动写成 NULL，而 task_ids 要求非空数组：空时用 '{}' 字面量。
	var taskIDsArg any = "{}"
	if len(taskIDs) > 0 {
		taskIDsArg = taskIDs
	}
	for i := range items {
		it := items[i]
		var id int64
		var created bool
		row := q.QueryRow(`
INSERT INTO components
    (type, task_ids, component_name, version, vendor, binary_path, config_path,
     started_by, firmware_sha256, port, open_ports, technologies, status, notes)
VALUES ($1, $2::bigint[], $3, NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), NULLIF($7,''),
        NULLIF($8,''), NULLIF($9,''), NULLIF($10,0), $11::jsonb[], $12::text[], $13, $14)
ON CONFLICT (COALESCE(firmware_sha256,''), type, component_name, COALESCE(version,''))
DO UPDATE SET
    version       = COALESCE(NULLIF(EXCLUDED.version,''), components.version),
    vendor        = COALESCE(NULLIF(EXCLUDED.vendor,''), components.vendor),
    binary_path   = COALESCE(NULLIF(EXCLUDED.binary_path,''), components.binary_path),
    config_path   = COALESCE(NULLIF(EXCLUDED.config_path,''), components.config_path),
    started_by    = COALESCE(NULLIF(EXCLUDED.started_by,''), components.started_by),
    port          = COALESCE(EXCLUDED.port, components.port),
    open_ports    = CASE WHEN cardinality(EXCLUDED.open_ports) > 0 THEN EXCLUDED.open_ports ELSE components.open_ports END,
    technologies  = CASE WHEN cardinality(EXCLUDED.technologies) > 0 THEN EXCLUDED.technologies ELSE components.technologies END,
    notes         = CASE WHEN EXCLUDED.notes <> '' THEN EXCLUDED.notes ELSE components.notes END,
    task_ids      = (SELECT array_agg(DISTINCT x) FROM unnest(components.task_ids || EXCLUDED.task_ids) AS x),
    last_seen     = now(),
    updated_at    = now()
RETURNING id, (xmax = 0) AS created`,
			it.Type, taskIDsArg, it.Name, it.Version, it.Vendor, it.BinaryPath, it.ConfigPath,
			it.StartedBy, it.FirmwareSha256, it.Port,
			marshalPortServices(it.OpenPorts), marshalStringArray(it.Technologies),
			it.Status, it.Notes)
		if err := row.Scan(&id, &created); err != nil {
			return inserted, updated, ids, err
		}
		if created {
			inserted++
		} else {
			updated++
		}
		ids = append(ids, id)
	}
	return inserted, updated, ids, nil
}

// ListComponents returns components matching f, plus the total count for pagination.
func (s *ComponentStore) ListComponents(f ComponentFilter) ([]*Component, int, error) {
	where := []string{"1=1"}
	var args []any
	if f.Type != "" {
		args = append(args, f.Type)
		where = append(where, fmt.Sprintf("type = $%d", len(args)))
	}
	if f.NameContains != "" {
		args = append(args, "%"+f.NameContains+"%")
		where = append(where, fmt.Sprintf("component_name ILIKE $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	if f.TaskID > 0 {
		args = append(args, f.TaskID)
		where = append(where, fmt.Sprintf("$%d = ANY(task_ids)", len(args)))
	}
	clause := strings.Join(where, " AND ")

	var total int
	if err := s.q().QueryRow("SELECT count(*) FROM components WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	rows, err := s.q().Query("SELECT "+componentCols()+" FROM components WHERE "+clause+
		fmt.Sprintf(" ORDER BY last_seen DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := scanComponents(rows)
	return out, total, err
}

// GetByIDs returns components by primary key.
func (s *ComponentStore) GetByIDs(ids []int64) ([]*Component, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.q().Query("SELECT "+componentCols()+" FROM components WHERE id = ANY($1::bigint[])", ids)
	if err != nil {
		return nil, err
	}
	return scanComponents(rows)
}

// DeleteByIDs removes components.
func (s *ComponentStore) DeleteByIDs(ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	res, err := s.q().Exec(`DELETE FROM components WHERE id = ANY($1::bigint[])`, ids)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteByTaskID detaches every component from a task and deletes the ones left orphaned.
func (s *ComponentStore) DeleteByTaskID(taskID int64) (int64, error) {
	if taskID <= 0 {
		return 0, nil
	}
	q := s.q()
	if _, err := q.Exec(`UPDATE components SET task_ids = array_remove(task_ids, $1) WHERE $1 = ANY(task_ids)`, taskID); err != nil {
		return 0, err
	}
	res, err := q.Exec(`DELETE FROM components WHERE cardinality(task_ids) = 0`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountsByType returns component counts per type (optionally scoped to a task).
func (s *ComponentStore) CountsByType(taskID int64) (map[string]int, error) {
	query := `SELECT type, count(*) FROM components WHERE status <> 'ignored'`
	args := []any{}
	if taskID > 0 {
		args = append(args, taskID)
		query += ` AND $1 = ANY(task_ids)`
	}
	query += ` GROUP BY type`
	rows, err := s.q().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}

// ComponentStats returns per-type progress for a task (denominator excludes ignored).
func (s *ComponentStore) ComponentStats(taskID int64) ([]TypeStat, error) {
	query := `SELECT type,
       count(*) FILTER (WHERE status <> 'ignored') AS total,
       count(*) FILTER (WHERE status = 'pending')   AS pending,
       count(*) FILTER (WHERE status = 'running')   AS running,
       count(*) FILTER (WHERE status = 'completed') AS completed,
       count(*) FILTER (WHERE status = 'ignored')   AS ignored
FROM components`
	var args []any
	if taskID > 0 {
		args = append(args, taskID)
		query += ` WHERE $1 = ANY(task_ids)`
	}
	query += ` GROUP BY type ORDER BY type`
	rows, err := s.q().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TypeStat
	for rows.Next() {
		var t TypeStat
		if err := rows.Scan(&t.Type, &t.Total, &t.Pending, &t.Running, &t.Completed, &t.Ignored); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetComponentStatus updates one component's mining status.
func (s *ComponentStore) SetComponentStatus(id int64, status string) error {
	st, ok := normalizeComponentStatus(status)
	if !ok {
		return fmt.Errorf("%w: status=%q 不在 %v 内", ErrComponentInvalid, status, ComponentStatuses)
	}
	res, err := s.q().Exec(`UPDATE components SET status=$2, updated_at=now() WHERE id=$1`, id, st)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("组件 %d 不存在", id)
	}
	return nil
}

// AttachComponentsToTask adds a task id to the given components and records provenance.
func (s *ComponentStore) AttachComponentsToTask(taskID int64, ids []int64, sourceSummary string) (int64, error) {
	if taskID <= 0 || len(ids) == 0 {
		return 0, fmt.Errorf("%w: task_id/组件 id 不能为空", ErrComponentInvalid)
	}
	q := s.q()
	res, err := q.Exec(`UPDATE components SET task_ids = (
        SELECT array_agg(DISTINCT x) FROM unnest(task_ids || $1::bigint[]) AS x
    ), updated_at = now() WHERE id = ANY($2::bigint[])`, []int64{taskID}, ids)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if _, err := q.Exec(`
INSERT INTO task_component_links(task_id, component_id, source, source_summary)
SELECT $1, unnest($2::bigint[]), 'manual', $3
ON CONFLICT (task_id, component_id) DO UPDATE SET source_summary = EXCLUDED.source_summary`,
			taskID, ids, sourceSummary); err != nil {
			return n, err
		}
	}
	return n, nil
}

// DetachComponentFromTask removes one component from a task.
func (s *ComponentStore) DetachComponentFromTask(taskID, componentID int64) (bool, error) {
	q := s.q()
	res, err := q.Exec(`UPDATE components SET task_ids = array_remove(task_ids, $1), updated_at = now()
WHERE id = $2 AND $1 = ANY(task_ids)`, taskID, componentID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	if _, err := q.Exec(`DELETE FROM task_component_links WHERE task_id=$1 AND component_id=$2`, taskID, componentID); err != nil {
		return true, err
	}
	return true, nil
}

// SetTaskComponentSource records how a task↔component association was obtained.
func (s *ComponentStore) SetTaskComponentSource(taskID, componentID int64, source, summary string, nodeID *int64) error {
	_, err := s.q().Exec(`
INSERT INTO task_component_links(task_id, component_id, source, source_summary, source_node_id)
VALUES ($1, $2, NULLIF($3,''), NULLIF($4,''), $5)
ON CONFLICT (task_id, component_id) DO UPDATE
   SET source = COALESCE(NULLIF(EXCLUDED.source,''), task_component_links.source),
       source_summary = COALESCE(NULLIF(EXCLUDED.source_summary,''), task_component_links.source_summary),
       source_node_id = COALESCE(EXCLUDED.source_node_id, task_component_links.source_node_id),
       updated_at = now()`,
		taskID, componentID, source, summary, nodeID)
	return err
}

// IntentComponent 是某意图（探索节点）锚定到的组件。
type IntentComponent struct {
	ID            int64  `json:"id"`
	ComponentID   int64  `json:"component_id"`
	Type          string `json:"type"`
	ComponentName string `json:"component_name"`
	Version       string `json:"version,omitempty"`
	Status        string `json:"status"`
}

// IntentComponents returns the components anchored to a task's exploration nodes.
func (s *ComponentStore) IntentComponents(taskID int64) ([]IntentComponent, error) {
	rows, err := s.q().Query(`
SELECT DISTINCT c.id, c.type, c.component_name, COALESCE(c.version,''), c.status
FROM exploration_anchors a
JOIN components c ON c.id = a.component_id
JOIN exploration_nodes n ON n.id = a.node_id
JOIN explorations e ON e.id = n.exploration_id
JOIN tasks t ON t.exploration_id = e.id
WHERE t.id = $1
ORDER BY c.type, c.component_name`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntentComponent
	for rows.Next() {
		var it IntentComponent
		if err := rows.Scan(&it.ID, &it.Type, &it.ComponentName, &it.Version, &it.Status); err != nil {
			return nil, err
		}
		it.ComponentID = it.ID
		out = append(out, it)
	}
	return out, rows.Err()
}

// hostsForTaskDeletion 历史上返回「删除任务后不再被其他任务引用的主机」。
// 组件表没有主机维度，恒返回空。
func hostsForTaskDeletion(_ *sql.Tx, _ int64, _ int64) ([]string, error) {
	return nil, nil
}

// ErrTaskComponentInvalid 表示任务↔组件挂载参数非法（空列表、id 非正）。
var ErrTaskComponentInvalid = errors.New("invalid task component")

// ErrTaskComponentTaskNotFound / ErrTaskComponentComponentNotFound 供 server 层做 404 映射。
var (
	ErrTaskComponentTaskNotFound      = errors.New("task not found")
	ErrTaskComponentComponentNotFound = errors.New("component not found")
)

// SetTaskComponentStatus updates one component's status with a task guard:
// the component must be attached to taskID (taskID<=0 skips the guard).
func (s *ComponentStore) SetTaskComponentStatus(taskID, id int64, status string) error {
	st, ok := normalizeComponentStatus(status)
	if !ok {
		return fmt.Errorf("%w: status=%q 不在 %v 内", ErrComponentInvalid, status, ComponentStatuses)
	}
	var (
		res sql.Result
		err error
	)
	if taskID > 0 {
		res, err = s.q().Exec(`UPDATE components SET status=$2, updated_at=now()
WHERE id=$1 AND $3 = ANY(task_ids)`, id, st, taskID)
	} else {
		res, err = s.q().Exec(`UPDATE components SET status=$2, updated_at=now() WHERE id=$1`, id, st)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("组件 %d 不在本任务范围内或不存在", id)
	}
	return nil
}
