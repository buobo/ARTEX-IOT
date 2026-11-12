package db

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// TaskScope is one row of a task's test scope — the coverage denominator and the
// per-task authorization edge. Rows come either from insertComponents (source='auto',
// conservative, one per explicitly-inserted component) or from the add_task_scope tool
// (source='agent', for company / domain / network / ICP / keyword scope).
type TaskScope struct {
	ID        int64  `json:"id"`
	TaskID    int64  `json:"task_id"`
	Kind      string `json:"kind"` // company|root_domain|subdomain|ip|cidr|icp|keyword|firmware|device
	CompanyID *int64 `json:"company_id,omitempty"`
	// CompanyName is resolved for kind=company so callers can label a scope row
	// without a second lookup. Empty when the row is not a company reference.
	CompanyName string `json:"company_name,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Net         string `json:"net,omitempty"`
	Value       string `json:"value,omitempty"`
	// Sha256 is set only for kind=firmware: lowercase 64-hex digest of the firmware
	// image. value(filename) + sha256 are the firmware's identity, so two different
	// images that share a filename stay distinct rows.
	Sha256 string `json:"sha256,omitempty"`
	// ExtractPath is set only for kind=firmware: the firmware's unpacked root
	// directory, RELATIVE to the task dir (e.g. "firmware/rootfs", "i50/extract/rootfs").
	// Empty means "not unpacked yet" — upload never writes it; the first unpacking
	// worker fills it in via the register_extract tool.
	ExtractPath string `json:"extract_path,omitempty"`
	// Vendor/Version 只对 kind=firmware 有意义：固件的厂商与版本。
	// 同一个 sha256 的所有行始终写着同一份值（写入时按 sha 全量同步）；
	// 人可以覆盖（MetaSource=manual），agent 只能补空。
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
	// MetaSource 记录固件厂商/版本是谁最后定的：manual | agent。
	MetaSource string `json:"meta_source,omitempty"`
	Source     string `json:"source"`
	Reason     string `json:"reason,omitempty"`
}

// stripHostPort drops a trailing :port from a host:port / ip:port / [ipv6]:port
// value, returning the bare host. Bare hosts, bare IPs (v4 or v6, whose colons make
// them ambiguous), and anything not in host:port form are returned unchanged. Scope
// is host/net based, so the port from a target like "10.0.188.136:3000" or
// "api.example.com:8080" is simply discarded rather than baked into the key.
func stripHostPort(v string) string {
	v = strings.TrimSpace(v)
	if host, _, err := net.SplitHostPort(v); err == nil {
		return host
	}
	return v
}

// ipToHostCIDR turns a bare IP into its single-host CIDR (/32 or /128). "" if invalid.
func ipToHostCIDR(ip string) string {
	ip = strings.TrimSpace(ip)
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if p.To4() != nil {
		return ip + "/32"
	}
	return ip + "/128"
}

// upsertTaskScope inserts one scope row idempotently (uq_task_scope). A duplicate is
// silently ignored. taskID<=0 or empty kind → no-op.
func (s *ComponentStore) upsertTaskScopeResult(ts TaskScope) (bool, error) {
	if ts.TaskID <= 0 || ts.Kind == "" {
		return false, nil
	}
	var domainVal, netVal, companyVal, valueVal any
	if ts.Domain != "" {
		domainVal = ts.Domain
	}
	if ts.Net != "" {
		netVal = ts.Net
	}
	if ts.CompanyID != nil && *ts.CompanyID > 0 {
		companyVal = *ts.CompanyID
	}
	if ts.Value != "" {
		valueVal = ts.Value
	}
	var shaVal any
	if ts.Sha256 != "" {
		shaVal = ts.Sha256
	}
	src := ts.Source
	if src == "" {
		src = "auto"
	}
	query := `
INSERT INTO task_scope(task_id, kind, company_id, domain, net, value, sha256, source, reason,
                       vendor, version, meta_source, meta_updated_at)
VALUES ($1,$2,$3,$4,$5::cidr,$6,$7,$8,NULLIF($9,''),
        NULLIF($10,''), NULLIF($11,''), NULLIF($12,''),
        CASE WHEN COALESCE($10,'')='' AND COALESCE($11,'')='' THEN NULL ELSE now() END)
ON CONFLICT DO NOTHING`
	var (
		result sql.Result
		err    error
	)
	if s.tx != nil {
		result, err = s.tx.Exec(query, ts.TaskID, ts.Kind, companyVal, domainVal, netVal, valueVal, shaVal, src, ts.Reason,
			ts.Vendor, ts.Version, ts.MetaSource)
	} else {
		result, err = s.db.Exec(query, ts.TaskID, ts.Kind, companyVal, domainVal, netVal, valueVal, shaVal, src, ts.Reason,
			ts.Vendor, ts.Version, ts.MetaSource)
	}
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}

func (s *ComponentStore) upsertTaskScope(ts TaskScope) error {
	_, err := s.upsertTaskScopeResult(ts)
	return err
}

func (s *ComponentStore) AddAgentScope(taskID int64, kind, value, reason, source string) (TaskScope, error) {
	if source == "" {
		source = "agent"
	}
	ts := TaskScope{TaskID: taskID, Kind: kind, Source: source, Reason: reason}
	if taskID <= 0 {
		return ts, fmt.Errorf("需要 task_id")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return ts, fmt.Errorf("value 不能为空")
	}
	switch kind {
	case "company":
		if s.company == nil {
			return ts, fmt.Errorf("company store 未启用")
		}
		var comp *Company
		var err error
		if id, e := strconv.ParseInt(value, 10, 64); e == nil {
			comp, err = s.company.GetCompany(id)
		} else {
			comp, err = s.company.GetCompanyByName(value)
		}
		if err != nil {
			return ts, err
		}
		if comp == nil {
			return ts, fmt.Errorf("company 不存在: %s（先用 list_companies 确认，或建好企业）", value)
		}
		ts.CompanyID = &comp.ID
	case "root_domain":
		d := DomainKey(stripHostPort(value))
		root, _ := RootDomain(d)
		if root == "" {
			root = d
		}
		if root == "" {
			return ts, fmt.Errorf("无效根域: %s", value)
		}
		ts.Domain = root
	case "subdomain":
		d := DomainKey(stripHostPort(value))
		if d == "" {
			return ts, fmt.Errorf("无效子域: %s", value)
		}
		ts.Domain = d
	case "ip", "cidr":
		v := value
		if !strings.Contains(v, "/") {
			v = ipToHostCIDR(stripHostPort(v))
			ts.Kind = "ip"
		} else {
			ts.Kind = "cidr"
		}
		if v == "" {
			return ts, fmt.Errorf("无效 ip/cidr: %s", value)
		}
		if _, _, err := net.ParseCIDR(v); err != nil {
			return ts, fmt.Errorf("无效 ip/cidr: %s", value)
		}
		ts.Net = v
	case "icp", "keyword":
		parsed, err := ParseScopeInput(ScopeInput{Kind: kind, Value: value})
		if err != nil {
			return ts, err
		}
		ts.Value = parsed.Value
	case "firmware":
		// 固件文件名。sha256 单独走 AddFirmwareScope（工具层在拿到摘要时调用），
		// 这里允许只登记文件名，保证"先登记固件、后算摘要"也能用。
		if len(value) > 256 {
			return ts, fmt.Errorf("firmware 文件名过长: %d 字符", len(value))
		}
		ts.Value = value
	case "device":
		// 靶机：value 形如 "192.168.1.50" 或 "192.168.1.50 RP09"（IP + 型号）。
		host, model := splitDeviceValue(value)
		netVal := ipToHostCIDR(host)
		if netVal == "" {
			return ts, fmt.Errorf("无效 device（需要一个 IP，可选跟型号）: %s", value)
		}
		if _, _, err := net.ParseCIDR(netVal); err != nil {
			return ts, fmt.Errorf("无效 device IP: %s", host)
		}
		ts.Net = netVal
		ts.Value = model
	default:
		return ts, fmt.Errorf("不支持的 kind: %s（company/root_domain/subdomain/ip/cidr/icp/keyword/firmware/device）", kind)
	}
	if err := s.upsertTaskScope(ts); err != nil {
		return ts, err
	}
	return ts, nil
}

// AddFirmwareScope records a firmware image as task scope (kind='firmware').
// filename + sha256 are the image's identity: two different images that happen to
// share a filename stay separate rows. sha256 may be empty (not hashed yet), but when
// present it must be 64 lowercase hex — we reject anything else instead of storing it.
func (s *ComponentStore) AddFirmwareScope(taskID int64, filename, sha256, reason, source string) (TaskScope, error) {
	if source == "" {
		source = "agent"
	}
	ts := TaskScope{TaskID: taskID, Kind: "firmware", Source: source, Reason: reason}
	if taskID <= 0 {
		return ts, fmt.Errorf("需要 task_id")
	}
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return ts, fmt.Errorf("firmware 文件名不能为空")
	}
	sha := strings.ToLower(strings.TrimSpace(sha256))
	if sha != "" && !isHex64(sha) {
		return ts, fmt.Errorf("sha256 需要 64 位十六进制（小写），收到 %d 字符", len(sha))
	}
	ts.Value = filename
	ts.Sha256 = sha
	// 同一个固件（sha）在所有任务里的厂商/版本必须一致：登记前先把已有值取出来，
	// 新行直接带着写，避免出现"这行有值、那行空"。
	if sha != "" {
		if m, mErr := s.FirmwareMetaBySha(sha); mErr == nil {
			ts.Vendor, ts.Version, ts.MetaSource = m.Vendor, m.Version, m.Source
		}
	}
	// 同名固件只留一行：调用方没给 sha、或库里已有同名的无 sha 老行时，复用/升级那一行，
	// 不再插新行（唯一键把 '' 和具体值当成两行，否则列表里会出现两条同名固件）。
	var existingID int64
	var existingSha, existingExtract string
	qerr := s.q().QueryRow(`SELECT id, COALESCE(sha256,''), COALESCE(extract_path,'') FROM task_scope
 WHERE task_id=$1 AND kind='firmware' AND value=$2
 ORDER BY (COALESCE(sha256,'') <> '') DESC, id LIMIT 1`, taskID, filename).Scan(&existingID, &existingSha, &existingExtract)
	switch {
	case qerr == nil && existingSha == "" && sha != "":
		if _, err := s.q().Exec(`UPDATE task_scope SET sha256=$2,
		       vendor=COALESCE(NULLIF(vendor,''), NULLIF($3,'')),
		       version=COALESCE(NULLIF(version,''), NULLIF($4,'')),
		       meta_source=COALESCE(NULLIF(meta_source,''), NULLIF($5,''))
		     WHERE id=$1`, existingID, sha, ts.Vendor, ts.Version, ts.MetaSource); err != nil {
			return ts, err
		}
		ts.ID = existingID
		ts.Sha256 = sha
		ts.ExtractPath = existingExtract
		return ts, nil
	case qerr == nil:
		ts.ID = existingID
		ts.Sha256 = existingSha
		ts.ExtractPath = existingExtract
		return ts, nil
	case !errors.Is(qerr, sql.ErrNoRows):
		return ts, qerr
	}
	if err := s.upsertTaskScope(ts); err != nil {
		return ts, err
	}
	return ts, nil
}

// SetFirmwareExtract records WHERE a firmware image was unpacked. Upload never sets
// it — the first worker that actually unpacks fills it in via the register_extract
// tool, so the column means "this image has been unpacked, here's the rootfs".
//
// Row resolution is sha256-FIRST on purpose: AddFirmwareScope above reuses a row by
// filename alone (same name, different content → still the old row), so matching by
// name here could write the path onto a different image. filename is only the
// fallback; when nothing matches, a firmware row is created (source='agent').
//
// relPath is stored verbatim (relative to the task dir); callers validate it first.
// Returns the updated row and the previous value ("" when it had none).
func (s *ComponentStore) SetFirmwareExtract(taskID int64, sha256, filename, relPath, reason string) (TaskScope, string, error) {
	ts := TaskScope{TaskID: taskID, Kind: "firmware", Source: "agent", Reason: reason}
	if taskID <= 0 {
		return ts, "", fmt.Errorf("需要 task_id")
	}
	relPath = strings.Trim(strings.TrimSpace(relPath), "/")
	if relPath == "" {
		return ts, "", fmt.Errorf("extract_path 不能为空")
	}
	sha := strings.ToLower(strings.TrimSpace(sha256))
	if sha != "" && !isHex64(sha) {
		return ts, "", fmt.Errorf("sha256 需要 64 位十六进制（小写），收到 %d 字符", len(sha))
	}
	filename = strings.TrimSpace(filename)

	var (
		id   int64
		prev string
	)
	// 1) 摘要优先：固件的真正身份。
	if sha != "" {
		var rowValue string
		err := s.q().QueryRow(`SELECT id, COALESCE(value,''), COALESCE(extract_path,'') FROM task_scope
 WHERE task_id=$1 AND kind='firmware' AND sha256=$2 ORDER BY id LIMIT 1`, taskID, sha).
			Scan(&id, &rowValue, &prev)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ts, "", err
		}
		if id > 0 && filename == "" {
			filename = rowValue
		}
	}
	// 2) 文件名兜底（老行可能还没 sha，顺手补上）。
	if id == 0 && filename != "" {
		var rowSha string
		err := s.q().QueryRow(`SELECT id, COALESCE(sha256,''), COALESCE(extract_path,'') FROM task_scope
 WHERE task_id=$1 AND kind='firmware' AND value=$2
 ORDER BY (COALESCE(sha256,'') <> '') DESC, id LIMIT 1`, taskID, filename).Scan(&id, &rowSha, &prev)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ts, "", err
		}
		if id > 0 && rowSha == "" && sha != "" {
			if _, err := s.q().Exec(`UPDATE task_scope SET sha256=$2 WHERE id=$1`, id, sha); err != nil {
				return ts, "", err
			}
			rowSha = sha
		}
		sha = rowSha
	}
	// 3) 都没有：登记一份新的固件行。
	if id == 0 {
		if filename == "" {
			return ts, "", fmt.Errorf("找不到对应固件行，也没给文件名，无法登记解包路径")
		}
		created, err := s.AddFirmwareScope(taskID, filename, sha, reason, "agent")
		if err != nil {
			return ts, "", err
		}
		id = created.ID
		if created.Sha256 != "" {
			sha = created.Sha256
		}
	}
	if _, err := s.q().Exec(`UPDATE task_scope SET extract_path=$2 WHERE id=$1`, id, relPath); err != nil {
		return ts, "", err
	}
	ts.ID = id
	ts.Value = filename
	ts.Sha256 = sha
	ts.ExtractPath = relPath
	return ts, prev, nil
}

// isHex64 reports whether s is exactly 64 lowercase hex chars (a sha256 digest).
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// splitDeviceValue splits a device scope value into host and model, accepting
// "192.168.1.50", "192.168.1.50 RP09", "192.168.1.50|RP09" and "192.168.1.50,RP09".
func splitDeviceValue(v string) (string, string) {
	fields := strings.FieldsFunc(strings.TrimSpace(v), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '|' || r == ','
	})
	if len(fields) == 0 {
		return "", ""
	}
	return stripHostPort(fields[0]), strings.Join(fields[1:], " ")
}

// DeleteTaskScope removes a single scope row by id, scoped to the given task.
// Returns whether a row was actually deleted.
func (s *ComponentStore) DeleteTaskScope(taskID, scopeID int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM task_scope WHERE id=$1 AND task_id=$2`, scopeID, taskID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListTaskScope returns all scope rows for a task.
func (s *ComponentStore) ListTaskScope(taskID int64) ([]TaskScope, error) {
	rows, err := s.db.Query(`
SELECT ts.id, ts.kind, COALESCE(ts.company_id,0), COALESCE(c.name,''), COALESCE(ts.domain,''),
       COALESCE(ts.net::text,''), COALESCE(ts.value,''), COALESCE(ts.sha256,''), ts.source, COALESCE(ts.reason,''),
       COALESCE(ts.extract_path,''), COALESCE(ts.vendor,''), COALESCE(ts.version,''),
       COALESCE(ts.meta_source,'')
FROM task_scope ts
LEFT JOIN companies c ON c.id=ts.company_id
WHERE ts.task_id=$1 ORDER BY ts.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskScope{}
	for rows.Next() {
		var t TaskScope
		var cid int64
		if err := rows.Scan(&t.ID, &t.Kind, &cid, &t.CompanyName, &t.Domain, &t.Net, &t.Value, &t.Sha256, &t.Source, &t.Reason, &t.ExtractPath,
			&t.Vendor, &t.Version, &t.MetaSource); err != nil {
			return nil, err
		}
		t.TaskID = taskID
		if cid > 0 {
			t.CompanyID = &cid
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CoverageComponent is one in-scope component (used for the untested backlog sample).
type CoverageComponent struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// CoverageByType is per-component-type coverage: total vs completed.
type CoverageByType struct {
	Type   string `json:"type"`
	Total  int    `json:"total"`
	Tested int    `json:"tested"`
}

// Coverage is a task's component mining coverage: 分母 = 本任务组件数（排除 ignored），
// 分子 = status='completed' 的组件数。是给 agent 和操作者的参考值，不是精确指标。
type Coverage struct {
	Enabled     bool             `json:"enabled"`     // 覆盖度功能是否开启
	Denominator int              `json:"denominator"` // 本任务组件数（不含 ignored）
	Tested      int              `json:"tested"`      // status=completed
	Pct         *float64         `json:"pct"`         // 分母 0 时 null
	ByType      []CoverageByType `json:"by_type"`
}

// CoverageEnabled reports whether a task has the coverage feature turned on.
func (s *ComponentStore) CoverageEnabled(taskID int64) bool {
	if taskID <= 0 {
		return true
	}
	var enabled bool
	if err := s.db.QueryRow(`SELECT COALESCE(coverage_enabled,true) FROM tasks WHERE id=$1`, taskID).Scan(&enabled); err != nil {
		return true
	}
	return enabled
}

// TaskCoverage computes component mining coverage for one task.
func (s *ComponentStore) TaskCoverage(taskID, _ int64) (*Coverage, error) {
	cov := &Coverage{Enabled: s.CoverageEnabled(taskID)}
	if taskID <= 0 {
		return cov, nil
	}
	if !cov.Enabled {
		return cov, nil
	}
	rows, err := s.db.Query(`
SELECT type,
       count(*) FILTER (WHERE status <> 'ignored') AS total,
       count(*) FILTER (WHERE status = 'completed') AS tested
FROM components
WHERE $1 = ANY(task_ids)
GROUP BY type
ORDER BY type`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var bt CoverageByType
		if err := rows.Scan(&bt.Type, &bt.Total, &bt.Tested); err != nil {
			return nil, err
		}
		cov.ByType = append(cov.ByType, bt)
		cov.Denominator += bt.Total
		cov.Tested += bt.Tested
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if cov.Denominator > 0 {
		pct := float64(cov.Tested) / float64(cov.Denominator) * 100
		cov.Pct = &pct
	}
	return cov, nil
}

// TaskCoverageWithSources 保留旧调用名；scope_rows 字段随组件化下线后，
// 它与 TaskCoverage 完全等价（调用点分布在 agent 工具与 HTTP 层，暂不改名）。
func (s *ComponentStore) TaskCoverageWithSources(taskID int64) (*Coverage, error) {
	return s.TaskCoverage(taskID, 0)
}

// ListTaskScopeWithSources returns the task's scope rows (source/reason included).
func (s *ComponentStore) ListTaskScopeWithSources(taskID int64) ([]TaskScope, error) {
	return s.ListTaskScope(taskID)
}

// ListUntestedComponents returns components of a task that are still pending/running.
func (s *ComponentStore) ListUntestedComponents(taskID, _ int64, typ string, limit, offset int) ([]CoverageComponent, int, error) {
	where := `$1 = ANY(task_ids) AND status IN ('pending','running')`
	args := []any{taskID}
	if typ != "" {
		args = append(args, typ)
		where += fmt.Sprintf(" AND type = $%d", len(args))
	}
	var total int
	if err := s.db.QueryRow("SELECT count(*) FROM components WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	rows, err := s.db.Query("SELECT id, type, component_name FROM components WHERE "+where+
		fmt.Sprintf(" ORDER BY type, component_name LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []CoverageComponent
	for rows.Next() {
		var c CoverageComponent
		if err := rows.Scan(&c.ID, &c.Type, &c.Label); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// ListUntestedComponentsWithSources 与 ListUntestedComponents 同义，保留 *WithSources
// 名称以兼容既有调用方（组件来源信息由 task_component_links 提供，这里不再单独填充）。
func (s *ComponentStore) ListUntestedComponentsWithSources(taskID int64, typ string, limit, offset int) ([]CoverageComponent, int, error) {
	return s.ListUntestedComponents(taskID, 0, typ, limit, offset)
}

// CoverageGraphNode is one node of the coverage graph: 组件类型 分组 → 组件。
type CoverageGraphNode struct {
	Key         string `json:"key"`
	Kind        string `json:"kind"` // 组件类型（web/mqtt/...）或 "component"
	Label       string `json:"label"`
	Tested      bool   `json:"tested"`
	InScope     bool   `json:"in_scope"`
	ComponentID int64  `json:"component_id,omitempty"`
	Status      string `json:"status,omitempty"`
	Version     string `json:"version,omitempty"`
}

// CoverageGraphEdge is a child→parent containment link (component→type).
type CoverageGraphEdge struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

// CoverageGraphData is the whole graph for one task.
type CoverageGraphData struct {
	Nodes []CoverageGraphNode `json:"nodes"`
	Edges []CoverageGraphEdge `json:"edges"`
}

func componentGraphKey(id int64) string { return "a:" + strconv.FormatInt(id, 10) }

// BuildCoverageGraph assembles a two-level graph: 组件类型 → 组件。
func (s *ComponentStore) BuildCoverageGraph(taskID, _ int64) (*CoverageGraphData, error) {
	comps, _, err := s.ListComponents(ComponentFilter{TaskID: taskID, Limit: 5000})
	if err != nil {
		return nil, err
	}
	g := &CoverageGraphData{}
	type groupStat struct {
		total, tested int
	}
	stats := map[string]*groupStat{}
	seen := map[string]bool{}
	for _, c := range comps {
		st, ok := stats[c.Type]
		if !ok {
			st = &groupStat{}
			stats[c.Type] = st
		}
		st.total++
		if c.Status == "completed" {
			st.tested++
		}
		if !seen[c.Type] {
			seen[c.Type] = true
			g.Nodes = append(g.Nodes, CoverageGraphNode{
				Key: "t:" + c.Type, Kind: c.Type, Label: c.Type, InScope: true,
			})
		}
		label := c.ComponentName
		if c.Version != "" {
			label = strings.TrimSpace(label + " " + c.Version)
		}
		g.Nodes = append(g.Nodes, CoverageGraphNode{
			Key: componentGraphKey(c.ID), Kind: "component", Label: label,
			Tested: c.Status == "completed", InScope: c.Status != "ignored",
			ComponentID: c.ID, Status: c.Status, Version: c.Version,
		})
		g.Edges = append(g.Edges, CoverageGraphEdge{Src: componentGraphKey(c.ID), Dst: "t:" + c.Type})
	}
	// 分组节点「已测」= 该类型下组件全部 completed，前端据此给类型着色。
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind == "component" {
			continue
		}
		if st, ok := stats[n.Kind]; ok && st.total > 0 && st.tested == st.total {
			n.Tested = true
		}
	}
	return g, nil
}

// ---- 固件的厂商/版本（vendor / version）-------------------------------
//
// 口径：只对 kind='firmware' 有意义，键是 sha256。
//   · 同一个 sha256 的所有行（跨任务、跨文件名）始终写着同一份值——写入按 sha 全量同步，
//     所以不存在"某行有值、某行空"的中间态，读任意一行都对。
//   · 人的操作允许覆盖（meta_source='manual'）；agent 只能补空（meta_source='agent'）。
//   · 组件的 vendor/version 是组件自身属性，与这里完全无关，互不写入。

// normalizeVendor 把固件厂商统一成「首字母大写、其余小写」：
// Tenda / TENDA / tenda → Tenda。空串保持空（表示没填）。
func normalizeVendor(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	r := []rune(strings.ToLower(s))
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// FirmwareMeta 是一次固件元信息读取的结果。
type FirmwareMeta struct {
	SHA       string `json:"sha256"`
	Vendor    string `json:"vendor,omitempty"`
	Version   string `json:"version,omitempty"`
	Source    string `json:"meta_source,omitempty"`
	Filename  string `json:"filename,omitempty"`
	RowCount  int    `json:"row_count"`
	UpdatedAt string `json:"meta_updated_at,omitempty"`
}

// FirmwareMetaBySha 读某个固件当前的厂商/版本（任取一行，因为所有行同步）。
func (s *ComponentStore) FirmwareMetaBySha(sha string) (FirmwareMeta, error) {
	out := FirmwareMeta{SHA: strings.ToLower(strings.TrimSpace(sha))}
	if out.SHA == "" {
		return out, nil
	}
	var vendor, version, src, updated sql.NullString
	var filename sql.NullString
	err := s.db.QueryRow(`SELECT COALESCE(vendor,''), COALESCE(version,''), COALESCE(meta_source,''),
       COALESCE(to_char(meta_updated_at,'YYYY-MM-DD HH24:MI:SS'),''), COALESCE(value,'')
  FROM task_scope
 WHERE kind='firmware' AND sha256=$1
 ORDER BY (COALESCE(vendor,'')<>'' OR COALESCE(version,'')<>'') DESC, id LIMIT 1`, out.SHA).
		Scan(&vendor, &version, &src, &updated, &filename)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Vendor, out.Version = vendor.String, version.String
	out.Source, out.UpdatedAt, out.Filename = src.String, updated.String, filename.String
	_ = s.db.QueryRow(`SELECT count(*) FROM task_scope WHERE kind='firmware' AND sha256=$1`, out.SHA).Scan(&out.RowCount)
	return out, nil
}

// FirmwareMetaByTask 读该任务固件行上的厂商/版本（顺带带回 sha 与文件名）。
func (s *ComponentStore) FirmwareMetaByTask(taskID int64) (FirmwareMeta, error) {
	out := FirmwareMeta{}
	if taskID <= 0 {
		return out, fmt.Errorf("需要 task_id")
	}
	var sha, vendor, version, src, updated, filename sql.NullString
	err := s.db.QueryRow(`SELECT COALESCE(sha256,''), COALESCE(vendor,''), COALESCE(version,''),
       COALESCE(meta_source,''), COALESCE(to_char(meta_updated_at,'YYYY-MM-DD HH24:MI:SS'),''), COALESCE(value,'')
  FROM task_scope WHERE task_id=$1 AND kind='firmware'
 ORDER BY (COALESCE(sha256,'')<>'') DESC, id DESC LIMIT 1`, taskID).
		Scan(&sha, &vendor, &version, &src, &updated, &filename)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.SHA, out.Vendor, out.Version = sha.String, vendor.String, version.String
	out.Source, out.UpdatedAt, out.Filename = src.String, updated.String, filename.String
	return out, nil
}

// SetFirmwareMeta 写固件的厂商/版本，并同步到该 sha 的所有固件行。
//
//	overwrite=true  人的操作：给定值原样写入（空串表示"这个字段不改"由调用方决定；
//	                这里把空串也写进去 —— 调用方用指针区分"没传"和"传空"）。
//	overwrite=false agent：只补空字段，已有值不动。
//
// 返回写完之后该 sha 的值（跨行一致的权威值）。
func (s *ComponentStore) SetFirmwareMeta(sha, vendor, version string, overwrite bool) (string, string, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !isHex64(sha) {
		return "", "", fmt.Errorf("sha256 需要 64 位十六进制（小写）")
	}
	vendor = normalizeVendor(vendor)
	version = strings.TrimSpace(version)
	src := "agent"
	if overwrite {
		src = "manual"
	}
	var q string
	if overwrite {
		// 人的操作：传了哪个字段就覆盖哪个字段（空串=不动），并把所有行一起改。
		q = `UPDATE task_scope SET
		       vendor  = COALESCE(NULLIF($2,''), vendor),
		       version = COALESCE(NULLIF($3,''), version),
		       meta_source = $4,
		       meta_updated_at = now()
		     WHERE kind='firmware' AND sha256=$1`
	} else {
		// agent：只补空。
		q = `UPDATE task_scope SET
		       vendor  = COALESCE(NULLIF(vendor,''),  NULLIF($2,'')),
		       version = COALESCE(NULLIF(version,''), NULLIF($3,'')),
		       meta_source = COALESCE(NULLIF(meta_source,''), $4),
		       meta_updated_at = now()
		     WHERE kind='firmware' AND sha256=$1`
	}
	if _, err := s.db.Exec(q, sha, vendor, version, src); err != nil {
		return "", "", err
	}
	// 没命中任何行 = 该 sha 还没登记过固件，值无处可落（调用方先登记固件行）。
	meta, err := s.FirmwareMetaBySha(sha)
	if err != nil {
		return "", "", err
	}
	return meta.Vendor, meta.Version, nil
}

// TaskFirmwareStaging 读建任务时人填、还没绑定到某个 sha 的厂商/版本。
func (s *ComponentStore) TaskFirmwareStaging(taskID int64) (vendor, version string) {
	if taskID <= 0 {
		return "", ""
	}
	_ = s.db.QueryRow(`SELECT COALESCE(firmware_vendor,''), COALESCE(firmware_version,'') FROM tasks WHERE id=$1`, taskID).
		Scan(&vendor, &version)
	return vendor, version
}

// SetTaskFirmwareStaging 写/清建任务时的暂存值（空串即清空）。
func (s *ComponentStore) SetTaskFirmwareStaging(taskID int64, vendor, version string) error {
	if taskID <= 0 {
		return fmt.Errorf("需要 task_id")
	}
	_, err := s.db.Exec(`UPDATE tasks SET firmware_vendor=NULLIF($2,''), firmware_version=NULLIF($3,'') WHERE id=$1`,
		taskID, normalizeVendor(vendor), strings.TrimSpace(version))
	return err
}
