package db

import "testing"

// 本文件只为「资产时代」遗留的 db 包测试提供最小兼容层，不参与生产构建。
// 组件时代没有根域名/IP/服务之分：所有对象都落到 components 表，
// 用 (type, component_name, version) 去重。测试只是需要一个可指认的实体，
// 因此这里把旧形态压平成一个组件。

type UpsertRootDomainReq struct {
	Domain string
	ICP    string
	TaskID int64
}

type UpsertIPReq struct {
	IP           string
	BoundDomains []string
	OpenPorts    []any
	TaskID       int64
}

type UpsertSubdomainReq struct {
	Domain      string
	RecordType  string
	RecordValue []string
	ICP         string
	TaskID      int64
}

type UpsertAppReq struct {
	Name        string
	BundleID    string
	Category    string
	Description string
	AppICP      string
	TaskID      int64
}

type UpsertHTTPServiceReq struct {
	URL           string
	Technologies  []string
	StatusCode    int
	ContentLength int64
	PageTitle     string
	FaviconMMH3   string
	Auth          string
	IP            string
	TaskID        int64
}

type UpsertOtherServiceReq struct {
	Domain      string
	IP          string
	Port        int
	ServiceName string
	Auth        string
	TaskID      int64
}

type UpsertEndpointReq struct {
	URL    string
	Method string
	Params string
	IP     string
	TaskID int64
}

func (s *ComponentStore) upsertLegacy(taskID int64, typ, name string) (int64, error) {
	var taskIDs []int64
	if taskID > 0 {
		taskIDs = []int64{taskID}
	}
	_, _, ids, err := s.UpsertComponents(taskIDs, []ComponentInput{{Type: typ, Name: name}})
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if taskID > 0 {
		_ = s.SetTaskComponentSource(taskID, ids[0], "test", "legacy test helper", nil)
	}
	return ids[0], nil
}

func (s *ComponentStore) UpsertRootDomain(req UpsertRootDomainReq) (int64, error) {
	return s.upsertLegacy(req.TaskID, "web", req.Domain)
}

func (s *ComponentStore) UpsertIP(req UpsertIPReq) (int64, error) {
	return s.upsertLegacy(req.TaskID, "other", req.IP)
}

func (s *ComponentStore) UpsertSubdomain(req UpsertSubdomainReq) (int64, error) {
	return s.upsertLegacy(req.TaskID, "web", req.Domain)
}

func (s *ComponentStore) UpsertApp(req UpsertAppReq) (int64, error) {
	return s.upsertLegacy(req.TaskID, "other", req.Name)
}

func (s *ComponentStore) UpsertHTTPService(req UpsertHTTPServiceReq) (int64, error) {
	return s.upsertLegacy(req.TaskID, "web", req.URL)
}

func (s *ComponentStore) UpsertOtherService(req UpsertOtherServiceReq) (int64, error) {
	return s.upsertLegacy(req.TaskID, "other", req.ServiceName)
}

func (s *ComponentStore) UpsertEndpoint(req UpsertEndpointReq) (int64, error) {
	return s.upsertLegacy(req.TaskID, "web", req.URL)
}

func (s *ComponentStore) QueryByTask(taskID int64, typ string, limit, offset int) ([]*Component, error) {
	items, _, err := s.ListComponents(ComponentFilter{TaskID: taskID, Type: typ, Limit: limit, Offset: offset})
	return items, err
}

func (s *ComponentStore) QueryByType(typ string, limit, offset int) ([]*Component, error) {
	items, _, err := s.ListComponents(ComponentFilter{Type: typ, Limit: limit, Offset: offset})
	return items, err
}

func (s *ComponentStore) QueryByCompany(_ int64, typ string, limit, offset int) ([]*Component, error) {
	items, _, err := s.ListComponents(ComponentFilter{Type: typ, Limit: limit, Offset: offset})
	return items, err
}

func (s *ComponentStore) CountByCompany(_ int64) (int, error) {
	_, total, err := s.ListComponents(ComponentFilter{Limit: 1})
	return total, err
}

func (s *ComponentStore) CountByTask(taskID int64) (int, error) {
	_, total, err := s.ListComponents(ComponentFilter{TaskID: taskID, Limit: 1})
	return total, err
}

func (s *ComponentStore) DeleteByHost(string) (map[string]int64, error) {
	return map[string]int64{}, nil
}

// testSetup 打开测试库并返回 DB + 组件/企业 store（原先定义在被删的资产测试文件里）。
func testSetup(t *testing.T) (*DB, *ComponentStore, *CompanyStore) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return d, d.Components(), d.Companies()
}

// deleteComponent 清理测试插入的组件行。
func deleteComponent(d *DB, id int64) {
	if d == nil || id <= 0 {
		return
	}
	_, _ = d.Exec(`DELETE FROM components WHERE id=$1`, id)
}

// HostsByTask 在组件时代返回任务下的组件名（旧测试把它们当 host 用）。
func (s *ComponentStore) HostsByTask(taskID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT component_name FROM components WHERE $1 = ANY(task_ids)`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// HostsForTaskDeletion 返回「只属于该任务」的组件名（删除任务时会一并清掉）。
func (s *ComponentStore) HostsForTaskDeletion(taskID, _ int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT component_name FROM components
WHERE $1 = ANY(task_ids) AND cardinality(task_ids) = 1`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
