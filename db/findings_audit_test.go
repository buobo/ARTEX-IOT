package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// newAuditFixture 建一个独立的任务 + 探索图，返回 taskID/expID 与一个插入漏洞的闭包。
func newAuditFixture(t *testing.T, d *DB, label string) (int64, int64, func(vulnclass, summary string, comps []int64) (nodeID, findingID int64)) {
	t.Helper()
	ctx := context.Background()
	var expID int64
	if err := d.QueryRowContext(ctx, `INSERT INTO explorations(description,goal) VALUES('',$1) RETURNING id`, label).Scan(&expID); err != nil {
		t.Fatalf("insert exploration: %v", err)
	}
	var taskID int64
	if err := d.QueryRowContext(ctx, `INSERT INTO tasks(description,goal,exploration_id) VALUES('',$1,$2) RETURNING id`, label, expID).Scan(&taskID); err != nil {
		t.Fatalf("insert task: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM activity WHERE exploration_id=$1`, expID)
		_, _ = d.Exec(`DELETE FROM findings WHERE task_id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM task_relations WHERE task_id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM exploration_nodes WHERE exploration_id=$1`, expID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	})
	insert := func(vulnclass, summary string, comps []int64) (int64, int64) {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"summary": summary, "vulnclass": vulnclass, "severity": "high"})
		var nodeID int64
		if err := d.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
			VALUES($1,'finding',$2,9,'confirmed','worker') RETURNING id`, expID, string(payload)).Scan(&nodeID); err != nil {
			t.Fatalf("insert node: %v", err)
		}
		compJSON, _ := json.Marshal(comps)
		var fid int64
		if err := d.QueryRowContext(ctx, `INSERT INTO findings(task_id,node_id,vulnclass,name,severity,summary,evidence,worker,component_ids,poc_files,status)
			VALUES($1,$2,$3,'标题','high',$4,'证据 http://10.0.0.1/cgi-bin/setup.cgi?cmd=1','worker',$5,'[]','pending') RETURNING id`,
			taskID, nodeID, vulnclass, summary, string(compJSON)).Scan(&fid); err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		return nodeID, fid
	}
	return taskID, expID, insert
}

func TestConsolidateFindings(t *testing.T) {
	dsn := testDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()
	ctx := context.Background()

	taskID, expID, insert := newAuditFixture(t, d, "合并测试")
	// 组件必须真实存在（新节点会挂 anchors，FK 会校验）。
	compID := func(name string) int64 {
		var id int64
		if err := d.QueryRow(`INSERT INTO components(type,component_name) VALUES('web',$1) RETURNING id`, name).Scan(&id); err != nil {
			t.Fatalf("insert component: %v", err)
		}
		t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM components WHERE id=$1`, id) })
		return id
	}
	c1, c2, c3 := compID("setup.cgi"), compID("jhttpd"), compID("admin.cgi")
	node1, f1 := insert("pre-auth command injection", "setup.cgi cmd 注入", []int64{c1, c2})
	node2, f2 := insert("pre-auth command injection", "setup.cgi 命令执行（另一 worker 上报）", []int64{c2})
	_, f3 := insert("stored xss", "另一处 xss", []int64{c3})

	// 子记录：流量证据 + 复测历史都挂在 f1 上。
	if _, err := d.Exec(`INSERT INTO traffic_evidence_snapshots(id,source_traffic_id,captured_at,url,method,status,req_head,resp_head,req_hash,resp_hash,req_len,resp_len)
		VALUES('snap-audit-1','t1',0,'http://10.0.0.1/cgi-bin/setup.cgi?cmd=1','GET',200,'','','h1','h2',1,1) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO finding_traffic_bindings(finding_id,snapshot_id,position) VALUES($1,'snap-audit-1',1)`, f1); err != nil {
		t.Fatalf("binding: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO finding_retests(finding_id,status,snapshot) VALUES($1,'completed','{}')`, f1); err != nil {
		t.Fatalf("retest: %v", err)
	}

	res, err := d.ConsolidateFindings(ctx, FindingAuditMerge{
		TaskID: taskID, ExplorationID: expID, FindingIDs: []int64{f2, f1},
		VulnClass: "pre-auth command injection", Name: "setup.cgi 预认证命令注入",
		Severity: "high", Summary: "整合摘要", Evidence: "整合证据", Report: "# 合并报告\n正文",
		ComponentIDs: []int64{c2}, Reason: "同一 CGI、同一参数、同一缺陷类", Operator: "auditor",
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if res.NewFindingID <= 0 || res.NewNodeID <= 0 {
		t.Fatalf("bad ids: %+v", res)
	}
	if len(res.Deleted) != 2 || res.Deleted[0] != f1 || res.Deleted[1] != f2 {
		t.Fatalf("deleted=%v want [%d %d]", res.Deleted, f1, f2)
	}
	if res.TrafficBindings != 1 || res.Retests != 1 {
		t.Fatalf("migrated traffic=%d retests=%d, want 1/1", res.TrafficBindings, res.Retests)
	}

	// 旧行与旧节点消失；新节点是 finding。
	var n int
	_ = d.QueryRow(`SELECT count(*) FROM findings WHERE id IN ($1,$2)`, f1, f2).Scan(&n)
	if n != 0 {
		t.Fatalf("old findings still present: %d", n)
	}
	_ = d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE id IN ($1,$2)`, node1, node2).Scan(&n)
	if n != 0 {
		t.Fatalf("old nodes still present: %d", n)
	}
	var kind string
	if err := d.QueryRow(`SELECT kind FROM exploration_nodes WHERE id=$1 AND exploration_id=$2`, res.NewNodeID, expID).Scan(&kind); err != nil || kind != KindFinding {
		t.Fatalf("new node kind=%q err=%v", kind, err)
	}
	// 子记录改挂新 id。
	if err := d.QueryRow(`SELECT count(*) FROM finding_traffic_bindings WHERE finding_id=$1`, res.NewFindingID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("traffic binding not migrated: %d err=%v", n, err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM finding_retests WHERE finding_id=$1`, res.NewFindingID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("retest not migrated: %d err=%v", n, err)
	}

	// 新行内容 + 快照是平的 2 条 + 已标审计。
	var report, status, auditResult, mergedJSON string
	var audited bool
	if err := d.QueryRow(`SELECT report, status, audit_result, COALESCE(merged_from,'[]'::jsonb), audited_at IS NOT NULL
		FROM findings WHERE id=$1`, res.NewFindingID).Scan(&report, &status, &auditResult, &mergedJSON, &audited); err != nil {
		t.Fatalf("load new row: %v", err)
	}
	if !strings.Contains(report, "合并报告") || status != FindingPending || auditResult != FindingAuditMerged || !audited {
		t.Fatalf("new row report=%q status=%q audit=%q audited=%v", report[:10], status, auditResult, audited)
	}
	var snaps []FindingSnapshot
	if err := json.Unmarshal([]byte(mergedJSON), &snaps); err != nil || len(snaps) != 2 {
		t.Fatalf("merged_from=%s err=%v", mergedJSON, err)
	}

	// 留痕：当前任务探索图里有整合活动。
	var summary string
	if err := d.QueryRow(`SELECT summary FROM activity WHERE exploration_id=$1 AND worker='auditor' ORDER BY id DESC LIMIT 1`, expID).Scan(&summary); err != nil {
		t.Fatalf("activity: %v", err)
	}
	if !strings.Contains(summary, "漏洞整合") {
		t.Fatalf("activity summary=%q", summary)
	}

	// 幂等：同一组再合一次 → 报「已不存在」。
	if _, err := d.ConsolidateFindings(ctx, FindingAuditMerge{
		TaskID: taskID, ExplorationID: expID, FindingIDs: []int64{f1, f2},
		VulnClass: "x", Name: "x", Severity: "high", Summary: "x", Evidence: "x", Report: "x", Operator: "auditor",
	}); err == nil || !strings.Contains(err.Error(), "已不存在") {
		t.Fatalf("second merge err=%v, want 已不存在", err)
	}

	// 组件越界：组内旧行的并集里没有 c3+100000。
	if _, err := d.ConsolidateFindings(ctx, FindingAuditMerge{
		TaskID: taskID, ExplorationID: expID, FindingIDs: []int64{res.NewFindingID, f3},
		VulnClass: "x", Name: "x", Severity: "high", Summary: "x", Evidence: "x", Report: "x",
		ComponentIDs: []int64{c3 + 100000}, Operator: "auditor",
	}); err == nil || !strings.Contains(err.Error(), "不在这些漏洞原有的组件") {
		t.Fatalf("component escape err=%v", err)
	}

	// 报告必填。
	if _, err := d.ConsolidateFindings(ctx, FindingAuditMerge{
		TaskID: taskID, ExplorationID: expID, FindingIDs: []int64{res.NewFindingID, f3},
		VulnClass: "x", Name: "x", Severity: "high", Summary: "x", Evidence: "x", Report: "  ", Operator: "auditor",
	}); err == nil || !strings.Contains(err.Error(), "报告") {
		t.Fatalf("empty report err=%v", err)
	}
}
