package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestAuditCommonality(t *testing.T) {
	mk := func(vulnclass string, comps []int64, evidence, summary string) *db.DBFinding {
		return &db.DBFinding{VulnClass: vulnclass, ComponentIDs: comps, Evidence: evidence, Summary: summary}
	}
	cases := []struct {
		name string
		rows []*db.DBFinding
		want bool
	}{
		{"vulnclass 相同（大小写/空白无关）", []*db.DBFinding{
			mk("Pre-Auth Command Injection", []int64{1}, "", ""),
			mk("pre-auth  command injection", []int64{2}, "", ""),
		}, true},
		{"组件有交集", []*db.DBFinding{
			mk("cmd injection", []int64{1, 2}, "", ""),
			mk("rce", []int64{2, 3}, "", ""),
		}, true},
		{"入口 URL path 相同", []*db.DBFinding{
			mk("info leak", []int64{1}, "GET http://10.0.0.1/cgi-bin/setup.cgi?cmd=1", ""),
			mk("cmd injection", []int64{2}, "POST https://10.0.0.2/cgi-bin/setup.cgi?cmd=2", ""),
		}, true},
		{"三者都不同", []*db.DBFinding{
			mk("cmd injection", []int64{1}, "http://10.0.0.1/a.cgi", ""),
			mk("stored xss", []int64{2}, "http://10.0.0.1/b.cgi", ""),
		}, false},
	}
	for _, c := range cases {
		if _, got := auditCommonality(c.rows); got != c.want {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestAuditURLPaths(t *testing.T) {
	f := &db.DBFinding{Evidence: "curl http://10.0.0.1:8080/cgi-bin/setup.cgi?cmd=1 -d x; also /admin.cgi?y=2"}
	got := auditURLPaths(f)
	if !got["/cgi-bin/setup.cgi"] {
		t.Fatalf("paths=%v, want /cgi-bin/setup.cgi", got)
	}
	if got["/cgi-bin/setup.cgi?cmd=1"] {
		t.Fatalf("query must be stripped: %v", got)
	}
}

func TestAuditBatchStateCoverage(t *testing.T) {
	s := newAuditBatchState()
	s.markMerged([]int64{2, 3}, 90)
	s.markDistinct([]int64{4}, "不同参数")
	if s.merged(2) != true || s.covered(2) != true {
		t.Fatal("merged id must be covered")
	}
	if s.covered(4) != true || s.covered(5) != false {
		t.Fatal("distinct/hole coverage wrong")
	}
	if got := s.uncovered([]int64{2, 3, 4, 5}); len(got) != 1 || got[0] != 5 {
		t.Fatalf("uncovered=%v want [5]", got)
	}
	if s.mergeCount() != 1 {
		t.Fatalf("merges=%d want 1", s.mergeCount())
	}
}

func TestAuditorPromptRenders(t *testing.T) {
	sys := auditorSystem("/data")
	for _, want := range []string{"consolidate_findings", "keep_separate", "三要素", "report"} {
		if !strings.Contains(sys, want) {
			t.Fatalf("system prompt missing %q", want)
		}
	}
}
