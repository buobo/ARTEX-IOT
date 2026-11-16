package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestFindingWorkflowSharedAssemblyAndSwitch(t *testing.T) {
	oldPolicy, oldResolve, oldAugment := FindingTrafficBindingEnabled, ToolResolve, ToolAugment
	t.Cleanup(func() { FindingTrafficBindingEnabled, ToolResolve, ToolAugment = oldPolicy, oldResolve, oldAugment })
	ToolAugment = nil
	on := false
	FindingTrafficBindingEnabled = func() bool { return on }
	ts := NewToolSet(nil, "fixture")
	ToolResolve = func(_ context.Context, _ string, base []actool.CoreTool) []actool.CoreTool {
		out := make([]actool.CoreTool, len(base))
		for i, tool := range base {
			out[i] = DecorateTool(tool, "CUSTOM DESCRIPTION", tool.InputSchema())
		}
		return out
	}
	for _, role := range []string{"worker", "planner", "mainagent", "auto", "pentest", "custom-agent"} {
		for _, enabled := range []bool{false, true, false} {
			on = enabled
			out, def, cleanup := AugmentTools(t.Context(), role, []actool.CoreTool{ts.addFinding(), ts.addHint()})
			cleanup()
			system, _ := deferredSystem("USER CUSTOM PROMPT", def)
			if !strings.HasPrefix(system[0], "USER CUSTOM PROMPT") {
				t.Fatal("custom prompt replaced")
			}
			if strings.Contains(system[0], "traffic_refs") != on {
				t.Fatalf("%s: guidance ignored switch: %v", role, on)
			}
			if on && (!strings.Contains(system[0], "TCP") || !strings.Contains(system[0], "evidence_hint_id")) {
				t.Fatal("missing optional/handoff contract")
			}
			for _, tool := range out {
				if !strings.HasPrefix(tool.Description(), "CUSTOM DESCRIPTION") {
					t.Fatal("custom description replaced")
				}
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				json.Unmarshal(raw, &schema)
				props := schema["properties"].(map[string]any)
				if (props["traffic_refs"] != nil) != on {
					t.Fatalf("%s: binding schema ignored switch", role)
				}
				if tool.Name() == "add_hint" {
					nested := props["hints"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
					if (nested["traffic_refs"] != nil) != on {
						t.Fatal("nested hint schema ignored switch")
					}
				}
			}
		}
	}
	on = true
	ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }
	out, def, cleanup := AugmentTools(t.Context(), "planner", []actool.CoreTool{ts.addFinding()})
	defer cleanup()
	if len(out) != 0 || def.FindingGuidance != "" {
		t.Fatal("reintroduced disabled tool or its guidance")
	}
}

// resultText 取工具结果里的文本（测试断言用）。
func resultText(res actool.Result) string {
	var b strings.Builder
	for _, blk := range res.Content {
		b.WriteString(blk.Text)
	}
	return b.String()
}

// TestCleanPocNameBareOnly poc_files / save_poc 的 name 只收裸文件名，
// 报错必须给出「改成什么」的示例（模型最常见的错法是照抄 poc/x.py）。
func TestCleanPocNameBareOnly(t *testing.T) {
	for _, in := range []string{"cgi_inject.py", "a.sh", "run.out.txt"} {
		got, err := cleanPocName(in)
		if err != nil || got != in {
			t.Fatalf("cleanPocName(%q) = %q, %v; want 原样通过", in, got, err)
		}
	}
	cases := []struct{ in, want string }{
		{"poc/cgi_inject.py", `改成 "cgi_inject.py"`},
		{"./poc/cgi_inject.py", `改成 "cgi_inject.py"`},
		{"sub/x.py", `改成 "x.py"`},
		{"./x.py", `改成 "x.py"`},
		{"../x.py", "上跳"},
		{"a/../x.py", "上跳"},
		{".hidden.py", "不能以 . 开头"},
		{"x.exe", "扩展名不支持"},
		{"", "不能为空"},
		{"/etc/passwd", "只接受单层文件名"},
	}
	for _, tc := range cases {
		got, err := cleanPocName(tc.in)
		if err == nil {
			t.Fatalf("cleanPocName(%q) 应该报错，却返回 %q", tc.in, got)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("cleanPocName(%q) 报错缺少 %q：%s", tc.in, tc.want, err.Error())
		}
	}
}

// TestValidatePocFilesMissingGivesDirAndHint 文件不在时，报错要给目录、目录现有文件（最多 3 个）和正确写法。
func TestValidatePocFilesMissingGivesDirAndHint(t *testing.T) {
	root := t.TempDir()
	pocDir := filepath.Join(root, "tasks", "7", "poc")
	if err := os.MkdirAll(pocDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a.py", "b.py", "c.py", "d.py", "e.sh", "INDEX.md"} {
		if err := os.WriteFile(filepath.Join(pocDir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ts := &ToolSet{dataDir: root, taskID: 7}

	if out, err := ts.validatePocFiles([]string{"a.py"}); err != nil || len(out) != 1 || out[0] != "a.py" {
		t.Fatalf("裸文件名应通过: %v %v", out, err)
	}
	_, err := ts.validatePocFiles([]string{"typo.py"})
	if err == nil {
		t.Fatal("缺失文件应报错")
	}
	msg := err.Error()
	for _, want := range []string{pocDir, "typo.py", "a.py", "不要带 poc/ 前缀"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("报错缺少 %q：%s", want, msg)
		}
	}
	if strings.Contains(msg, "d.py") || strings.Contains(msg, "INDEX.md") {
		t.Fatalf("目录清单应只列前 3 个且跳过 INDEX.md：%s", msg)
	}
	_, err = ts.validatePocFiles([]string{"poc/a.py"})
	if err == nil || !strings.Contains(err.Error(), `改成 "a.py"`) {
		t.Fatalf("带 poc/ 前缀要给定向提示: %v", err)
	}
}

// TestSavePocReturnsNameAndWritesFile save_poc 返回 name（供 poc_files 直接照抄），
// 且文件真的落在 tasks/<id>/poc/<name>。
func TestSavePocReturnsNameAndWritesFile(t *testing.T) {
	root := t.TempDir()
	ts := &ToolSet{dataDir: root, taskID: 3}
	res, err := ts.savePoc().Call(context.Background(),
		json.RawMessage(`{"name":"x.py","content":"print(1)"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("save_poc 失败: %v %s", err, resultText(res))
	}
	txt := resultText(res)
	if !strings.Contains(txt, `"name":"x.py"`) {
		t.Fatalf("返回里缺 name: %s", txt)
	}
	if !strings.Contains(txt, `"path":"poc/x.py"`) {
		t.Fatalf("返回里缺展示用 path: %s", txt)
	}
	if _, err := os.Stat(filepath.Join(root, "tasks", "3", "poc", "x.py")); err != nil {
		t.Fatalf("文件没落盘: %v", err)
	}
	// 带前缀写文件也要被拒，并给出正确写法
	res, err = ts.savePoc().Call(context.Background(),
		json.RawMessage(`{"name":"poc/y.py","content":"print(2)"}`), nil)
	if err != nil || !res.IsError || !strings.Contains(resultText(res), `改成 "y.py"`) {
		t.Fatalf("save_poc 接受带前缀的文件名了: %v %s", err, resultText(res))
	}
}
