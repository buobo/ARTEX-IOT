package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

type retestProvider struct {
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
}

func (p retestProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.complete(ctx, req)
}
func (p retestProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("test expects non-streaming"))
	}
}

func newRetestServer(t *testing.T) (*Server, int64) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test postgres not configured")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{ctx: ctx, m: &Manager{pg: pg, dir: td, tasks: map[string]*Task{}},
		chatBusy: map[string]bool{}, chatCancel: map[string]context.CancelCauseFunc{}}
	if err := s.seedFindingRetester(); err != nil {
		t.Fatal(err)
	}
	fid, err := pg.AddFinding(0, 0, "retest-server", "复测测试", "high", "summary", "original proof", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	oldAugment, oldResolve, oldPrompt := agent.ToolAugment, agent.ToolResolve, agent.PromptOverride
	agent.ToolAugment = func(context.Context, string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		return s.findingRetestTools(), agent.DeferredInfo{}, func() {}
	}
	agent.ToolResolve = nil
	agent.PromptOverride = func(string) (string, bool) { return agent.RetesterDefaultPrompt, true }
	t.Cleanup(func() {
		cancel()
		waitRetestIdle(t, s)
		agent.ToolAugment, agent.ToolResolve, agent.PromptOverride = oldAugment, oldResolve, oldPrompt
		_, _ = pg.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_retests WHERE finding_id=$1)`, fid)
		_, _ = pg.DeleteFinding(fid)
		pg.Close()
	})
	return s, fid
}

func setRetestProvider(s *Server, p retestProvider) {
	s.chatAgent = agent.NewChatAgent(p, "test", s.m.dir, nil, 10000)
	s.chatAgent.SetNonStreaming(func() bool { return true })
}

func retestRequest(handler http.HandlerFunc, method string, id int64, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func waitRetestIdle(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.chatMu.Lock()
		n := len(s.chatBusy)
		s.chatMu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("conversation did not become idle")
}

// snapshotPrompt 记住某内置 agent 当前的提示词版本，测试结束删掉测试期间追加的版本并把
// current_prompt_id 指回原版本。开发库同时也是"生产"库：不这样做，每跑一次测试都会往真实
// agent 的提示词历史里追加 test / restore 版本，运行期间还会临时替换生效提示词。
func snapshotPrompt(t *testing.T, pg *db.DB, key string) {
	t.Helper()
	row, err := pg.GetAgentByKey(key)
	if err != nil || row == nil {
		t.Fatalf("missing agent %s: %v", key, err)
	}
	var cur sql.NullInt64
	if err := pg.QueryRow(`SELECT current_prompt_id FROM agents WHERE id=$1`, row.ID).Scan(&cur); err != nil {
		t.Fatalf("read current prompt %s: %v", key, err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM agent_prompts WHERE agent_id=$1 AND id>$2`, row.ID, cur.Int64)
		if cur.Valid {
			_, _ = pg.Exec(`UPDATE agents SET current_prompt_id=$1 WHERE id=$2`, cur.Int64, row.ID)
		} else {
			_, _ = pg.Exec(`UPDATE agents SET current_prompt_id=NULL WHERE id=$1`, row.ID)
		}
	})
}

func TestRetestActiveStatusLifecycle(t *testing.T) {
	s, fid := newRetestServer(t)
	check := func(want string, conversationID int64) {
		t.Helper()
		w := retestRequest(s.listActiveFindingRetests, http.MethodGet, 0, "")
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var body struct {
			Retests []db.ActiveFindingRetest `json:"retests"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		var matches []db.ActiveFindingRetest
		for _, item := range body.Retests {
			if item.FindingID == fid {
				matches = append(matches, item)
			}
		}
		if want == "" {
			if len(matches) != 0 {
				t.Fatalf("terminal retest still active: %+v", matches)
			}
		} else if len(matches) != 1 || matches[0].Status != want || matches[0].ConversationID != conversationID {
			t.Fatalf("active=%+v want status=%s conversation=%d", matches, want, conversationID)
		}
		for _, field := range []string{`"snapshot"`, `"evidence"`, `"notes"`, `"summary"`} {
			if strings.Contains(w.Body.String(), field) {
				t.Fatalf("status response leaks %s", field)
			}
		}
	}
	check("", 0)
	for _, terminal := range []string{"completed", "failed", "stopped"} {
		r, c, _, err := s.m.pg.CreateFindingRetest(t.Context(), fid, "private notes")
		if err != nil {
			t.Fatal(err)
		}
		check("pending", c.ID)
		if _, err := s.m.pg.StartFindingRetest(t.Context(), r.ID); err != nil {
			t.Fatal(err)
		}
		check("running", c.ID)
		if terminal == "completed" {
			if err := s.m.pg.RecordFindingRetestResult(t.Context(), c.ID, "fixed", "summary", "proof"); err != nil {
				t.Fatal(err)
			}
			check("running", c.ID) // A staged verdict is still running until the turn ends.
		}
		if err := s.m.pg.FinishFindingRetest(r.ID, terminal, ""); err != nil {
			t.Fatal(err)
		}
		check("", 0)
	}
}

func TestRetestHTTPThroughConversationAndTools(t *testing.T) {
	s, fid := newRetestServer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	setRetestProvider(s, retestProvider{complete: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		n := calls.Add(1)
		if n == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return llm.Message{}, "", llm.Usage{}, ctx.Err()
			}
		}
		name, input := "get_finding_retest_context", `{}`
		if n == 2 {
			serialized, _ := json.Marshal(req.Messages)
			if !bytes.Contains(serialized, []byte("original proof")) {
				t.Error("agent did not receive source evidence")
			}
			name, input = "record_finding_retest_result", `{"verdict":"inconclusive","summary":"缺少测试登录态","evidence":"已检查原证据；当前缺少有效登录态，无法确认修复状态。"}`
		}
		if n > 2 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("复测结论已保存")}}, "end_turn", llm.Usage{}, nil
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: strconv.Itoa(int(n)), Name: name, Input: json.RawMessage(input)}}}, "tool_use", llm.Usage{}, nil
	}})
	w := retestRequest(s.startFindingRetest, "POST", fid, `{"notes":"仅验证原接口"}`)
	if w.Code != 202 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("provider not called")
	}
	dup := retestRequest(s.startFindingRetest, "POST", fid, `{}`)
	if dup.Code != 200 || !strings.Contains(dup.Body.String(), `"created":false`) {
		t.Fatalf("duplicate %d %s", dup.Code, dup.Body)
	}
	close(release)
	waitRetestIdle(t, s)
	rows, err := s.m.pg.ListFindingRetests(fid)
	if err != nil || len(rows) != 1 || rows[0].Status != "completed" || rows[0].Verdict != "inconclusive" {
		t.Fatalf("history=%+v err=%v", rows, err)
	}
	if calls.Load() != 3 {
		t.Fatal("unexpected LLM calls", calls.Load())
	}
	f, _ := s.m.pg.GetFinding(fid)
	if f.Status != db.FindingPending || f.Evidence != "original proof" {
		t.Fatal("source modified")
	}
	listing := retestRequest(s.listFindingRetests, "GET", fid, "")
	if listing.Code != 200 || strings.Contains(listing.Body.String(), `"snapshot"`) {
		t.Fatalf("history %d %s", listing.Code, listing.Body)
	}
	res, err := s.findingRetestTools()[1].Call(intercept.WithConvID(t.Context(), *rows[0].ConversationID), json.RawMessage(`{"verdict":"fixed","summary":"bad overwrite","evidence":"bad"}`), nil)
	if err != nil || !res.IsError {
		t.Fatal("sealed result accepted", res, err)
	}
}

func TestRetestStopsFailuresAndNoVerdict(t *testing.T) {
	for _, mode := range []string{"stop", "failure", "no_verdict"} {
		t.Run(mode, func(t *testing.T) {
			s, fid := newRetestServer(t)
			setRetestProvider(s, retestProvider{complete: func(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				if mode == "stop" {
					<-ctx.Done()
					return llm.Message{}, "", llm.Usage{}, ctx.Err()
				}
				if mode == "failure" {
					return llm.Message{}, "", llm.Usage{}, errors.New("test model failed")
				}
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("未保存结论")}}, "end_turn", llm.Usage{}, nil
			}})
			w := retestRequest(s.startFindingRetest, "POST", fid, `{}`)
			if w.Code != 202 {
				t.Fatalf("create %d %s", w.Code, w.Body)
			}
			if mode == "stop" {
				var body struct {
					Retest db.FindingRetest `json:"retest"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &body)
				stop := retestRequest(s.pgStopConversation, "POST", *body.Retest.ConversationID, `{}`)
				if stop.Code != 200 || !strings.Contains(stop.Body.String(), "stopping") {
					t.Fatalf("immediate stop: %d %s", stop.Code, stop.Body)
				}
			}
			waitRetestIdle(t, s)
			rows, _ := s.m.pg.ListFindingRetests(fid)
			want := "failed"
			if mode == "stop" {
				want = "stopped"
			}
			if len(rows) != 1 || rows[0].Status != want || rows[0].Error == "" {
				t.Fatalf("expected %s: %+v", want, rows)
			}
		})
	}
}

func TestRetestFixedUpdatesFindingThroughConversation(t *testing.T) {
	s, fid := newRetestServer(t)
	var calls atomic.Int32
	setRetestProvider(s, retestProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		if calls.Add(1) == 1 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "fixed-result", Name: "record_finding_retest_result", Input: json.RawMessage(`{"verdict":"fixed","summary":"修复生效","evidence":"原触发条件失效，正常对照仍可用。"}`)}}}, "tool_use", llm.Usage{}, nil
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("结论已保存")}}, "end_turn", llm.Usage{}, nil
	}})
	w := retestRequest(s.startFindingRetest, "POST", fid, `{}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	waitRetestIdle(t, s)
	f, err := s.m.pg.GetFinding(fid)
	if err != nil || f.Status != db.FindingFixed || f.Evidence != "original proof" {
		t.Fatalf("fixed finding=%+v err=%v", f, err)
	}
	// The new manual status is also accepted by the existing update API.
	w = retestRequest(s.patchFinding, "PATCH", fid, `{"status":"fixed"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"fixed"`) {
		t.Fatalf("manual fixed: %d %s", w.Code, w.Body)
	}
}

func TestRetestValidationSeedingAndScope(t *testing.T) {
	s, fid := newRetestServer(t)
	for _, tc := range []struct {
		id   int64
		body string
		code int
	}{{0, `{}`, 400}, {fid, `{`, 400}, {fid, `{"notes":"` + strings.Repeat("文", 4001) + `"}`, 400}, {999999999, `{}`, 404}, {fid, `{}`, 503}} {
		w := retestRequest(s.startFindingRetest, "POST", tc.id, tc.body)
		if w.Code != tc.code {
			t.Fatalf("code=%d want=%d %s", w.Code, tc.code, w.Body)
		}
	}
	rows, _ := s.m.pg.ListFindingRetests(fid)
	if len(rows) != 0 {
		t.Fatal("invalid request created state")
	}
	for _, tool := range s.findingRetestTools() {
		res, err := tool.Call(t.Context(), json.RawMessage(`{"verdict":"fixed","summary":"x","evidence":"y"}`), nil)
		if err != nil || !res.IsError {
			t.Fatal("unassociated conversation accepted", tool.Name(), res, err)
		}
	}
	a, _ := s.m.pg.GetAgentByKey(db.FindingRetestAgentKey)
	if a == nil || a.Builtin {
		t.Fatal("missing editable retester")
	}
	var triggers int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM agent_triggers WHERE agent_key=$1`, db.FindingRetestAgentKey).Scan(&triggers); err != nil || triggers != 0 {
		t.Fatal("unexpected automatic trigger", triggers, err)
	}
	snapshotPrompt(t, s.m.pg, db.FindingRetestAgentKey)
	if _, err := s.m.pg.SavePrompt(a.ID, "customized retest prompt", "test", "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.seedFindingRetester(); err != nil {
		t.Fatal(err)
	}
	var prompt string
	if err := s.m.pg.QueryRow(`SELECT p.template_text FROM agent_prompts p JOIN agents a ON a.current_prompt_id=p.id WHERE a.key=$1`, a.Key).Scan(&prompt); err != nil || prompt != "customized retest prompt" {
		t.Fatal("seed overwrote prompt", prompt, err)
	}
}

func TestSlicePaneExtractsCommandOutput(t *testing.T) {
	pane := strings.Join([]string{
		"david@host:~$ bash .cmd-7.sh; printf '\\n__ARTEX_END_7_%d__\\n' $?",
		"line1",
		"colored: \x1b[32mGREEN\x1b[0m",
		"",
		"__ARTEX_END_7_3__",
		"david@host:~$ ",
	}, "\n")
	out, code, ok := slicePane(pane, 7)
	if !ok {
		t.Fatal("sentinel not detected")
	}
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !strings.Contains(out, "line1") || strings.Contains(out, "\x1b[") {
		t.Fatalf("unexpected output: %q", out)
	}
	if strings.Contains(out, "__ARTEX_END_") || strings.Contains(out, "printf") {
		t.Fatalf("echoed command or sentinel leaked into output: %q", out)
	}
}

func TestSlicePaneIgnoresOtherSeq(t *testing.T) {
	pane := "bash .cmd-2.sh; ...\nold\n__ARTEX_END_2_0__\n"
	if _, _, ok := slicePane(pane, 3); ok {
		t.Fatal("matched a sentinel from another sequence")
	}
}

// TestRetestRecorderEndToEnd 真起 Xvfb+tmux+xterm+ffmpeg，验证命令执行结果、
// 退出码、mp4 落盘、画面非黑、进程清理。缺任一依赖则跳过（CI 通常没有 xterm）。
func TestRetestRecorderEndToEnd(t *testing.T) {
	for _, b := range []string{"Xvfb", "tmux", "xterm", "ffmpeg", "ffprobe"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("missing %s", b)
		}
	}
	dir := t.TempDir()
	rec := &retestRecorder{convID: 9001, retestID: 1, taskID: 1, recID: 1, app: "terminal", fps: recFPS}
	if err := rec.start(dir); err != nil {
		t.Fatalf("start: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			rec.stop()
		}
	}()

	out, code, running, err := rec.run(context.Background(), "echo first; echo second; exit 7", "", 30*time.Second)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if running {
		t.Fatal("command reported as still running")
	}
	if code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	for _, want := range []string{"first", "second"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q missing %q", out, want)
		}
	}

	time.Sleep(1200 * time.Millisecond)
	durMS, size, sha := rec.stop()
	stopped = true
	if size <= 0 {
		t.Fatalf("empty recording at %s", rec.absPath)
	}
	if durMS < 500 {
		t.Fatalf("duration too short: %dms", durMS)
	}
	if len(sha) != 64 {
		t.Fatalf("sha256 = %q", sha)
	}
	if fi, err := os.Stat(rec.absPath); err != nil || fi.Size() != size {
		t.Fatalf("recording file mismatch: %v", err)
	}
	if peak := testFramePeak(t, rec.absPath); peak < 100 {
		t.Fatalf("video has no bright content (YMAX=%.1f)", peak)
	}
	if exec.Command("tmux", "has-session", "-t", rec.session).Run() == nil {
		t.Fatalf("tmux session %s still alive", rec.session)
	}
	if _, err := os.Stat(filepath.Join("/tmp", ".X"+strings.TrimPrefix(rec.display, ":")+"-lock")); err == nil {
		t.Fatalf("Xvfb %s lock still present", rec.display)
	}
}

func testFramePeak(t *testing.T, path string) float64 {
	t.Helper()
	out, err := exec.Command("ffmpeg", "-hide_banner", "-i", path,
		"-vf", "signalstats,metadata=print:key=lavfi.signalstats.YMAX", "-an", "-f", "null", "-").CombinedOutput()
	if err != nil {
		t.Fatalf("ffmpeg signalstats: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "YMAX="); i >= 0 {
			if v, err := strconv.ParseFloat(strings.TrimSpace(line[i+5:]), 64); err == nil {
				return v
			}
		}
	}
	t.Fatal("no YMAX in ffmpeg output")
	return 0
}

// TestStopTaskRecordingsSealsOrphans 覆盖归档前收尾的兜底路径：
// 进程句柄已丢（服务重启/崩溃），但 tmux 会话还在、DB 行仍是 recording。
func TestStopTaskRecordingsSealsOrphans(t *testing.T) {
	s, fid := newRetestServer(t)
	pg := s.m.pg
	const taskID = int64(0)

	var retestID, recID int64
	if err := pg.QueryRow(`INSERT INTO finding_retests(finding_id,status,snapshot)
VALUES($1,'running','{}'::jsonb) RETURNING id`, fid).Scan(&retestID); err != nil {
		t.Fatal(err)
	}
	const sess = "artex-retest-arch-1"
	if err := pg.QueryRow(`INSERT INTO finding_retest_recordings(retest_id,task_id,app,display,tmux_session,path,status)
VALUES($1,$2,'terminal',':107',$3,'recordings/test/1.mp4','recording') RETURNING id`, retestID, taskID, sess).Scan(&recID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("tmux", "kill-session", "-t", sess).Run()
		_, _ = pg.Exec(`DELETE FROM finding_retest_recordings WHERE id=$1`, recID)
		_, _ = pg.Exec(`DELETE FROM finding_retests WHERE id=$1`, retestID)
	})
	if out, err := exec.Command("tmux", "-f", "/dev/null", "new-session", "-d", "-s", sess, "sleep", "300").CombinedOutput(); err != nil {
		t.Skipf("tmux unavailable: %v %s", err, out)
	}

	if err := s.stopTaskRecordings(context.Background(), taskID); err != nil {
		t.Fatalf("stopTaskRecordings: %v", err)
	}
	var status, errNote string
	if err := pg.QueryRow(`SELECT status,error FROM finding_retest_recordings WHERE id=$1`, recID).Scan(&status, &errNote); err != nil {
		t.Fatal(err)
	}
	if status != "interrupted" || errNote == "" {
		t.Fatalf("want interrupted with reason, got %q / %q", status, errNote)
	}
	if exec.Command("tmux", "has-session", "-t", sess).Run() == nil {
		t.Fatal("tmux session survived archive seal")
	}
	if err := s.stopTaskRecordings(context.Background(), 999999); err != nil {
		t.Fatalf("task without recordings should be a no-op: %v", err)
	}
}

// TestStopTaskRecordingsStopsLiveRecorder 覆盖归档前收尾的主路径：
// 进程内还有句柄，归档必须让 ffmpeg 写完 moov、DB 封口、进程清理。
func TestStopTaskRecordingsStopsLiveRecorder(t *testing.T) {
	for _, b := range []string{"Xvfb", "tmux", "xterm", "ffmpeg"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("missing %s", b)
		}
	}
	s, fid := newRetestServer(t)
	pg := s.m.pg
	dataDir := t.TempDir()
	s.m.dir = dataDir

	var retestID, recID int64
	if err := pg.QueryRow(`INSERT INTO finding_retests(finding_id,status,snapshot)
VALUES($1,'running','{}'::jsonb) RETURNING id`, fid).Scan(&retestID); err != nil {
		t.Fatal(err)
	}
	if err := pg.QueryRow(`INSERT INTO finding_retest_recordings(retest_id,task_id,app,path,status)
VALUES($1,0,'terminal','pending','recording') RETURNING id`, retestID).Scan(&recID); err != nil {
		t.Fatal(err)
	}
	rec := &retestRecorder{convID: 0, retestID: retestID, taskID: 0, recID: recID, app: "terminal", fps: recFPS}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			rec.stop()
		}
		_, _ = pg.Exec(`DELETE FROM finding_retest_recordings WHERE id=$1`, recID)
		_, _ = pg.Exec(`DELETE FROM finding_retests WHERE id=$1`, retestID)
	})
	if err := rec.start(dataDir); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := pg.Exec(`UPDATE finding_retest_recordings SET path=$2, tmux_session=$3, display=$4 WHERE id=$1`,
		recID, rec.relPath, rec.session, rec.display); err != nil {
		t.Fatal(err)
	}
	s.putRecorder(rec)

	if _, _, _, err := rec.run(context.Background(), "echo archive-stop; sleep 1", "", 30*time.Second); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := s.stopTaskRecordings(context.Background(), 0); err != nil {
		t.Fatalf("stopTaskRecordings: %v", err)
	}
	stopped = true

	var status string
	var size int64
	if err := pg.QueryRow(`SELECT status,size_bytes FROM finding_retest_recordings WHERE id=$1`, recID).
		Scan(&status, &size); err != nil {
		t.Fatal(err)
	}
	if status != "interrupted" {
		t.Fatalf("status = %q, want interrupted", status)
	}
	if size <= 0 {
		t.Fatal("recording produced no bytes")
	}
	if fi, err := os.Stat(rec.absPath); err != nil || fi.Size() != size {
		t.Fatalf("file/DB size mismatch: %v", err)
	}
	if s.recorderFor(0) != nil {
		t.Fatal("recorder still registered after archive seal")
	}
	if exec.Command("tmux", "has-session", "-t", rec.session).Run() == nil {
		t.Fatal("tmux session survived archive seal")
	}
}
