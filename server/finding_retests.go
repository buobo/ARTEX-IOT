package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) listActiveFindingRetests(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	items, err := pg.ListActiveFindingRetests(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(items) > 0 {
		ids := make([]int64, 0, len(items))
		for i := range items {
			ids = append(ids, items[i].ID)
		}
		recs, rerr := pg.RetestRecordingsForRetests(r.Context(), ids)
		if rerr != nil {
			log.Printf("[retests active] load recordings: %v", rerr)
			writeErr(w, 500, "读取复测录屏失败: "+rerr.Error())
			return
		}
		for i := range items {
			for _, rec := range recs[items[i].ID] {
				rec.URL = recordingURL(rec.ID)
			}
			items[i].Recordings = recs[items[i].ID]
		}
	}
	writeJSON(w, 200, map[string]any{"retests": items})
}

func (s *Server) listFindingRetests(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	items, err := pg.ListFindingRetests(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 一次性带出历史录屏，避免每条复测再查一次。
	// 查询失败必须显式报错：静默降级会让前端看起来"功能没做"，排查成本极高。
	recs, err := pg.RetestRecordingsForFinding(r.Context(), id)
	if err != nil {
		log.Printf("[finding %d] load retest recordings: %v", id, err)
		writeErr(w, 500, "读取复测录屏失败: "+err.Error())
		return
	}
	for _, item := range items {
		for _, rec := range recs[item.ID] {
			rec.URL = recordingURL(rec.ID)
		}
		item.Recordings = recs[item.ID]
	}
	writeJSON(w, 200, map[string]any{"retests": items})
}

func (s *Server) startFindingRetest(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	var req struct {
		Notes string `json:"notes"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	req.Notes = strings.TrimSpace(req.Notes)
	if utf8.RuneCountInString(req.Notes) > 4000 {
		writeErr(w, 400, "复测补充说明最多 4000 个字符")
		return
	}
	f, err := pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if f == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	a, err := pg.GetAgentByKey(db.FindingRetestAgentKey)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if a == nil || !a.Enabled {
		writeErr(w, 409, "漏洞复测 Agent 不存在或未启用，请在 Agent 管理中配置 retester")
		return
	}
	for _, key := range []string{"get_finding_retest_context", "record_finding_retest_result"} {
		t, err := pg.GetTool(key)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if t == nil || !t.Enabled || !slices.Contains(t.Agents, a.Key) {
			writeErr(w, 409, "请为复测 Agent 启用并绑定工具："+key)
			return
		}
	}
	if s.resolveChatAgent(&db.Conversation{AgentKey: a.Key}) == nil {
		writeErr(w, 503, s.chatUnavailableReason())
		return
	}
	if s.ctx.Err() != nil {
		writeErr(w, 503, "服务正在停止")
		return
	}
	retest, conv, created, err := pg.CreateFindingRetest(r.Context(), id, req.Notes)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "finding not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if created {
		busyKey := s.convBusyKey(conv.ID)
		s.chatMu.Lock()
		s.chatBusy[busyKey] = true
		s.chatMu.Unlock()
		s.runConversation(conv, retest.InitialMessage(), busyKey)
	}
	code := http.StatusOK
	if created {
		code = http.StatusAccepted
	}
	writeJSON(w, code, map[string]any{"retest": retest, "created": created})
}

// retestPocFiles 把漏洞登记的 poc_files 拼成绝对路径，并标出文件是否还在。
// 复测会话的工作目录不是任务目录，相对路径跑不通，所以这里直接给出绝对路径。
func (s *Server) retestPocFiles(f *db.DBFinding) []map[string]any {
	out := []map[string]any{}
	if f == nil || f.TaskID == nil {
		return out
	}
	dir := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(*f.TaskID, 10), "poc")
	for _, name := range f.PocFiles {
		abs := filepath.Join(dir, name)
		_, err := os.Stat(abs)
		out = append(out, map[string]any{"name": name, "absolute_path": abs, "exists": err == nil})
	}
	return out
}

// Both tools derive the finding from server-owned conversation context. Tool
// arguments cannot redirect a result into a different finding or conversation.
func (s *Server) findingRetestTools() []actool.CoreTool {
	return append([]actool.CoreTool{
		roTool("get_finding_retest_context", "读取当前复测会话关联的漏洞证据快照、复测状态、补充说明与当前任务约束。无参数，只能读取本会话。",
			objSchema(map[string]any{}), func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
				r, err := s.m.pg.FindingRetestForConversation(ctx, intercept.ConvIDFromContext(ctx))
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if r == nil {
					return actool.Errorf("当前会话未关联复测记录，请从漏洞详情发起复测"), nil
				}
				var constraints []db.Constraint
				f, err := s.m.pg.GetFinding(r.FindingID)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if f != nil && f.TaskID != nil {
					if task, ok := s.m.Task(strconv.FormatInt(*f.TaskID, 10)); ok {
						constraints, err = task.Store.ListConstraints()
						if err != nil {
							return actool.Errorf(err.Error()), nil
						}
					}
				}
				return jsonResult(map[string]any{"retest": r, "current_constraints": constraints, "poc_files": s.retestPocFiles(f)})
			}),
		wrTool("record_finding_retest_result", "为当前复测会话保存唯一结论；原漏洞证据与报告保持不变。会话成功结束且结论为 fixed 时，系统自动将漏洞状态改为已修复；其他结论保留原状态。必须提供本次实际检查的证据，无法确认时写明阻塞原因。",
			objSchema(map[string]any{
				"verdict":  map[string]any{"type": "string", "enum": []string{"reproduced", "fixed", "inconclusive"}},
				"summary":  strParam("本次复测结论摘要"),
				"evidence": strParam("Markdown：本次实际步骤、观察、对照、结论依据；无法确认则列出已检查内容和阻塞原因"),
			}, "verdict", "summary", "evidence"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
				var a struct {
					Verdict  string `json:"verdict"`
					Summary  string `json:"summary"`
					Evidence string `json:"evidence"`
				}
				if err := json.Unmarshal(in, &a); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				bad, err := s.discardedRecordingRefs(ctx, a.Summary+"\n"+a.Evidence)
				if err != nil {
					return actool.Errorf("校验录屏引用失败: " + err.Error()), nil
				}
				if len(bad) > 0 {
					ids := make([]string, 0, len(bad))
					for _, id := range bad {
						ids = append(ids, "#"+strconv.FormatInt(id, 10))
					}
					return actool.Errorf(fmt.Sprintf("evidence/summary 引用了已丢弃的录屏 %s：请改为指向本次仍有效的录屏（action=list 的 path），或重录一段再引用", strings.Join(ids, "、"))), nil
				}
				if err := s.m.pg.RecordFindingRetestResult(ctx, intercept.ConvIDFromContext(ctx), a.Verdict, a.Summary, a.Evidence); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"saved": true, "verdict": a.Verdict})
			}),
	}, s.retestRecordingTools()...)
}

// recordingRefRe 匹配 evidence 里对录屏文件的引用（recordings/<retest>/<rec>.mp4）。
var recordingRefRe = regexp.MustCompile(`recordings/(\d+)/(\d+)\.mp4`)

// discardedRecordingRefs 找出文本里引用、但本次复测已丢弃的录屏 id（按出现顺序去重）。
func (s *Server) discardedRecordingRefs(ctx context.Context, text string) ([]int64, error) {
	if s.m == nil || s.m.pg == nil || !recordingRefRe.MatchString(text) {
		return nil, nil
	}
	discarded, err := s.m.pg.DiscardedRecordingIDs(ctx, intercept.ConvIDFromContext(ctx))
	if err != nil {
		return nil, err
	}
	return discardedRefsAmong(text, discarded), nil
}

// discardedRefsAmong 是纯函数：从文本里挑出落在 discarded 集合里的录屏 id。
func discardedRefsAmong(text string, discarded map[int64]struct{}) []int64 {
	if len(discarded) == 0 {
		return nil
	}
	var out []int64
	seen := map[int64]struct{}{}
	for _, m := range recordingRefRe.FindAllStringSubmatch(text, -1) {
		id, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			continue
		}
		if _, ok := discarded[id]; !ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// retestRecordingTools 提供「显式上镜」录制：只有经这里的工具执行的命令才进视频。
func (s *Server) retestRecordingTools() []actool.CoreTool {
	return []actool.CoreTool{
		wrTool("retest_recording", "控制本复测会话的录屏。先 action=capabilities 看可用后端；start 必须指定 app，由你根据证据类型自行决定：terminal（命令行证据：curl/nc/gdb/qemu）或 chrome（界面证据：登录跳转/XSS/CSRF/前端权限，需要 http(s) target）。mark 记录关键时间点；stop 生成 mp4 并返回路径。list 列出本次复测仍有效的录屏（id / path / 时长 / marks）。discard 丢弃一段不合格的录屏：必须给 recording_id 与 reason，丢弃后这段视频对人侧不可见（行留痕可审计），evidence 里也不能再引用它；本次复测最多丢弃 5 段，录坏了就丢掉重录。注意：只有经 retest_terminal_exec / retest_terminal_send 执行的命令会出现在 terminal 录像中。",
			objSchema(map[string]any{
				"action":       map[string]any{"type": "string", "enum": []string{"capabilities", "start", "stop", "mark", "status", "list", "discard"}},
				"app":          map[string]any{"type": "string", "enum": []string{"terminal", "chrome"}, "description": "start 时必填，自行判断"},
				"target":       strParam("app=chrome 时的起始 URL（http/https）"),
				"label":        strParam("本次录制名称，便于报告引用"),
				"note":         strParam("mark 的时间点说明"),
				"recording_id": map[string]any{"type": "integer", "description": "discard 必填：要丢弃的录屏 id（先 action=list 查）"},
				"reason":       strParam("discard 必填：一句话说明这段录屏为什么不能用（黑屏 / 步骤跑偏 / 录到敏感信息 …）"),
			}, "action"), s.retestRecordingTool),
		wrTool("retest_terminal_exec", "在可见终端中执行命令并等待结束：命令与输出都会出现在录屏里，画面里显示的就是命令原文。一条字符串会按 shell 语法自动拆成多条（顶层 ; && || 换行）逐条执行、逐条上镜，&& / || 的短路语义保留；也可用 commands 数组显式分步。含 heredoc / 复合语句（for/if/case）/ 后台 & / exit / set -e 这类命令整条按脚本执行（画面里是 bash .cmd-N.sh）。语义与 Bash 等价但会上镜；普通 Bash 执行的命令不会出现在录像中。交互式程序（gdb/nc/tail）请改用 retest_terminal_send + retest_terminal_snapshot。",
			objSchema(map[string]any{
				"command":   strParam("要执行的命令（bash 语法）；含多条时按 ; && || 换行自动拆开逐条执行"),
				"commands":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "按顺序逐条执行的命令列表（与 command 二选一，优先用本字段）"},
				"cwd":       strParam("工作目录，默认本会话工作目录；与终端当前目录不同时会在第一条命令前补 cd"),
				"timeout_s": map[string]any{"type": "integer", "description": "超时秒数（整次调用预算，拆开的各条共用），默认 120，最大 600"},
			}), s.retestTerminalExec),
		wrTool("retest_terminal_send", "向可见终端输入文本（默认追加回车），用于 gdb/nc 等交互式程序；不等待输出，随后用 retest_terminal_snapshot 查看。需要能看到终端输出时使用。",
			objSchema(map[string]any{
				"input":   strParam("要输入的文本"),
				"newline": map[string]any{"type": "boolean", "description": "是否追加回车，默认 true"},
			}, "input"), s.retestTerminalSend),
		roTool("retest_terminal_snapshot", "读取可见终端当前屏幕（含滚动历史），用于查看交互式命令的输出。",
			objSchema(map[string]any{
				"lines": map[string]any{"type": "integer", "description": "回溯行数，默认 80，最大 2000"},
			}), s.retestTerminalSnapshot),
	}
}

func (s *Server) retestRecordingTool(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var a struct {
		Action      string `json:"action"`
		App         string `json:"app"`
		Target      string `json:"target"`
		Label       string `json:"label"`
		Note        string `json:"note"`
		RecordingID int64  `json:"recording_id"`
		Reason      string `json:"reason"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	convID := intercept.ConvIDFromContext(ctx)
	switch a.Action {
	case "capabilities":
		return jsonResult(s.recordingCapabilities())
	case "start":
		row, err := s.startRetestRecording(ctx, convID, a.App, a.Target, a.Label)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return jsonResult(map[string]any{"recording": row,
			"hint": "录制已开始。terminal 模式请用 retest_terminal_exec 执行需要留证的命令；chrome 模式直接操作浏览器。结束时调用 action=stop。"})
	case "stop":
		row, err := s.stopRetestRecording(ctx, convID, "")
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return jsonResult(map[string]any{"recording": row})
	case "mark":
		rec := s.recorderFor(convID)
		if rec == nil {
			return actool.Errorf("当前没有进行中的录制"), nil
		}
		offset := time.Since(rec.startedAt).Seconds()
		if err := s.m.pg.AddRetestRecordingMark(ctx, rec.recID, offset, strings.TrimSpace(a.Note)); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return jsonResult(map[string]any{"recording_id": rec.recID, "offset_s": offset, "note": a.Note})
	case "status":
		if rec := s.recorderFor(convID); rec != nil {
			return jsonResult(map[string]any{"recording_id": rec.recID, "status": "recording", "app": rec.app,
				"display": rec.display, "offset_s": time.Since(rec.startedAt).Seconds()})
		}
		row, err := s.m.pg.ActiveRetestRecordingForConversation(ctx, convID)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if row == nil {
			return jsonResult(map[string]any{"recording": nil})
		}
		row.URL = recordingURL(row.ID)
		return jsonResult(map[string]any{"recording": row})
	case "list":
		rows, err := s.m.pg.RetestRecordingsForDiscard(ctx, convID)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		items := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			items = append(items, map[string]any{
				"recording_id": row.ID, "app": row.App, "status": row.Status,
				"path": row.Path, "duration_ms": row.DurationMS, "size_bytes": row.SizeBytes,
				"exec_count": row.ExecCount, "marks": row.Marks, "started_at": row.StartedAt,
			})
		}
		return jsonResult(map[string]any{"recordings": items, "discard_limit": db.RetestDiscardMax})
	case "discard":
		if a.RecordingID <= 0 {
			return actool.Errorf("必须指定 recording_id：先用 action=list 查本次复测的录屏 id"), nil
		}
		if rec := s.recorderFor(convID); rec != nil && rec.recID == a.RecordingID {
			return actool.Errorf("这段录屏还在录制中：先 action=stop 再丢弃"), nil
		}
		row, err := s.m.pg.DiscardRetestRecording(ctx, convID, a.RecordingID, a.Reason)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		freed, deleted := int64(0), false
		warn := ""
		if row.Path == "" {
			warn = "该录屏没有文件（录制失败或未落盘）"
		} else if !filepath.IsLocal(row.Path) {
			warn = "录屏路径异常，未删除文件"
		} else {
			abs := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(row.TaskID, 10), row.Path)
			if fi, err := os.Stat(abs); err != nil || fi.IsDir() {
				warn = "录屏文件已不存在"
			} else {
				freed = fi.Size()
				if err := os.Remove(abs); err != nil {
					warn = "文件删除失败: " + err.Error()
				} else {
					deleted = true
				}
			}
		}
		res := map[string]any{
			"discarded": true, "recording_id": row.ID, "app": row.App,
			"duration_ms": row.DurationMS, "freed_bytes": freed, "file_deleted": deleted,
			"hint": "这段录屏对人侧已不可见。要留证请重录一段，并让 evidence 指向新录屏（path 见 action=list）。",
		}
		if warn != "" {
			res["note"] = warn
		}
		return jsonResult(res)
	}
	return actool.Errorf("action 只能是 capabilities / start / stop / mark / status / list / discard"), nil
}

func (s *Server) recordingCapabilities() map[string]any {
	caps := map[string]any{}
	for _, app := range []string{"terminal", "chrome"} {
		bins := []string{"ffmpeg", "Xvfb"}
		if app == "terminal" {
			bins = append(bins, "tmux", "xterm")
		} else {
			bins = append(bins, "google-chrome")
		}
		missing := []string{}
		for _, b := range bins {
			if _, err := exec.LookPath(b); err != nil {
				missing = append(missing, b)
			}
		}
		caps[app] = map[string]any{"ok": len(missing) == 0, "missing": missing}
	}
	freeDisplays := 0
	for n := 99; n <= 110; n++ {
		if _, err := os.Stat(fmt.Sprintf("/tmp/.X%d-lock", n)); err == nil {
			continue
		}
		freeDisplays++
	}
	disk, _ := diskFree(s.m.dir)
	return map[string]any{
		"backend":      "virtual",
		"apps":         caps,
		"display_free": freeDisplays,
		"disk_free_gb": disk >> 30,
		"limits": map[string]any{
			"max_duration_s": recMaxSecond,
			"max_size_bytes": recMaxBytes,
			"fps":            recFPS,
		},
		"note": "terminal 只录制经 retest_terminal_exec/send 执行的命令；普通 Bash 不进画面。",
	}
}

// terminalRecorder 取本会话的 terminal 录制器并校验状态。
func (s *Server) terminalRecorder(ctx context.Context, needExplicit bool) (*retestRecorder, error) {
	rec := s.recorderFor(intercept.ConvIDFromContext(ctx))
	if rec == nil {
		if needExplicit {
			return nil, errors.New("当前没有进行中的录制，请先 retest_recording(action=start, app=terminal)")
		}
		return nil, errors.New("当前没有进行中的录制")
	}
	if rec.app != "terminal" {
		return nil, errors.New("当前录制是 chrome 模式，不能用终端工具")
	}
	return rec, nil
}

func (s *Server) retestTerminalExec(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var a struct {
		Command  string   `json:"command"`
		Commands []string `json:"commands"`
		Cwd      string   `json:"cwd"`
		TimeoutS int      `json:"timeout_s"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var steps []recStep
	for _, c := range a.Commands {
		if v := strings.TrimSpace(c); v != "" {
			steps = append(steps, recStep{Conn: ";", Command: v})
		}
	}
	if len(steps) == 0 && strings.TrimSpace(a.Command) == "" {
		return actool.Errorf("command 或 commands 至少给一个"), nil
	}
	rec, err := s.terminalRecorder(ctx, true)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	timeout := time.Duration(a.TimeoutS) * time.Second
	if a.TimeoutS <= 0 {
		timeout = 120 * time.Second
	}
	if timeout > 600*time.Second {
		timeout = 600 * time.Second
	}
	cwd := strings.TrimSpace(a.Cwd)
	if cwd == "" {
		convID := intercept.ConvIDFromContext(ctx)
		cwd = filepath.Join(s.m.dir, "sessions", fmt.Sprintf("conv-%d", convID))
	}
	var run *termRun
	if len(steps) > 0 {
		run, err = rec.runExplicit(ctx, steps, cwd, timeout)
	} else {
		run, err = rec.run(ctx, a.Command, cwd, timeout)
	}
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	res := map[string]any{
		"mode":      run.Mode,
		"steps":     run.Steps,
		"exit_code": run.Code,
		"running":   run.Running,
		"output":    joinStepOutput(run.Steps),
	}
	if len(run.Skipped) > 0 {
		res["skipped_steps"] = run.Skipped
	}
	if run.Mode == "script" {
		res["note"] = "含 heredoc / 复合语句 / 会改变会话 shell 状态的命令整条按脚本执行，画面里是 bash .cmd-N.sh"
	}
	if run.Running {
		res["hint"] = "命令仍在运行（已超时）。可用 retest_terminal_snapshot 继续观察，或 retest_terminal_send(\"\\u0003\") 中断。"
	}
	return jsonResult(res)
}

func (s *Server) retestTerminalSend(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var a struct {
		Input   string `json:"input"`
		Newline *bool  `json:"newline"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	rec, err := s.terminalRecorder(ctx, true)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	newline := a.Newline == nil || *a.Newline
	if err := rec.send(a.Input, newline); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return jsonResult(map[string]any{"sent": true})
}

func (s *Server) retestTerminalSnapshot(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var a struct {
		Lines int `json:"lines"`
	}
	_ = json.Unmarshal(in, &a)
	rec, err := s.terminalRecorder(ctx, true)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	lines := a.Lines
	if lines <= 0 {
		lines = 80
	}
	if lines > 2000 {
		lines = 2000
	}
	out, err := rec.snapshotPane(lines)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return jsonResult(map[string]any{"output": strings.TrimRight(recANSI.ReplaceAllString(out, ""), " \t\n"),
		"offset_s": time.Since(rec.startedAt).Seconds()})
}

// streamFindingRetestRecording 播放录屏。文件随任务归档时会消失，
// 这里返回 409 + 明确提示，而不是让前端看到莫名的 404。
// deleteFindingRetest 硬删一条复测记录及其全部相关数据（**人侧专用**，Agent 工具面没有）：
// 复测行 + 录屏行（外键 CASCADE）、录屏目录（mp4 与直敲留下的 .cmd 脚本）、
// 复测会话及其转录文件。没有软删/回收站，删了不可恢复。
//
// 运行中的复测一律拒绝：录制协程还在往 mp4 和 DB 写，边删边写会留下半截文件与脏行。
func (s *Server) deleteFindingRetest(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad retest id")
		return
	}
	ctx := r.Context()
	retest, err := pg.FindingRetestByID(ctx, id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if retest == nil {
		writeErr(w, 404, "复测记录已删除")
		return
	}
	recs, err := pg.RetestRecordingsAll(ctx, id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if retest.Status == "pending" || retest.Status == "running" {
		writeErr(w, 409, "该复测仍在进行，请先在会话里停止再删")
		return
	}
	for _, rec := range recs {
		switch rec.Status {
		case "starting", "recording", "stopping":
			writeErr(w, 409, "该复测的录屏仍在录制，请先停止录屏再删")
			return
		}
	}

	var warnings []string
	var freed int64
	for _, rec := range recs {
		if rec.TmuxSession != "" {
			_ = exec.Command("tmux", "kill-session", "-t", rec.TmuxSession).Run()
		}
		freed += rec.SizeBytes
		// 录屏行自带 task_id：按行定位目录，不猜当前上下文任务。
		dir := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(rec.TaskID, 10),
			"recordings", strconv.FormatInt(rec.RetestID, 10))
		if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("录屏目录删除失败 %s: %v", dir, err))
		}
	}

	convDeleted := false
	if retest.ConversationID != nil {
		convID := *retest.ConversationID
		s.cancelConversation(convID)
		if err := pg.DeleteConversation(convID); err != nil {
			warnings = append(warnings, "删除复测会话失败: "+err.Error())
		} else {
			convDeleted = true
			// 转录文件按会话名匹配（conv-<id>.jsonl / conv-<id>-xxx），存在的都清掉。
			matches, _ := filepath.Glob(filepath.Join(s.m.dir, "transcripts", fmt.Sprintf("conv-%d*", convID)))
			for _, m := range matches {
				if err := os.RemoveAll(m); err != nil && !os.IsNotExist(err) {
					warnings = append(warnings, fmt.Sprintf("转录文件删除失败 %s: %v", m, err))
				}
			}
		}
	}

	deleted, err := pg.DeleteFindingRetest(ctx, id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !deleted {
		writeErr(w, 404, "复测记录已删除")
		return
	}
	log.Printf("[retest %d] 人工删除：录屏 %d 段 / %d 字节，会话 %v", id, len(recs), freed, convDeleted)
	res := map[string]any{
		"deleted":              id,
		"recordings":           len(recs),
		"bytes":                freed,
		"conversation_deleted": convDeleted,
	}
	if len(warnings) > 0 {
		res["warnings"] = warnings
	}
	writeJSON(w, 200, res)
}

func (s *Server) streamFindingRetestRecording(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad recording id")
		return
	}
	rec, err := pg.RetestRecordingByID(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if rec == nil {
		writeErr(w, 404, "recording not found")
		return
	}
	// 已丢弃的录屏对人侧不可见：拿着旧 URL 也当不存在。
	if rec.DiscardedAt != nil {
		writeErr(w, 404, "recording not found")
		return
	}
	abs := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(rec.TaskID, 10), rec.Path)
	if fi, err := os.Stat(abs); err != nil || fi.IsDir() {
		state, _ := pg.TaskArchiveState(rec.TaskID)
		if state != "" && state != db.ArchiveFailed {
			writeJSON(w, http.StatusConflict, map[string]any{
				"archived": true, "state": state,
				"message": "任务已归档，恢复后可播放录屏",
			})
			return
		}
		writeErr(w, 404, "录屏文件不存在")
		return
	}
	w.Header().Set("Content-Type", "video/mp4")
	http.ServeFile(w, r, abs)
}

// Seed the editable agent atomically, without an automatic discovery trigger.
// Once seeded, user edits/deletion survive restarts; a pre-existing key is kept.
func (s *Server) seedFindingRetester() error {
	for _, t := range s.findingRetestTools() {
		schema, _ := json.Marshal(t.InputSchema())
		bindings, _ := json.Marshal([]string{db.FindingRetestAgentKey})
		if err := s.m.pg.SeedTool(t.Name(), t.Description(), schema, bindings); err != nil {
			return err
		}
	}
	const flag = "finding_retester_seed_v1"
	tx, err := s.m.pg.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Lock this migration, including concurrent server initialization.
	if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(7337741010)`); err != nil {
		return err
	}
	var done string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, flag).Scan(&done)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// tools 行是 ON CONFLICT DO NOTHING 种进来的：之后改工具描述/入参（例如此次
	// retest_terminal_exec 新增 commands 分步）不会自己生效，用独立标记刷一次。
	const refreshFlag = "retest_recording_discard_v1"
	var refreshed string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=$1`, refreshFlag).Scan(&refreshed)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if refreshed != "true" {
		for _, t := range s.findingRetestTools() {
			schema, _ := json.Marshal(t.InputSchema())
			if _, err = tx.Exec(`UPDATE tools SET description=$2, schema=$3 WHERE key=$1`,
				t.Name(), t.Description(), schema); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES ($1,'true') ON CONFLICT(key) DO UPDATE SET value='true'`, refreshFlag); err != nil {
			return err
		}
	}
	if done == "true" {
		return tx.Commit()
	}
	var id int64
	err = tx.QueryRow(`INSERT INTO agents(key,name,description,role,builtin,enabled)
	VALUES ($1,'漏洞复测','从漏洞详情手动启动，读取原证据并保存独立复测结论。','assistant',false,true)
	ON CONFLICT (key) DO NOTHING RETURNING id`, db.FindingRetestAgentKey).Scan(&id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if id > 0 {
		var pid int64
		if err = tx.QueryRow(`INSERT INTO agent_prompts(agent_id,version,template_text,note,updated_by)
		VALUES ($1,1,$2,'内置默认','system') RETURNING id`, id, agent.RetesterDefaultPrompt).Scan(&pid); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE agents SET current_prompt_id=$1 WHERE id=$2`, pid, id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT INTO settings(key,value) VALUES ($1,'true') ON CONFLICT(key) DO UPDATE SET value='true'`, flag); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) finishRetest(id int64, status, reason string) {
	if err := s.m.pg.FinishFindingRetest(id, status, reason); err != nil {
		// Surface failure to the conversation runner rather than inventing a result.
		log.Printf("[retest %d] finish: %v", id, err)
	}
}

// ===========================================================================
// 复测录屏（P0）
//
// 显式上镜：只有经 retest_terminal_exec / retest_terminal_send 送进可见终端的
// 命令才会出现在视频里；普通 Bash 工具仍在后台跑，不进画面。
//
// 录制结构：Xvfb(:99–:110) → tmux(真 pty) → xterm(渲染) → ffmpeg x11grab → mp4
// 文件落点：<data>/tasks/<taskID>/recordings/<retestID>/<recID>.mp4
//   必须放在 tasks/ 下：任务归档只搬 tasks/ 与 transcripts/expN-*，
//   放别处会变成孤儿文件，恢复时也回不来。
// ===========================================================================

const (
	recFPS       = 15
	recMaxSecond = 1800             // 单段最长 30 分钟
	recMaxBytes  = int64(512) << 20 // 单段最大 512MB
	recMinDisk   = int64(2) << 30   // 剩余磁盘 <2GB 拒绝开始
	recCols      = 124
	recRows      = 38
	recScreen    = "1280x800x24"
	recPollEvery = 150 * time.Millisecond
	recMaxOutput = 256 << 10 // 单条命令回传上限 256KB
)

// retestTmuxConf 是录屏终端专属的 tmux 配置：用 -f 指定它就不读用户的 ~/.tmux.conf。
// tmux 3.2 默认 default-terminal=screen，256 色/真彩会降级，画面因此发灰。
const retestTmuxConf = `set -g default-terminal "tmux-256color"
set -as terminal-features "xterm*:RGB"
set -g status off
set -g history-limit 5000
set -g escape-time 0
`

// retestShellRC 是录屏终端专属的 bash rc：只影响画面观感，不读取用户 ~/.bashrc。
// 默认 bash 提示符没有颜色，xterm 里看起来就是一片灰白；这里给提示符上色，
// 并让 ls/grep 在交互场景下带颜色（--color=auto 在管道里自动关闭，不会污染文本）。
const retestShellRC = `PS1='\[\e[1;36m\]\u@\h\[\e[0m\]:\[\e[1;33m\]\w\[\e[0m\]\$ '
export TERM="${TERM:-xterm-256color}" COLORTERM=truecolor
alias ls='ls --color=auto'
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
bind 'set bell-style none' 2>/dev/null
# 退出码无痕回传：命令跑完、提示符重画之前把 $? 写进 ARTEX_RC。
# 用 PROMPT_COMMAND 而不是 "; echo $?"，画面上不会多出一行，命令原文不被污染。
if [ -n "$ARTEX_RC" ]; then
  PROMPT_COMMAND='printf %s $? > "$ARTEX_RC"'
fi
`

// runHeader 注入到每条命令脚本头部：脚本是非交互执行的，别名不生效，
// 用函数补上 tty 感知的上色（有管道时 --color=auto 会自动退化）。
const runHeader = `export TERM="${TERM:-xterm-256color}" COLORTERM=truecolor
ls() { command ls --color=auto "$@"; }
grep() { command grep --color=auto "$@"; }
`

var (
	recANSI   = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]")
	recGeom   = regexp.MustCompile(`(\d+)x(\d+)\+`)
	recPrompt = regexp.MustCompile(`^[\w.-]+@[\w.-]+:[^$#]*[$#]\s*$`)
)

var (
	pocPathRe   = regexp.MustCompile(`(?:^|[\s"'=:])poc/([A-Za-z0-9][A-Za-z0-9._-]*)`)
	cmdSkipWord = map[string]bool{
		"cd": true, "export": true, "echo": true, "printf": true,
		"set": true, "local": true, "true": true, "sleep": true,
	}
)

// cmdScriptName 给每条命令的临时脚本起名：.cmd-<seq>-<提示>.sh。
// 提示优先取命令里 poc/<文件名> 的主名（好让录屏对得上跑的是哪个 PoC），
// 否则取命令首词；都取不到就退回 .cmd-<seq>.sh。
func cmdScriptName(seq int64, command string) string {
	if hint := cmdNameHint(command); hint != "" {
		return fmt.Sprintf(".cmd-%d-%s.sh", seq, hint)
	}
	return fmt.Sprintf(".cmd-%d.sh", seq)
}

func cmdNameHint(command string) string {
	if m := pocPathRe.FindStringSubmatch(command); len(m) == 2 {
		name := m[1]
		if i := strings.LastIndex(name, "."); i > 0 {
			name = name[:i]
		}
		return cmdSlug(name)
	}
	for _, seg := range strings.FieldsFunc(command, func(r rune) bool {
		return r == '&' || r == ';' || r == '\n' || r == '|'
	}) {
		for _, f := range strings.Fields(seg) {
			if cmdSkipWord[f] || strings.HasPrefix(f, "-") || strings.Contains(f, "=") {
				continue
			}
			if s := cmdSlug(f); s != "" {
				return s
			}
		}
	}
	return ""
}

func cmdSlug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// recStep 是一条待上镜的命令：Conn 是它与前一条之间的连接符（; && ||）。
type recStep struct {
	Conn    string
	Command string
}

// splitCommands 把一条命令行按 shell 语法拆成可逐条上镜的若干条。
// 只认顶层（不在引号 / 转义 / $() 里）的 ; && || 和换行；管道 | 属于同一条命令。
// 第二个返回值为非空时表示拆不了或不能直敲，调用方整条按脚本方式执行
// （画面里是一次 bash .cmd-N.sh），避免污染交互 shell 或把代码块拆坏。
func splitCommands(raw string) ([]recStep, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, "命令为空"
	}
	if strings.Contains(s, "<<") {
		return nil, "含 heredoc / herestring"
	}
	if strings.HasSuffix(s, "\\") {
		return nil, "以续行符结尾"
	}
	for _, kw := range []string{"for ", "while ", "until ", "if ", "case ", "select ", "function "} {
		if strings.HasPrefix(s, kw) {
			return nil, "复合语句（" + strings.TrimSpace(kw) + "）"
		}
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "(") {
		return nil, "复合语句 / 子 shell"
	}

	var (
		out      []recStep
		cur      strings.Builder
		conn     = ";"
		quote    rune
		depth    int
		backtick bool
	)
	flush := func() {
		if v := strings.TrimSpace(cur.String()); v != "" {
			out = append(out, recStep{Conn: conn, Command: v})
		}
		cur.Reset()
		conn = ";"
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if quote != 0 {
			cur.WriteRune(c)
			switch {
			case c == '\\' && quote == '"' && i+1 < len(rs):
				i++
				cur.WriteRune(rs[i])
			case c == quote:
				quote = 0
			}
			continue
		}
		if backtick {
			cur.WriteRune(c)
			if c == '`' {
				backtick = false
			}
			continue
		}
		switch {
		case c == '"' || c == '\'':
			quote = c
			cur.WriteRune(c)
		case c == '`':
			backtick = true
			cur.WriteRune(c)
		case c == '\\' && i+1 < len(rs):
			cur.WriteRune(c)
			i++
			cur.WriteRune(rs[i])
		case c == '(':
			depth++
			cur.WriteRune(c)
		case c == ')':
			if depth > 0 {
				depth--
			}
			cur.WriteRune(c)
		case depth == 0 && (c == ';' || c == '\n'):
			flush()
		case depth == 0 && c == '&' && i+1 < len(rs) && rs[i+1] == '&':
			flush()
			conn = "&&"
			i++
		case depth == 0 && c == '|' && i+1 < len(rs) && rs[i+1] == '|':
			flush()
			conn = "||"
			i++
		default:
			cur.WriteRune(c)
		}
	}
	if quote != 0 {
		return nil, "引号未闭合"
	}
	if backtick {
		return nil, "反引号未闭合"
	}
	if depth != 0 {
		return nil, "括号未闭合"
	}
	flush()
	if len(out) == 0 {
		return nil, "命令为空"
	}
	for _, st := range out {
		if why := notTypableReason(st.Command); why != "" {
			return nil, why
		}
	}
	return out, ""
}

// notTypableReason 判断一条命令能不能直接敲进交互 shell。
// 直敲与脚本的差别在于「跑在会话 shell 里而不是子 shell」：会改变会话 shell
// 状态的语句（set -e / trap / exec / exit …）必须退回脚本方式，
// 否则一次复测之后整个录屏终端就废了。
func notTypableReason(cmd string) string {
	if strings.HasSuffix(cmd, "&") && !strings.HasSuffix(cmd, "&&") {
		return "含后台执行 &"
	}
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return "命令为空"
	}
	switch f[0] {
	case "exit", "exec", "set", "trap", "shopt", "bind", "enable", "ulimit", "umask", "logout":
		return "会改变会话 shell 状态（" + f[0] + "）"
	}
	return ""
}

// termStep 是一条上镜命令的执行结果。
type termStep struct {
	N        int    `json:"n"`
	Conn     string `json:"conn"`
	Command  string `json:"command"`
	Output   string `json:"output"`
	ExitCode int    `json:"exit_code"`
	Running  bool   `json:"running,omitempty"`
}

// termRun 是一次 retest_terminal_exec 的完整结果。
type termRun struct {
	Mode    string     `json:"mode"` // split=逐条直敲原命令；script=整条走临时脚本
	Steps   []termStep `json:"steps"`
	Code    int        `json:"exit_code"`
	Running bool       `json:"running"`
	Skipped []int      `json:"skipped_steps,omitempty"`
}

// joinStepOutput 给只认 output 的旧调用方留一个可用文本：
// 单条直接回原文，多条按 #n 加标题拼接。
func joinStepOutput(steps []termStep) string {
	switch len(steps) {
	case 0:
		return ""
	case 1:
		return steps[0].Output
	}
	var b strings.Builder
	for _, st := range steps {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "=== #%d %s\n%s", st.N, st.Command, st.Output)
	}
	return b.String()
}

// retestRecorder 是一次录制的运行时句柄；与 DB 行 1:1。
type retestRecorder struct {
	mu        sync.Mutex
	convID    int64
	retestID  int64
	taskID    int64
	recID     int64
	app       string
	target    string
	display   string
	session   string
	rcFile    string
	tmuxConf  string
	dir       string // 绝对目录
	relPath   string // 任务相对路径
	absPath   string
	width     int
	height    int
	fps       int
	startedAt time.Time
	seq       int64
	stopped   bool

	// execMu 串行化对同一个 pane 的写操作：两条命令同时往一个交互 shell 里
	// 敲，后一条会被当成前一条程序的 stdin，两条都拿不到退出码。
	execMu sync.Mutex
	// rcPath 是 PROMPT_COMMAND 回传退出码的文件（会话级，与 artEx rc 里的 ARTEX_RC 对应）。
	rcPath string
	// paneCwd 是录屏终端当前所处目录，用于判断要不要在命令前补 cd。
	paneCwd string

	xvfb   *exec.Cmd
	xterm  *exec.Cmd
	chrome *exec.Cmd
	ffmpeg *exec.Cmd
	ffDone chan error
}

func (s *Server) recorderFor(convID int64) *retestRecorder {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	return s.recorders[convID]
}

func (s *Server) putRecorder(r *retestRecorder) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.recorders == nil {
		s.recorders = map[int64]*retestRecorder{}
	}
	s.recorders[r.convID] = r
}

func (s *Server) dropRecorder(r *retestRecorder) {
	s.recMu.Lock()
	defer s.recMu.Unlock()
	if s.recorders[r.convID] == r {
		delete(s.recorders, r.convID)
	}
}

func recordingURL(id int64) string {
	return fmt.Sprintf("/api/finding-retest-recordings/%d/stream", id)
}

// startRetestRecording 校验 → 建行 → 起进程 → 探测 → 开录。
// 任何一步失败都把 DB 行标 failed 并回收进程，绝不留下"看起来成功"的空文件。
func (s *Server) startRetestRecording(ctx context.Context, convID int64, app, target, label string) (*db.FindingRetestRecording, error) {
	app = strings.TrimSpace(app)
	target = strings.TrimSpace(target)
	if app == "" {
		return nil, errors.New("app 必填：terminal（命令行证据）或 chrome（界面证据）")
	}
	if app != "terminal" && app != "chrome" {
		return nil, errors.New("app 只能是 terminal 或 chrome")
	}
	if app == "chrome" {
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			return nil, errors.New("app=chrome 需要 http(s) 起始 URL（target 参数）")
		}
	} else if target != "" {
		return nil, errors.New("app=terminal 不接受 target；要执行的命令用 retest_terminal_exec")
	}

	retest, err := s.m.pg.FindingRetestForConversation(ctx, convID)
	if err != nil {
		return nil, err
	}
	if retest == nil {
		return nil, errors.New("当前会话未关联复测记录")
	}
	if retest.Status != "running" {
		return nil, db.ErrRetestNotRunning
	}
	f, err := s.m.pg.GetFinding(retest.FindingID)
	if err != nil {
		return nil, err
	}
	if f == nil || f.TaskID == nil {
		return nil, errors.New("漏洞未关联任务，无法确定录制落点")
	}
	taskID := *f.TaskID

	if s.recorderFor(convID) != nil {
		return nil, errors.New("本次复测已有录制进行中")
	}
	bins := []string{"ffmpeg", "Xvfb"}
	if app == "terminal" {
		bins = append(bins, "tmux", "xterm")
	} else {
		bins = append(bins, "google-chrome")
	}
	for _, b := range bins {
		if _, err := exec.LookPath(b); err != nil {
			return nil, fmt.Errorf("缺少依赖 %s，无法录制 %s", b, app)
		}
	}
	if free, err := diskFree(s.m.dir); err == nil && free < recMinDisk {
		return nil, fmt.Errorf("磁盘剩余不足 %dGB，已拒绝开始录制", recMinDisk>>30)
	}

	row, err := s.m.pg.CreateRetestRecording(ctx, retest.ID, taskID, app)
	if err != nil {
		return nil, err
	}
	rec := &retestRecorder{
		convID: convID, retestID: retest.ID, taskID: taskID, recID: row.ID,
		app: app, target: target, fps: recFPS,
	}
	s.putRecorder(rec)
	if err := rec.start(s.m.dir); err != nil {
		rec.stop()
		rec.cleanupDirs()
		s.dropRecorder(rec)
		_ = s.m.pg.FailRetestRecording(context.Background(), row.ID, err.Error())
		return nil, err
	}
	if err := s.m.pg.SetRetestRecordingLive(ctx, row.ID, rec.display, rec.session, rec.relPath, rec.width, rec.height, rec.fps); err != nil {
		rec.stop()
		s.dropRecorder(rec)
		_ = s.m.pg.FailRetestRecording(context.Background(), row.ID, err.Error())
		return nil, err
	}
	row, err = s.m.pg.RetestRecordingByID(ctx, row.ID)
	if err != nil || row == nil {
		return nil, fmt.Errorf("读取录制记录失败: %v", err)
	}
	row.URL = recordingURL(row.ID)
	return row, nil
}

// stopRetestRecording 收尾并封口；status 为空表示正常完成。
func (s *Server) stopRetestRecording(ctx context.Context, convID int64, status string) (*db.FindingRetestRecording, error) {
	rec := s.recorderFor(convID)
	if rec == nil {
		return nil, errors.New("当前没有进行中的录制")
	}
	row, err := s.m.pg.RetestRecordingByID(ctx, rec.recID)
	if err != nil || row == nil {
		return nil, fmt.Errorf("读取录制记录失败: %v", err)
	}
	_ = s.m.pg.SetRetestRecordingStopping(ctx, rec.recID)
	durMS, size, sha := rec.stop()
	final := "completed"
	if status == "interrupted" {
		final = "interrupted"
	}
	errNote := ""
	s.dropRecorder(rec)
	if durMS < 500 || size <= 0 {
		final = "failed"
		errNote = "录制未产生有效文件"
	} else if peak, perr := videoPeak(rec.absPath); perr == nil && peak < 100 {
		// 录后复核：文件有效但画面全黑（应用崩溃/窗口被关）不能算成功。
		final = "failed"
		errNote = "录制画面没有内容（应用可能提前退出）"
	}
	if err := s.m.pg.FinishRetestRecording(ctx, rec.recID, final, durMS, size, sha, errNote); err != nil {
		return nil, err
	}
	if final == "failed" {
		_ = s.m.pg.FailRetestRecording(context.Background(), rec.recID, "录制未产生有效画面")
	}
	out, err := s.m.pg.RetestRecordingByID(ctx, rec.recID)
	if err != nil {
		return nil, err
	}
	if out != nil {
		out.URL = recordingURL(out.ID)
	}
	return out, nil
}

// stopRecordingForConversation 供复测会话结束/停止时兜底收尾。
func (s *Server) stopRecordingForConversation(convID int64, retestRunning bool) {
	rec := s.recorderFor(convID)
	if rec == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	status := ""
	if !retestRunning {
		status = "interrupted"
	}
	if _, err := s.stopRetestRecording(ctx, convID, status); err != nil {
		log.Printf("[retest recording %d] auto stop: %v", rec.recID, err)
	}
}

// stopTaskRecordings 归档打包前强制收尾该任务的所有录制。
// 必须先收尾再 stageTaskArchiveFiles，否则 ffmpeg 还在写的半截 mp4
// （没有 moov）会被打进归档，恢复后也放不了。
func (s *Server) stopTaskRecordings(ctx context.Context, taskID int64) error {
	if s.m == nil || s.m.pg == nil {
		return nil
	}
	recs, convs, err := s.m.pg.ActiveRecordingsForTask(ctx, taskID)
	if err != nil {
		return fmt.Errorf("查询任务录制: %w", err)
	}
	for i, row := range recs {
		convID := convs[i]
		if rec := s.recorderFor(convID); rec != nil && rec.recID == row.ID {
			if _, err := s.stopRetestRecording(ctx, convID, "interrupted"); err != nil {
				log.Printf("[retest recording %d] archive stop: %v", row.ID, err)
			}
			continue
		}
		// 进程内没有句柄（服务重启/崩溃残留）：清理命名会话与虚拟屏，再封口。
		if row.TmuxSession != "" {
			_ = exec.Command("tmux", "kill-session", "-t", row.TmuxSession).Run()
		}
		killXvfb(row.Display)
		if err := s.m.pg.InterruptRetestRecording(ctx, row.ID, "任务归档前收尾，录制已中断"); err != nil {
			return fmt.Errorf("封口录制 %d: %w", row.ID, err)
		}
		log.Printf("[retest recording %d] archived without live handle, sealed", row.ID)
	}
	return nil
}

// recoverRetestRecordings 在服务启动时封口上一进程遗留的录制并清理残留进程。
func (s *Server) recoverRetestRecordings() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	rows, err := s.m.pg.RecoverRetestRecordings()
	if err != nil {
		log.Printf("[retest recording] recover: %v", err)
		return
	}
	for _, r := range rows {
		if r.TmuxSession != "" {
			_ = exec.Command("tmux", "kill-session", "-t", r.TmuxSession).Run()
		}
		if r.Display != "" {
			killXvfb(r.Display)
		}
	}
}

func (r *retestRecorder) start(dataDir string) error {
	disp, err := allocateDisplay()
	if err != nil {
		return err
	}
	r.display = disp
	r.dir = filepath.Join(dataDir, "tasks", strconv.FormatInt(r.taskID, 10), "recordings", strconv.FormatInt(r.retestID, 10))
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return err
	}
	r.relPath = filepath.ToSlash(filepath.Join("recordings", strconv.FormatInt(r.retestID, 10), strconv.FormatInt(r.recID, 10)+".mp4"))
	r.absPath = filepath.Join(dataDir, "tasks", strconv.FormatInt(r.taskID, 10), r.relPath)
	r.session = fmt.Sprintf("artex-retest-%d-%d", r.convID, r.recID)

	r.xvfb = exec.Command("Xvfb", disp, "-screen", "0", recScreen, "-nolisten", "tcp")
	if err := startGrouped(r.xvfb); err != nil {
		return fmt.Errorf("Xvfb 启动失败: %w", err)
	}
	if err := waitDisplay(disp, 6*time.Second); err != nil {
		return fmt.Errorf("虚拟屏未就绪: %w", err)
	}
	if r.app == "terminal" {
		if err := r.startTerminal(); err != nil {
			return err
		}
	} else {
		if err := r.startChrome(); err != nil {
			return err
		}
	}
	w, h, err := waitWindow(disp, r.app, 12*time.Second)
	if err != nil {
		return err
	}
	r.width, r.height = w, h
	// 窗口大于虚拟屏时 x11grab 会直接报错，提前给出可读的原因。
	if w > 1280 || h > 800 {
		return fmt.Errorf("应用窗口 %dx%d 超出虚拟屏 1280x800（字体过大或窗口尺寸不符）", w, h)
	}
	if r.app == "terminal" {
		// 等 tmux 画出提示符：刚 attach 时 pane 还是空的，探针会误判成黑屏。
		if err := waitPaneText(r.session, 6*time.Second); err != nil {
			return err
		}
	}
	mean, peak, err := probeStats(disp, w, h)
	if err != nil {
		return err
	}
	// 深色终端背景的平均亮度和大黑屏一样（~16），所以看峰值：
	// 有文字/界面必然存在接近白色的像素；mean 高则说明是亮色页面。
	if peak < 100 && mean < 40 {
		return fmt.Errorf("画面没有内容（亮度峰值 %.0f、均值 %.0f），应用可能没有渲染", peak, mean)
	}
	r.startedAt = time.Now()
	args := []string{"-hide_banner", "-loglevel", "error",
		"-f", "x11grab", "-framerate", strconv.Itoa(r.fps),
		"-video_size", fmt.Sprintf("%dx%d", w, h), "-i", disp,
		"-t", strconv.Itoa(recMaxSecond),
		"-c:v", "libx264", "-preset", "ultrafast", "-crf", "26",
		"-pix_fmt", "yuv420p", "-movflags", "+faststart", "-y", r.absPath}
	cmd := exec.Command("ffmpeg", args...)
	r.ffmpeg = cmd
	r.ffDone = make(chan error, 1)
	if err := startGrouped(cmd); err != nil {
		return fmt.Errorf("ffmpeg 启动失败: %w", err)
	}
	go func(c *exec.Cmd, ch chan error) { ch <- c.Wait() }(cmd, r.ffDone)
	time.Sleep(400 * time.Millisecond)
	select {
	case err := <-r.ffDone:
		if err == nil {
			err = errors.New("ffmpeg 提前退出")
		}
		return fmt.Errorf("录制启动失败: %w", err)
	default:
	}
	return nil
}

func (r *retestRecorder) startTerminal() error {
	// 同名会话可能来自上次异常退出，先清掉再建，避免 duplicate session。
	_ = exec.Command("tmux", "kill-session", "-t", r.session).Run()
	// 默认 default-terminal 是 screen（8 色、无 truecolor），程序据此降级成单色。
	// set-option 需要已有 server，而 start-server 起的空 server 会立刻退出，
	// 所以把配置写进专属 tmux.conf，在 new-session 起 server 时生效
	// （同时仍然不读用户的 ~/.tmux.conf，避免泄露其状态栏/环境）。
	conf := filepath.Join(os.TempDir(), fmt.Sprintf("artex-tmux-%d-%d.conf", r.convID, r.recID))
	if err := os.WriteFile(conf, []byte(retestTmuxConf), 0o600); err != nil {
		return fmt.Errorf("写 tmux 配置失败: %w", err)
	}
	r.tmuxConf = conf
	r.rcPath = filepath.Join(os.TempDir(), fmt.Sprintf("artex-rc-state-%d-%d", r.convID, r.recID))
	_ = os.Remove(r.rcPath)
	r.paneCwd = r.dir
	rc := filepath.Join(os.TempDir(), fmt.Sprintf("artex-rc-%d-%d", r.convID, r.recID))
	if err := os.WriteFile(rc, []byte(retestShellRC), 0o600); err != nil {
		return fmt.Errorf("写录屏终端 rc 失败: %w", err)
	}
	r.rcFile = rc

	newSession := func(withEnv bool) error {
		args := []string{"-f", conf, "new-session", "-d", "-s", r.session,
			"-x", strconv.Itoa(recCols), "-y", strconv.Itoa(recRows), "-c", r.dir}
		if withEnv {
			args = append(args, "-e", "ARTEX_RC="+r.rcPath)
		}
		args = append(args, "bash --rcfile "+shellQuote(rc)+" -i")
		if out, err := exec.Command("tmux", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := newSession(true); err != nil {
		// tmux < 3.2 不支持 new-session -e，退不进去就直接把 rcPath 置空：
		// typeAndWait 会自己回落到脚本方式（画面里恢复成 bash .cmd-N.sh）。
		_ = exec.Command("tmux", "kill-session", "-t", r.session).Run()
		r.rcPath = ""
		if err2 := newSession(false); err2 != nil {
			return fmt.Errorf("tmux 启动失败: %v", err)
		}
	}
	_ = exec.Command("tmux", "set-option", "-t", r.session, "-g", "status", "off").Run()
	_ = exec.Command("tmux", "set-option", "-t", r.session, "-g", "history-limit", "5000").Run()

	args := []string{"-display", r.display,
		"-geometry", fmt.Sprintf("%dx%d+0+0", recCols, recRows),
		"-title", "ARTEX retest terminal",
		"-fa", "DejaVu Sans Mono", "-fs", "12",
		"-bg", "#0b1020", "-fg", "#c8d6e5",
		"-e", "tmux", "attach", "-t", r.session}
	cmd := exec.Command("xterm", args...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	r.xterm = cmd
	if err := startGrouped(cmd); err != nil {
		return fmt.Errorf("xterm 启动失败: %w", err)
	}
	return nil
}

func (r *retestRecorder) startChrome() error {
	profile := filepath.Join(os.TempDir(), fmt.Sprintf("artex-chrome-%d-%d", r.convID, r.recID))
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return err
	}
	args := []string{"--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
		"--no-first-run", "--no-default-browser-check", "--password-store=basic",
		"--disable-sync", "--disable-component-update", "--disable-background-networking",
		"--ozone-platform=x11",
		"--user-data-dir", profile,
		"--window-size", "1280,800", "--window-position", "0,0",
		r.target}
	cmd := exec.Command("google-chrome", args...)
	cmd.Env = append(os.Environ(), "DISPLAY="+r.display)
	r.chrome = cmd
	if err := startGrouped(cmd); err != nil {
		return fmt.Errorf("Chrome 启动失败: %w", err)
	}
	return nil
}

// stop 收尾：先 SIGINT 让 ffmpeg 写 moov，超时才 SIGKILL；随后清理应用与虚拟屏。
// 返回时长、大小与 sha256，供 DB 记录与事后校验。
func (r *retestRecorder) stop() (int64, int64, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return 0, 0, ""
	}
	r.stopped = true
	if r.ffmpeg != nil {
		signalGroup(r.ffmpeg, syscall.SIGINT)
		if r.ffDone != nil {
			select {
			case <-r.ffDone:
			case <-time.After(5 * time.Second):
				signalGroup(r.ffmpeg, syscall.SIGKILL)
				select {
				case <-r.ffDone:
				case <-time.After(2 * time.Second):
				}
			}
		}
	}
	if r.chrome != nil {
		signalGroup(r.chrome, syscall.SIGTERM)
		time.Sleep(300 * time.Millisecond)
		signalGroup(r.chrome, syscall.SIGKILL)
	}
	if r.session != "" {
		_ = exec.Command("tmux", "kill-session", "-t", r.session).Run()
	}
	if r.xterm != nil {
		signalGroup(r.xterm, syscall.SIGKILL)
	}
	killXvfb(r.display)

	var size int64
	if fi, err := os.Stat(r.absPath); err == nil {
		size = fi.Size()
	}
	durMS := time.Since(r.startedAt).Milliseconds()
	if r.absPath != "" {
		if out, err := exec.Command("ffprobe", "-v", "error", "-show_entries", "format=duration",
			"-of", "default=nw=1:nk=1", r.absPath).Output(); err == nil {
			if sec, perr := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); perr == nil && sec > 0 {
				durMS = int64(sec * 1000)
			}
		}
	}
	sha, _ := fileSHA256(r.absPath)
	return durMS, size, sha
}

// cleanupDirs 删除启动失败留下的空文件与临时 profile。
func (r *retestRecorder) cleanupDirs() {
	if r.absPath != "" {
		_ = os.Remove(r.absPath)
	}
	if r.rcFile != "" {
		_ = os.Remove(r.rcFile)
	}
	if r.rcPath != "" {
		_ = os.Remove(r.rcPath)
	}
	if r.tmuxConf != "" {
		_ = os.Remove(r.tmuxConf)
	}
	if r.convID > 0 {
		_ = os.RemoveAll(filepath.Join(os.TempDir(), fmt.Sprintf("artex-chrome-%d-%d", r.convID, r.recID)))
	}
}

// run 把命令写进脚本文件再送进可见终端：避免引号/换行/heredoc 转义地狱，
// 也让回显只占一行，输出切片边界确定。
func (r *retestRecorder) nextSeq() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	return r.seq
}

// run 执行一次 retest_terminal_exec：能直敲就逐条把原命令敲进可见终端
// （画面里就是原命令本身），拆不了或会污染会话 shell 的整条退回脚本方式。
func (r *retestRecorder) run(ctx context.Context, command, cwd string, timeout time.Duration) (*termRun, error) {
	return r.runLocked(ctx, command, false, nil, cwd, timeout)
}

// runExplicit 用于调用方已用 commands 数组显式分好步的情况：不再拆字符串。
func (r *retestRecorder) runExplicit(ctx context.Context, steps []recStep, cwd string, timeout time.Duration) (*termRun, error) {
	return r.runLocked(ctx, "", true, steps, cwd, timeout)
}

func (r *retestRecorder) runLocked(ctx context.Context, command string, explicit bool, steps []recStep, cwd string, timeout time.Duration) (*termRun, error) {
	r.execMu.Lock()
	defer r.execMu.Unlock()
	if r.stopped {
		return nil, errors.New("录制已停止")
	}
	script := command
	direct := steps
	why := ""
	if explicit {
		var parts []string
		direct = nil
		for _, st := range steps {
			v := strings.TrimSpace(st.Command)
			if v == "" {
				continue
			}
			parts = append(parts, v)
			direct = append(direct, recStep{Conn: st.Conn, Command: v})
		}
		script = strings.Join(parts, "\n")
		for _, st := range direct {
			if w := notTypableReason(st.Command); w != "" {
				why = w
				break
			}
		}
		if len(direct) > 0 && direct[0].Conn == "" {
			direct[0].Conn = ";"
		}
	} else {
		direct, why = splitCommands(command)
	}
	if why != "" || len(direct) == 0 {
		out, code, running, err := r.runScript(ctx, script, cwd, timeout)
		if err != nil {
			return nil, err
		}
		return &termRun{Mode: "script", Code: code, Running: running, Steps: []termStep{{
			N: 1, Conn: ";", Command: script, Output: out, ExitCode: code, Running: running,
		}}}, nil
	}
	return r.runSteps(ctx, direct, cwd, timeout)
}

// runSteps 逐条上镜：每条单独贴进 pane、等它跑完再发下一条。
// && / || 的短路语义保留：前一条失败（|| 时是成功）就跳过后续，并记在 skipped 里。
func (r *retestRecorder) runSteps(ctx context.Context, steps []recStep, cwd string, timeout time.Duration) (*termRun, error) {
	res := &termRun{Mode: "split"}
	deadline := time.Now().Add(timeout)
	dir := strings.TrimSpace(cwd)
	needCd := dir != "" && filepath.Clean(dir) != filepath.Clean(r.paneCwd)
	prev := 0
	for i, st := range steps {
		if i > 0 {
			if (st.Conn == "&&" && prev != 0) || (st.Conn == "||" && prev == 0) {
				res.Skipped = append(res.Skipped, i+1)
				continue
			}
		}
		cmd := st.Command
		withCd := false
		if needCd {
			if isCdCommand(cmd) {
				// 命令自己就在换目录：再加前缀只会出现 «cd X && cd X»（真实录制里出现过）。
				needCd = false
				r.paneCwd = "" // 去哪由命令自己决定，下一次调用重新补前缀
			} else {
				cmd = "cd -- " + shellQuote(dir) + " && " + cmd
				needCd = false
				withCd = true
			}
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			res.Running = true
			break
		}
		out, code, running, err := r.typeAndWait(ctx, cmd, remain)
		if err != nil {
			return nil, err
		}
		res.Steps = append(res.Steps, termStep{N: i + 1, Conn: st.Conn, Command: cmd, Output: out, ExitCode: code, Running: running})
		prev = code
		res.Code = code
		if withCd && !running && code == 0 {
			r.paneCwd = filepath.Clean(dir)
		}
		if running {
			res.Running = true
			break
		}
	}
	return res, nil
}

// isCdCommand 判断这一步是不是自己就在换目录（避免再套一层 cd 前缀）。
func isCdCommand(cmd string) bool {
	f := strings.Fields(cmd)
	return len(f) > 0 && f[0] == "cd"
}

// typeAndWait 用 bracketed paste 把命令原文贴进可见终端（多行/含括号的内容
// 不会被逐行执行，也不会被键位解释），回车后等 PROMPT_COMMAND 把退出码写进
// ARTEX_RC；输出从发送前那一行（提示符）之后切。
func (r *retestRecorder) typeAndWait(ctx context.Context, command string, timeout time.Duration) (string, int, bool, error) {
	if r.rcPath == "" {
		return r.runScript(ctx, command, "", timeout)
	}
	seq := r.nextSeq()
	_ = os.Remove(r.rcPath)
	anchor := ""
	beforeLines := 0
	if before, err := r.snapshotJoined(); err == nil {
		ls := strings.Split(before, "\n")
		beforeLines = len(ls)
		for i := len(ls) - 1; i >= 0; i-- {
			if strings.TrimSpace(paneLine(ls[i])) != "" {
				anchor = paneLine(ls[i])
				break
			}
		}
	}
	buf := fmt.Sprintf("artex-%d-%d", r.recID, seq)
	if out, err := exec.Command("tmux", "set-buffer", "-b", buf, "--", command).CombinedOutput(); err != nil {
		return "", 0, false, fmt.Errorf("写入终端缓冲失败: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("tmux", "paste-buffer", "-p", "-d", "-b", buf, "-t", r.session).CombinedOutput(); err != nil {
		return "", 0, false, fmt.Errorf("贴入终端失败: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("tmux", "send-keys", "-t", r.session, "Enter").CombinedOutput(); err != nil {
		return "", 0, false, fmt.Errorf("发送回车失败: %s", strings.TrimSpace(string(out)))
	}

	deadline := time.Now().Add(timeout)
	var pane string
	for {
		if p, err := r.snapshotJoined(); err == nil {
			pane = p
		}
		if b, err := os.ReadFile(r.rcPath); err == nil && strings.TrimSpace(string(b)) != "" {
			code, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			if p, err := r.snapshotJoined(); err == nil {
				pane = p
			}
			out := clipAfterAnchor(pane, beforeLines, anchor, command)
			if len(out) > recMaxOutput {
				out = out[:recMaxOutput] + "\n…(输出已截断)"
			}
			if incExecCountHook != nil {
				_ = incExecCountHook(r)
			}
			return out, code, false, nil
		}
		if time.Now().After(deadline) {
			return clipAfterAnchor(pane, beforeLines, anchor, command), 0, true, nil
		}
		select {
		case <-ctx.Done():
			return "", 0, true, ctx.Err()
		case <-time.After(recPollEvery):
		}
	}
}

// runScript 是老的执行方式：写临时脚本 + trap 落退出码，画面里是 bash .cmd-N.sh。
// heredoc / 复合语句 / 会改会话 shell 状态的命令只能走这里。
func (r *retestRecorder) runScript(ctx context.Context, command, cwd string, timeout time.Duration) (string, int, bool, error) {
	seq := r.nextSeq()

	base := cmdScriptName(seq, command)
	script := filepath.Join(r.dir, base)
	rcPath := filepath.Join(r.dir, fmt.Sprintf(".cmd-%d.rc", seq))
	_ = os.Remove(rcPath)
	// 退出码走 EXIT trap 落到文件：命令里自带 exit / set -e 也能拿到，
	// 终端上不再多打那行哨兵。
	body := "#!/bin/bash\n" + runHeader
	body += "trap 'printf \"%d\" $? > " + shellQuote(rcPath) + "' EXIT\n"
	if cwd = strings.TrimSpace(cwd); cwd != "" {
		body += "cd -- " + shellQuote(cwd) + " || exit 125\n"
	}
	body += command + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		return "", 0, false, err
	}
	defer os.Remove(script)
	defer os.Remove(rcPath)

	typed := "bash " + base
	// 录屏终端的 cwd 被 cd 改到别处后，相对路径就找不到脚本了：改用绝对路径。
	if filepath.Clean(r.paneCwd) != filepath.Clean(r.dir) {
		typed = "bash " + shellQuote(script)
	}
	if out, err := exec.Command("tmux", "send-keys", "-t", r.session, typed, "Enter").CombinedOutput(); err != nil {
		return "", 0, false, fmt.Errorf("发送命令失败: %s", strings.TrimSpace(string(out)))
	}

	deadline := time.Now().Add(timeout)
	var pane string
	for {
		if p, err := r.snapshotPane(2000); err == nil {
			pane = p
		}
		if b, err := os.ReadFile(rcPath); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			code, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			if p, err := r.snapshotPane(2000); err == nil {
				pane = p
			}
			out, _ := slicePaneOpen(pane, seq)
			if len(out) > recMaxOutput {
				out = out[:recMaxOutput] + "\n…(输出已截断)"
			}
			if incExecCountHook != nil {
				_ = incExecCountHook(r)
			}
			return out, code, false, nil
		}
		if time.Now().After(deadline) {
			tail, _ := slicePaneOpen(pane, seq)
			return tail, 0, true, nil
		}
		select {
		case <-ctx.Done():
			return "", 0, true, ctx.Err()
		case <-time.After(recPollEvery):
		}
	}
}

// snapshotJoined 抓整屏历史并把折行合并成一条逻辑行（-J）。
// 直敲时靠它定位「发送前那一行」，长命令折几行都不用猜。
func (r *retestRecorder) snapshotJoined() (string, error) {
	out, err := exec.Command("tmux", "capture-pane", "-pJ", "-S", "-", "-t", r.session).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// paneLine 把一行终端文本归一化（去 ANSI、去尾随空格）。
// capture-pane -J 会给折行补尾随空格，直接逐字节比较会匹配不到。
func paneLine(s string) string {
	return strings.TrimRight(recANSI.ReplaceAllString(s, ""), " \t")
}

// clipAfterAnchor 取发送前最后一行（提示符）之后的内容，
// 再去掉命令回显与末尾重新画出的提示符。
// 提示符每行长得一模一样，所以先剥掉末尾那几行提示符，再回退找锚点，
// 否则会命中命令跑完后新画的提示符、切出空输出。
func clipAfterAnchor(pane string, beforeLines int, anchor, command string) string {
	lines := strings.Split(pane, "\n")
	end := len(lines)
	for end > 0 {
		t := paneLine(lines[end-1])
		if strings.TrimSpace(t) == "" || recPrompt.MatchString(strings.TrimSpace(t)) {
			end--
			continue
		}
		break
	}
	lines = lines[:end]

	start := -1
	if anchor != "" && beforeLines > 0 && beforeLines <= len(lines) && paneLine(lines[beforeLines-1]) == anchor {
		start = beforeLines
	}
	if start < 0 && anchor != "" {
		for i := len(lines) - 1; i >= 0; i-- {
			if paneLine(lines[i]) == anchor {
				start = i + 1
				break
			}
		}
	}
	if start < 0 {
		// 历史被 5000 行上限挤掉、行号与锚点都漂了：退回按命令回显定位。
		// 只认「提示符 + 命令」那一行（needle 前面必须有 $ / #），
		// 并从后往前找最近的：输出里出现同名文本时才不会切错。
		needle := echoNeedle(command)
		for i := len(lines) - 1; i >= 0 && needle != ""; i-- {
			t := paneLine(lines[i])
			at := strings.Index(t, needle)
			if at < 0 {
				continue
			}
			if prefix := t[:at]; strings.Contains(prefix, "$ ") || strings.Contains(prefix, "# ") {
				start = i
				break
			}
		}
	}
	if start < 0 || start > len(lines) {
		start = 0
		if len(lines) > 200 {
			start = len(lines) - 200
		}
	}
	return stripEchoAndPrompt(lines[start:], command)
}

// stripEchoAndPrompt 去掉首行「提示符 + 命令回显」和末尾重新画出的提示符。
func stripEchoAndPrompt(lines []string, command string) string {
	if len(lines) > 0 {
		if strings.Contains(paneLine(lines[0]), echoNeedle(command)) {
			lines = lines[1:]
		}
	}
	for len(lines) > 0 {
		last := paneLine(lines[len(lines)-1])
		if strings.TrimSpace(last) == "" || recPrompt.MatchString(strings.TrimSpace(last)) {
			lines = lines[:len(lines)-1]
			continue
		}
		break
	}
	return strings.TrimRight(recANSI.ReplaceAllString(strings.Join(lines, "\n"), ""), " \t\n")
}

// echoNeedle 取命令开头一小段，用来认出「这一行是回显不是输出」。
func echoNeedle(command string) string {
	c := strings.TrimSpace(command)
	if r := []rune(c); len(r) > 24 {
		c = string(r[:24])
	}
	return c
}

// incExecCountHook 由 New 注入：recorder 不持有 DB 句柄，run 里只做计数回调。
var incExecCountHook func(*retestRecorder) error

func (r *retestRecorder) send(input string, newline bool) error {
	args := []string{"send-keys", "-t", r.session, input}
	if newline {
		args = append(args, "Enter")
	}
	out, err := exec.Command("tmux", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("发送失败: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *retestRecorder) snapshotPane(lines int) (string, error) {
	if lines <= 0 {
		lines = 200
	}
	out, err := exec.Command("tmux", "capture-pane", "-t", r.session, "-pS", "-"+strconv.Itoa(lines)).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// slicePaneOpen 用于超时：从回显行之后截到当前最后一行。
func slicePaneOpen(pane string, seq int64) (string, error) {
	if pane == "" {
		return "", nil
	}
	return joinPaneLines(strings.Split(pane, "\n"), seq, len(strings.Split(pane, "\n"))), nil
}

func joinPaneLines(lines []string, seq int64, endIdx int) string {
	prefix := fmt.Sprintf(".cmd-%d", seq)
	startIdx := -1
	for i := endIdx - 1; i >= 0; i-- {
		idx := strings.Index(lines[i], prefix)
		if idx < 0 {
			continue
		}
		// 名字带提示时是 .cmd-7-poc.sh；不带时是 .cmd-7.sh。别把 .cmd-70 认成 .cmd-7。
		if rest := lines[i][idx+len(prefix):]; rest == "" || rest[0] == '.' || rest[0] == '-' {
			startIdx = i
			break
		}
	}
	if startIdx < 0 {
		startIdx = 0
	}
	if endIdx > len(lines) {
		endIdx = len(lines)
	}
	body := lines[startIdx+1 : endIdx]
	for len(body) > 0 {
		last := strings.TrimRight(body[len(body)-1], " \t")
		if strings.TrimSpace(last) == "" {
			body = body[:len(body)-1]
			continue
		}
		// 末尾这行是 shell 打完命令后重新画出来的提示符（user@host:path$ ），不是输出。
		if recPrompt.MatchString(strings.TrimSpace(recANSI.ReplaceAllString(last, ""))) {
			body = body[:len(body)-1]
			continue
		}
		break
	}
	out := recANSI.ReplaceAllString(strings.Join(body, "\n"), "")
	return strings.TrimRight(out, " 	\n")
}

// ---- 进程 / 环境辅助 ----

func startGrouped(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Start()
}

func signalGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, sig)
}

func allocateDisplay() (string, error) {
	for n := 99; n <= 110; n++ {
		if _, err := os.Stat(fmt.Sprintf("/tmp/.X%d-lock", n)); err == nil {
			continue
		}
		if _, err := os.Stat(fmt.Sprintf("/tmp/.X11-unix/X%d", n)); err == nil {
			continue
		}
		return fmt.Sprintf(":%d", n), nil
	}
	return "", errors.New("没有可用的虚拟屏（:99–:110 全部占用）")
}

func waitDisplay(disp string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if out, err := exec.Command("xdpyinfo", "-display", disp).Output(); err == nil && len(out) > 0 {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.New("等不到虚拟屏就绪")
}

func killXvfb(display string) {
	if display == "" {
		return
	}
	num := strings.TrimPrefix(display, ":")
	b, err := os.ReadFile("/tmp/.X" + num + "-lock")
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
}

// waitWindow 等应用窗口出现并返回几何；宽度/高度即录制画幅。
func waitWindow(disp, app string, d time.Duration) (int, int, error) {
	needle := "(\"xterm\""
	if app == "chrome" {
		needle = "(\"google-chrome"
	}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		out, err := exec.Command("xwininfo", "-display", disp, "-root", "-tree").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if !strings.Contains(line, needle) {
					continue
				}
				m := recGeom.FindStringSubmatch(line)
				if m == nil {
					continue
				}
				w, _ := strconv.Atoi(m[1])
				h, _ := strconv.Atoi(m[2])
				if w >= 200 && h >= 200 {
					return w, h, nil
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, 0, fmt.Errorf("等不到 %s 窗口（12s）", app)
}

// probeStats 抓一帧算亮度均值与峰值。深色终端背景的平均亮度与黑屏无异，
// 必须靠峰值判断"有没有画出内容"。
func probeStats(disp string, w, h int) (mean, peak float64, err error) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("artex-probe-%d.png", time.Now().UnixNano()))
	defer os.Remove(tmp)
	out, err := exec.Command("ffmpeg", "-hide_banner", "-loglevel", "error",
		"-f", "x11grab", "-video_size", fmt.Sprintf("%dx%d", w, h), "-i", disp,
		"-frames:v", "1", "-y", tmp).CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("探测帧失败: %s", strings.TrimSpace(string(out)))
	}
	f, err := os.Open(tmp)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return 0, 0, err
	}
	b := img.Bounds()
	var sum, n float64
	for y := b.Min.Y; y < b.Max.Y; y += 3 {
		for x := b.Min.X; x < b.Max.X; x += 3 {
			r, g, bl, _ := img.At(x, y).RGBA()
			l := 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(bl>>8)
			sum += l
			if l > peak {
				peak = l
			}
			n++
		}
	}
	if n == 0 {
		return 0, 0, errors.New("探测帧为空")
	}
	return sum / n, peak, nil
}

// videoPeak 抽样检查录制文件的亮度峰值（每秒一帧），用于录后复核"有没有画面"。
func videoPeak(path string) (float64, error) {
	out, err := exec.Command("ffmpeg", "-hide_banner", "-i", path,
		"-vf", "fps=1,signalstats,metadata=print:key=lavfi.signalstats.YMAX",
		"-an", "-f", "null", "-").CombinedOutput()
	if err != nil {
		return 0, err
	}
	peak := 0.0
	for _, line := range strings.Split(string(out), "\n") {
		i := strings.Index(line, "YMAX=")
		if i < 0 {
			continue
		}
		if v, perr := strconv.ParseFloat(strings.TrimSpace(line[i+5:]), 64); perr == nil && v > peak {
			peak = v
		}
	}
	if peak == 0 {
		return 0, errors.New("录制文件没有可解析的帧")
	}
	return peak, nil
}

// waitPaneText 等 tmux pane 有内容（提示符或输出），避免把刚 attach 的空屏当黑屏。
func waitPaneText(session string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		out, err := exec.Command("tmux", "capture-pane", "-t", session, "-p").Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("终端会话没有输出提示符")
}

func diskFree(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// 让 image 包被引用（png.Decode 的返回类型在文档上属于 image.Image）。
var _ image.Image = image.NewRGBA(image.Rect(0, 0, 1, 1))
