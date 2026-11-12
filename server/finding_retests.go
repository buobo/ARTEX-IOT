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
				if err := s.m.pg.RecordFindingRetestResult(ctx, intercept.ConvIDFromContext(ctx), a.Verdict, a.Summary, a.Evidence); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(map[string]any{"saved": true, "verdict": a.Verdict})
			}),
	}, s.retestRecordingTools()...)
}

// retestRecordingTools 提供「显式上镜」录制：只有经这里的工具执行的命令才进视频。
func (s *Server) retestRecordingTools() []actool.CoreTool {
	return []actool.CoreTool{
		wrTool("retest_recording", "控制本复测会话的录屏。先 action=capabilities 看可用后端；start 必须指定 app，由你根据证据类型自行决定：terminal（命令行证据：curl/nc/gdb/qemu）或 chrome（界面证据：登录跳转/XSS/CSRF/前端权限，需要 http(s) target）。mark 记录关键时间点；stop 生成 mp4 并返回路径。注意：只有经 retest_terminal_exec / retest_terminal_send 执行的命令会出现在 terminal 录像中。",
			objSchema(map[string]any{
				"action": map[string]any{"type": "string", "enum": []string{"capabilities", "start", "stop", "mark", "status"}},
				"app":    map[string]any{"type": "string", "enum": []string{"terminal", "chrome"}, "description": "start 时必填，自行判断"},
				"target": strParam("app=chrome 时的起始 URL（http/https）"),
				"label":  strParam("本次录制名称，便于报告引用"),
				"note":   strParam("mark 的时间点说明"),
			}, "action"), s.retestRecordingTool),
		wrTool("retest_terminal_exec", "在可见终端中执行一条命令并等待结束：返回输出与退出码，同时该命令及输出会出现在录屏里。语义与 Bash 等价但会上镜；普通 Bash 执行的命令不会出现在录像中。交互式程序（gdb/nc/tail）请改用 retest_terminal_send + retest_terminal_snapshot。",
			objSchema(map[string]any{
				"command":   strParam("要执行的命令（bash 语法）"),
				"cwd":       strParam("工作目录，默认本会话工作目录"),
				"timeout_s": map[string]any{"type": "integer", "description": "超时秒数，默认 120，最大 600"},
			}, "command"), s.retestTerminalExec),
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
		Action string `json:"action"`
		App    string `json:"app"`
		Target string `json:"target"`
		Label  string `json:"label"`
		Note   string `json:"note"`
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
	}
	return actool.Errorf("action 只能是 capabilities / start / stop / mark / status"), nil
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
		Command  string `json:"command"`
		Cwd      string `json:"cwd"`
		TimeoutS int    `json:"timeout_s"`
	}
	if err := json.Unmarshal(in, &a); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if strings.TrimSpace(a.Command) == "" {
		return actool.Errorf("command 不能为空"), nil
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
	out, code, running, err := rec.run(ctx, a.Command, cwd, timeout)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	res := map[string]any{"output": out, "exit_code": code, "running": running}
	if running {
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
	if done == "true" {
		return nil
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
export COLORTERM=truecolor
alias ls='ls --color=auto'
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
bind 'set bell-style none' 2>/dev/null
`

// runHeader 注入到每条命令脚本头部：脚本是非交互执行的，别名不生效，
// 用函数补上 tty 感知的上色（有管道时 --color=auto 会自动退化）。
const runHeader = `export TERM="${TERM:-xterm-256color}" COLORTERM=truecolor
ls() { command ls --color=auto "$@"; }
grep() { command grep --color=auto "$@"; }
`

var (
	recANSI = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]")
	recGeom = regexp.MustCompile(`(\d+)x(\d+)\+`)
	recPrompt = regexp.MustCompile(`^[\w.-]+@[\w.-]+:[^$#]*[$#]\s*$`)
)

var (
	pocPathRe = regexp.MustCompile(`(?:^|[\s"'=:])poc/([A-Za-z0-9][A-Za-z0-9._-]*)`)
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
	rc := filepath.Join(os.TempDir(), fmt.Sprintf("artex-rc-%d-%d", r.convID, r.recID))
	if err := os.WriteFile(rc, []byte(retestShellRC), 0o600); err != nil {
		return fmt.Errorf("写录屏终端 rc 失败: %w", err)
	}
	r.rcFile = rc
	tm := exec.Command("tmux", "-f", conf, "new-session", "-d", "-s", r.session,
		"-x", strconv.Itoa(recCols), "-y", strconv.Itoa(recRows), "-c", r.dir,
		"bash --rcfile "+shellQuote(rc)+" -i")
	if out, err := tm.CombinedOutput(); err != nil {
		return fmt.Errorf("tmux 启动失败: %s", strings.TrimSpace(string(out)))
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
	if r.tmuxConf != "" {
		_ = os.Remove(r.tmuxConf)
	}
	if r.convID > 0 {
		_ = os.RemoveAll(filepath.Join(os.TempDir(), fmt.Sprintf("artex-chrome-%d-%d", r.convID, r.recID)))
	}
}

// run 把命令写进脚本文件再送进可见终端：避免引号/换行/heredoc 转义地狱，
// 也让回显只占一行，输出切片边界确定。
func (r *retestRecorder) run(ctx context.Context, command, cwd string, timeout time.Duration) (string, int, bool, error) {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return "", 0, false, errors.New("录制已停止")
	}
	r.seq++
	seq := r.seq
	r.mu.Unlock()

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
