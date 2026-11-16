package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/report"
)

func writeFindingsEvidenceZip(out io.Writer, findings []*db.DBFinding, stage string, now time.Time) error {
	zw := zip.NewWriter(out)
	if err := writeFindingsZipEntries(zw, findings, stage, now); err != nil {
		zw.Close()
		return err
	}
	return zw.Close()
}

func writeFindingsZipEntries(zw *zip.Writer, findings []*db.DBFinding, stage string, now time.Time) error {
	store := evidence.New(nil, nil, stage) // private export copy; not subject to GC
	used := map[string]int{}
	for _, f := range findings {
		base := report.FindingFilename(f)
		name := base
		if n := used[base]; n > 0 {
			name = fmt.Sprintf("%s-%d.md", strings.TrimSuffix(base, ".md"), n+1)
		}
		used[base]++
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err = io.WriteString(w, report.SingleFindingMarkdown(f, now)); err != nil {
			return err
		}
		for _, b := range f.TrafficBindings {
			prefix := fmt.Sprintf("evidence/%d/%d/", f.ID, b.ID)
			w, err := zw.Create(prefix + "manifest.json")
			if err != nil {
				return err
			}
			if err = json.NewEncoder(w).Encode(b); err != nil {
				return err
			}
			for _, side := range []string{"request", "response"} {
				if err := func() error {
					body, _, err := store.OpenBody(b.Snapshot, side)
					if err != nil {
						return err
					}
					defer body.Close()
					w, err := zw.Create(prefix + side + ".http")
					if err != nil {
						return err
					}
					head := b.Snapshot.ReqHead
					if side == "response" {
						head = b.Snapshot.RespHead
					}
					if _, err = io.WriteString(w, strings.TrimRight(head, "\r\n")+"\n\n"); err != nil {
						return err
					}
					if _, err = io.Copy(w, body); err != nil {
						return err
					}
					if _, err = body.Seek(0, io.SeekStart); err != nil {
						return err
					}
					w, err = zw.Create(prefix + side + ".bin")
					if err != nil {
						return err
					}
					_, err = io.Copy(w, body)
					return err
				}(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func buildFindingsEvidenceZip(path string, findings []*db.DBFinding, stage string, now time.Time) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeFindingsEvidenceZip(f, findings, stage, now)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	// Re-read every compressed entry to validate the finished ZIP, including CRCs,
	// before the caller starts an HTTP download response.
	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer archive.Close()
	for _, entry := range archive.File {
		r, err := entry.Open()
		if err != nil {
			return err
		}
		_, readErr := io.Copy(io.Discard, r)
		if err := errors.Join(readErr, r.Close()); err != nil {
			return err
		}
	}
	return nil
}

// ===== 单条漏洞产物导出：一个 finding 一个 zip =====
//
// 取数规则（防串）：只按 finding 主键取；PoC 只取 poc_files 列出的文件（不扫任务
// poc 目录）；视频走 finding_retests.finding_id；流量走该 finding 的 bindings；
// 路径根用 finding 自己的 task_id（跨任务 provenance 不会取错任务）。
// 打包后做集合自检：zip 条目必须与写出的条目集合完全相等，多一个或少一个都报错。

const (
	artifactReport   = "report"
	artifactPoc      = "poc"
	artifactVideo    = "video"
	artifactTraffic  = "traffic"
	artifactEvidence = "evidence"
)

// findingArtifactKeys 是固定顺序，弹框按它渲染。
var findingArtifactKeys = []string{artifactReport, artifactPoc, artifactVideo, artifactTraffic, artifactEvidence}

var findingArtifactLabels = map[string]string{
	artifactReport:   "报告文档",
	artifactPoc:      "PoC 脚本",
	artifactVideo:    "复现视频",
	artifactTraffic:  "流量证据",
	artifactEvidence: "证据文本",
}

type findingArtifactFile struct {
	Name       string `json:"name"`
	Bytes      int64  `json:"bytes"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

type findingArtifactItem struct {
	Key       string                `json:"key"`
	Label     string                `json:"label"`
	Count     int                   `json:"count"`
	Bytes     int64                 `json:"bytes"`
	Available bool                  `json:"available"`
	Note      string                `json:"note,omitempty"`
	Files     []findingArtifactFile `json:"files"`
}

type findingArtifactSet struct {
	ID         int64                 `json:"id"`
	Name       string                `json:"name"`
	TaskID     int64                 `json:"task_id"`
	TotalBytes int64                 `json:"total_bytes"`
	Items      []findingArtifactItem `json:"items"`
}

// parseFindingArtifactItems 解析 items=report,poc,...；空值表示全选。
func parseFindingArtifactItems(raw string) (map[string]bool, error) {
	out := make(map[string]bool, len(findingArtifactKeys))
	if strings.TrimSpace(raw) == "" {
		for _, k := range findingArtifactKeys {
			out[k] = true
		}
		return out, nil
	}
	for _, part := range strings.Split(raw, ",") {
		k := strings.TrimSpace(part)
		if k == "" {
			continue
		}
		if _, ok := findingArtifactLabels[k]; !ok {
			return nil, fmt.Errorf("items 里有未知产物：%s（可用 %s）", k, strings.Join(findingArtifactKeys, ","))
		}
		out[k] = true
	}
	if len(out) == 0 {
		for _, k := range findingArtifactKeys {
			out[k] = true
		}
	}
	return out, nil
}

// parseFindingArtifactFiles 解析 files=a,b,c（弹框里逐文件勾选时的产物条目名）。
// 返回 nil 表示未指定（= 该类产物的全部文件）。
func parseFindingArtifactFiles(raw string) map[string]bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := make(map[string]bool, 8)
	for _, part := range strings.Split(raw, ",") {
		if name := strings.TrimSpace(part); name != "" {
			out[name] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validateArtifactFiles 保证 files 里每个名字都是这条（些）finding 自己的产物条目名，
// 避免被拿来指定任意路径。
func validateArtifactFiles(sets []findingArtifactSet, only map[string]bool) error {
	known := make(map[string]bool, 32)
	for _, set := range sets {
		for _, item := range set.Items {
			for _, file := range item.Files {
				known[file.Name] = true
			}
		}
	}
	var bad []string
	for name := range only {
		if !known[name] {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("这些文件不在这条漏洞的产物里：%s", firstFew(bad, 3))
	}
	return nil
}

// findingZipName 内层包名：<FindingFilename 去 .md>.zip；FindingFilename 已带 #id，
// 不带时补 -<id>，保证不同 finding 永不撞名。
func findingZipName(f *db.DBFinding) string {
	base := strings.TrimSuffix(report.FindingFilename(f), ".md")
	if !strings.Contains(base, fmt.Sprintf("#%d", f.ID)) {
		base += fmt.Sprintf("-%d", f.ID)
	}
	return base + ".zip"
}

// barePocName 判断 poc_files 里的名字是单层文件名（poc_files 落库恒为裸名）。
func barePocName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\\") && filepath.IsLocal(name)
}

func recDurationLabel(ms int64) string {
	switch {
	case ms <= 0:
		return "0s"
	case ms < 1000:
		return fmt.Sprintf("%dms", ms)
	default:
		return fmt.Sprintf("%ds", ms/1000)
	}
}

func firstFew(list []string, n int) string {
	if len(list) <= n {
		return strings.Join(list, "、")
	}
	return strings.Join(list[:n], "、") + fmt.Sprintf(" 等 %d 个", len(list))
}

// findingTaskDir 返回该 finding 所属任务目录（跨任务 provenance 用 finding 自己的 task_id）。
func (s *Server) findingTaskDir(f *db.DBFinding) string {
	if f.TaskID == nil || *f.TaskID <= 0 {
		return ""
	}
	return filepath.Join(s.m.dir, "tasks", strconv.FormatInt(*f.TaskID, 10))
}

// findingVideos 取该 finding 名下未丢弃的录屏（RetestRecordingsForFinding 已过滤），按 id 升序。
func (s *Server) findingVideos(ctx context.Context, findingID int64) []*db.FindingRetestRecording {
	byRetest, err := s.m.pg.RetestRecordingsForFinding(ctx, findingID)
	if err != nil {
		return nil
	}
	out := make([]*db.FindingRetestRecording, 0, len(byRetest))
	for _, list := range byRetest {
		out = append(out, list...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// findingArtifacts 构建清单：不打开 body、不读视频，体积靠 stat / snapshot 长度。
func (s *Server) findingArtifacts(ctx context.Context, f *db.DBFinding, want map[string]bool) findingArtifactSet {
	set := findingArtifactSet{ID: f.ID, Name: f.Name, Items: make([]findingArtifactItem, 0, len(findingArtifactKeys))}
	if set.Name == "" {
		set.Name = f.VulnClass
	}
	if f.TaskID != nil {
		set.TaskID = *f.TaskID
	}
	taskDir := s.findingTaskDir(f)

	for _, key := range findingArtifactKeys {
		it := findingArtifactItem{Key: key, Label: findingArtifactLabels[key], Files: []findingArtifactFile{}}
		if !want[key] {
			it.Note = "未勾选"
			set.Items = append(set.Items, it)
			continue
		}
		switch key {
		case artifactReport:
			if strings.TrimSpace(f.Report) == "" {
				it.Note = "尚未生成报告"
				break
			}
			it.Available = true
			it.Count = 1
			it.Bytes = int64(len(f.Report))
			it.Files = append(it.Files, findingArtifactFile{Name: "report.md", Bytes: it.Bytes})

		case artifactPoc:
			var missing []string
			for _, name := range f.PocFiles {
				if !barePocName(name) || taskDir == "" {
					missing = append(missing, name)
					continue
				}
				st, err := os.Stat(filepath.Join(taskDir, "poc", name))
				if err != nil || st.IsDir() {
					missing = append(missing, name)
					continue
				}
				it.Files = append(it.Files, findingArtifactFile{Name: "poc/" + name, Bytes: st.Size()})
				it.Bytes += st.Size()
				it.Count++
			}
			it.Available = it.Count > 0
			switch {
			case len(f.PocFiles) == 0:
				it.Note = "无 PoC 文件"
			case !it.Available:
				it.Note = "文件已丢失：" + firstFew(missing, 3)
			case len(missing) > 0:
				it.Note = "缺 " + firstFew(missing, 3)
			}

		case artifactVideo:
			marks := make([]map[string]any, 0, 4)
			for _, rec := range s.findingVideos(ctx, f.ID) {
				if rec.Path == "" || taskDir == "" || !filepath.IsLocal(rec.Path) {
					continue
				}
				abs := filepath.Join(taskDir, rec.Path)
				size := rec.SizeBytes
				if st, err := os.Stat(abs); err == nil && !st.IsDir() {
					size = st.Size()
				} else {
					continue // 文件不在：不进包（清单里也不会显示这一段）
				}
				it.Files = append(it.Files, findingArtifactFile{
					Name:       fmt.Sprintf("videos/%d-%s-%s.mp4", rec.ID, rec.App, recDurationLabel(rec.DurationMS)),
					Bytes:      size,
					DurationMS: rec.DurationMS,
				})
				it.Bytes += size
				it.Count++
				marks = append(marks, map[string]any{
					"recording_id": rec.ID,
					"app":          rec.App,
					"duration_ms":  rec.DurationMS,
					"marks":        rec.Marks,
				})
			}
			if it.Count == 0 {
				it.Note = "无复现视频"
				break
			}
			// 标记点对复现证据有价值：汇总成 videos/marks.json 一起打包。
			if body, err := json.MarshalIndent(marks, "", "  "); err == nil {
				it.Files = append(it.Files, findingArtifactFile{Name: "videos/marks.json", Bytes: int64(len(body))})
				it.Bytes += int64(len(body))
			}
			it.Available = true

		case artifactTraffic:
			it.Count = len(f.TrafficBindings)
			for _, b := range f.TrafficBindings {
				prefix := fmt.Sprintf("evidence/traffic/%d/", b.ID)
				reqBytes := int64(len(b.Snapshot.ReqHead)) + b.Snapshot.ReqLen
				respBytes := int64(len(b.Snapshot.RespHead)) + b.Snapshot.RespLen
				it.Bytes += reqBytes + respBytes
				it.Files = append(it.Files,
					findingArtifactFile{Name: prefix + "manifest.json"},
					findingArtifactFile{Name: prefix + "request.http", Bytes: reqBytes},
					findingArtifactFile{Name: prefix + "response.http", Bytes: respBytes},
				)
			}
			it.Available = it.Count > 0
			if !it.Available {
				it.Note = "无流量绑定"
			}

		case artifactEvidence:
			if strings.TrimSpace(f.Evidence) == "" {
				it.Note = "证据文本为空"
				break
			}
			it.Available = true
			it.Count = 1
			it.Bytes = int64(len(f.Evidence))
			it.Files = append(it.Files, findingArtifactFile{Name: "evidence/evidence.md", Bytes: it.Bytes})
		}
		set.TotalBytes += it.Bytes
		set.Items = append(set.Items, it)
	}
	return set
}

// writeFindingArtifactEntries 把一条 finding 的产物写进 zw，返回写出的条目名（供自检）。
func (s *Server) writeFindingArtifactEntries(ctx context.Context, zw *zip.Writer, f *db.DBFinding, want, only map[string]bool, stage string, now time.Time) ([]string, error) {
	ev := evidence.New(nil, nil, stage) // 私有导出副本，不受 GC 影响
	taskDir := s.findingTaskDir(f)
	names := make([]string, 0, 16)
	// only 非 nil 时只写它里面的条目（弹框逐文件勾选）；nil = 该类产物全要。
	allow := func(name string) bool { return only == nil || only[name] }

	addBytes := func(name string, body []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err = w.Write(body); err != nil {
			return err
		}
		names = append(names, name)
		return nil
	}
	addFile := func(name, abs string, storeOnly bool) error {
		fh, err := os.Open(abs)
		if err != nil {
			return err
		}
		defer fh.Close()
		h := &zip.FileHeader{Name: name, Modified: now}
		if storeOnly {
			h.Method = zip.Store // 已压缩内容（mp4）不再压
		} else {
			h.Method = zip.Deflate
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err = io.Copy(w, fh); err != nil {
			return err
		}
		names = append(names, name)
		return nil
	}

	if want[artifactReport] && strings.TrimSpace(f.Report) != "" && allow("report.md") {
		if err := addBytes("report.md", []byte(f.Report)); err != nil {
			return names, err
		}
	}
	if want[artifactPoc] && taskDir != "" {
		for _, name := range f.PocFiles {
			if !barePocName(name) {
				continue
			}
			abs := filepath.Join(taskDir, "poc", name)
			if st, err := os.Stat(abs); err != nil || st.IsDir() {
				continue
			}
			if !allow("poc/" + name) {
				continue
			}
			if err := addFile("poc/"+name, abs, false); err != nil {
				return names, err
			}
		}
	}
	if want[artifactVideo] && taskDir != "" {
		recs := s.findingVideos(ctx, f.ID)
		marks := make([]map[string]any, 0, len(recs))
		for _, rec := range recs {
			if rec.Path == "" || !filepath.IsLocal(rec.Path) {
				continue
			}
			abs := filepath.Join(taskDir, rec.Path)
			if st, err := os.Stat(abs); err != nil || st.IsDir() {
				continue
			}
			name := fmt.Sprintf("videos/%d-%s-%s.mp4", rec.ID, rec.App, recDurationLabel(rec.DurationMS))
			if !allow(name) {
				continue
			}
			if err := addFile(name, abs, true); err != nil {
				return names, err
			}
			marks = append(marks, map[string]any{
				"recording_id": rec.ID,
				"app":          rec.App,
				"duration_ms":  rec.DurationMS,
				"marks":        rec.Marks,
			})
		}
		if len(marks) > 0 && allow("videos/marks.json") {
			body, err := json.MarshalIndent(marks, "", "  ")
			if err != nil {
				return names, err
			}
			if err := addBytes("videos/marks.json", body); err != nil {
				return names, err
			}
		}
	}
	if want[artifactTraffic] {
		for _, b := range f.TrafficBindings {
			prefix := fmt.Sprintf("evidence/traffic/%d/", b.ID)
			if allow(prefix + "manifest.json") {
				man, err := json.MarshalIndent(b, "", "  ")
				if err != nil {
					return names, err
				}
				if err := addBytes(prefix+"manifest.json", man); err != nil {
					return names, err
				}
			}
			for _, side := range []string{"request", "response"} {
				if !allow(prefix + side + ".http") {
					continue
				}
				body, _, err := ev.OpenBody(b.Snapshot, side)
				if err != nil {
					return names, err
				}
				head := b.Snapshot.ReqHead
				if side == "response" {
					head = b.Snapshot.RespHead
				}
				w, err := zw.Create(prefix + side + ".http")
				if err != nil {
					body.Close()
					return names, err
				}
				if _, err = io.WriteString(w, strings.TrimRight(head, "\r\n")+"\n\n"); err != nil {
					body.Close()
					return names, err
				}
				if _, err = io.Copy(w, body); err != nil {
					body.Close()
					return names, err
				}
				body.Close()
				names = append(names, prefix+side+".http")
			}
		}
	}
	if want[artifactEvidence] && strings.TrimSpace(f.Evidence) != "" && allow("evidence/evidence.md") {
		if err := addBytes("evidence/evidence.md", []byte(f.Evidence)); err != nil {
			return names, err
		}
	}
	return names, nil
}

// buildFindingArtifactZip 生成「一条 finding 一个包」的 zip，并做集合自检。
func (s *Server) buildFindingArtifactZip(ctx context.Context, path string, f *db.DBFinding, want, only map[string]bool, stage string, now time.Time) ([]string, error) {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	zw := zip.NewWriter(out)
	names, writeErr := s.writeFindingArtifactEntries(ctx, zw, f, want, only, stage, now)
	closeErr := zw.Close()
	syncErr := out.Sync()
	fileErr := out.Close()
	if err := errors.Join(writeErr, closeErr, syncErr, fileErr); err != nil {
		return nil, err
	}
	// 自检：条目集合必须与写出的完全相等，多一个或少一个都算失败（不返回半成品）。
	arc, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer arc.Close()
	got := make(map[string]bool, len(arc.File))
	for _, e := range arc.File {
		got[e.Name] = true
	}
	if len(got) != len(names) {
		return nil, fmt.Errorf("产物包条目数不符：包里 %d，写出 %d", len(got), len(names))
	}
	for _, n := range names {
		if !got[n] {
			return nil, fmt.Errorf("产物包缺少条目：%s", n)
		}
	}
	return names, nil
}

// buildFindingsArtifactBundle 生成批量包：外层 zip，里面每条 finding 一个独立 zip。
func (s *Server) buildFindingsArtifactBundle(ctx context.Context, path string, fs []*db.DBFinding, want, only map[string]bool, stage string, now time.Time) error {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	var writeErr error
	for _, f := range fs {
		name := findingZipName(f)
		inner := filepath.Join(stage, name)
		if _, err := s.buildFindingArtifactZip(ctx, inner, f, want, only, stage, now); err != nil {
			writeErr = err
			break
		}
		src, err := os.Open(inner)
		if err != nil {
			writeErr = err
			break
		}
		h := &zip.FileHeader{Name: name, Modified: now, Method: zip.Store}
		w, err := zw.CreateHeader(h)
		if err == nil {
			_, err = io.Copy(w, src)
		}
		src.Close()
		if err != nil {
			writeErr = err
			break
		}
	}
	closeErr := zw.Close()
	syncErr := out.Sync()
	fileErr := out.Close()
	return errors.Join(writeErr, closeErr, syncErr, fileErr)
}
