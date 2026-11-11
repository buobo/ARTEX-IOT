package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

const maxTaskComponentRequestBytes = 512 << 10

func writeTaskComponentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrTaskComponentInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, db.ErrTaskComponentTaskNotFound), errors.Is(err, db.ErrTaskComponentComponentNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) attachTaskComponents(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskComponentRequestBytes)
	var request struct {
		ComponentIDs  []int64            `json:"component_ids"`
		SourceSummary string             `json:"source_summary"`
		Scope         companyScopeInputs `json:"scope"`
	}
	if err := decode(r, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	request.SourceSummary = strings.TrimSpace(request.SourceSummary)
	taskID, _ := parseTaskID(task.ID)
	if request.Scope != nil && len(request.ComponentIDs) > 0 {
		writeErr(w, http.StatusBadRequest, "scope 与 component_ids 不能同时提交")
		return
	}
	if request.Scope != nil {
		writeErr(w, http.StatusGone, "范围登记已下线：请在任务中上传固件（POST /api/tasks/{id}/firmware）")
		return
	}
	mutation, err := s.m.Components().AttachComponentsToTask(taskID, request.ComponentIDs, request.SourceSummary)
	if err != nil {
		writeTaskComponentError(w, err)
		return
	}
	task.Notify()
	writeJSON(w, http.StatusOK, mutation)
}

func (s *Server) detachTaskComponent(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	componentID, ok := pathInt(r, "componentID")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad component id")
		return
	}
	taskID, _ := parseTaskID(task.ID)
	detached, err := s.m.Components().DetachComponentFromTask(taskID, componentID)
	if err != nil {
		writeTaskComponentError(w, err)
		return
	}
	if !detached {
		writeErr(w, http.StatusNotFound, "component is not associated with this task")
		return
	}
	task.Notify()
	writeJSON(w, http.StatusOK, map[string]any{"detached": componentID})
}

func (s *Server) taskIntentComponents(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	taskID, _ := parseTaskID(task.ID)
	components, err := s.m.Components().IntentComponents(taskID)
	if err != nil {
		writeTaskComponentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"components": components})
}

// taskPocFiles 列出任务 PoC 目录下的文件，并标出每个文件被哪些漏洞引用。
// PoC 目录由 save_poc 维护（<dataDir>/tasks/<id>/poc），这里只读不写。
func (s *Server) taskPocFiles(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if _, ok := s.m.Task(id); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	dir := filepath.Join(s.m.dir, "tasks", id, "poc")

	// 引用映射：分页扫完该任务的全部漏洞（不设上限，大任务才不漏）。
	refs := map[string][]map[string]any{}
	for page := 1; ; page++ {
		fs, total, err := s.m.pg.ListFindingsPage(db.FindingFilter{TaskID: id}, page, 200)
		if err != nil {
			break
		}
		for _, f := range fs {
			for _, name := range f.PocFiles {
				refs[name] = append(refs[name], map[string]any{"id": f.ID, "name": f.Name})
			}
		}
		if len(fs) == 0 || page*200 >= total {
			break
		}
	}

	out := []map[string]any{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, map[string]any{"dir": "tasks/" + id + "/poc", "files": out})
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "INDEX.md" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		used := refs[e.Name()]
		if used == nil {
			used = []map[string]any{}
		}
		out = append(out, map[string]any{
			"name":          e.Name(),
			"size":          info.Size(),
			"modified_at":   info.ModTime().UTC().Format(time.RFC3339),
			"referenced_by": used,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"dir": "tasks/" + id + "/poc", "files": out})
}

// taskPocDownload 取回单个 PoC 文件；?inline=1 时按文本预览，否则按附件下载。
func (s *Server) taskPocDownload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if _, ok := s.m.Task(id); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" || name != filepath.Base(name) || strings.Contains(name, "..") || strings.HasPrefix(name, ".") {
		writeErr(w, http.StatusBadRequest, "文件名非法")
		return
	}
	path := filepath.Join(s.m.dir, "tasks", id, "poc", name)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "PoC 文件不存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	disp := "attachment"
	if r.URL.Query().Get("inline") == "1" {
		disp = "inline"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=%q", disp, name))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeContent(w, r, name, st.ModTime(), f)
}
