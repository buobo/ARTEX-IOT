package server

import (
	"errors"
	"net/http"
	"strings"

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
		ComponentIDs      []int64            `json:"component_ids"`
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
