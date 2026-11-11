package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// companyScopeInputs accepts both the new [{kind,value}] contract and the
// historical ["example.com","203.0.113.10"] contract.
type companyScopeInputs []db.ScopeInput

const maxCompanyMutationBodyBytes = 2 << 20

func decodeCompanyMutationRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxCompanyMutationBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(value); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		}
		return false
	}
	return true
}

func (items *companyScopeInputs) UnmarshalJSON(data []byte) error {
	var rawItems []json.RawMessage
	if err := json.Unmarshal(data, &rawItems); err != nil {
		return err
	}
	out := make([]db.ScopeInput, 0, len(rawItems))
	for i, raw := range rawItems {
		var legacy string
		if err := json.Unmarshal(raw, &legacy); err == nil {
			out = append(out, db.ScopeInput{Value: legacy})
			continue
		}
		var structured db.ScopeInput
		if err := json.Unmarshal(raw, &structured); err != nil {
			return fmt.Errorf("scope[%d] must be a string or {kind,value}", i)
		}
		out = append(out, structured)
	}
	*items = out
	return nil
}

// componentStore returns the component store.
func (s *Server) componentStore() *db.ComponentStore {
	if s.m.pg == nil {
		return nil
	}
	return s.m.pg.Components()
}

// companyStore returns the company store.
func (s *Server) companyStore() *db.CompanyStore {
	if s.m.pg == nil {
		return nil
	}
	return s.m.pg.Companies()
}

// =====================================================================
// GET /api/companies
// =====================================================================

func (s *Server) listCompanies(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	companies, err := cs.ListCompanies()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, companies)
}

// =====================================================================
// POST /api/companies
// =====================================================================

func (s *Server) createCompany(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		Name  string             `json:"name"`
		Logo  string             `json:"logo"`
		Scope companyScopeInputs `json:"scope"`
	}
	if !decodeCompanyMutationRequest(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, 400, "name required")
		return
	}
	if err := db.ValidateCompanyScopeInputBounds(req.Scope); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, added, skipped, invalid, scopeErrs, err := cs.CreateCompanyWithScope(req.Name, req.Logo, req.Scope, "api")
	if err != nil {
		if errors.Is(err, db.ErrCompanyNameConflict) {
			writeErr(w, http.StatusConflict, "企业名称已存在")
			return
		}
		var validationErr *db.CompanyScopeValidationError
		if errors.As(err, &validationErr) {
			writeErr(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{
		"id":            id,
		"created":       true,
		"scope_added":   added,
		"scope_skipped": skipped,
		"scope_invalid": invalid,
	}
	if len(scopeErrs) > 0 {
		out["scope_errors"] = scopeErrs
	}
	writeJSON(w, 201, out)
}

// =====================================================================
// GET /api/companies/{id}
// =====================================================================

func (s *Server) getCompany(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	c, err := cs.GetCompany(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if c == nil {
		writeErr(w, 404, "company not found")
		return
	}
	scope, err := cs.GetScope(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"company": c, "scope": scope})
}

// =====================================================================
// POST /api/companies/{id}/scope
// =====================================================================

func (s *Server) addCompanyScope(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid company id")
		return
	}
	var req struct {
		Scope  companyScopeInputs `json:"scope"`
		Reason string             `json:"reason"`
		Reset  bool               `json:"reset"` // if true, replace existing scope
	}
	if !decodeCompanyMutationRequest(w, r, &req) {
		return
	}
	if err := db.ValidateCompanyScopeInputBounds(req.Scope); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var added, skipped, invalid int
	var errs []string
	var mutationErr error
	if req.Reset {
		added, invalid, errs, mutationErr = cs.UpdateScopeInputsChecked(id, req.Scope, req.Reason)
	} else {
		added, skipped, invalid, errs, mutationErr = cs.AddScopeInputsChecked(id, req.Scope, req.Reason)
	}
	if mutationErr != nil {
		if errors.Is(mutationErr, db.ErrCompanyNotFound) {
			writeErr(w, http.StatusNotFound, "company not found")
			return
		}
		var validationErr *db.CompanyScopeValidationError
		if errors.As(mutationErr, &validationErr) {
			writeErr(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, mutationErr.Error())
		return
	}
	out := map[string]any{
		"added":   added,
		"skipped": skipped,
		"invalid": invalid,
	}
	if len(errs) > 0 {
		out["errors"] = errs
	}
	// Reported separately from errors: this is pre-existing bad data, not a fault
	// in the submitted rules, but the operator still has to see it or those components
	// look like the IP/CIDR rules simply never match. A failure to build the
	// warning must not fail the scope write that already committed.
	if warning, err := cs.MalformedIPComponentWarning(); err == nil && warning != "" {
		out["warnings"] = []string{warning}
	}
	writeJSON(w, 200, out)
}

// =====================================================================
// DELETE /api/companies/{id}
// =====================================================================

func (s *Server) deleteCompany(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid id")
		return
	}
	var req struct {
		DeleteComponents bool `json:"delete_components"`
	}
	// The body is optional. Only an actual empty body is ignored; malformed or
	// trailing JSON is a client error.
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	} else {
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			if err == nil {
				writeErr(w, http.StatusBadRequest, "invalid JSON: multiple values")
			} else {
				writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			}
			return
		}
	}

	componentsDeleted, err := s.m.DeleteCompanyWithComponents(id, req.DeleteComponents)
	if err != nil {
		if errors.Is(err, db.ErrCompanyNotFound) {
			writeErr(w, http.StatusNotFound, "company not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": 1, "components_deleted": componentsDeleted})
}

// =====================================================================
// POST /api/companies/reattribute
// =====================================================================

func (s *Server) reattribute(w http.ResponseWriter, r *http.Request) {
	cs := s.companyStore()
	if cs == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	if err := cs.RecomputeAttribution(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// =====================================================================
// GET /api/components
// =====================================================================

const (
	defaultComponentPageSize = 50
	maxComponentPageSize     = 200
)

func (s *Server) listComponents(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	q := r.URL.Query()
	typ := q.Get("type")
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = defaultComponentPageSize
	} else if limit > maxComponentPageSize {
		limit = maxComponentPageSize
	}
	if offset < 0 {
		offset = 0
	}

	components := []*db.Component{}
	var err error
	// total is the full match count ignoring limit/offset. Count first so an offset
	// beyond the last row can return an empty page without an expensive scan.
	total := 0

	// firmware=<sha256> 时按固件归属过滤：拼成 DSL 子句，与 dsl/type/status 同一条路径，
	// 保证 total 和分页口径一致（组件可能在多固件任务里复用，这是唯一能按固件切开的维度）。
	dsl := strings.TrimSpace(q.Get("dsl"))
	if fw := strings.TrimSpace(q.Get("firmware")); fw != "" {
		if !isSha256Hex(fw) {
			writeErr(w, http.StatusBadRequest, "firmware 需要 64 位十六进制 sha256")
			return
		}
		clause := "firmware_sha256==" + fw
		if dsl == "" {
			dsl = clause
		} else {
			dsl = "(" + dsl + ") AND " + clause
		}
	}
	if dsl != "" {
		if err := db.ValidateDSL(dsl); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// task_id scopes the DSL search to a task's components (the task detail
		// "测试组件" search); 0 means the global component view.
		taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
		total, err = as.CountDSL(dsl, typ, q.Get("status"), taskID)
		if err == nil && offset < total {
			components, err = as.QueryDSL(dsl, typ, q.Get("status"), taskID, limit, offset)
		}
	} else {
		taskID, _ := strconv.ParseInt(q.Get("task_id"), 10, 64)
		components, total, err = as.ListComponents(db.ComponentFilter{
			Type: typ, Status: q.Get("status"), TaskID: taskID, Limit: limit, Offset: offset,
		})
	}

	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"count":      len(components),
		"total":      total,
		"components": components,
	})
}

// =====================================================================
// GET /api/components/counts
// =====================================================================

// isSha256Hex reports whether v is a 64-char lowercase/uppercase hex string.
func isSha256Hex(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func (s *Server) componentCounts(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	// by=firmware 时按固件 sha256 汇总（组件页的固件筛选下拉用）。
	if r.URL.Query().Get("by") == "firmware" {
		counts, err := as.FirmwareCounts(taskID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, counts)
		return
	}
	// by=status 时按挖掘状态汇总（任务详情「组件」页的进度按钮用），默认按类型汇总。
	if r.URL.Query().Get("by") == "status" {
		counts, err := as.StatusCounts(taskID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, counts)
		return
	}
	counts, err := as.CountsByType(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, counts)
}

// =====================================================================
// DELETE /api/components
// =====================================================================

func (s *Server) deleteComponents(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeErr(w, 400, "ids required")
		return
	}
	deleted, err := as.DeleteByIDs(req.IDs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": deleted})
}

// =====================================================================
// POST /api/components
// =====================================================================

func (s *Server) insertComponents(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		TaskID         int64               `json:"task_id"`
		Components     []db.ComponentInput `json:"components"`
		Type           string              `json:"type"`
		ComponentName  string              `json:"component_name"`
		Version        string              `json:"version"`
		Vendor         string              `json:"vendor"`
		BinaryPath     string              `json:"binary_path"`
		ConfigPath     string              `json:"config_path"`
		StartedBy      string              `json:"started_by"`
		FirmwareSha256 string              `json:"firmware_sha256"`
		Port           int                 `json:"port"`
		Technologies   []string            `json:"technologies"`
		Notes          string              `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	items := req.Components
	if len(items) == 0 {
		items = []db.ComponentInput{{
			Type: req.Type, Name: req.ComponentName, Version: req.Version,
			Vendor: req.Vendor, BinaryPath: req.BinaryPath, ConfigPath: req.ConfigPath,
			StartedBy: req.StartedBy, FirmwareSha256: req.FirmwareSha256,
			Port: req.Port, Technologies: req.Technologies, Notes: req.Notes,
		}}
	}
	var taskIDs []int64
	if req.TaskID > 0 {
		taskIDs = []int64{req.TaskID}
	}
	inserted, updated, ids, err := as.UpsertComponents(taskIDs, items)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.TaskID > 0 {
		for _, id := range ids {
			_ = as.SetTaskComponentSource(req.TaskID, id, "api", "通过组件 API 登记", nil)
		}
	}
	writeJSON(w, 200, map[string]any{"inserted": inserted, "updated": updated, "ids": ids})
}

// =====================================================================
// POST /api/components/{id}/status
// =====================================================================

func (s *Server) setComponentStatus(w http.ResponseWriter, r *http.Request) {
	as := s.componentStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid component id")
		return
	}
	var req struct {
		Status string `json:"status"`
		TaskID int64  `json:"task_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	// 带 task_id 时按任务守卫（与 set_component_status 工具同一口径：只有该任务范围内的
	// 组件才能改状态）；不带则是组件库全局视角。
	taskID := req.TaskID
	if taskID <= 0 {
		taskID, _ = strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	}
	if err := as.SetTaskComponentStatus(taskID, id, req.Status); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": req.Status})
}
