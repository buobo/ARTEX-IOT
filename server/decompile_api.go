package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 反编译 API。鉴权走统一的 requireAuth（路由挂在已鉴权的 mux 上）。
// 安全要点：binary_path 只能解析到 data/tasks/<id>/ 之内；code/{addr} 的 addr
// 只作为 index.json 里的 key 查表，绝不参与拼文件路径。

// decompileRoots 取本任务已登记的解包根（task_scope.kind='firmware' 的 extract_path）。
// 这是解析宿主机文件的唯一依据——worker 解包完成后必须调 register_extract 登记；
// 不再遍历 i*/rootfs 猜实例。
func (s *Server) decompileRoots(taskID int64) []string {
	as := s.m.Components()
	if as == nil {
		return nil
	}
	rows, err := as.ListTaskScope(taskID)
	if err != nil {
		return nil
	}
	var roots []string
	for _, r := range rows {
		if r.Kind != "firmware" {
			continue
		}
		p := strings.TrimSpace(r.ExtractPath)
		// extract_path 由 worker 写入，仍按不可信处理：必须是任务目录内的相对路径。
		if p == "" || strings.HasPrefix(p, "/") || strings.Contains(filepath.ToSlash(p), "..") {
			continue
		}
		roots = append(roots, p)
	}
	return roots
}

// decompileCreate POST /api/tasks/{id}/decompile
// body: {component_ids:[...]} 或 {binary_path:"/usr/sbin/jhttpd"}
func (s *Server) decompileCreate(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, 400, "任务 id 无效")
		return
	}
	var body struct {
		ComponentIDs []int64 `json:"component_ids"`
		BinaryPath   string  `json:"binary_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	if s.decomp == nil || s.m.pg == nil {
		writeErr(w, 503, "反编译能力未启用（无数据库）")
		return
	}
	cfg := s.decomp.config()
	if _, _, idaErr := s.decomp.locateIDA(cfg); idaErr != nil {
		writeErr(w, 503, idaErr.Error())
		return
	}
	// 配额：产物目录已经超过 decompile_task_quota_mb 就不再建新 job（P2 的"好维护"）。
	if used, limit := s.decomp.decompileUsage(taskID), cfg.quotaBytes; limit > 0 && used >= limit {
		writeErr(w, 429, fmt.Sprintf("本任务反编译产物已占 %d MB，超过配额 %d MB：先删掉不用的导出再建", used>>20, limit>>20))
		return
	}
	roots := s.decompileRoots(taskID)
	if len(roots) == 0 {
		writeErr(w, 400, "本任务还没有登记解包路径：worker 解包完成后会调用 register_extract；先完成解包再来导出")
		return
	}
	type want struct {
		componentID *int64
		name        string
		path        string
	}
	var wants []want
	var skipped []string // 没有 binary_path 的组件：明确回给前端，不静默丢
	if len(body.ComponentIDs) > 0 {
		if len(body.ComponentIDs) > cfg.maxComps {
			writeErr(w, 400, fmt.Sprintf("单次最多勾选 %d 个组件", cfg.maxComps))
			return
		}
		as := s.m.Components()
		if as == nil {
			writeErr(w, 503, "component store 未启用")
			return
		}
		comps, err := as.TaskComponentsForDecompile(taskID, body.ComponentIDs)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		var missing []string
		for _, c := range comps {
			if strings.TrimSpace(c.BinaryPath) == "" {
				missing = append(missing, c.Name+"（未登记二进制路径）")
				skipped = append(skipped, c.Name)
				continue
			}
			id := c.ID
			wants = append(wants, want{componentID: &id, name: c.Name, path: c.BinaryPath})
		}
		if len(wants) == 0 {
			writeErr(w, 400, "所选组件都没有二进制路径: "+strings.Join(missing, "、"))
			return
		}
	} else if p := strings.TrimSpace(body.BinaryPath); p != "" {
		wants = append(wants, want{name: filepath.Base(p), path: p})
	} else {
		writeErr(w, 400, "需要 component_ids 或 binary_path")
		return
	}

	jobs := make([]map[string]any, 0, len(wants))
	for _, it := range wants {
		abs, sha, exportDir, err := s.decomp.resolveSource(taskID, it.path, roots)
		if err != nil {
			writeErr(w, 400, it.name+": "+err.Error())
			return
		}
		job, reused, err := s.m.pg.CreateOrReuseDecompileJob(&db.DecompileJob{
			TaskID:       taskID,
			ComponentID:  it.componentID,
			BinaryPath:   it.path,
			BinarySha256: sha,
			AbsPath:      abs,
			ExportDir:    exportDir,
			CreatedBy:    s.sessionUser(r),
		})
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if !reused {
			s.decomp.kick()
		}
		jobs = append(jobs, map[string]any{
			"id": job.ID, "component_id": job.ComponentID, "status": job.Status,
			"binary_path": job.BinaryPath, "binary_sha256": job.BinarySha256,
			"func_total": job.FuncTotal, "func_done": job.FuncDone, "reused": reused,
		})
	}
	writeJSON(w, 200, map[string]any{"jobs": jobs, "skipped": skipped})
}

// sessionUser 标识触发来源。现在是单口令 + 无用户名 JWT，没有"谁"可记，
// 统一记 'user'（人工从界面触发）；将来接入多用户再把这里换成 claims 里的名字。
func (s *Server) sessionUser(r *http.Request) string {
	return "user"
}

// attachTaskNames 给 job 列表补上任务名（列表按任务分组时要显示名字而不是编号）。
func (s *Server) attachTaskNames(jobs []*db.DecompileJob) {
	if s.m.pg == nil || len(jobs) == 0 {
		return
	}
	seen := map[int64]bool{}
	var ids []int64
	for _, j := range jobs {
		if !seen[j.TaskID] {
			seen[j.TaskID] = true
			ids = append(ids, j.TaskID)
		}
	}
	names, err := s.m.pg.TaskNames(ids)
	if err != nil {
		log.Printf("[decompile] 取任务名失败: %v", err)
		return
	}
	for _, j := range jobs {
		j.TaskName = names[j.TaskID]
	}
}

// decompileTaskJobs GET /api/tasks/{id}/decompile/jobs
func (s *Server) decompileTaskJobs(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	jobs, err := s.m.pg.ListDecompileJobs(taskID, "")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.attachTaskNames(jobs)
	writeJSON(w, 200, map[string]any{"jobs": jobs})
}

// decompileList GET /api/decompile/jobs?task_id=&status=
func (s *Server) decompileList(w http.ResponseWriter, r *http.Request) {
	taskID, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("task_id")), 10, 64)
	jobs, err := s.m.pg.ListDecompileJobs(taskID, strings.TrimSpace(r.URL.Query().Get("status")))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.attachTaskNames(jobs)
	writeJSON(w, 200, map[string]any{"jobs": jobs})
}

// decompileGet GET /api/decompile/jobs/{jobID}
func (s *Server) decompileGet(w http.ResponseWriter, r *http.Request) {
	j, err := s.decompileJobFromPath(r)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	// 状态条要显示产物大小，顺手把目录占用算出来（单个 job 的产物目录）。
	payload := struct {
		*db.DecompileJob
		ArtifactBytes int64 `json:"artifact_bytes"`
	}{DecompileJob: j}
	if abs := s.decompAbs(j.ExportDir); abs != "" {
		payload.ArtifactBytes = dirSizeBytes(abs)
	}
	writeJSON(w, 200, payload)
}

func (s *Server) decompileJobFromPath(r *http.Request) (*db.DecompileJob, error) {
	id, err := strconv.ParseInt(r.PathValue("jobID"), 10, 64)
	if err != nil || id <= 0 {
		return nil, errors.New("jobID 无效")
	}
	if s.m.pg == nil {
		return nil, errors.New("无数据库")
	}
	return s.m.pg.GetDecompileJob(id)
}

// decompileCancel POST /api/decompile/jobs/{jobID}/cancel
func (s *Server) decompileCancel(w http.ResponseWriter, r *http.Request) {
	j, err := s.decompileJobFromPath(r)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if j.Status == db.DecompileCompleted || j.Status == db.DecompileFailed || j.Status == db.DecompileCanceled {
		writeJSON(w, 200, map[string]any{"ok": true, "status": j.Status})
		return
	}
	// 正在跑 → 杀进程组；还在排队 → 直接把状态改掉，队列取到时会跳过。
	_ = s.decomp.cancel(j.ID)
	_ = s.m.pg.FinishDecompileJob(j.ID, db.DecompileCanceled, "用户取消", j.FuncTotal, j.FuncDone)
	writeJSON(w, 200, map[string]any{"ok": true, "status": db.DecompileCanceled})
}

// decompileDelete DELETE /api/decompile/jobs/{jobID} —— 删记录 + 删产物目录。
func (s *Server) decompileDelete(w http.ResponseWriter, r *http.Request) {
	j, err := s.decompileJobFromPath(r)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	_ = s.decomp.cancel(j.ID)
	if _, err := s.m.pg.DeleteDecompileJob(j.ID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if dir := s.decompAbs(j.ExportDir); dir != "" {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("[decompile] 清理产物失败 %s: %v", dir, err)
		}
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// decompileAbs 把库里的相对产物目录转成绝对路径，并挡住越界（必须落在 tasks/ 下）。
func (s *Server) decompAbs(rel string) string {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return ""
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || !strings.HasPrefix(clean, "tasks/") {
		return ""
	}
	return filepath.Join(s.decomp.dir, filepath.FromSlash(clean))
}

// decompileFunctions GET /api/decompile/jobs/{jobID}/functions?q=&page=&limit=
func (s *Server) decompileFunctions(w http.ResponseWriter, r *http.Request) {
	j, err := s.decompileJobFromPath(r)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if j.Status != db.DecompileCompleted {
		writeErr(w, 409, "导出还没完成，暂无函数列表")
		return
	}
	idx, err := s.decomp.loadDecompileIndex(j)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var hits []decompileFunc
	for _, f := range idx.Funcs {
		if q != "" && !strings.Contains(strings.ToLower(f.Name), q) && !strings.Contains(strings.ToLower(f.Addr), q) {
			continue
		}
		hits = append(hits, f)
	}
	total := len(hits)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	items := hits[start:end]
	if items == nil {
		items = []decompileFunc{}
	}
	sort.SliceStable(items, func(i, k int) bool { return items[i].Addr < items[k].Addr })
	writeJSON(w, 200, map[string]any{"total": total, "page": page, "limit": limit, "items": items})
}

// decompileCode GET /api/decompile/jobs/{jobID}/code/{addr}
func (s *Server) decompileCode(w http.ResponseWriter, r *http.Request) {
	j, err := s.decompileJobFromPath(r)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	addr := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(r.PathValue("addr"), "0x")))
	if addr == "" {
		writeErr(w, 400, "addr 无效")
		return
	}
	idx, err := s.decomp.loadDecompileIndex(j)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// addr 只在索引里查表，文件名来自 ReadDir，绝不把请求参数拼进路径。
	var hit *decompileFunc
	for i := range idx.Funcs {
		if idx.Funcs[i].Addr == addr {
			hit = &idx.Funcs[i]
			break
		}
	}
	if hit == nil {
		writeErr(w, 404, "没有这个函数")
		return
	}
	abs := s.decompAbs(j.ExportDir)
	if abs == "" {
		writeErr(w, 500, "产物目录非法")
		return
	}
	code, _, truncated, err := readDecompileFile(filepath.Join(codeDir(abs), hit.File))
	if err != nil {
		writeErr(w, 404, "函数文件不存在")
		return
	}
	writeJSON(w, 200, map[string]any{
		"addr": hit.Addr, "name": hit.Name, "code": code, "truncated": truncated,
		"size": hit.Size, "callers": hit.Callers, "callees": hit.Callees,
	})
}

// decompileSearch GET /api/decompile/jobs/{jobID}/search?q=
func (s *Server) decompileSearch(w http.ResponseWriter, r *http.Request) {
	j, err := s.decompileJobFromPath(r)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		writeErr(w, 400, "搜索词至少 2 个字符")
		return
	}
	items, err := s.decomp.searchDecompile(j, q, decompileSearchCap)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	idx, _ := s.decomp.loadDecompileIndex(j)
	for i := range items {
		if a, ok := items[i]["addr"].(string); ok {
			if name := decompileFuncName(idx, a); name != "" {
				items[i]["name"] = name
			}
		}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// decompileLog GET /api/decompile/jobs/{jobID}/log —— 未完成的 job 只能看进度和
// 日志尾部（不给看半成品代码）。读的是 export_dir/idat.log 的尾巴，最多 32KB。
func (s *Server) decompileLog(w http.ResponseWriter, r *http.Request) {
	j, err := s.decompileJobFromPath(r)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	abs := s.decompAbs(j.ExportDir)
	if abs == "" {
		writeErr(w, 400, "产物目录非法")
		return
	}
	text := readLogTail(filepath.Join(abs, "idat.log"), 32<<10)
	writeJSON(w, 200, map[string]any{"status": j.Status, "log": text})
}

// decompileRetry POST /api/decompile/jobs/{jobID}/retry —— 失败/取消的 job 重新排队。
func (s *Server) decompileRetry(w http.ResponseWriter, r *http.Request) {
	j, err := s.decompileJobFromPath(r)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	out, err := s.m.pg.RetryDecompileJob(j.ID)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	s.decomp.kick()
	writeJSON(w, 200, out)
}

// decompileNames GET /api/decompile/jobs/{jobID}/names —— 只回函数名列表。
// 前端用它判断"光标下的标识符是不是可跳转函数"，据此把手型光标打在代码上。
func (s *Server) decompileNames(w http.ResponseWriter, r *http.Request) {
	j, err := s.decompileJobFromPath(r)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if j.Status != db.DecompileCompleted {
		writeJSON(w, 200, map[string]any{"names": []string{}})
		return
	}
	idx, err := s.decomp.loadDecompileIndex(j)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	names := make([]string, 0, len(idx.Funcs))
	for _, f := range idx.Funcs {
		names = append(names, f.Name)
	}
	writeJSON(w, 200, map[string]any{"names": names})
}
