package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// DecompileJob is one IDA headless export of a single binary. Artifacts live in
// data/tasks/<task_id>/decompile/<sha8>/; see IOT-AUDIT-反编译集成方案.md §4.
//
// One job per binary, keyed by (task_id, binary_sha256): clicking twice never
// creates a second job, and a component upgrade (different sha) is a new job.
type DecompileJob struct {
	ID           int64  `json:"id"`
	TaskID       int64  `json:"task_id"`
	ComponentID  *int64 `json:"component_id,omitempty"`
	BinaryPath   string `json:"binary_path"`
	BinarySha256 string `json:"binary_sha256"`
	AbsPath      string `json:"abs_path"`
	ExportDir    string `json:"export_dir"`
	Status       string `json:"status"`
	FuncTotal    int    `json:"func_total"`
	FuncDone     int    `json:"func_done"`
	Error        string `json:"error,omitempty"`
	CreatedBy    string `json:"created_by,omitempty"`
	// TaskName 不是表字段：列表接口按 task_id 回填，供界面显示任务名（重名时前端再加编号）。
	TaskName   string     `json:"task_name,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// Decompile job statuses. pending → running → completed / failed / canceled.
const (
	DecompilePending   = "pending"
	DecompileRunning   = "running"
	DecompileCompleted = "completed"
	DecompileFailed    = "failed"
	DecompileCanceled  = "canceled"
)

const decompileCols = `id, task_id, component_id, binary_path, binary_sha256, abs_path,
  export_dir, status, func_total, func_done, error, created_by, created_at, started_at, finished_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanDecompileJob(sc rowScanner) (*DecompileJob, error) {
	var (
		j   DecompileJob
		cid sql.NullInt64
		sa  sql.NullTime
		fa  sql.NullTime
	)
	if err := sc.Scan(&j.ID, &j.TaskID, &cid, &j.BinaryPath, &j.BinarySha256, &j.AbsPath,
		&j.ExportDir, &j.Status, &j.FuncTotal, &j.FuncDone, &j.Error, &j.CreatedBy,
		&j.CreatedAt, &sa, &fa); err != nil {
		return nil, err
	}
	if cid.Valid {
		v := cid.Int64
		j.ComponentID = &v
	}
	if sa.Valid {
		v := sa.Time
		j.StartedAt = &v
	}
	if fa.Valid {
		v := fa.Time
		j.FinishedAt = &v
	}
	return &j, nil
}

// GetDecompileJob returns one job by id.
func (d *DB) GetDecompileJob(id int64) (*DecompileJob, error) {
	return scanDecompileJob(d.QueryRowContext(context.Background(),
		`SELECT `+decompileCols+` FROM decompile_jobs WHERE id=$1`, id))
}

// GetDecompileJobBySha finds the job of this task for the same binary content.
// Used to reuse an existing export instead of queueing a duplicate.
func (d *DB) GetDecompileJobBySha(taskID int64, sha string) (*DecompileJob, error) {
	return scanDecompileJob(d.QueryRowContext(context.Background(),
		`SELECT `+decompileCols+` FROM decompile_jobs WHERE task_id=$1 AND binary_sha256=$2`,
		taskID, sha))
}

// ListDecompileJobs returns a task's jobs newest-first; taskID<=0 means all tasks.
func (d *DB) ListDecompileJobs(taskID int64, status string) ([]*DecompileJob, error) {
	q := `SELECT ` + decompileCols + ` FROM decompile_jobs WHERE ($1=0 OR task_id=$1)`
	args := []any{taskID}
	if status != "" {
		q += ` AND status=$2`
		args = append(args, status)
	}
	q += ` ORDER BY id DESC LIMIT 500`
	rows, err := d.QueryContext(context.Background(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DecompileJob
	for rows.Next() {
		j, err := scanDecompileJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// CreateOrReuseDecompileJob inserts a job, or returns the existing one for the
// same (task_id, binary_sha256). A failed/canceled export is reset to pending so
// clicking again retries it; completed/running/pending are returned untouched.
// reused reports whether an existing row was returned.
func (d *DB) CreateOrReuseDecompileJob(j *DecompileJob) (out *DecompileJob, reused bool, err error) {
	old, gerr := d.GetDecompileJobBySha(j.TaskID, j.BinarySha256)
	switch {
	case gerr == nil:
		// Keep the original 路径/产物目录（同一个 sha 就一定是同一份内容，产物也能复用）。
		old.BinaryPath = j.BinaryPath
		if old.Status == DecompileFailed || old.Status == DecompileCanceled {
			if _, uerr := d.ExecContext(context.Background(), `UPDATE decompile_jobs
SET status='pending', error='', func_total=0, func_done=0, started_at=NULL, finished_at=NULL,
    binary_path=$2, abs_path=$3, export_dir=$4, component_id=$5
WHERE id=$1`, old.ID, j.BinaryPath, j.AbsPath, j.ExportDir, j.ComponentID); uerr != nil {
				return nil, false, uerr
			}
			old.Status, old.Error, old.FuncTotal, old.FuncDone = DecompilePending, "", 0, 0
			old.StartedAt, old.FinishedAt = nil, nil
			old.AbsPath, old.ExportDir, old.ComponentID = j.AbsPath, j.ExportDir, j.ComponentID
			// 重新排队了，不是"复用已有结果"——调用方要立刻唤醒队列。
			return old, false, nil
		}
		return old, true, nil
	case !errors.Is(gerr, sql.ErrNoRows):
		return nil, false, gerr
	}
	row := d.QueryRowContext(context.Background(), `INSERT INTO decompile_jobs
    (task_id, component_id, binary_path, binary_sha256, abs_path, export_dir, status, created_by)
VALUES ($1,$2,$3,$4,$5,$6,'pending',$7) RETURNING `+decompileCols,
		j.TaskID, j.ComponentID, j.BinaryPath, j.BinarySha256, j.AbsPath, j.ExportDir, j.CreatedBy)
	created, err := scanDecompileJob(row)
	if err != nil {
		return nil, false, err
	}
	return created, false, nil
}

// ClaimNextPendingDecompileJob takes the oldest pending job and marks it running.
// Returns (nil, nil) when the queue is empty.
func (d *DB) ClaimNextPendingDecompileJob() (*DecompileJob, error) {
	row := d.QueryRowContext(context.Background(), `UPDATE decompile_jobs
SET status='running', started_at=now(), error='', func_done=0
WHERE id = (SELECT id FROM decompile_jobs WHERE status='pending' ORDER BY id LIMIT 1)
RETURNING `+decompileCols)
	j, err := scanDecompileJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return j, err
}

// UpdateDecompileProgress records the number of exported .c files.
func (d *DB) UpdateDecompileProgress(id int64, done, total int) error {
	_, err := d.ExecContext(context.Background(),
		`UPDATE decompile_jobs SET func_done=$2, func_total=$3 WHERE id=$1 AND status='running'`,
		id, done, total)
	return err
}

// FinishDecompileJob moves a job to a terminal state. NOTE: a failed export still
// keeps its artifacts (partial .c set) — the row says failed, the files stay.
func (d *DB) FinishDecompileJob(id int64, status, errText string, total, done int) error {
	_, err := d.ExecContext(context.Background(), `UPDATE decompile_jobs
SET status=$2, error=$3, func_total=$4, func_done=$5, finished_at=now(), started_at=COALESCE(started_at, now())
WHERE id=$1`, id, status, errText, total, done)
	return err
}

// ReconcileDecompileJobs is the startup guard: any job left 'running' by a dead
// process is marked failed (the child process handle is memory-only, so "no
// process" is decided by the fact that this process just started).
func (d *DB) ReconcileDecompileJobs() (int64, error) {
	res, err := d.ExecContext(context.Background(), `UPDATE decompile_jobs
SET status='failed', error=CASE WHEN error='' THEN 'interrupted: 服务重启，导出中断' ELSE error END,
    finished_at=now()
WHERE status='running'`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteDecompileJob removes the row and returns it so the caller can clean the
// artifact directory it points at.
func (d *DB) DeleteDecompileJob(id int64) (*DecompileJob, error) {
	row := d.QueryRowContext(context.Background(),
		`DELETE FROM decompile_jobs WHERE id=$1 RETURNING `+decompileCols, id)
	return scanDecompileJob(row)
}

// DecompileJobsByTaskCount returns how many jobs a task has and how much disk
// its exports claim (sum of completed function counts is not bytes; callers that
// need bytes stat the directories themselves).
func (d *DB) DecompileJobsByTaskCount(taskID int64) (int, error) {
	var n int
	err := d.QueryRowContext(context.Background(),
		`SELECT count(*) FROM decompile_jobs WHERE task_id=$1`, taskID).Scan(&n)
	return n, err
}

// ComponentInfo is the minimal component identity the decompile API needs:
// its display name (for error messages) and the container-internal binary path.
type ComponentInfo struct {
	ID         int64
	Name       string
	BinaryPath string
}

// TaskComponentsForDecompile returns identity info for the given component ids,
// but only those that belong to this task (task_ids array guard).
func (s *ComponentStore) TaskComponentsForDecompile(taskID int64, ids []int64) ([]ComponentInfo, error) {
	rows, err := s.db.QueryContext(context.Background(), `
SELECT id, COALESCE(component_name,''), COALESCE(binary_path,'')
FROM components
WHERE $1 = ANY(task_ids) AND id = ANY($2)`, taskID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComponentInfo
	for rows.Next() {
		var c ComponentInfo
		if err := rows.Scan(&c.ID, &c.Name, &c.BinaryPath); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RetryDecompileJob 把 failed/canceled 的 job 重新排回 pending（保留产物目录，
// INP 会跳过已导出的 .c，所以重试是续跑而不是重头来）。completed 不允许重试。
func (d *DB) RetryDecompileJob(id int64) (*DecompileJob, error) {
	row := d.QueryRowContext(context.Background(), `UPDATE decompile_jobs
SET status='pending', error='', func_total=0, func_done=0, started_at=NULL, finished_at=NULL
WHERE id=$1 AND status IN ('failed','canceled') RETURNING `+decompileCols, id)
	j, err := scanDecompileJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("只有 failed / canceled 的导出可以重试")
	}
	return j, err
}

// TaskNames 批量取任务名（反编译列表按任务分组显示用）。id 不存在的不返回，
// 调用方按空串处理即可。
func (d *DB) TaskNames(ids []int64) (map[int64]string, error) {
	out := map[int64]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := d.QueryContext(context.Background(), `SELECT id, name FROM tasks WHERE id = ANY($1)`, ids)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return out, err
		}
		out[id] = name
	}
	return out, rows.Err()
}
