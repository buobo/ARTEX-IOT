package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Autumn-27/artex/db"
)

// 反编译集成（IDA 无头 + INP 导出），见 IOT-AUDIT-反编译集成方案.md。
// 只面向人查阅：不进 agent 工具集、不进 planner 上下文。
const (
	decompileTimeout      = 1800 * time.Second // 默认单 job 上限，可被 decompile_timeout_seconds 覆盖
	decompilePollEvery    = 2 * time.Second    // 进度轮询
	decompileSearchCap    = 200                // search 返回上限
	decompileFileMaxBytes = 2 << 20            // search 单文件上限
	decompileLogTailBytes = 1 << 20            // idat.log 进 server_logs；极端大日志截到 1MB
	decompileIdlePoll     = 10 * time.Second   // 队列空时的兜底轮询（不能只靠 kick，否则进程外插的 pending 会饿死）
)

// decompileConfig 是 decompile_* 这组设置解析后的结果（settings 表里没写的用默认值）。
// 键名见 IOT-AUDIT-反编译集成方案.md §8；系统配置页还没铺这组键，先由 DB 直读。
type decompileConfig struct {
	idaDir     string        // decompile_ida_install_dir，其次 ARTEX_IDA_DIR，最后 PATH 里的 idat
	pluginPath string        // decompile_idat_plugin_path，默认 <ida>/plugins/INP.py
	timeout    time.Duration // decompile_timeout_seconds，默认 1800
	maxComps   int           // decompile_max_components，默认 8
	quotaBytes int64         // decompile_task_quota_mb，默认 2048 MB
}

// decompiler 是进程内队列 + 执行器。并发固定 1：IDA 许可与内存都不允许多实例叠加。
type decompiler struct {
	dir string // data 根目录（绝对路径）
	pg  *db.DB

	mu    sync.Mutex
	procs map[int64]*exec.Cmd // jobID → 正在跑的 idat 进程（取消/重启兜底用）
	wake  chan struct{}

	startOnce sync.Once

	// idat 位置缓存：键是「设置里的目录 + 插件路径」，改设置后自动重找。
	idaMu    sync.Mutex
	idaCache map[string]idaState
}

type idaState struct {
	idat, plugin string
	err          error
}

// config 读 decompile_* 设置并套默认值。读库失败就用默认值（不能因为设置表抖动导不出）。
func (d *decompiler) config() decompileConfig {
	cfg := decompileConfig{
		idaDir:     strings.TrimSpace(os.Getenv("ARTEX_IDA_DIR")),
		timeout:    decompileTimeout,
		maxComps:   8,
		quotaBytes: 2048 << 20,
	}
	if d.pg == nil {
		return cfg
	}
	kv, err := d.pg.SettingsByPrefix("decompile_")
	if err != nil {
		log.Printf("[decompile] 读设置失败，用默认值: %v", err)
		return cfg
	}
	if v := strings.TrimSpace(kv["decompile_ida_install_dir"]); v != "" {
		cfg.idaDir = v
	}
	if v := strings.TrimSpace(kv["decompile_idat_plugin_path"]); v != "" {
		cfg.pluginPath = v
	}
	// 并发键位保留：无论写什么都按 1 跑（IDA 许可不允许多 seat 并发）。
	if n, err := strconv.Atoi(strings.TrimSpace(kv["decompile_concurrency"])); err == nil && n > 1 {
		log.Printf("[decompile] decompile_concurrency=%d 已忽略：并发固定 1（IDA 许可）", n)
	}
	if n, err := strconv.Atoi(strings.TrimSpace(kv["decompile_timeout_seconds"])); err == nil && n >= 60 {
		cfg.timeout = time.Duration(n) * time.Second
	}
	if n, err := strconv.Atoi(strings.TrimSpace(kv["decompile_max_components"])); err == nil && n > 0 && n <= 32 {
		cfg.maxComps = n
	}
	if n, err := strconv.Atoi(strings.TrimSpace(kv["decompile_task_quota_mb"])); err == nil && n > 0 {
		cfg.quotaBytes = int64(n) << 20
	}
	return cfg
}

func newDecompiler(dir string, pg *db.DB) *decompiler {
	// 一律用绝对路径：run() 把 cmd.Dir 设成产物目录，若样本路径是相对的就变成
	// 「cwd + 相对路径」叠两次，idat 找不到输入文件（表现是库初始化失败）。
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return &decompiler{dir: dir, pg: pg, procs: map[int64]*exec.Cmd{},
		wake: make(chan struct{}, 1), idaCache: map[string]idaState{}}
}

// start 做两件事：把上次进程留下的 running 置 failed（进程句柄只在内存，重启即失效），
// 然后起队列循环。只跑一次。
func (d *decompiler) start() {
	d.startOnce.Do(func() {
		if d.pg == nil {
			return
		}
		if n, err := d.pg.ReconcileDecompileJobs(); err != nil {
			log.Printf("[decompile] 启动兜底失败: %v", err)
		} else if n > 0 {
			log.Printf("[decompile] 启动兜底: %d 个中断的导出置为 failed", n)
		}
		go d.loop()
	})
}

// kick 唤醒队列（新建 job 后调用）。非阻塞。
func (d *decompiler) kick() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *decompiler) loop() {
	for {
		if d.pg == nil {
			return
		}
		j, err := d.pg.ClaimNextPendingDecompileJob()
		if err != nil {
			log.Printf("[decompile] 取队列失败: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if j == nil {
			// 队列空：等新建 job 唤醒，但也要定时重扫——服务启动前/外面直接插进
			// 来的 pending 不会有人 kick，纯阻塞会把它饿死。
			select {
			case <-d.wake:
			case <-time.After(decompileIdlePoll):
			}
			continue
		}
		// 单个 job 的 panic 不能带走队列：包一层 recover，把它落成 failed。
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[decompile] job %d panic: %v", j.ID, r)
					_ = d.pg.FinishDecompileJob(j.ID, db.DecompileFailed, fmt.Sprintf("内部错误: %v", r), j.FuncTotal, j.FuncDone)
				}
			}()
			d.run(j)
		}()
	}
}

// cancel 杀掉正在跑这个 job 的进程组。返回 false 表示它不在运行（可能已结束）。
func (d *decompiler) cancel(jobID int64) bool {
	d.mu.Lock()
	cmd := d.procs[jobID]
	d.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return false
	}
	killProcessGroup(cmd)
	return true
}

// locateIDA 找 idat 与 INP 插件：
// decompile_ida_install_dir 设置 → ARTEX_IDA_DIR → PATH 里的 idat；插件路径默认
// <ida>/plugins/INP.py，可用 decompile_idat_plugin_path 覆盖。找不到直接报错（建 job 时 503），
// 不猜安装路径。结果按「目录+插件」缓存，改设置后自动重找。
func (d *decompiler) locateIDA(cfg decompileConfig) (string, string, error) {
	key := cfg.idaDir + "|" + cfg.pluginPath
	d.idaMu.Lock()
	defer d.idaMu.Unlock()
	if st, ok := d.idaCache[key]; ok {
		return st.idat, st.plugin, st.err
	}
	st := idaState{}
	switch {
	case cfg.idaDir != "":
		st.idat = filepath.Join(cfg.idaDir, "idat")
		st.plugin = filepath.Join(cfg.idaDir, "plugins")
	default:
		if p, err := exec.LookPath("idat"); err == nil {
			st.idat = p
			st.plugin = filepath.Join(filepath.Dir(p), "plugins")
		} else {
			st.err = errors.New("找不到 idat：设 decompile_ida_install_dir 或 ARTEX_IDA_DIR 指向 IDA 安装目录，或把 idat 加进 PATH")
			d.idaCache[key] = st
			return "", "", st.err
		}
	}
	pluginScript := cfg.pluginPath
	if pluginScript == "" {
		pluginScript = filepath.Join(st.plugin, "INP.py")
	} else if !filepath.IsAbs(pluginScript) {
		pluginScript = filepath.Join(st.plugin, pluginScript)
	}
	st.plugin = filepath.Dir(pluginScript)
	if _, err := os.Stat(st.idat); err != nil {
		st.err = fmt.Errorf("idat 不存在: %s", st.idat)
	} else if _, err := os.Stat(pluginScript); err != nil {
		st.err = fmt.Errorf("INP 插件缺失: %s", pluginScript)
	}
	d.idaCache[key] = st
	return st.idat, st.plugin, st.err
}

// resolveSource 把「容器内路径」解析成宿主机真实文件。
//
// 唯一依据是 task_scope 里 kind='firmware' 且 extract_path 非空的解包根
// （worker 解包完成后用 register_extract 登记）——不再遍历 i*/rootfs 猜实例。
// 多个解包根里都存在同一路径：内容一致则复用，不一致则报错（无法判断该审计哪份）。
func (d *decompiler) resolveSource(taskID int64, binaryPath string, roots []string) (abs, sha, exportDir string, err error) {
	p := filepath.ToSlash(strings.TrimSpace(binaryPath))
	if p == "" || !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return "", "", "", fmt.Errorf("binary_path 必须是容器内绝对路径（如 /usr/sbin/jhttpd）")
	}
	if len(roots) == 0 {
		return "", "", "", errors.New("本任务还没有登记解包路径：worker 解包完成后需调用 register_extract（落在固件范围的 extract_path 上）")
	}
	taskDir := filepath.Join(d.dir, "tasks", fmt.Sprint(taskID))
	var hits []string
	for _, root := range roots {
		cand := filepath.Join(taskDir, filepath.FromSlash(strings.TrimPrefix(root, "/")), filepath.FromSlash(strings.TrimPrefix(p, "/")))
		if fi, statErr := os.Stat(cand); statErr == nil && fi.Mode().IsRegular() {
			hits = append(hits, cand)
		}
	}
	if len(hits) == 0 {
		return "", "", "", fmt.Errorf("解包根里没有 %s（已查 %d 个登记的解包目录）", p, len(roots))
	}
	abs = hits[0]
	sha, err = fileSHA256Hex(abs)
	if err != nil {
		return "", "", "", err
	}
	for _, other := range hits[1:] {
		if s2, e := fileSHA256Hex(other); e == nil && s2 != sha {
			return "", "", "", fmt.Errorf("%s 在多个解包实例里内容不同（%s vs %s），请先确认要审计哪一个", p, short(abs), short(other))
		}
	}
	return abs, sha, filepath.ToSlash(filepath.Join("tasks", fmt.Sprint(taskID), "decompile", sha[:8])), nil
}

func short(s string) string { return filepath.Base(filepath.Dir(s)) + "/" + filepath.Base(s) }

func fileSHA256Hex(p string) (string, error) {
	f, err := os.Open(p)
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

// decompileRunnerPy 是 idat 的 -S 脚本：等自动分析结束，再让 INP 导出每函数 .c。
// 目录通过环境变量传，避免脚本里拼路径。INP_EXPORT_CTREE=0 在 run() 里固定传。
const decompileRunnerPy = `import os, sys
sys.path.insert(0, os.environ["INP_PLUGIN_DIR"])
import ida_auto
ida_auto.auto_wait()
import INP
INP.do_export(export_dir=os.environ["INP_OUT_DIR"], ask_user=False)
`

// run 执行一个 job：拷样本 → 起 idat → 轮询进度 → 建索引 → 落终态。
func (d *decompiler) run(j *db.DecompileJob) {
	exportAbs := filepath.Join(d.dir, filepath.FromSlash(j.ExportDir))
	outDir := filepath.Join(exportAbs, "out")
	fail := func(msg string, total, done int) {
		log.Printf("[decompile] job %d 失败: %s", j.ID, msg)
		_ = d.pg.FinishDecompileJob(j.ID, db.DecompileFailed, msg, total, done)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fail("创建产物目录失败: "+err.Error(), 0, 0)
		return
	}
	cfg := d.config()
	idat, pluginDir, err := d.locateIDA(cfg)
	if err != nil {
		fail(err.Error(), 0, 0)
		return
	}
	// 样本副本放导出目录：让 idat 的 .i64/.id0 落在这里，不污染 rootfs。
	sample := filepath.Join(exportAbs, "binary")
	if err := copyFile(j.AbsPath, sample); err != nil {
		fail("复制样本失败: "+err.Error(), 0, 0)
		return
	}
	runner := filepath.Join(exportAbs, "runner.py")
	if err := os.WriteFile(runner, []byte(decompileRunnerPy), 0o644); err != nil {
		fail("写 runner.py 失败: "+err.Error(), 0, 0)
		return
	}
	logPath := filepath.Join(exportAbs, "idat.log")
	cmd := exec.Command(idat, "-A", "-L"+logPath, "-S"+runner, sample)
	cmd.Dir = exportAbs
	cmd.Env = append(os.Environ(),
		"INP_EXPORT_CTREE=0", // INP 默认导出 ctree（大 9 倍），必须显式关
		"INP_OUT_DIR="+outDir,
		"INP_PLUGIN_DIR="+pluginDir,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // 取消/超时要杀整个进程组，idat 会带子进程
	// idat 自己的 stdout/stderr 单独留一份：许可、加载器、GUI 这类失败往往只在这里，
	// 不进 -L 日志，排障全靠它。
	outFile, outErr := os.Create(filepath.Join(exportAbs, "idat.out"))
	if outErr == nil {
		cmd.Stdout, cmd.Stderr = outFile, outFile
		defer outFile.Close()
	}
	if err := cmd.Start(); err != nil {
		fail("启动 idat 失败: "+err.Error(), 0, 0)
		return
	}
	d.mu.Lock()
	d.procs[j.ID] = cmd
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.procs, j.ID)
		d.mu.Unlock()
	}()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	timer := time.NewTimer(cfg.timeout)
	tick := time.NewTicker(decompilePollEvery)
	defer tick.Stop()
	defer timer.Stop()
	var done, total int
	for {
		select {
		case <-tick.C:
			done = countCFiles(outDir)
			if n := readProgressProcessed(outDir); n > done {
				done = n // .export_progress 比 .c 文件更早反映进度（个别函数解不出 .c）
			}
			_ = d.pg.UpdateDecompileProgress(j.ID, done, 0)
		case werr := <-waited:
			done = countCFiles(outDir)
			logText := readLogTail(logPath, decompileLogTailBytes)
			if outText := readLogTail(filepath.Join(exportAbs, "idat.out"), 8<<10); outText != "" {
				logText = strings.TrimSpace(logText + "\n[stdout/stderr]\n" + outText)
			}
			if len(logText) > 0 {
				_, _ = d.pg.InsertLog("info", "decompile", fmt.Sprintf("job %d (%s)\n%s", j.ID, j.BinaryPath, logText))
			}
			ok := werr == nil && strings.Contains(logText, "Export completed") && done > 0
			if !ok {
				msg := lastNonEmptyLine(logText)
				switch {
				case werr != nil && msg != "":
					msg = "idat 退出异常: " + werr.Error() + " · " + msg
				case werr != nil:
					msg = "idat 退出异常: " + werr.Error()
				case msg == "":
					msg = "导出失败（idat 日志为空）"
				}
				fail(msg, 0, done)
				return
			}
			if err := buildDecompileIndex(exportAbs, outDir, j.BinaryPath, j.BinarySha256); err != nil {
				fail("建函数索引失败: "+err.Error(), total, done)
				return
			}
			if err := d.pg.FinishDecompileJob(j.ID, db.DecompileCompleted, "", done, done); err != nil {
				log.Printf("[decompile] job %d 落终态失败: %v", j.ID, err)
				return
			}
			log.Printf("[decompile] job %d 完成: %s (%d 个函数)", j.ID, j.BinaryPath, done)
			return
		case <-timer.C:
			killProcessGroup(cmd)
			<-waited
			fail(fmt.Sprintf("超时 %ds，已终止导出", int(cfg.timeout.Seconds())), 0, done)
			return
		}
	}
}

// ---- 函数索引 ----

// decompileFunc 是 index.json 里的一条：地址、符号名、大小、调用关系。
type decompileFunc struct {
	Addr    string   `json:"addr"`
	Name    string   `json:"name"`
	Size    int      `json:"size"`
	Callers []string `json:"callers,omitempty"`
	Callees []string `json:"callees,omitempty"`
	File    string   `json:"file"`
}

type decompileIndex struct {
	Binary  string          `json:"binary"`
	Sha256  string          `json:"sha256"`
	BuiltAt time.Time       `json:"built_at"`
	Funcs   []decompileFunc `json:"functions"`
}

// buildDecompileIndex 解析每个 .c 头部（func-name / func-address / callers / callees），
// 写 index.json。浏览侧只读索引，不扫盘。
func buildDecompileIndex(exportAbs, outDir, binary, sha string) error {
	dir := filepath.Join(outDir, "decompile")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	idx := decompileIndex{Binary: binary, Sha256: sha, BuiltAt: time.Now()}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".c") {
			continue
		}
		fn, err := parseDecompileFunc(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // 单个函数文件坏掉不该让整次导出失败
		}
		idx.Funcs = append(idx.Funcs, fn)
	}
	sort.Slice(idx.Funcs, func(i, k int) bool { return idx.Funcs[i].Addr < idx.Funcs[k].Addr })
	raw, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(exportAbs, "index.json"), raw, 0o644)
}

// parseDecompileFunc 读文件头部的注释块。INP 的格式：
//
//	/*
//	 * func-name: sub_10550
//	 * func-address: 0x10550
//	 * callers: 0x10560, 0x10570    （或 none）
//	 * callees: none
//	 */
func parseDecompileFunc(path string) (decompileFunc, error) {
	f, err := os.Open(path)
	if err != nil {
		return decompileFunc{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return decompileFunc{}, err
	}
	head := make([]byte, 2048)
	n, _ := io.ReadFull(f, head)
	fn := decompileFunc{File: filepath.Base(path), Size: int(fi.Size())}
	fn.Addr = strings.ToUpper(strings.TrimSuffix(filepath.Base(path), ".c"))
	for _, raw := range strings.Split(string(head[:n]), "\n") {
		line := strings.TrimSpace(raw)
		line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
		switch {
		case strings.HasPrefix(line, "func-name:"):
			fn.Name = strings.TrimSpace(strings.TrimPrefix(line, "func-name:"))
		case strings.HasPrefix(line, "func-address:"):
			if a := normAddr(strings.TrimPrefix(line, "func-address:")); a != "" {
				fn.Addr = a
			}
		case strings.HasPrefix(line, "callers:"):
			fn.Callers = splitAddrs(strings.TrimPrefix(line, "callers:"))
		case strings.HasPrefix(line, "callees:"):
			fn.Callees = splitAddrs(strings.TrimPrefix(line, "callees:"))
		}
		if strings.HasSuffix(line, "*/") {
			break
		}
	}
	if fn.Name == "" {
		fn.Name = "sub_" + fn.Addr
	}
	return fn, nil
}

func normAddr(s string) string {
	s = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "0x")))
	if s == "" || s == "none" {
		return ""
	}
	return strings.ToUpper(s)
}

func splitAddrs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "none") {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if a := normAddr(part); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// readDecompileFile 返回一个函数文件的 (函数体, 头注释)。code 去掉头部注释块。
func readDecompileFile(path string) (code, header string, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", false, err
	}
	defer f.Close()
	const capBytes = 512 << 10
	raw := make([]byte, capBytes)
	n, _ := io.ReadFull(f, raw)
	text := string(raw[:n])
	if i := strings.Index(text, "*/"); i >= 0 {
		end := i + 2
		if strings.HasPrefix(text[end:], "\r\n") {
			end += 2
		} else if strings.HasPrefix(text[end:], "\n") {
			end++
		}
		return text[end:], strings.TrimSpace(text[:end]), n >= capBytes, nil
	}
	return text, "", n >= capBytes, nil
}

// ---- 小工具 ----

func codeDir(exportAbs string) string { return filepath.Join(exportAbs, "out", "decompile") }

func countCFiles(outDir string) int {
	entries, err := os.ReadDir(filepath.Join(outDir, "decompile"))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".c") {
			n++
		}
	}
	return n
}

// readProgressProcessed 从 INP 的 .export_progress 数「已处理」函数条数。
// 该文件是逐地址状态表（ADDR|done / ADDR|failed|...），不含总数——总数只有导完才知道，
// 所以运行中 func_total 保持 0，前端显示「已导出 N 个（总数未知）」而不是假进度。
func readProgressProcessed(outDir string) int {
	f, err := os.Open(filepath.Join(outDir, ".export_progress"))
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 32<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}

func readLogTail(path string, limit int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	off := fi.Size() - limit
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return ""
	}
	raw, _ := io.ReadAll(f)
	return string(raw)
}

func lastNonEmptyLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			if len(s) > 300 {
				s = s[:300]
			}
			return s
		}
	}
	return ""
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// loadDecompileIndex 读 job 的 index.json。
func (d *decompiler) loadDecompileIndex(j *db.DecompileJob) (*decompileIndex, error) {
	raw, err := os.ReadFile(filepath.Join(d.dir, filepath.FromSlash(j.ExportDir), "index.json"))
	if err != nil {
		return nil, fmt.Errorf("读不到函数索引：导出可能还没完成，任务也可能已归档（产物随任务目录一起进归档包）: %w", err)
	}
	var idx decompileIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, err
	}
	return &idx, nil
}

// searchDecompile 在当前 job 的 .c 里按行搜（大小写不敏感），上限 decompileSearchCap。
func (d *decompiler) searchDecompile(j *db.DecompileJob, q string, limit int) ([]map[string]any, error) {
	dir := filepath.Join(d.dir, filepath.FromSlash(j.ExportDir), "out", "decompile")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	lq := strings.ToLower(q)
	out := []map[string]any{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".c") {
			continue
		}
		fi, err := e.Info()
		if err != nil || fi.Size() > decompileFileMaxBytes {
			continue
		}
		addr := strings.ToUpper(strings.TrimSuffix(e.Name(), ".c"))
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			text := sc.Text()
			if strings.Contains(strings.ToLower(text), lq) {
				item := map[string]any{"addr": addr, "line": lineNo, "text": strings.TrimSpace(text)}
				out = append(out, item)
				if len(out) >= limit {
					f.Close()
					return out, nil
				}
			}
		}
		f.Close()
	}
	return out, nil
}

// decompileFuncName 在索引里按地址找函数名（search 结果补名字用）。
func decompileFuncName(idx *decompileIndex, addr string) string {
	if idx == nil {
		return ""
	}
	for _, f := range idx.Funcs {
		if f.Addr == addr {
			return f.Name
		}
	}
	return ""
}

// decompileUsage 返回本任务反编译产物已占的字节数（data/tasks/<id>/decompile）。
// 配额判定用；目录不存在按 0 算。
func (d *decompiler) decompileUsage(taskID int64) int64 {
	root := filepath.Join(d.dir, "tasks", strconv.FormatInt(taskID, 10), "decompile")
	var total int64
	_ = filepath.WalkDir(root, func(_ string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		if fi, statErr := e.Info(); statErr == nil {
			total += fi.Size()
		}
		return nil
	})
	return total
}

// dirSizeBytes 统计目录下普通文件总字节数（配额与状态条用）。
func dirSizeBytes(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		if fi, statErr := e.Info(); statErr == nil {
			total += fi.Size()
		}
		return nil
	})
	return total
}

// StopDecompile 在进程退出时杀掉所有在跑的 idat 进程组。
// 不杀会留孤儿 idat 占着 IDA 许可；下次启动虽把 job 置 failed，但机器上多一个隐形实例。
func (s *Server) StopDecompile() {
	if s == nil || s.decomp == nil {
		return
	}
	s.decomp.stopAll()
}

func (d *decompiler) stopAll() {
	d.mu.Lock()
	cms := make([]*exec.Cmd, 0, len(d.procs))
	for _, c := range d.procs {
		cms = append(cms, c)
	}
	d.mu.Unlock()
	for _, c := range cms {
		killProcessGroup(c)
	}
}
