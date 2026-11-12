# 反编译集成方案（IDA 无头 + INP 导出）

面向人的只读能力：把固件里的二进制交给 IDA 无头导出每函数 `.c`，在 Web 里按任务/组件浏览、搜索、跳转。
**不进 Agent 工具集，不进 planner 上下文**，纯人工查阅。

---

## 1. 实测前提（2026-11-11 本机验证）

| 项 | 结果 |
|---|---|
| `/home/david/tools/ida/idat` | IDA Pro 9.2，`-A -L -S` 无头可用 |
| 探测脚本 | `idat -A -Lidat.log -Sprobe.py ./true.bin` → exit 0，打印 `IDA_OK 9.2` |
| INP 加载 | IDA 启动自动加载，日志有 `[-] Export for AI plugin unloaded` |
| `INP.do_export` | `/bin/true` 实跑成功，产物 `out/decompile/<地址>.c` + `.export_progress` |
| 体量参照 | batch19_ac15：1403 个 `.c` = 6.0 MB；ctree 单列 55 MB —— **不导出** |
| 磁盘 | `/home` 可用 704 GB |

关键事实：`idat` 子进程模式足够，不需要 idalib、不需要 Python 桥；导出按函数地址一文件，头部自带 `func-name / func-address / callers / callees`。

---

## 2. 架构：两条独立链路

```
导出侧（异步写）
  按钮 → 建 job(pending) → 队列(并发1) → idat 子进程 → 产物落盘 → 后处理建索引

浏览侧（同步只读）
  反编译页 → 函数列表(index.json) → 取单个 .c → 高亮渲染 → callers/callees 跳转
```

HTTP 请求里绝不等 IDA。5 MB 的 httpd 导出通常几分钟，必须异步 + 进度。

---

## 3. 存储布局

```
data/tasks/<task_id>/decompile/
  <binary_sha8>/
    binary                  分析用样本副本（避免 .i64 落进 rootfs）
    idat.log                idat -L 日志
    out/decompile/*.c       INP 产物（文件名 = 函数地址，如 10550.c）
    out/.export_version     格式版本，变了 INP 会全量重导
    out/.export_progress    断点续跑用
    index.json              我方后处理生成：函数索引 + 反向 xref
```

按 **binary sha256 前 8 位** 分目录：同一任务里多个组件指向同一二进制（如 `smbd`/`nmbd`、多实例同文件）只导一次。

### binary_path 解析

`components.binary_path` 是**容器内路径**（`/usr/sbin/jhttpd`），不是宿主机路径：
解析依据 = `task_scope` 里 `kind='firmware'` 且 `extract_path` 非空的解包根
（worker 解包完成后用 `register_extract` 登记，落在固件范围的那一列上）。

```
roots = select extract_path from task_scope where task_id=<id> and kind='firmware' and extract_path<>''
for root in roots:
    candidate = data/tasks/<task_id>/<root> + binary_path
    存在 → 计算 sha256 → 命中
一个 root 都没登记        → 400：先完成解包并 register_extract
多个 root 命中、sha 相同  → 用第一个（复用同一导出）
多个 root 命中、sha 不同  → 报错让人选（不猜用哪一份）
```

不再遍历 `i*/rootfs` 猜实例：解包目录由 worker 登记、平台可查，猜出来的路径
既可能指错实例，也无法解释"为什么是这个目录"。

---

## 4. 数据表

新增一张表，不改现有表结构：

```sql
CREATE TABLE decompile_jobs (
  id            BIGSERIAL PRIMARY KEY,
  task_id       BIGINT NOT NULL,
  component_id  BIGINT,                 -- 触发它的组件，可为空（按路径直导）
  binary_path   TEXT NOT NULL,          -- 容器内路径
  binary_sha256 TEXT NOT NULL,
  abs_path      TEXT NOT NULL,          -- 实际分析的文件
  export_dir    TEXT NOT NULL,          -- data/tasks/<id>/decompile/<sha8>
  status        TEXT NOT NULL DEFAULT 'pending',  -- pending/running/completed/failed/canceled
  func_total    INT NOT NULL DEFAULT 0,
  func_done     INT NOT NULL DEFAULT 0,
  error         TEXT NOT NULL DEFAULT '',
  created_by    TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at    TIMESTAMPTZ,
  finished_at   TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_decompile_jobs_v1 ON decompile_jobs (task_id, binary_sha256);
```

唯一键的作用：重复点击不产生第二个 job；已完成的直接复用，失败的允许重试（`status` 回 pending）。

### 字段说明

| 字段 | 含义 | 谁写、什么时候写 |
|---|---|---|
| `id` | job 主键。API 里所有 `/api/decompile/jobs/{jobID}` 的 `jobID` 就是它，前端轮询/取消/删除都按这个定位 | DB 自增，建 job 时生成 |
| `task_id` | 归属任务。一物三用：拼产物根目录 `data/tasks/<task_id>/decompile/`、任务详情页列表只查自己任务、任务删除时按它清产物 | 建 job 时（入口必带任务上下文） |
| `component_id` | 触发这次导出的组件 `components.id`。**可为空**：走「按路径直导」入口时没有组件，或组件事后被删。本表不对 `components` 建外键——删组件不该连带删掉已经导出的产物。只用于展示与回跳组件行，**不参与任何路径计算** | 建 job 时，从勾选的组件带过来 |
| `binary_path` | **容器内**路径（`/usr/sbin/jhttpd`），人认的那份标识。不能直接拿去 `open`——它是解析 `abs_path` 的输入之一 | 建 job 时，取 `components.binary_path` 或手填 |
| `binary_sha256` | 真实分析样本的内容哈希。唯一键的一半：同任务内同内容二进制（`smbd`/`nmbd`、多实例指向同一文件）只导一次；也是判断「组件升级后要不要重导」的唯一依据（sha 变了就是新 job） | 解析阶段算一次，之后只读 |
| `abs_path` | 解析出来的**宿主机真实文件**（`data/tasks/<id>/<extract_path>` + `binary_path`）。执行时先 `cp` 到 `export_dir/binary` 再交给 idat；留库是为了事后能看出当时分析的到底是哪个实例的哪份文件 | 解析阶段 |
| `export_dir` | 产物目录（相对 data 根），`data/tasks/<id>/decompile/<sha8>`。DELETE job 时删它，P2 任务删除时也按它清 | 建 job 时按 sha 前 8 位生成 |
| `status` | 状态机：`pending` → `running` → `completed` / `failed` / `canceled`。启动兜底把「`running` 但进程已不存在」置 `failed`；重试把 `failed` 改回 `pending`；取消置 `canceled`（产物保留） | 队列状态机，唯一权威 |
| `func_total` | 该二进制应导出的函数总数。完成时 = 磁盘上 `.c` 的个数；运行中先读 `out/.export_progress` 补齐，读不到先填 0（前端进度条退化为不确定态，不至于显示 100%） | 运行中随进度更新，收尾时校正 |
| `func_done` | 已落盘的 `.c` 个数。每 2 秒数一次目录刷新；只在 `running` 时变化。`completed` 后它与 `func_total` 应一致，但失败判据只看 `func_done = 0`，不看两者不等（导出可能因个别函数失败而少几个，不算 job 失败） | 进度轮询 |
| `error` | 失败原因**摘要一行**（如 `exit 1: INP not loaded`）。全文在 `export_dir/idat.log`，并已进 `server_logs`；置 `failed` 时写，重试时清空 | 失败判定时 |
| `created_by` | 触发人（登录用户名）。多人排队时区分谁占的队，出错时知道找谁；空串表示系统/后台触发 | 建 job 时从会话取 |
| `created_at` | 建 job 时间。列表默认按它倒序，也是配额统计（`task_quota_mb`）的基准 | DB 默认 `now()` |
| `started_at` | 真正开始跑的时间（`status` 置 `running` 那刻）。`NULL` = 还在队列里没轮到，前端据此显示「排队中」而不是「导出中」 | 队列取到 job 时 |
| `finished_at` | 进入终态（`completed`/`failed`/`canceled`）的时间。和 `started_at` 相减即这次导出耗时，用于校准「单个二进制 1–10 分钟」的预期 | 进入终态时 |

### 刻意不设的字段

- **进度百分比**：`func_done / func_total` 算得出来，落库必然出现「存的值和目录里的文件数不一致」。
- **ctree 路径与开关**：已定不导出（见第 5 章 env），没有产物就不需要字段。
- **pid / pgid**：进程句柄只在内存，重启即失效；重启兜底靠「`status=running` 且进程不存在」判断，不靠 pid。
- **样本副本路径**（`export_dir/binary`）：可由 `export_dir` 拼出，不重复存。

---

## 5. 作业执行细节

进程内队列，并发固定 1（IDA 许可与内存都不允许多实例叠加）：

```
取 job → status=running, started_at
准备   → cp <abs_path> <export_dir>/binary
执行   → idat -A -L<export_dir>/idat.log -S<runner.py> <export_dir>/binary
         runner.py: ida_auto.auto_wait() → import INP → do_export(out, ask_user=False)
进度   → 每 2s 数 out/decompile/*.c 个数 → func_done；读 .export_progress 补总数
收尾   → 解析每个 .c 头部 → index.json → status=completed
```

要点：

- **超时**默认 1800s，`context.WithTimeout`；超时/取消用 `kill(-pgid, SIGKILL)` 杀进程组（idat 有子进程，只杀父进程会留孤儿）
- **失败判定**三条任一：进程非 0 退出 / 日志无 `Export completed` / `func_done = 0`
- **env**：固定 `INP_EXPORT_CTREE=0`。INP.py 里 `CTREE_EXPORT_ENABLED` 的默认值是开（`os.environ.get("INP_EXPORT_CTREE", "1")`），所以**必须显式传 0**，不是"关掉一个本来关着的东西"。产物只留 `out/decompile/*.c`，不产出 `ctree/`（大 9 倍，本期不需要，不做开关）
- **日志**：idat.log 全文进 `server_logs`；job 表只留最后一行错误摘要
- **重启兜底**：服务启动时把 `running` 但进程不存在的 job 置 `failed`
- **取消**：杀进程组，状态 `canceled`，产物保留，可手动 DELETE 清理

---

## 6. API

沿用 PoC 那套 REST 风格（参考 `server/task_components.go`）：

```
POST   /api/tasks/{id}/decompile                {component_ids:[...]} | {binary_path}
                                                → {jobs:[{id, component_id, status}]}
GET    /api/tasks/{id}/decompile/jobs           → 任务内 job 列表（含进度）
GET    /api/decompile/jobs?task_id=&status=     → 全局列表（反编译页左树用）
GET    /api/decompile/jobs/{jobID}              → 单 job 详情 + 进度
POST   /api/decompile/jobs/{jobID}/cancel
POST   /api/decompile/jobs/{jobID}/retry       → failed/canceled 重新排队（已导出的 .c 会跳过，续跑）
DELETE /api/decompile/jobs/{jobID}              → 删记录 + 删 export_dir（二次确认）

GET    /api/decompile/jobs/{jobID}/functions?q=&page=&limit=
                                                → {total, items:[{addr,name,size,callers,callees}]}
GET    /api/decompile/jobs/{jobID}/code/{addr}  → {addr,name,code,callers,callees,truncated}
GET    /api/decompile/jobs/{jobID}/search?q=    → [{addr,name,line,text}]（上限 200 条）
GET    /api/decompile/jobs/{jobID}/log          → {status, log}（idat.log 尾部 32KB，未完成时看进度用）
```

约束：

- 鉴权全部走现有 `requireAuth`
- `binary_path` 必须解析到 `data/tasks/<id>/` 之内，越界直接 400
- `code/{addr}` 的 addr 只作为十六进制 key 查 `index.json`，**不拼文件路径**（杜绝路径穿越）
- `functions` / `code` 读索引，不扫盘；`search` 才扫 `.c`，单文件 2 MB 上限

---

## 7. 前端改动

### 7.1 任务详情「测试组件」页签（第 8 个 tab）

#### 工具条右侧

```
[已选 2] [全选本页] [清空] [改状态为… ▾] [应用] [删除选中]  |  [导出反编译]
```

- 勾选组件后可用；`binary_path` 为空的组件置灰 + Tooltip「该组件未登记二进制路径」
- 点击弹确认框：组件名 + 容器路径 + 解析出的宿主机路径 + 产物目录，注明「IDA 导出，单个二进制通常 1–10 分钟」
- 提交后工具条就地变进度：`jhttpd 导出中 342/1180`，2 秒轮询 `GET /api/tasks/{id}/decompile/jobs`
- 已完成的组件行：行内按钮变绿色完成态（title 显示已导出函数数）；「查看反编译」跳转随 P1 的反编译页一起接

#### 表格行内（第 7 列，与「从本任务移除」图标并排）

该列现在只有一个 ghost 图标按钮（`UnlinkIcon`，title「从本任务移除（不删组件本身）」）。在它**左侧**再加一枚同规格的导出按钮：

```
... [状态] │ [⤓ 导出] [🔗 移除] │
```

- 图标按钮，`variant="ghost"` `size="icon"` `size-7`，title 写「导出反编译」；与移除按钮同视觉权重，不加文字标签
- 操作列宽从 `w-10` 调到 `w-16`（两枚 28px 图标 + gap），否则第二个按钮会挤出单元格
- `binary_path` 为空时 `disabled`，title 换成「该组件未登记二进制路径」——与工具条同一套禁用条件
- 语义是**只导这一个组件**：不依赖勾选、不受 `max_components`（8）限制；打同一个接口，body `{component_ids:[id]}`，一个组件一个 job
- 点击后按钮就地变 spinner，2 秒轮询；按 job 状态换形态：`pending` → 「排队中」、`running` → 「342/1180」（列窄，数字放 title 里，不撑破行高）、`completed` → 换「查看反编译」跳反编译页并定位 job、`failed` → 红色，title 带 `error` 摘要，再点即重试（`status` 回 pending）
- 该组件已有 `completed` job 时点击不建新 job：唯一键 `(task_id, binary_sha256)` 撞上直接复用，前端直接跳转
- 工具条与行内是**两条入口、一套后端**：工具条批量、行内单发；重复点击都落在同一个唯一键上，不会产生第二个 job

### 7.2 新增页面 `/(main)/function/decompile`

入口两处：侧栏 function 组（放在「组件」之后）+ 顶部 header 按钮（只做链接，不重复实现）。

三栏布局：

```
┌ 左：任务/组件树 ─┬ 中：函数列表 ──────────┬ 右：代码面板 ───────────┐
│ 任务A            │ 搜索框 [sub_1A2C]      │ /* func-name: sub_10550 */│
│  └ jhttpd ✓      │ 0x10550 sub_10550 4.2K │ 行号 + C 高亮             │
│  └ telnetd ⟳ 30% │ 0x10174 sub_10174 1.1K │ callers 可点击            │
│ 任务B            │ …（虚拟滚动）          │ callees 可点击            │
└──────────────────┴────────────────────────┴───────────────────────────┘
```

- 代码面板复用 PoC 弹框那套词法器（`poc-tab.tsx`），关键字表补 C（`if/else/for/while/switch/return/void/int/char/unsigned/struct/typedef/sizeof/goto/static/extern`），行号栏、行 hover、复制/下载照搬
- 点 callers/callees 的地址 → 切到该函数，面包屑保留返回栈
- 顶部状态条：`已完成 · 1180 个函数 · 2026-11-11 18:40 · 6.0 MB`
- 未完成的 job 点进去只显示进度 + 日志尾部，不给看半成品

---

## 8. 配置项（系统配置新增 `decompile_*` 一组）

| 键 | 默认 | 说明 |
|---|---|---|
| `ida_install_dir` | 无默认值 | 读取顺序：`decompile_ida_install_dir` 设置 → `ARTEX_IDA_DIR` 环境变量 → `PATH` 里的 `idat`（不写死安装路径）；找到后要求同目录有 `plugins/INP.py`。找不到时建 job 直接报错（503，文案说明这三种办法）。设置页已铺这组键，并回显 `decompile_status`（idat 是否真的可用） |
| `idat_plugin_path` | `<ida>/plugins/INP.py` | 插件缺失则拒绝导出 |
| `concurrency` | `1` | 写死 1，键位保留：设成 >1 只打日志警告、不生效（IDA 许可） |
| `timeout_seconds` | `1800` | 单 job 上限 |
| `max_components` | `8` | 单次勾选上限 |
| `task_quota_mb` | `2048` | `data/tasks/<id>/decompile` 已占 ≥ 配额时拒绝新建 job（429） |

---

## 9. 分期

```
P0 能导出   表 + 队列 + 3 个 job 接口 + 测试组件页两个入口（工具条批量 / 行内单发）+ 极简列表（纯文本代码）
P1 能看     反编译页三栏 + C 高亮 + 函数搜索 + callers/callees 跳转
P2 好维护   取消/删除/配额/重启兜底/失败重试/任务删除联动清产物
```

P0–P2 已全部落地。额外补的两处：队列空转时 10s 兜底重扫（进程外插入的 pending
不会因为没人 kick 而饿死）；进程退出时杀掉在跑的 idat 进程组（否则孤儿进程占着许可）。

ctree 不导出（已定，见第 5 章 env）；P0 不做全局搜索、不做跨任务视图。

---

## 10. 已拍板（4 点，2026-11-12 定）

| # | 问题 | 决定 |
|---|---|---|
| 1 | 产物放任务内还是全局 | **任务内** `data/tasks/<id>/decompile/`，跟归档/删除/备份联动 |
| 2 | 导出单位：每二进制一个 job，还是整任务一次全导 | **每个二进制一个 job**，排队跑（并发 1） |
| 3 | ctree 要不要 | **不要**：不导出 ctree，不做开关，env 固定 `INP_EXPORT_CTREE=0` |
| 4 | 反编译页入口：只侧栏，还是侧栏 + header 按钮 | **两处都做**：侧栏入口 + header 按钮，header 只做链接 |

四条全部按原建议落定，无改动项；实现按第 9 章 P0 开始。

---

## 11. 风险与边界

- **IDA 许可**：并发写死 1，避免多 seat 冲突；若以后要并行需先确认许可数目
- **大二进制**：`jhttpd` 这类 5 MB 程序导出可能 10 分钟以上，进度必须可见，否则用户会以为卡死
- **符号缺失**：多数函数是 `sub_XXXX`，人读价值有限；后续可接函数指纹/字符串/调用链排序提高命中率（本期不做）
- **磁盘**：单固件约 6 MB（只导 `.c`，不导 ctree），配额按此估算
- **产物孤儿**：任务删除时需联动清理 `decompile/`（安排在 P2，P0 先手动 DELETE job）
- **不进 Agent**：不注册成 tool、不写进 planner 上下文，避免污染 token 与规划

---

## 12. 验收方式

```
1. 组件表挑一个 binary_path 非空的组件（如 jhttpd /usr/sbin/jhttpd）
2. 测试组件页勾上 → 工具条「导出反编译」→ 观察进度从 0 递增
2b. 不勾选，直接点行内「⤓ 导出」→ 同样建一个 job，两枚按钮状态同步（同组件只有一个 job）
3. 查库：SELECT id,status,func_total,func_done,error FROM decompile_jobs ORDER BY id DESC;
4. 落盘：ls data/tasks/<task_id>/decompile/<sha8>/out/decompile | wc -l  == func_total
5. 反编译页打开 → 函数列表可搜 → 点开代码有高亮 → callers/callees 能跳
6. 取消链路：新 job 点取消 → 进程消失（ps 无 idat）→ status=canceled
7. 越界防护：`binary_path` 带 `..` 或不是绝对路径 → 400；`/etc/passwd` 只解析到**固件 rootfs 内**的同名文件（不碰宿主机），IDA 分析它会失败并给明确原因
```
