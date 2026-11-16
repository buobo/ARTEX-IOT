# 单条漏洞产物导出（一个 finding 一个压缩包）设计

> 状态：**已按本方案实现**（后端 + 前端已写完并通过编译，未部署、未跑测试）· 2026-11-16
> 拍板要点：批量与单条共用一套接口；批量用「嵌套 zip」（每条 finding 一个独立 zip）；不做 PoC 覆盖缓解。

## 1. 目标

1. 每条 finding 后面有「下载」按钮，弹框列出**这条 finding 当前真实可用**的产物，勾选后打包下载。
2. **一个 finding 一个压缩包**：包内只包含这条 finding 自己的产物，绝不混入其它 finding 的内容。
3. 批量导出保留现有四种格式（md-single / md-zip / csv / json）一行不改；另外新增「全产物 zip」，同样是**每条 finding 一个独立 zip**（外层再套一个 zip 收纳）。
4. 三个界面都放按钮：findings 列表、任务详情的 findings tab、finding 详情页；三处共用同一个弹框与同一套接口。

## 2. 非目标

- 不做 Word/PDF 报告（只有 markdown）。
- 不做 PoC 内容隔离/快照（同名覆盖问题按用户决定不处理，见 §7.2）。
- 不做 zip 缓存、断点续传、体积拦截（只在弹框里红字提示）。
- 不新增路由、不新增数据库列、不做数据迁移。

## 3. 现状：能复用什么（带出处）

| 能力 | 现状 | 出处 |
| --- | --- | --- |
| 导出入口 | `GET /api/exploration/findings/export`，已有 `scope=selected|filtered|all` + `ids=` + `format=md-single|md-zip|csv|json` | `server/server.go:2212` |
| zip 出口 | `writeFindingsEvidenceZip` / `writeFindingsZipEntries`（每条 finding 的 md + 流量 request/response） | `server/finding_traffic_export.go:22`、`:31` |
| 流量 body | `evidence.New(...).OpenBody(b.Snapshot, side)` | `server/finding_traffic_export.go:52` |
| 报告命名 | `report.FindingFilename(f)` | `report/findings.go:126` |
| finding 字段 | `report`（markdown，可空）、`evidence`、`poc_files`（JSONB） | `db/schema.sql:1218`（report :1238、poc_files :1232） |
| PoC 物理路径 | `<data>/tasks/<taskID>/poc/<裸文件名>`；`poc_files` 自本次改动起**恒为裸文件名** | `agent/tools_insert.go:948`（`pocDir`） |
| 复现视频 | `RetestRecordingsForFinding(findingID)`，已按 `discarded_at IS NULL` 过滤 | `db/finding_retests.go:515` |
| 前端下载样板 | `exportFindings`（blob + 从 `Content-Disposition` 取文件名） | `web/src/lib/api.ts:701` |
| 行按钮位 | findings 列表 `:296–337`；任务详情 findings tab `:88–124` | `web/src/app/(main)/function/findings/_components/findings-table.tsx`、`.../tasks/detail/_tabs/findings-tab.tsx` |
| 批量导出菜单 | `page.tsx:286`（`format` 联合类型所在处） | `web/src/app/(main)/function/findings/page.tsx` |

结论：**打包、清单、下载三步都能挂在现有 export 路由上**，单条只是 `ids` 里一个元素；差异只在新 format 与产物集合。

## 4. 交互：弹框（三个入口共用一个组件）

打开即拉清单（不下载内容），每项一行：

```
☑ 报告文档    report.md · 12.4 KB
☑ PoC 脚本    2 个：softcenter_proxy_unauth_rce.py、probe.sh
☑ 复现视频    2 段 · 41.2 MB（已丢弃的段不出现，也不提示丢弃数）
☐ 流量证据    3 组 request/response · 180 KB
☑ 证据文本    evidence.md · 3.1 KB
────────────────────────────────
合计 41.4 MB                       [ 打包下载 ]
```

- 默认全选可用项；不可用项置灰并在右侧写原因：「尚未生成报告」「文件已丢失」「无复现视频」「无流量绑定」。
- 底部：合计体积 + 「打包下载」；单项缺失不影响整体，缺失项直接不进包（不产生空目录）。
- 体积超过 500 MB 时红字提示，不拦截。
- 永远返回 zip（不做「只勾一个文件就直发」的分支）。

入口：

1. findings 列表行按钮（`findings-table.tsx` 行按钮组）——该组件被「平铺视图」与「按任务分组视图」共用，加一次两个视图都有。
2. 任务详情 → findings tab 行按钮（`findings-tab.tsx`）。
3. finding 详情页右上角（`web/src/app/(main)/function/findings/detail/page.tsx`）。
4. 批量导出菜单新增一项「全产物 zip（报告+PoC+视频+证据）」。

## 5. 接口（复用一条现有路由，不新增）

`GET /api/exploration/findings/export`

| 参数 | 取值 | 说明 |
| --- | --- | --- |
| `scope` | `selected`（本功能用这个） | 沿用现有 |
| `ids` | `288` 或 `288,290` | 单条 = 一个 id |
| `format` | `manifest`（新）、`zip`（新）、其余四个不变 | — |
| `items` | `report,poc,video,traffic,evidence` | 逗号分隔；缺省 = 全部可用项 |

行为：

- `format=manifest` → 200 JSON，**不落盘**，给弹框渲染用（形状见下）。
- `format=zip` + `ids` 一个 → 直接返回该 finding 的 zip，根下即内容，文件名 `finding-<id>-<名>.zip`。
- `format=zip` + `ids` 多个 → 外层 zip `findings-<yyyyMMdd-HHmmss>.zip`，里面每条 finding 一个内层 zip。
- `items` 出现未知 key → 400，指明是哪一项；所有勾选项都不可用 → 400「该漏洞没有可下载产物」。
- 响应头 `Content-Type: application/zip` + `Content-Disposition`（UTF-8 文件名照抄 `server/workspace.go:226` 的写法）。

manifest 形状（单条时前端取 `findings[0]`）：

```json
{
  "generated_at": "2026-11-16T15:40:00+08:00",
  "findings": [{
    "id": 288,
    "name": "Koolshare Softcenter 未认证 RCE",
    "task_id": 115,
    "total_bytes": 43211890,
    "items": [
      {"key":"report","label":"报告文档","count":1,"bytes":12700,"available":true,
       "files":[{"name":"report.md","bytes":12700}]},
      {"key":"video","label":"复现视频","count":2,"bytes":43200000,"available":true,
       "files":[{"name":"videos/17-terminal-31s.mp4","bytes":41800000,"duration_ms":31000}]},
      {"key":"traffic","label":"流量证据","count":0,"bytes":0,"available":false,
       "note":"无流量绑定","files":[]}
    ]
  }]
}
```

## 6. 打包格式：一个 finding 一个 zip

**单条**（`ids` 一个）→ 直接返回这个 finding 的 zip，根下就是内容：

```
report.md
poc/softcenter_proxy_unauth_rce.py
poc/probe.sh
videos/17-terminal-31s.mp4
videos/marks.json
evidence/evidence.md
evidence/traffic/12/manifest.json
evidence/traffic/12/request.http
evidence/traffic/12/response.http
```

**批量**（`ids` 多个）→ 外层包，里面每条 finding 一个独立 zip：

```
softcenter-rce-288.zip
hicore-溢出-290.zip
```

每个内层包的内容与单条下载**完全一致**（同一个构建函数，只是入口不同）。

实现要点：

- 内层包先写到临时文件 `<stage>/<name>-<id>.zip`，再用 `zip.CreateHeader{Method: zip.Store}` + `io.Copy` 流进外层 —— 视频不进内存。
- 内层包名 `<sanitize(FindingFilename 去 .md)>-<id>`：`-<id>` 保证不同 finding 永不撞名（同名漏洞也各自独立）。
- 已压缩内容（mp4）用 `zip.Store`，markdown / http 文本用 Deflate。
- 临时目录每次请求 `os.MkdirTemp` + `defer os.RemoveAll`（沿用现有 handler 的做法）。

## 7. 防串：五条硬规则

| # | 规则 | 为什么 |
| --- | --- | --- |
| R1 | 取数只认 finding 主键：报告/证据读 `findings` 单行字段；PoC **只取 `findings.poc_files` 列出的文件**，不 scan 任务 poc 目录；视频走 `finding_retests.finding_id` join；流量只取 `finding_traffic_bindings.finding_id` | 「扫目录」是串的根源：同一任务的 poc 目录里有全部 finding 的脚本 |
| R2 | 路径根一律 `<data>/tasks/<f.task_id>/`，跨任务 provenance 用 **finding 自己的 task_id**，每段过 `filepath.IsLocal` | 用当前上下文任务会取到别的任务的同名文件 |
| R3 | 一个 finding 一个独立 zip，包内条目不含任何跨 finding 的共享文件 | 从归档结构上杜绝混装 |
| R4 | 打包后自检：zip 条目集合必须与清单的文件集合**完全相等**，多一个或少一个都 500，不返回半成品 | 防止过滤逻辑漏写导致意外多带文件 |
| R5 | 临时目录每次请求独立创建、结束删除 | 防止上一次请求的残留文件被卷进来 |

### 7.2 已知边界（按决定不处理）

`save_poc` 把 PoC 存在任务级共享目录 `<data>/tasks/<id>/poc/`，同名直接覆盖。实测当前库里 38 个不同 PoC 名、42 次引用，其中 `qemu_repro.sh` 被 3 条 finding、`preauth_takeover.sh` / `tls_mitm_poc.sh` 各被 2 条引用 —— 文件只有一份。

本方案保证的是**引用维度的专属**（只打包这条 finding 引用到的文件，不多带一条别人的），**不保证内容隔离**（文件内容可能已被后来的 finding 覆盖，库里没有快照可还原）。按用户决定不做缓解（不加 `poc/SHARED.txt`），此限制记录在案。

## 8. 清单怎么算（每项 available 判定）

| key | 取数 | available 判定 | note 示例 |
| --- | --- | --- | --- |
| `report` | `f.Report` | 非空 | 「尚未生成报告」 |
| `poc` | `f.PocFiles`（裸名）逐个 `stat <task>/poc/<name>` | 至少一个存在 | 「文件已丢失：x.py」「缺 1 个：y.sh」 |
| `video` | `RetestRecordingsForFinding(f.ID)`（已排除 discarded） | 至少一段 | 「无复现视频」 |
| `traffic` | `len(f.TrafficBindings)` | >0 | 「无流量绑定」 |
| `evidence` | `f.Evidence` | 非空 | 「证据文本为空」 |

体积：`report`/`evidence` 按字符串字节数；`poc` 与 `video` 用 `os.Stat`；`traffic` 用 binding 的 snapshot 长度（**不打开 body**，避免为算体积把大响应读进内存）。`total_bytes` = 五项之和。

`marks.json` 的内容：把这条 finding 名下所有未丢弃录屏的 marks 汇总成
`[{"recording_id":17,"app":"terminal","duration_ms":31000,"marks":[{"t_ms":4000,"note":"可达性确认"}]}]`。

## 9. 改动面清单

| 文件 | 改动 | 量级 |
| --- | --- | --- |
| `server/finding_traffic_export.go` | `findingArtifacts`（清单）+ `writeFindingZip`（内层包，含集合自检）+ `writeFindingsBundle`（外层嵌套） | +195 行 |
| `server/server.go` | `findingsExport` 加 `case "manifest"` / `case "zip"`，`items` 解析与默认值 | +20 行 |
| `web/src/lib/api.ts` | `findingArtifacts(ids)` / `downloadFindings(ids, items)`，复用现有 blob 下载逻辑 | +45 行 |
| `web/src/components/finding-download-dialog.tsx` | 新组件（Dialog + Checkbox，读 manifest、勾选、下载） | +150 行 |
| `findings-table.tsx`（列表行按钮） | 一个 ghost Button + 一个受控 dialog | +8 行 |
| `_tabs/findings-tab.tsx`（任务详情行按钮） | 同上 | +8 行 |
| `findings/detail/page.tsx`（详情页右上角） | 同上 | +8 行 |
| `findings/page.tsx`（批量导出菜单） | `format` 联合类型加 `"zip"` + 菜单一项 | +5 行 |
| 数据库 | 无列、无表、无迁移 | 0 |

合计约 215 行后端、220 行前端；现有四种导出格式与 `md-zip` 分支一行不动。

## 10. 验收

1. **集合相等**：单条下载后 `unzip -l` 的条目集合与 manifest 里 files 集合完全相等（脚本比对，不多不少）。
2. **嵌套正确**：批量选 3 条 → 外层 `unzip -l` 看到 3 个 `.zip`；逐个解开，内容与单条下载一致。
3. **不串**：拿 `qemu_repro.sh` 被引用的那 3 条 finding 各下一次，每个包里只有自己引用的 PoC（不出现另外两条独有的脚本）。
4. **丢弃生效**：discard 掉一段录屏 → manifest 与包内都不含它，`marks.json` 里也没有。
5. **残缺发现**：无报告 / 无 PoC / 无视频 的三条 finding → 置灰原因正确，包内无空目录。
6. **跨任务 provenance**：按 `finding.task_id` 解析，包里不含其它任务的文件。
7. **非法入参**：`items=bogus` → 400 且指明 `bogus`；全部不可用 → 400「该漏洞没有可下载产物」。
8. **老格式回归**：`md-single` / `md-zip` / `csv` / `json` 各点一次，与改动前一致。

## 11. 风险与回滚

- **回滚开关**：新逻辑全在 `format=manifest|zip` 两个分支与一个新组件里；把前端入口按钮删掉即回到今天的行为，后端分支留着也不影响其它格式。
- 磁盘：内层包 + 外层包都会落临时文件，峰值约为「所选产物总大小 × 2」。批量勾很多大视频时容易吃满 `/tmp`，因此提示阈值取 500 MB（弹框红字），不硬拦。
- 并发：每个请求独立临时目录、结束即删；不做队列，靠磁盘余量。要更稳可后续加并发上限（不在本期）。
- 下载过程中 finding 被合并/删除：以请求时刻的 DB 快照为准；finding 已不存在 → 404。
- 自检失败（集合不等）→ 500 并写日志，不返回半成品包；这是唯一会让用户看到失败的路径，属于正确失败。

## 12. 被否决的替代方案

| 方案 | 否掉的原因 |
| --- | --- |
| 直接扩现有 `md-zip` 分支 | 会改到正在使用的批量导出行为，回归面大；新增 `format=zip` 与它并存更安全 |
| 打包时扫任务 `poc/` 目录 | 同任务所有 finding 的脚本都在里面，必然串（R1 的由来） |
| 单条也套一层外层 zip | 包里只有一条 finding，多一层纯噪音 |
| 把多条 finding 装进一个目录树（不是各自一包） | 用户明确要求「一个 finding 一个压缩包」 |
| 边打包边 chunked 流式发送 | 无法做 R4 的集合自检，失败时用户会拿到半包 |

## 13. 已定 / 待定

已定：一个 finding 一个 zip、批量用嵌套 zip、五个产物项（无 meta）、三处入口 + 批量菜单共用一套接口、不做 PoC 覆盖缓解。

待定（三项，都不影响开工）：

1. 体积红字阈值（建议 500 MB，只提示不拦截）
2. 批量菜单文案：「全产物 zip（报告+PoC+视频+证据）」
3. 是否要记一笔「谁在什么时候导出了哪些 finding」（建议不做，属审计需求）

## 14. 附录：事实出处

| 事实 | 出处 |
| --- | --- |
| 导出路由与既有四种格式 | `server/server.go:2212` |
| 现有 zip 打包与流量 body 读取 | `server/finding_traffic_export.go:22`、`:31`、`:52` |
| 报告文件名规则 | `report/findings.go:126` |
| `findings.report` / `evidence` / `poc_files` | `db/schema.sql:1218`（:1238 / :1228 / :1232） |
| PoC 目录与裸文件名约定 | `agent/tools_insert.go:948`（`pocDir`）、本次改动后的 `cleanPocName` |
| 录屏列表（排除已丢弃） | `db/finding_retests.go:515` |
| 前端下载样板 | `web/src/lib/api.ts:701` |
| 三处入口位置 | `findings-table.tsx:296` / `_tabs/findings-tab.tsx:88` / `findings/detail/page.tsx` |
| 批量导出菜单 | `findings/page.tsx:286` |
| 实测 PoC 共享情况 | 38 个不同名 / 42 次引用；`qemu_repro.sh` 3 条 finding 共用 |

## 15. 落地差异（实现时与本稿的两处微调）

1. **内层包名不重复拼 id**：`FindingFilename` 本身已带 `#<id>`（如 `critical_SQL注入_#288.md`），
   所以 `findingZipName` 只在名字里没有 `#<id>` 时才补 `-<id>`，避免出现 `…#288-288.zip`。
   唯一性仍然由 id 保证。
2. **流量证据每段只写 3 个文件**（`manifest.json` / `request.http` / `response.http`），
   `.http` 里是「头 + 空行 + body」，不再额外写一份 `.bin` 重复 body。这是按本稿 §6 的目录结构来的，
   与旧 `md-zip` 导出（会多写 `.bin`）有意不同。
3. 前端 `api.ts` 里把 blob 下载抽成 `saveBlobResponse`、鉴权头抽成 `authHeaders`，
   由 `exportFindings` / `downloadFindingArtifacts` 共用（旧函数行为不变，多认 `filename*` 中文名）。
