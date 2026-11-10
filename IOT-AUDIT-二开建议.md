# 把 ARTEX 改造成「固件漏洞挖掘 Agent」——二开建议清单

> 行号基于当前 HEAD（6de3dfd）。每条给「改哪里（文件:行）」「为什么」「代价」。

---

## 工作规则（每次开工前先看这一节）

1. **以本文档当前版本为准**，按下表从上到下逐条改，一次只做一条，不并行、不顺手捎带。
2. **改之前先汇报**：要改哪个文件、改成什么样、为什么这么改、有什么风险。等我说「可以」再动手。
3. **改完只汇报、不验证**：告诉我实际改了哪些文件/哪几行，以及**我自己可以怎么验证**（命令、页面、观察点）。不要替我跑构建和测试。
4. **我说「没问题」之后，你才可以**在下面的进度表把该条标成 ✅ 已改完（写上日期与文件），然后进入下一条。
5. 我说「跳过」或「改法不对」就停在那条，不往下走；我说「这条重来」就按新要求重做。
6. 不要顺手改这条之外的东西；发现别的问题，只在汇报里点出来，由我决定是否新增一条。

### 进度表

| # | 条目 | 章节 | 动什么 | 状态 |
|---|---|---|---|---|
| 1 | planner + worker 提示词 | A1 | `agent/planner.go`(298 / 318 / 324-325)、`agent/worker.go`(230 / 237 / 240 / 242 / 245) | ✅ 已改完 2026-11-10 |
| 2 | goals + mainagent + reporter + retester 提示词 | A1 | `agent/goals.go`(19/27/35)、`agent/mainagent.go`(87)、`agent/promptcatalog.go`(76/96/99)、`agent/retester.go`(4/7/16) | ✅ 已改完 2026-11-10 |
| 3 | `firmware-extract` 技能 | A2 | `skills/firmware-extract/SKILL.md`（搬迁自 ~/.hermes/skills/ctf/iot-firmware，删模拟/重打包，160 行） | ✅ 已改完 2026-11-10 |
| 4 | `component-inventory` 技能 | A2 | `skills/component-inventory/SKILL.md` + `references/` | ⏭ 已跳过 2026-11-10 |
| 5 | `poc-authoring` 技能 | A2 | `skills/poc-authoring/SKILL.md` | ⏭ 已跳过 2026-11-10 |
| 6 | `web-component-hunt` 技能 | A2 | `skills/web-component-hunt/` | ⏭ 已跳过 2026-11-10 |
| 7 | `mqtt-component-hunt` 技能 | A2 | `skills/mqtt-component-hunt/` | ⏭ 已跳过 2026-11-10 |
| 8 | `ros-component-hunt` 技能 | A2 | `skills/ros-component-hunt/` | ⏭ 已跳过 2026-11-10 |
| 9 | `credential-hunt` 技能 | A2 | `skills/credential-hunt/` | ⏭ 已跳过 2026-11-10 |
| 10 | `task_scope` 加 `firmware` / `device` | B1 | `db/schema.sql`(768/774/785/788/792-795)、`db/task_scope.go`(26-29/79-100/222-241/244/250-300/318/330/382-384)、`db/task_assets_context.go`(98/111)、`server/server.go`(1887/1895-1901)、`agent/tools_insert.go`(435-444/454-459/471-487)、`agent/tools.go`(841-843)、`agent/goals.go`(62-63)、`web/src/lib/types.ts`(357/363)、`overview-tab.tsx`(59-63/78-79/839-840/852-856) | ✅ 已改完 2026-11-10 |
| 10b | 固件上传 + 详情页固件行 | B1 | 新建任务对话框支持拖文件 → `server/workspace.go` 落盘算 sha256 并写一条 `kind=firmware` scope；`overview-tab.tsx` 顶部显示「固件 / sha256 前 12 位 / 已解包」 | ⬜ 待做 |
| 11 | 组件 `extra` 规范 + DSL 维度 | C1/C2 | 文档 + `db/asset_dsl.go` | ⬜ 待做 |
| 12 | 仿真 + 抓包（pcap 进 evidence） | E2 | 技能脚本 + `evidence` 的 pcap 入口 | ⬜ 待做 |
| 13 | 组件指纹 / 版本库 | E3 | `skills/component-inventory/references/` | ⬜ 待做 |
| 14 | PoC 落目录 + 挂 finding | E4 | `data/tasks/<id>/poc/` 规范 + 复测侧接线 | ⬜ 待做 |
| 15 | 解绑 / 隐藏 | D1 | DB 绑定与前端入口 | ⬜ 待做 |

---

## 0. 定位：输入一个固件，输出组件清单 + 可复现的 PoC

**输入 = 一个固件文件**（`RP09_1.0.44.bin`、`RAX50-V1.0.12.120.chk`）。
**输出 = 组件清单 + 每个组件的漏洞发现 + 能跑起来的 PoC + 复现证据。**

"审计"是**手段**（把组件清点干净、知道该挖谁），**挖洞和 PoC 才是目的**。
所以这个产品里要消失的词是「资产」，要立起来的词是「组件」和「PoC」。

### 0.1 为什么粒度一定是组件

1. **组件是可穷举的**。一个固件里的组件就几十个，能列清单、能算"还剩几个没挖"。域名资产是发散的，组件是收敛的。
2. **组件类型决定挖掘手法**。web 组件（lighttpd/goahead/uhttpd）挖注入、路径穿越、未授权 CGI；mqtt 组件（mosquitto/EMQX）挖匿名接入、ACL 越权；ros 组件挖 11311 未授权、话题注入。比"按端口乱扫"准得多。
3. **组件能跨固件复用**。同一个 `lighttpd 1.4.35` 出现在十个型号里，挖出来的 PoC 直接复用——知识图谱这才开始省 token。

### 0.2 三层模型（整套改造的骨架）

| 层 | 例子 | 怎么存（先不改表） |
|---|---|---|
| ① 固件包 | `RP09_1.0.44.bin` | `assets` 一行，`extra.kind="firmware"` |
| ② 组件 | `lighttpd 1.4.35` / `mosquitto 2.0.11` / `roscore` | `assets` 一行，`type='service'`，`extra.component_kind="web"/"mqtt"/"ros"` |
| ③ 实例 | `80/tcp /cgi-bin/luci`、`1883/tcp`、`11311/tcp` | 还是组件那一行的 `open_ports` / `url` / `port` |

`assets.extra` 是现成的 JSONB 字段，**一行代码不改就能先跑起来**。
`findings.asset_ids` 本来就是"这条发现挂在哪些资产上"——挂到组件上，报告天然能按组件分章。

### 0.3 架构不动：固件照样走 planner + worker

**不改 `pentest`**，也不给固件单开一个新 agent。一个固件完全适配现有三件套：

- **planner**：读"已清点的组件 + 已挖出的结论"，铺下一条挖掘意图
- **worker**：领一条意图，动手挖；挖到就产 PoC、写回 finding/fact
- **mainagent / goals**：人给目标、看态势、判完成

编排和领域无关，固件只是"很多个可被挖的组件"。要动的只有**提示词怎么说**和**技能里有什么手法**——都不改代码。

---

## 1. 改动分四层，节奏别搞反

| 层次 | 现在写死成"渗透"的地方 | 改动量 |
|---|---|---|
| ① 提示词 | `agent/planner.go`、`agent/worker.go`、`agent/goals.go`、`agent/mainagent.go`、`agent/promptcatalog.go`、`agent/retester.go` | 改文案 |
| ② 技能库 | `skills/`（7 个，只有 2 个偏 IoT，**没有一个讲固件、没有一个讲 PoC 怎么写**） | 写文档 |
| ③ 组件模型 | `assets` 表只有域名/IP/子域/应用/服务/端点 | 先用 extra 绕，后改表 |
| ④ 取证通道 | `traffic/` 是 HTTP 中间人；固件要的是**仿真 + 抓包 + 录屏** | 结构性 |

**顺序**：先改嘴（提示词）→ 再改知识（技能）→ 再改组件挂载 → 最后改地基（表结构、取证）。
反过来做（先动 `assets` 表、先写 Go 工具）是最容易烂尾的顺序。

---

## A. 零代码改动（第一天就能看到效果）

### A1. 换掉提示词——最划算的一刀 ★★★

**为什么**：Agent 的人格几乎全在 system prompt 里。同一个引擎，说"打点"它就是红队，说"清点组件后逐组件挖"它就是固件猎手。

**改哪里**：
- 代码默认值：`agent/promptcatalog.go:113` 的 `BuiltinPromptSeeds()`，正文分别在
  - 目标拆解 `agent/goals.go:19`｜规划者 `agent/planner.go:298`｜执行者 `agent/worker.go:230`
  - 主控 `agent/mainagent.go:87`｜报告 `agent/promptcatalog.go:76`｜复测 `agent/retester.go:4`
- 运行时真正生效的是 DB 表 `agent_prompts`（系统 → Agent 页面可编辑）

**坑**：种子只在"该 agent 还没有提示词"时写入。**已经跑过一次的库，改代码不会覆盖 DB**——去 UI 贴新文案，或 `DELETE FROM agent_prompts WHERE agent_key='worker'` 再重启。

**词表替换**：

| 现在 | 换成 |
|---|---|
| 渗透测试系统 / 授权渗透 | 固件漏洞挖掘 / 授权测试 |
| 攻击面、打点、利用链 | 组件面、挖洞点、利用链 |
| 资产（域名/IP/端点） | 固件 / 组件 / 组件实例 |
| 确认漏洞（RCE） | （不变） |
| PoC / 复现步骤 | （不变，而且要更硬：PoC 必须能跑） |
| 先怀疑自检、别把版本号当漏洞 | **保留**，这句对固件更关键（版本号猜 CVE 是重灾区） |

**三个角色各自改什么**：

1. **planner（铺方向）**：把"探索意图"理解成**「某个组件的一项挖掘方向」**。两条硬约束：
   - **先穷举组件、再逐个组件深挖**——不许在拿到组件清单前就 fuzz 某个二进制；
   - 每条意图要落到"哪个组件、哪个入口、什么手法"，避免"再深入看看这个固件"这种没靶子的意图。
2. **worker（干活）**：核心变化是**产出从"结论"变成"结论 + 可执行 PoC"**：
   - **先认组件**（名字/版本/怎么启动/配置在哪），再谈漏洞；
   - 结论必须来自**解包产物 / 二进制内容 / 仿真响应**，不许只凭版本号或字符串猜；
   - **挖到就要出 PoC**：能直接跑的脚本或命令序列，落在工作空间里，路径写进 finding；
   - 仿真/真机上的写操作、重启、改配置，先说影响再执行。
3. **reporter（写报告）**：每条发现都要附 PoC 路径与复现证据；没跑通的只写"线索"，不写成"已确认"。

### A2. 技能库：固件主线 + 按组件挖 + PoC 怎么写 ★★★

**为什么**：技能就是这个 Agent 的专业手册，方法论全在 `skills/` 里。现在 7 个技能里**没有一个讲固件怎么解包、没有一个讲 PoC 怎么写**。

**改哪里**：`skills/`（每子目录一个 `SKILL.md`），加载 `server/assembly.go:41`；路径来自 `config.json` 的 `skill_dir`；也能用 Auto 的 `create_skill` 在线写（`server/platform_tools.go:83`）。

| 技能 | 管什么 | 关键内容 | 素材 |
|---|---|---|---|
| `firmware-extract` | 前置 | binwalk / unsquashfs / jffs2 / ubifs / 加密固件识别 | 你的 `iot-firmware` |
| `component-inventory` | **全部组件** | **组件清点**：启动脚本、监听端口、二进制、包清单 → 组件清单 ★核心 | 新建 |
| `web-component-hunt` | web | httpd/cgi/lighttpd/goahead/uhttpd/Lua 路由：未授权、注入、路径穿越 | 你的 `iot-web-service` |
| `mqtt-component-hunt` | mqtt | mosquitto/EMQX：匿名接入、ACL 越权、保留消息泄露 | 你的 `mqtt-iov` |
| `ros-component-hunt` | ros | roscore / roslaunch / 11311 / 话题注入 | 你的 `ros1-master-forgery` |
| `credential-hunt` | 全部 | 硬编码口令、私钥、证书、默认凭据 | 你的 `iot-auth-bypass` |
| `poc-authoring` | 全部 | **PoC 长什么样**：触发脚本、前置条件、判定成功的标志、清理动作 | 新建 |

`component-inventory` 是心脏——它定义"一个固件里的组件长什么样、怎么算找到一个"，后面所有专项都靠它的输出排活。
`poc-authoring` 是第二个心脏——不写它，worker 挖出来的"洞"会变成一堆没法复现的文字。

**PoC 技能里必须写死的三条**：
1. 一个 PoC 一个文件，参数化目标地址（仿真里 `127.0.0.1:端口`，真机上换 IP 不改代码）；
2. 自带"成功判定"（返回码/回显特征/文件落地），不靠人看输出猜；
3. 自带清理（删掉写入的文件、恢复改过的配置），否则仿真环境会被自己污染。

### A3. 先"不绑"而不是"删文件"

技能和工具都靠绑定关系给到某个 agent（`db/agent_visibility`、`tools.agents`）。不想用的**先解绑**，秒级可逆。

具体：`traffic/`（HTTP 中间人）**留着**——审设备 Web 管理面要用；FOFA 同步只有做"公网暴露面"项目才用，默认解绑而不是删。

---

## B. 小改代码

### B1. 任务输入改成"固件包"（`db/schema.sql:765`）★★

`task_scope.kind` 已加 `firmware` / `device`（进度表第 10 条）：`firmware` 用 `value`(文件名) + `sha256` 唯一标识，`device` 用 `net`(靶机 IP) + `value`(型号)；两者都不参与覆盖度分母。其中"一个固件文件"就是你的唯一输入。

```sql
ALTER TABLE task_scope DROP CONSTRAINT IF EXISTS task_scope_kind_check;
ALTER TABLE task_scope ADD CONSTRAINT task_scope_kind_check
  CHECK (kind IN ('company','root_domain','subdomain','ip','cidr','icp','keyword',
                  'collection','firmware','device'));
```

配套比约束更重要：
1. **上传**：新建任务时直接拖 `.bin/.img/.tar.gz`，落到 `data/tasks/<task_id>/`（工作空间已支持文件操作，`server/workspace.go`）；
2. **展示**：任务详情页顶部显示"固件：RP09_1.0.44.bin / sha256:xxxx / 已解包"；
3. `kind='device'` 只在"把仿真里挖到的洞拿到真机确认"时才用，不是主路径。

---

## C. 组件模型（原来的"资产模型"）

### C1. 不改表，用 `assets.extra` 装三层（`db/schema.sql:40`）★★★

现有 `assets.type` 只有 `root_domain / ip / subdomain / app / service / endpoint`，字段是 `favicon_mmh3`、`status_code`、`page_title`、`technologies`——**整套为 Web 资产设计**。

**别第一步就改表**：`assets` 被 `db/assets.go`（1536 行）、`db/asset_dsl.go`（637 行）、前端 assets 页（1216 行）、findings 资产树全依赖那个 CHECK 约束，改一处要全链路跟。

**过渡方案**：固件和组件都塞进 `extra`，`type` 统一先用 `service`（`service_type` 的 CHECK 是 `http|other`，正好能装 mqtt/ros）。

```json
// ① 固件那一行
{"kind":"firmware","vendor":"Xiaomi","model":"RP09","version":"1.0.44","sha256":"9f2c...","size":31457280}

// ② 组件那一行（一个组件一行，finding 挂它）
{"component_kind":"web","name":"lighttpd","version":"1.4.35",
 "binary":"/usr/sbin/lighttpd","config":"/etc/lighttpd.conf","started_by":"/etc/init.d/S50httpd"}
```

等跑通 2–3 个真实固件、确认字段稳定，再考虑升正式列。

### C2. DSL 加组件维度（`db/asset_dsl.go`）★

`list_assets` 现在能按域名/指纹/端口/状态码查。加三个维度就够用：
`component_kind=`、`component_name=`、`component_version=`（都指向 `extra` 的键）。

"把这个固件里所有 mosquitto 组件找出来""哪些固件用了 1.4.35 以下的 lighttpd"——这两句现在都查不了。

### C3. 长期：组件升成一等公民

组件名 / 版本 / 二进制路径 / 启动方式 建议最终成为正式列 + 索引，因为组件复用、CVE 匹配、PoC 复用全依赖它们。

---

## D. 增删总表

**判断标准只有一条：这东西在"给一个固件挖洞、出可复现 PoC"里用得上吗？**

### D1. 解绑 / 隐藏（不减代码，只减噪音）

| 对象 | 位置 | 处理 |
|---|---|---|
| `playwright-cli` 技能 | `skills/playwright-cli/` | 默认解绑——只有要审设备 Web 后台时才需要 |
| 企业 / ICP / 工商 | `db/companies.go`(774行)、`db/company_scope.go`(272行)、`assets.icp` | **UI 隐藏，代码不删**——输入是固件，没有 ICP 归属 |
| FOFA 同步 | `server/sync_fofa.go` | **默认解绑，功能保留**——只有做"公网暴露面"项目才用 |
| 任务范围里的 company/域名类 kind | `db/schema.sql:765` | 不删，前端只露出 `firmware` / `device` |

### D2. 必须加

| 对象 | 为什么 | 章节 |
|---|---|---|
| 换掉的提示词（6 处） | 行为 90% 由提示词决定，不换等于没改 | A1 |
| 固件主线 + 组件专项 + PoC 技能（7 个） | 决定它会不会解包、认不认 mqtt/ros、出的 PoC 能不能跑 | A2 |
| `task_scope` 的 `firmware` | 现在没有"输入一个固件"这个选项 | B1 |
| 组件三层模型（extra 规范） | 没有它，挖洞没靶子、报告没法按组件分章 | C1 |
| 组件指纹/版本库 | 组件 → 版本 → CVE 线索，是挖掘的起点 | E3 |
| 仿真 + 抓包 | 固件的动态验证只能在仿真里做，抓不到包就没证据 | E2 |
| PoC 一等产物 + 自动验证 | 挖到 ≠ 能复现；没跑通的不算洞 | E4 |

### D3. 保留、别动

这些看着"很渗透"，其实是通用能力，删了要重写：

- **探索图谱 + planner/worker 编排**：任务怎么拆、怎么并行、怎么收敛，跟领域无关
- **guard 高危卡点 + 审批**（`guard/guard.go`、`db/intercept*.go`）：仿真/真机上一条 `reboot` 能烧掉一次现场
- **复测 + 录屏**（6de3dfd）：这就是现成的 **PoC 验证机**（见 E4）——最值钱的一块
- **任务归档/恢复**（`db/task_archives.go`）：一个固件的完整挖掘过程要能打包交付
- **命令留痕**（"工具执行"页）：证据链要"每一步可追溯"
- **skill / MCP 机制**：你的 fwtaint、iotvul_hunter 都能用 MCP 接进来，不改主程序

---

## E. 固件挖掘主链路（这是主干，不是附加功能）

### E1. 六步，每步都要落成图谱里的东西 ★★★

**现状**：项目里没有任何固件概念，只有 `Bash` + "工作空间"页（`server/workspace.go`），等于"自己扔文件、自己跑命令"。

| 步 | 动作 | 落到哪 |
|---|---|---|
| 1 | 导入固件 | `assets` 一行（`extra.kind=firmware` + sha256） |
| 2 | 解包 `binwalk -Me` | 产物目录记进 `fact` |
| 3 | **组件清点** | 每个组件一行 `assets`（`type=service` + `extra.component_kind`） |
| 4 | 逐组件挖 | 每条方向 = 一条 `intent`，结论 = `fact`，确认的 = `finding`（挂组件） |
| 5 | **出 PoC** | 脚本落到 `data/tasks/<id>/poc/`，路径写进 finding |
| 6 | 验证 | 仿真里跑 PoC + 录屏（见 E4） |

**第 3 步是分水岭**。组件从哪来，四种手段按可靠性排序：

1. **启动脚本**：`/etc/init.d/*`、`/etc/rc.d/*`、`inittab`、systemd unit —— 最准，直接说明谁在跑
2. **监听端口**：`inetd.conf`、busybox 的 `httpd.conf`、代码里的 `bind()` 端口常量 —— 说明对外暴露什么
3. **二进制与字符串**：`file` / `readelf` / `strings`（版本号、`Server:` 头、`mosquitto version`）
4. **包清单**：`opkg`/`dpkg` 数据库、`/usr/lib/opkg/status`、`*.ipk` 残留 —— 直接给 SBOM

### E2. 仿真 + 抓包（固件的"动态证据"）★★

**为什么**：`traffic/` 是 HTTP/HTTPS 中间人（`traffic/traffic.go:221` 用 goproxy），只能看 HTTP。而固件里的 mqtt/ros/rtsp 组件，**要么在 qemu 仿真里跑起来才能验证，要么根本没法验**。

- 仿真：qemu-user（你本机已验证可用）起 httpd/mosquitto/roscore，**不碰真机**就能复现
- 抓包：仿真侧 `tcpdump -i any -w x.pcap`；真机确认时才需要镜像口/ARP 欺骗
- 存储：`evidence/store.go` 是**内容寻址**仓库（按 sha256，`hashPath`），能直接存 pcap——只是入口都叫 "HTTP body"，加一个 `kind='pcap'` 即可复用
- 展示：第一期只做「下载 + tshark 摘要」（`tshark -r x.pcap -q -z io,phs`），别急着做可视化

### E3. 组件指纹 / 版本库（把"组件"和"CVE"接起来）★★

**做法全是数据，不是代码**：`skills/component-inventory/references/`

- **组件识别表**：`Server:` 头、`strings` 特征、配置文件路径 → 组件名（`GoAhead-Webs`、`lighttpd/1.4.35`、`mosquitto version 2.0.11`）
- **端口 → 组件类型**：80/443/8080=web、1883/8883=mqtt、11311=ros、554=rtsp、502=modbus
- **组件 → CVE 映射**：只作**线索**，必须仿真复现后才登记为发现（这条要写进 worker 提示词）

### E4. PoC 当成一等产物：生成 → 自动验证 ★★★

**这是整套改造里最值钱的一块，而且不用新写代码——现有"复测 + 录屏"就是一台 PoC 验证机。**

链路：

```
worker 挖到 → 写 poc/<finding_id>.py（+ 前置条件 + 成功判定）
          → report_finding 的 evidence 里写 PoC 路径
          → 复测会话拿 PoC 在仿真里跑一遍（retest_terminal_exec）
          → 全程录屏（retest_recording，已实现）
          → verdict：confirmed（能复现）/ needs-work（跑不通，退回补）
```



---

## F. 验收：拿一个固件跑一遍

1. **组件清点**：它能不能自己解包、列出组件清单（含版本、启动方式、端口），并且**没漏掉启动脚本里那些不监听端口的组件**？
2. **挖洞**：挑一个 mqtt 组件（mosquitto），看它能不能在仿真里验出匿名接入，证据是仿真输出而不是"版本 2.0.11 有 CVE"。
3. **PoC 可复现**：把 worker 产出的 PoC 单独拿出来、换台机器跑，**不改代码也能跑通**吗？跑不通就不算挖到。
4. **不过度上报**：跑完看 findings 里有多少条是"仅静态线索"被写成了"已确认"——这个比例应该接近 0。

四条里第 1 条过不了，说明 `component-inventory` 没写对；第 3 条过不了，说明 `poc-authoring` 没写对。其余都白搭。

---

## 附：一句话记住优先级

**先改嘴（提示词）→ 再改知识（技能，尤其 PoC 怎么写）→ 再改组件挂载 → 最后改地基（表结构、取证）。**

反过来做（先动 `assets` 表、先写 Go 工具）是最容易烂尾的顺序。

