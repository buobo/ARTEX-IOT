package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// =====================================================================
// insert_components：组件登记
// =====================================================================

// SetComponentStore wires the component store and company store onto this ToolSet
// so the insert_components / add_company_scope / list_components tools are active.
func (t *ToolSet) SetComponentStore(as *db.ComponentStore, cs *db.CompanyStore) {
	t.as = as
	t.cs = cs
}

// componentInputItem is one element of the insert_components "components" array.
type componentInputItem struct {
	Type           string   `json:"type"`
	ComponentName  string   `json:"component_name"`
	Version        string   `json:"version"`
	Vendor         string   `json:"vendor"`
	BinaryPath     string   `json:"binary_path"`
	ConfigPath     string   `json:"config_path"`
	StartedBy      string   `json:"started_by"`
	FirmwareSha256 string   `json:"firmware_sha256"`
	Port           int      `json:"port"`
	Technologies   []string `json:"technologies"`
	Notes          string   `json:"notes"`
	Status         string   `json:"status"`
}

// componentInputLabel 返回一条待登记组件的简短标识。
func componentInputLabel(item componentInputItem) string {
	name := strings.TrimSpace(item.ComponentName)
	if name == "" {
		return "(未命名组件)"
	}
	if v := strings.TrimSpace(item.Version); v != "" {
		return name + " " + v
	}
	return name
}

// insertComponents is the unified insert_components agent tool.
func (t *ToolSet) insertComponents() actool.CoreTool {
	return writeTool(
		"insert_components",
		"登记固件里的组件（一行 = 一个组件，例如 lighttpd/mosquitto/roscore）。\n"+
			"type 取值：web / mqtt / ros / ssh / telnet / upnp / onvif / rtsp / ftp / other；不确定就填 other。\n"+
			"component_name 必填（可执行名或服务名，如 lighttpd）。version 只在确知时填，不要猜。\n"+
			"可选：vendor 厂商、binary_path 可执行文件路径、config_path 配置文件、started_by 启动脚本(/etc/init.d/xxx)、\n"+
			"      port 主监听端口、technologies 依赖库/特征、notes 备注（如「busybox telnetd，默认无认证」）。\n"+
			"同一 (firmware_sha256, type, component_name, version) 只会有一行：重复登记会补齐空字段而不是新增。\n"+
			"status 默认 pending（待挖）；开始分析某组件时用 set_component_status 置 running，分析完置 completed。\n"+
			"返回：{inserted, updated, ids}",
		obj(map[string]any{
			"components": map[string]any{
				"type":        "array",
				"description": "批量：[{type, component_name, version?, vendor?, binary_path?, config_path?, started_by?, port?, technologies?, notes?}]",
				"items":       map[string]any{"type": "object"},
			},
			"type":            str("[单条] web/mqtt/ros/ssh/telnet/upnp/onvif/rtsp/ftp/other"),
			"component_name":  str("[单条] 组件名（lighttpd / mosquitto / roscore）"),
			"version":         str("[单条] 版本号，确知才填"),
			"binary_path":     str("[单条] 可执行文件绝对路径"),
			"config_path":     str("[单条] 配置文件路径"),
			"started_by":      str("[单条] 启动脚本路径"),
			"vendor":          str("[单条] 厂商/品牌（如 Xiaomi、Realtek）"),
			"port":            intp("[单条] 主监听端口"),
			"technologies":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "[单条] 依赖库/协议栈等特征"},
			"status":          str("[单条] 初始状态 pending/running/completed/ignored，默认 pending"),
			"firmware_sha256": str("[单条] 仅当该组件明确来自某个固件：固件 sha256(64 位十六进制)"),
			"notes":           str("[单条] 备注"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("insert_components 未启用: ComponentStore 未初始化"), nil
			}
			var a struct {
				Items []componentInputItem `json:"components"`
				componentInputItem
				FirmwareSha256 string `json:"firmware_sha256"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			items := a.Items
			if len(items) == 0 {
				items = []componentInputItem{a.componentInputItem}
			}
			if len(items) == 0 {
				return actool.Errorf("components 不能为空"), nil
			}

			// 固件 sha256：单条/批量都可显式指定，否则回落到任务范围里登记的固件。
			// 只在任务里恰好登记了一个固件时回落：多固件任务无从判断这条组件来自哪个固件，
			// 宁可留空（组件库按 COALESCE(sha,'') 归并），也不能把它标到随便一个固件名下。
			sha := strings.TrimSpace(a.FirmwareSha256)
			if sha == "" && t.taskID > 0 && t.as != nil {
				if scopes, err := t.as.ListTaskScope(t.taskID); err == nil {
					for _, sc := range scopes {
						if sc.Kind != "firmware" || sc.Sha256 == "" {
							continue
						}
						if sha == "" {
							sha = sc.Sha256
						} else if sha != sc.Sha256 {
							sha = "" // 多固件：不猜
							break
						}
					}
				}
			}

			var inputs []db.ComponentInput
			for i := range items {
				it := items[i]
				if it.FirmwareSha256 == "" {
					it.FirmwareSha256 = sha
				}
				inputs = append(inputs, db.ComponentInput{
					Type:           it.Type,
					Name:           it.ComponentName,
					Version:        it.Version,
					Vendor:         it.Vendor,
					BinaryPath:     it.BinaryPath,
					ConfigPath:     it.ConfigPath,
					StartedBy:      it.StartedBy,
					FirmwareSha256: it.FirmwareSha256,
					Port:           it.Port,
					Technologies:   it.Technologies,
					Notes:          it.Notes,
					Status:         it.Status,
				})
			}

			var taskIDs []int64
			if t.taskID > 0 {
				taskIDs = []int64{t.taskID}
			}
			inserted, updated, ids, err := t.as.UpsertComponents(taskIDs, inputs)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// 来源链路（与旧的资产工具一致）：把组件锚到本次执行节点（worker=意图节点）
			// 并写任务↔组件来源行。两者都是批量一次写；失败不影响「组件已入库」这个结果。
			if t.ts != nil && t.ownerNode > 0 {
				_ = t.ts.AnchorMany(t.ownerNode, ids)
			}
			if t.taskID > 0 {
				summary := "Agent 通过 insert_components 登记"
				var sourceNodeID *int64
				if t.ownerNode > 0 {
					n := t.ownerNode
					sourceNodeID = &n
					summary = fmt.Sprintf("Worker 意图 #%d 通过 insert_components 登记", t.ownerNode)
				}
				_ = t.as.SetTaskComponentSources(t.taskID, ids, "agent", summary, sourceNodeID)
			}
			return jsonResult(map[string]any{
				"inserted": inserted,
				"updated":  updated,
				"ids":      ids,
			})
		},
	)
}

// addCompanyScope writes to company_scope table and triggers component attribution.
func (t *ToolSet) addCompanyScope() actool.CoreTool {
	return writeTool(
		"add_company_scope",
		"把域名/IP/CIDR/ICP备案/企业关键词加入某公司的【范围】——域名、网络和ICP记录在该公司范围下，关键词只提供给Agent作为范围提示。\n"+
			"公司名唯一：company 不存在则新建，已存在则复用(只把范围并进去)。\n"+
			"scope 一行一条，系统自动识别：根域名 / URL / 单个 IP / CIDR 网段 / ICP备案 / 企业关键词。\n"+
			"务必给 reason 说明归属依据(whois/证书/ASN 等)。\n"+
			"护栏：拒绝裸 TLD 与过宽网段(IPv4前缀需为/16-/32、IPv6前缀需为/32-/128)，非法行会被跳过并在 errors 返回。",
		obj(map[string]any{
			"company": str("公司名(不存在则新建、存在则复用；名称唯一)"),
			"scope":   str("范围，一行一条：域名 / URL / IP / CIDR / ICP备案 / 企业关键词"),
			"reason":  str("归属依据(证据/来源)，务必填写"),
			"logo":    str("公司图标 URL(可选；仅新建公司时生效)"),
		}, "company", "scope"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("add_company_scope 未启用: CompanyStore 未初始化"), nil
			}
			var a struct {
				Company string `json:"company"`
				Scope   string `json:"scope"`
				Reason  string `json:"reason"`
				Logo    string `json:"logo"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(a.Company) == "" {
				return actool.Errorf("company 不能为空"), nil
			}
			companyID, _, err := t.cs.UpsertCompany(a.Company, a.Logo)
			if err != nil {
				return actool.Errorf("创建/获取公司失败: " + err.Error()), nil
			}
			lines := splitLines(a.Scope)
			added, skipped, invalid, errMsgs := t.cs.AddScope(companyID, lines, a.Reason)
			out := map[string]any{
				"company_id": companyID,
				"added":      added,
				"skipped":    skipped,
				"invalid":    invalid,
			}
			if len(errMsgs) > 0 {
				out["errors"] = errMsgs
			}
			return jsonResult(out)
		},
	)
}

// addTaskScope lets the plan agent add test scope to THE CURRENT TASK — the coverage
// denominator and the task's authorization edge. Worker discoveries are auto-scoped
// (precise host) by insertComponents; this tool is for DELIBERATELY WIDENING: pull a whole
// root domain or whole company into scope, or add a specific subdomain / ip.
func (t *ToolSet) addTaskScope() actool.CoreTool {
	return writeTool(
		"add_task_scope",
		"把测试范围加入【本任务】——这是本任务的授权边界，也是组件测试覆盖度的分母。\n"+
			"kind 支持：company(整个公司) / root_domain(整个根域，含所有子域) / subdomain(单个精确子域) / ip / cidr / icp / keyword / firmware(本任务要审计的固件) / device(可选的靶机)。\n"+
			"说明：worker 逐个碰到的主机会被系统【自动】加进范围(精确子域)；本工具用于【主动扩大】——把整个根域/整个公司纳入，或补充指定某子域/IP；固件类任务用 firmware 登记被审计的固件，有靶机时用 device 登记。\n"+
			"value：company 传公司名或 id(公司须已存在)；root_domain/subdomain 传域名；ip/cidr 传 IP 或网段；icp/keyword 传备案号或企业关键词；firmware 传固件文件名；device 传「IP」或「IP 型号」。\n"+
			"sha256：仅 firmware 用，传固件文件的 sha256(64 位十六进制)；算不出来就先不传，之后补。\n"+
			"务必给 reason 说明依据(可审计)。多条用 entries 数组。",
		obj(map[string]any{
			"entries": map[string]any{"type": "array", "description": "批量：[{kind, value, sha256?}]。kind∈company/root_domain/subdomain/ip/cidr/icp/keyword/firmware/device。", "items": map[string]any{"type": "object"}},
			"kind":    str("[单条] company / root_domain / subdomain / ip / cidr / icp / keyword / firmware / device"),
			"value":   str("[单条] 公司名或id / 域名 / IP / CIDR / ICP / 关键词 / 固件文件名 / 靶机 IP(可跟型号)"),
			"sha256":  str("[单条] 仅 firmware：固件 sha256(64 位十六进制，可选)"),
			"reason":  str("加入依据(用于审计)，务必填写"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("add_task_scope 未启用: ComponentStore 未初始化"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("add_task_scope 需要任务上下文(当前无 task)"), nil
			}
			type scopeEntry struct {
				Kind   string `json:"kind"`
				Value  string `json:"value"`
				Sha256 string `json:"sha256"` // 仅 kind=firmware
			}
			var a struct {
				Entries    []scopeEntry `json:"entries"`
				scopeEntry              // 单条模式
				Reason     string       `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			items := a.Entries
			if len(items) == 0 {
				items = []scopeEntry{a.scopeEntry}
			}
			var added []map[string]any
			errs := map[string]string{}
			for i, e := range items {
				kind := strings.TrimSpace(e.Kind)
				var (
					ts  db.TaskScope
					err error
				)
				if kind == "firmware" {
					// 固件走专用入口：文件名 + sha256 一起构成唯一键。
					ts, err = t.as.AddFirmwareScope(t.taskID, e.Value, e.Sha256, a.Reason, "agent")
				} else {
					ts, err = t.as.AddAgentScope(t.taskID, kind, e.Value, a.Reason, "agent")
				}
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				added = append(added, map[string]any{"kind": ts.Kind, "domain": ts.Domain, "net": ts.Net, "value": ts.Value, "sha256": ts.Sha256, "company_id": ts.CompanyID})
			}
			out := map[string]any{"added": added}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		},
	)
}

// listUntestedComponents lets the plan agent pull the current + directly inherited
// scope's not-yet-tested components on demand (filter by type, paginated).
func (t *ToolSet) listUntestedComponents() actool.CoreTool {
	return readTool(
		"list_untested_components",
		"查询【本任务】范围内、还没被事实锚点覆盖的组件（关联范围只读，供你自己判断要不要补测，不代替你决策）。\n"+
			"可选按组件类型过滤：web/mqtt/ros/ssh/telnet/upnp/onvif/rtsp/ftp/other。\n"+
			"分页：page 从 1 起、page_size 默认 10。返回 {components:[{id,type,label}], total, page, page_size}。仅任务上下文可用。",
		obj(map[string]any{
			"type":      str("组件类型过滤（可选）：web/mqtt/ros/ssh/telnet/upnp/onvif/rtsp/ftp/other"),
			"page":      intp("页码，从 1 起（默认 1）"),
			"page_size": intp("每页数量（默认 10）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_untested_components 未启用: ComponentStore 未初始化"), nil
			}
			if t.taskID <= 0 || t.ts == nil {
				return actool.Errorf("list_untested_components 需要任务上下文"), nil
			}
			var a struct {
				Type     string `json:"type"`
				Page     int    `json:"page"`
				PageSize int    `json:"page_size"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Page <= 0 {
				a.Page = 1
			}
			if a.PageSize <= 0 {
				a.PageSize = 10
			}
			offset := (a.Page - 1) * a.PageSize
			components, total, err := t.as.ListUntestedComponentsWithSources(t.taskID, strings.TrimSpace(a.Type), a.PageSize, offset)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"components": components, "total": total, "page": a.Page, "page_size": a.PageSize,
			})
		},
	)
}

// listComponents lets an agent query the component table.
func (t *ToolSet) listComponents() actool.CoreTool {
	return readTool(
		"list_components",
		"查询组件库：DSL 表达式搜索，或按 id/ids 直取；支持分页。只返回本任务范围内的组件。\n"+
			"DSL：field=value 模糊(ILIKE) | field==value 精确 | field!=value 排除 | 数字字段支持 > >= < <= | 裸词=全文模糊；AND/OR 组合(AND 优先级高)，可用括号分组。组件类型用独立 type 参数，不写进 DSL。\n"+
			"未传 id/ids 时 dsl 必须非空（不允许无条件全量查询）。\n"+
			"可用字段：component_name(组件名)、version、vendor、binary_path、config_path、started_by、status(pending|running|completed|ignored)、firmware_sha256、technology(数组，=模糊 ==精确)、port(整数)。\n"+
			"示例：status==pending AND type==web ；component_name=lighttpd ；port==1883",
		obj(map[string]any{
			"dsl":    str(`DSL 查询表达式（语法/字段见工具描述）。未传 id/ids 时必须非空。`),
			"type":   str("组件类型过滤：web|mqtt|ros|ssh|telnet|upnp|onvif|rtsp|ftp|other（独立字段，可与 dsl 叠加；单独 type 不足以查询，仍需 dsl）"),
			"id":     intp("直接按单个组件 id 取（可选，与 dsl/type 互斥）"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "直接按多个组件 id 取（可选，与 dsl/type 互斥）"},
			"limit":  intp("返回上限，默认 10（可选）"),
			"offset": intp("分页偏移，默认 0（可选）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_components 未启用: ComponentStore 未初始化"), nil
			}
			var a struct {
				DSL    string  `json:"dsl"`
				Type   string  `json:"type"`
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Limit  int     `json:"limit"`
				Offset int     `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 {
				a.Limit = 10
			}

			var components []*db.Component
			var err error
			switch {
			case a.ID > 0:
				components, err = t.as.GetByIDsInScope(t.taskID, []int64{a.ID})
			case len(a.IDs) > 0:
				components, err = t.as.GetByIDsInScope(t.taskID, a.IDs)
			case a.DSL != "":
				components, err = t.as.QueryDSLInScope(a.DSL, a.Type, "", t.taskID, a.Limit, a.Offset)
			default:
				return actool.Errorf("未传 id/ids 时 dsl 不能为空：不允许无条件查询全部组件，请提供查询条件"), nil
			}
			if err != nil {
				return actool.Errorf("DSL 错误: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count":      len(components),
				"components": components,
			})
		},
	)
}

// listCompanies lets an agent enumerate companies (企业) with their scope + component count.
func (t *ToolSet) listCompanies() actool.CoreTool {
	return readTool(
		"list_companies",
		"列出【企业/公司】及其范围(scope)。企业模块仅作为组织维度保留，组件不按企业归属。"+
			"可选 search 按公司名模糊过滤(不区分大小写)，留空返回全部。",
		obj(map[string]any{
			"search": str("按公司名模糊过滤(可选，不区分大小写)；留空返回全部"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("list_companies 未启用: CompanyStore 未初始化"), nil
			}
			var a struct {
				Search string `json:"search"`
			}
			_ = json.Unmarshal(in, &a)
			cos, err := t.cs.ListCompanies()
			if err != nil {
				return actool.Errorf("查询公司失败: " + err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Search))
			type companyOut struct {
				ID             int64    `json:"id"`
				Name           string   `json:"name"`
				ComponentCount int      `json:"component_count"`
				Scope          []string `json:"scope"`
			}
			out := make([]companyOut, 0, len(cos))
			for _, c := range cos {
				if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
					continue
				}
				scope := make([]string, 0, len(c.Scope))
				for _, r := range c.Scope {
					scope = append(scope, r.Raw)
				}
				out = append(out, companyOut{ID: c.ID, Name: c.Name, ComponentCount: c.ComponentCount, Scope: scope})
			}
			return jsonResult(map[string]any{"count": len(out), "companies": out})
		},
	)
}

// splitLines splits a multi-line string into non-empty trimmed lines.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// WorkerTools returns the tool set for a work agent.
func (t *ToolSet) WorkerTools() []actool.CoreTool {
	return []actool.CoreTool{
		// list_findings 保留：报漏洞前先查本任务已确认漏洞，避免重复上报同一漏洞。
		t.listFindings(),
		t.addFinding(), t.recordFact(),
		// component management (handlers guard nil store internally)。
		// add_company_scope 不给 worker：定义企业范围属规划/主控/Auto 的职责，worker 只执行探索。
		t.insertComponents(), t.listComponents(), t.savePoc(),
		// register_extract：解包完成后登记根目录，后续意图复用（不再重复解包）。
		// 只给 worker —— planner/main 不负责解包，也就不登记。
		t.registerExtract(),
		// 跨 work 回看：worker 也可复用其他 work 的观察，避免重复劳动。
		// search_all_worker_traces：不必先知道 intent_id，按关键字全局捞命中步骤；
		// get_worker_trace：锁定某条 work 后列步骤/就地搜/取完整内容。
		t.searchAllWorkerTraces(), t.getWorkerTrace(),
		// node_detail：worker 拿到 intent_id/节点 id 后可查该节点完整详情（配合上面的回看）。
		t.nodeDetail(),
		// 经验沉淀：write_experience 收尾必写（写在本意图节点上），read_experience 按
		// 自然语言检索本任务历史经验（工具内部调一次模型做筛选+压缩，用量走 llmrec）。
		t.writeExperience(), t.readExperience(),
		// 以下工具仍【不给】worker，只留给 planner/main（读上下文、跨 work 复盘是规划职责，
		// worker 只做单条意图的执行与写回）：list_facts / list_companies / list_worker_traces。
	}
}

// MainAgentTools returns the human-interface tool set.
func (t *ToolSet) MainAgentTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.expandDigest(), // cold-digest §6.1
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.addHint(), t.addIntent(),
		// steer_work：人可对某条正在运行的意图(work)实时注入纠偏指令（不打断、不丢进展）。
		t.steerWorkTool(),
		// set_goals：人可在运行时给本任务补一个新的最终目标（规划者据此重判是否达成）。
		t.setGoals(),
		// set_constraints：人可在运行时给本任务补/改操作约束（allow/deny），约束 planner/worker 的探索边界。
		t.setConstraints(),
		// component management (handlers guard nil store internally)
		t.insertComponents(), t.addCompanyScope(), t.listComponents(), t.setComponentStatus(),
		t.savePoc(),
		t.addFinding(), t.recordFact(),
		t.addTaskScope(),
		// list_untested_components：按需查本任务范围内未测组件(类型+分页)，自行决定补测。
		t.listUntestedComponents(),
		// read_experience：人可检索"本任务历史意图沉淀下来的经验"（只读）。
		// 刻意不给 write_experience——经验只能由执行该意图的 worker 自己写，
		// 人在旁边补写会把"这条意图到底做了什么"搅浑。
		t.readExperience(),
	}
}

// AllDomainTools returns the union of all domain tools across all agent types,
// deduped by name (mainagent order wins). Used by the server to build a registry
// for injecting domain tools into agents (Auto, custom) that don't own a per-task
// ToolSet. The caller provides real stores; tools are callable at taskID=0 scope.
func (t *ToolSet) AllDomainTools() []actool.CoreTool {
	seen := map[string]bool{}
	var out []actool.CoreTool
	all := append(append(t.MainAgentTools(), t.PlannerTools()...), t.WorkerTools()...)
	for _, tool := range all {
		if !seen[tool.Name()] {
			seen[tool.Name()] = true
			out = append(out, tool)
		}
	}
	return out
}

// setComponentStatus marks a component's mining progress so 覆盖度 reflects reality.
func (t *ToolSet) setComponentStatus() actool.CoreTool {
	return writeTool(
		"set_component_status",
		"更新组件挖掘状态（本任务范围内的组件才能改）。\n"+
			"status 取值：pending(待挖，登记后的默认值) / running(正在挖) / completed(已挖完，计入覆盖度分子) / ignored(不挖，不计入分母)。\n"+
			"开始分析某个组件时置 running；这条组件在本任务里挖完（该看的入口都看过）置 completed；判定不值得挖置 ignored。\n"+
			"支持 ids 批量，或 id 单个。返回 {updated, errors}",
		obj(map[string]any{
			"id":     intp("[单个] 组件 id（来自 insert_components / list_components）"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "[批量] 组件 id 列表"},
			"status": str("pending|running|completed|ignored"),
		}, "status"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("set_component_status 未启用: ComponentStore 未初始化"), nil
			}
			var a struct {
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Status string  `json:"status"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ids := a.IDs
			if a.ID > 0 {
				ids = append(ids, a.ID)
			}
			if len(ids) == 0 {
				return actool.Errorf("id 或 ids 至少给一个"), nil
			}
			var errs []string
			updated := 0
			for _, id := range ids {
				if err := t.as.SetTaskComponentStatus(t.taskID, id, a.Status); err != nil {
					errs = append(errs, fmt.Sprintf("%d: %v", id, err))
					continue
				}
				updated++
			}
			return jsonResult(map[string]any{"updated": updated, "errors": errs})
		},
	)
}

// =====================================================================
// save_poc：PoC 落盘 + INDEX.md 索引
// =====================================================================

// =====================================================================
// register_extract：解包产物登记（task_scope.extract_path）
// =====================================================================

// registerExtract 让真正解包的那个 worker 把根目录登记到本任务的 firmware 行上。
// 上传时不写这一列，第一次解包后才回填；之后所有意图复用同一路径，不再重复解包。
func (t *ToolSet) registerExtract() actool.CoreTool {
	return writeTool(
		"register_extract",
		"解包完成后调用：把解包得到的根目录登记到本任务（task_scope 的 firmware 行 extract_path），"+
			"之后其它意图复用这个路径，不用再解一遍。\n"+
			"path：解包得到的根目录，可以就在 firmware/ 下（例如 firmware/rootfs）；只接受本任务目录内的路径。\n"+
			"firmware：可选，固件文件名或 64 位 sha256；任务里有多份固件时必须指定。\n"+
			"note：可选，解包器与主命令（例如 sasquatch -d rootfs R6220.bin），便于复现。\n"+
			"返回：{extract_path(相对), abs_path, firmware:{value,sha256}, scope_row_id, entries, already, previous}",
		obj(map[string]any{
			"path":     str("解包得到的根目录（相对任务目录或绝对路径，必须落在本任务目录内）"),
			"firmware": str("可选：固件文件名或 64 位 sha256；多份固件时必填"),
			"note":     str("可选：解包器与主命令，便于复现"),
		}, "path"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path     string `json:"path"`
				Firmware string `json:"firmware"`
				Note     string `json:"note"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if t.as == nil {
				return actool.Errorf("register_extract 未启用: ComponentStore 未初始化"), nil
			}
			if t.taskID <= 0 || t.dataDir == "" {
				return actool.Errorf("register_extract 需要任务上下文与数据目录"), nil
			}
			taskDir := filepath.Join(t.dataDir, "tasks", strconv.FormatInt(t.taskID, 10))
			raw := strings.TrimSpace(a.Path)
			if raw == "" {
				return actool.Errorf("path 不能为空：填解包得到的根目录"), nil
			}
			abs := raw
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(taskDir, raw)
			}
			// 软链逃逸防护：两侧都取真实路径后再比前缀。
			real, err := filepath.EvalSymlinks(filepath.Clean(abs))
			if err != nil {
				return actool.Errorf(fmt.Sprintf("路径不存在或无法解析: %v", err)), nil
			}
			base := taskDir
			if b, err := filepath.EvalSymlinks(taskDir); err == nil {
				base = b
			}
			rel, err := filepath.Rel(base, real)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return actool.Errorf("path 必须在本任务目录内（" + base + "）"), nil
			}
			st, err := os.Stat(real)
			if err != nil || !st.IsDir() {
				return actool.Errorf("path 不是已存在的目录"), nil
			}
			entries, err := os.ReadDir(real)
			if err != nil {
				return actool.Errorf("读取目录失败: " + err.Error()), nil
			}
			if len(entries) < 20 {
				return actool.Errorf(fmt.Sprintf("目录里只有 %d 个条目，看起来是半成品；确认解包完整后再登记", len(entries))), nil
			}

			fwName, fwSha, err := t.locateFirmwareFile(filepath.Join(taskDir, "firmware"), a.Firmware, real)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			reason := "解包登记"
			if note := strings.TrimSpace(a.Note); note != "" {
				reason = "解包登记: " + note
			}
			ts, prev, err := t.as.SetFirmwareExtract(t.taskID, fwSha, fwName, filepath.ToSlash(rel), reason)
			if err != nil {
				return actool.Errorf("登记失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"ok":           true,
				"extract_path": ts.ExtractPath,
				"abs_path":     real,
				"firmware":     map[string]any{"value": ts.Value, "sha256": ts.Sha256},
				"scope_row_id": ts.ID,
				"entries":      len(entries),
				"already":      prev == ts.ExtractPath,
				"previous":     prev,
			})
		})
}

// locateFirmwareFile 找到本次解包对应的固件文件，返回 (文件名, sha256)。
// skip 是刚登记的解包目录本身——它可能就在 firmware/ 下，枚举时必须排除。
func (t *ToolSet) locateFirmwareFile(fwDir, spec, skip string) (string, string, error) {
	spec = strings.TrimSpace(spec)
	// 显式文件名：直接取，不猜。
	if spec != "" && !looksLikeSha256(spec) {
		if strings.ContainsAny(spec, `/\`) {
			return "", "", fmt.Errorf("firmware 只接受文件名或 sha256，不要带路径")
		}
		p := filepath.Join(fwDir, spec)
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			return "", "", fmt.Errorf("firmware/ 下找不到固件文件 %s", spec)
		}
		sum, err := sha256File(p)
		if err != nil {
			return "", "", fmt.Errorf("计算固件摘要失败: %v", err)
		}
		return spec, sum, nil
	}
	// 其余情况：只看 firmware/ 下的常规文件（跳过目录，解包产物可能就在里面）。
	ents, err := os.ReadDir(fwDir)
	if err != nil {
		return "", "", fmt.Errorf("读不到固件目录 firmware/：%v", err)
	}
	type cand struct{ name, path string }
	var cands []cand
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join(fwDir, e.Name())
		if skip != "" && p == skip {
			continue
		}
		if st, err := e.Info(); err != nil || !st.Mode().IsRegular() {
			continue
		}
		cands = append(cands, cand{e.Name(), p})
	}
	if len(cands) == 0 {
		return "", "", fmt.Errorf("firmware/ 下没有固件文件，无法登记解包产物")
	}
	// 指定了 sha：逐一比对。
	if spec != "" {
		for _, c := range cands {
			if sum, err := sha256File(c.path); err == nil && strings.EqualFold(sum, spec) {
				return c.name, sum, nil
			}
		}
		return "", "", fmt.Errorf("firmware/ 下没有摘要为 %s 的固件", spec)
	}
	// 没指定：恰好一份就直接用；多份则用任务范围里已登记的文件名收敛。
	if len(cands) > 1 {
		known := map[string]bool{}
		if rows, err := t.as.ListTaskScope(t.taskID); err == nil {
			for _, r := range rows {
				if r.Kind == "firmware" && r.Value != "" {
					known[r.Value] = true
				}
			}
		}
		var only []cand
		for _, c := range cands {
			if known[c.name] {
				only = append(only, c)
			}
		}
		if len(only) != 1 {
			names := make([]string, 0, len(cands))
			for _, c := range cands {
				names = append(names, c.name)
			}
			return "", "", fmt.Errorf("firmware/ 下有多份固件，请用 firmware 参数指定：%s", strings.Join(names, ", "))
		}
		cands = only
	}
	sum, err := sha256File(cands[0].path)
	if err != nil {
		return "", "", fmt.Errorf("计算固件摘要失败: %v", err)
	}
	return cands[0].name, sum, nil
}

// looksLikeSha256 判断是否 64 位十六进制摘要。
func looksLikeSha256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range strings.ToLower(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sha256File 流式计算文件摘要（跳过目录/非普通文件）。
func sha256File(p string) (string, error) {
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

// pocDir 返回本任务的 PoC 目录 <dataDir>/tasks/<taskID>/poc。
// 拿不到任务上下文时返回错误——路径只能由代码决定，不让模型自己拼。
func (t *ToolSet) pocDir() (string, error) {
	if t.dataDir == "" {
		return "", fmt.Errorf("save_poc/PoC 校验不可用：数据目录未注入")
	}
	if t.taskID <= 0 {
		return "", fmt.Errorf("save_poc 需要任务上下文；平台对话请把 PoC 交给任务 Agent")
	}
	return filepath.Join(t.dataDir, "tasks", strconv.FormatInt(t.taskID, 10), "poc"), nil
}

var pocExts = map[string]bool{".py": true, ".sh": true, ".c": true, ".txt": true, ".http": true, ".md": true, ".js": true, ".rb": true}

// cleanPocName 只接受单层文件名：拒绝路径分隔符、上跳、隐藏前缀与不认识的扩展名。
func cleanPocName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	name = strings.Trim(name, "`'\"")
	if name == "" {
		return "", fmt.Errorf("name 不能为空")
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") || strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("name 只能是单层文件名（不含路径/上跳）：%s", raw)
	}
	if !pocExts[strings.ToLower(filepath.Ext(name))] {
		return "", fmt.Errorf("name 扩展名不支持：%s（可用 .py/.sh/.c/.js/.rb/.txt/.http/.md）", name)
	}
	return name, nil
}

// pocIndexPath 返回 PoC 索引文件路径。
func pocIndexPath(dir string) string { return filepath.Join(dir, "INDEX.md") }

// upsertPocIndex 在 INDEX.md 里写入/更新一行。索引由代码维护，避免模型忘写或写坏格式。
func upsertPocIndex(dir, name, component, summary string, findingID int64) error {
	const header = "| 文件名 | 组件 | 一句话漏洞 | finding id |\n|---|---|---|---|\n"
	cells := []string{"`" + name + "`", component, summary, ""}
	if findingID > 0 {
		cells[3] = strconv.FormatInt(findingID, 10)
	}
	row := "| " + strings.Join(cells, " | ") + " |"

	path := pocIndexPath(dir)
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(b) == 0 {
		lines = strings.Split(strings.TrimRight(header, "\n"), "\n")
	}
	replaced := false
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "| `"+name+"`") || strings.HasPrefix(strings.TrimSpace(ln), "| "+name+" |") {
			lines[i] = row
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append(lines, row)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// backfillPocIndexFinding 把 report_finding 得到的 finding id 写回 poc/INDEX.md 对应行。
// save_poc 通常发生在登记之前，那时还没有 finding id；这里补上，索引才不会一直空着。
func backfillPocIndexFinding(dir, name string, findingID int64) error {
	if findingID <= 0 {
		return nil
	}
	path := pocIndexPath(dir)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil // 没有索引文件 = 没走 save_poc，无需补
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	changed := false
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if !strings.HasPrefix(trimmed, "| `"+name+"`") && !strings.HasPrefix(trimmed, "| "+name+" |") {
			continue
		}
		if strings.HasSuffix(trimmed, "|") {
			body := strings.TrimSuffix(trimmed, "|")
			if idx := strings.LastIndex(body, "|"); idx >= 0 {
				body = strings.TrimRight(body[:idx], " ")
			}
			lines[i] = body + " | " + strconv.FormatInt(findingID, 10) + " |"
			changed = true
		}
		break
	}
	if !changed {
		return nil
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// backfillPocRefs 按 poc_files 里的文件逐个回填 finding id。
func (t *ToolSet) backfillPocRefs(names []string, findingID int64) {
	dir, err := t.pocDir()
	if err != nil {
		return
	}
	for _, name := range names {
		if err := backfillPocIndexFinding(dir, name, findingID); err != nil {
			log.Printf("[poc] 回填 INDEX 失败 %s: %v", name, err)
		}
	}
}

// validatePocFiles 校验 poc_files 里的每个文件都已落盘，返回规范化后的单层文件名。
// 这是漏洞与 PoC 的唯一关联方式（结构化），不再解析 evidence 文本。
func (t *ToolSet) validatePocFiles(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	dir, err := t.pocDir()
	if err != nil {
		return nil, fmt.Errorf("poc_files 需要任务上下文：%v", err)
	}
	out := make([]string, 0, len(names))
	var missing []string
	for _, raw := range names {
		name, err := cleanPocName(raw)
		if err != nil {
			return nil, err
		}
		if st, err := os.Stat(filepath.Join(dir, name)); err != nil || st.IsDir() {
			missing = append(missing, name)
			continue
		}
		out = append(out, name)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("poc_files 里的文件不存在：%s。先用 save_poc 落盘（它返回 path），把文件名传进来",
			strings.Join(missing, "、"))
	}
	return out, nil
}

// savePoc 是 PoC 落盘工具：路径、目录、索引全由代码决定。
func (t *ToolSet) savePoc() actool.CoreTool {
	return writeTool(
		"save_poc",
		"把已复现漏洞的 PoC 存成本任务的 PoC 文件，并自动登记到 poc/INDEX.md。\n"+
			"不要用 shell 重定向自己写文件——路径写错会让复测跑不起来。\n"+
			"写完把文件名填进 report_finding 的 poc_files 参数（工具会校验文件存在，缺了就登记失败）。\n"+
			"name 只接受单层文件名，扩展名限 .py/.sh/.c/.js/.rb/.txt/.http/.md；同名覆盖。\n"+
			"返回：{path, absolute_path, bytes}",
		obj(map[string]any{
			"name":         str("文件名，例如 cgi_inject.py"),
			"content":      str("PoC 正文（完整可运行脚本/命令序列/payload）"),
			"summary":      str("一句话漏洞（写进 INDEX.md）"),
			"component":    str("受影响组件名（可带版本，如 lighttpd 1.4.35）"),
			"finding_id":   idp("可选：已登记漏洞 id；先报漏洞再存 PoC 时填，便于索引关联"),
			"component_id": idp("可选：受影响组件 id（仅用于校验/提示，不改变索引格式）"),
		}, "name", "content"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name        string `json:"name"`
				Content     string `json:"content"`
				Summary     string `json:"summary"`
				Component   string `json:"component"`
				FindingID   int64  `json:"finding_id"`
				ComponentID int64  `json:"component_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			name, err := cleanPocName(a.Name)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(a.Content) == "" {
				return actool.Errorf("content 不能为空：PoC 必须能照做复现"), nil
			}
			dir, err := t.pocDir()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return actool.Errorf(fmt.Sprintf("创建 PoC 目录失败: %v", err)), nil
			}
			path := filepath.Join(dir, name)
			// 覆盖提示：同名文件已存在时如实告诉模型，别让它以为又新建了一份。
			overwritten := ""
			if st, err := os.Stat(path); err == nil && !st.IsDir() {
				overwritten = fmt.Sprintf("覆盖了已有文件（原 %d 字节，修改于 %s）", st.Size(), st.ModTime().Format("2006-01-02 15:04"))
			}
			if err := os.WriteFile(path, []byte(a.Content), 0o644); err != nil {
				return actool.Errorf(fmt.Sprintf("写入 PoC 失败: %v", err)), nil
			}
			component := strings.TrimSpace(a.Component)
			if component == "" && a.ComponentID > 0 && t.as != nil {
				if cs, err := t.as.GetByIDs([]int64{a.ComponentID}); err == nil && len(cs) > 0 {
					component = cs[0].ComponentName
					if cs[0].Version != "" {
						component += " " + cs[0].Version
					}
				}
			}
			if err := upsertPocIndex(dir, name, component, strings.TrimSpace(a.Summary), a.FindingID); err != nil {
				return actool.Errorf(fmt.Sprintf("更新 poc/INDEX.md 失败: %v", err)), nil
			}
			out := map[string]any{
				"path":          "poc/" + name,
				"absolute_path": path,
				"bytes":         len(a.Content),
			}
			if overwritten != "" {
				out["overwritten"] = true
				out["note"] = overwritten + "；poc_files 里填这个名字仍指向这一份"
			}
			return jsonResult(out)
		})
}

// =====================================================================
// 经验沉淀与检索：write_experience / read_experience
// =====================================================================
//
// 每条意图结束时把这一轮的"经验"写在自己的节点上（exploration_nodes.experience），
// read_experience 再按自然语言 query 从本任务的这些经验里检索、压缩后返回。
// 设计见 意图经验沉淀与检索-设计方案.md。

const (
	// maxExperienceRunes caps one note. Every later retrieval reads these in bulk, so
	// an unbounded blob would poison the whole experience pool; 8KB is far above a
	// useful note (four sections, a few commands) and still bounded.
	maxExperienceRunes = 8192
	// read_experience is a real model call: bound it per run, bound the candidate
	// window handed to the model, and bound what comes back to the worker.
	experienceReadsPerRun   = 3
	experienceCandidatesMax = 200
	experienceCandidates    = 30
	experienceCandidateChar = 800
	experienceDigestLimit   = 5
	experienceDigestRunes   = 6000
	experienceReadTimeout   = 45 * time.Second
	experienceCacheTTL      = 10 * time.Minute
	// experienceWorkerLane labels these calls in llm_usage so the config page can
	// report the retrieval spend apart from the worker's own tokens.
	experienceWorkerLane = "experience"
)

// writeExperience stores the note distilled at the end of the current intent.
// It is a write tool on the intent node the worker claimed (ownerNode).
func (t *ToolSet) writeExperience() actool.CoreTool {
	return t.writeExpTool(
		"write_experience",
		"把本轮执行沉淀成经验，写在你当前这条意图上（**收尾前必须写，没写经验的本轮不算完成**）。\n"+
			"重跑会覆盖旧经验，不必担心重复。按四段写：\n"+
			"① 表面：打了哪个组件 / 入口 / 文件（原始路径、URL、端口）\n"+
			"② 结论：成还是没成，原因是什么（失败经验同样有价值，写清卡在哪）\n"+
			"③ 可复用手法：具体命令、路径、参数、判据（原样照抄，别概括）\n"+
			"④ 坑：浪费时间的弯路、看错的信号\n"+
			"返回 {ok, intent, chars, replaced, prev_chars}",
		obj(map[string]any{
			"experience": str("本轮经验正文，按四段模板写；命令/路径/参数保持原文"),
		}, "experience"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Experience string `json:"experience"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			text := strings.TrimSpace(a.Experience)
			if text == "" {
				return actool.Errorf("experience 不能为空：把这一轮的结论、可复用手法、踩过的坑写下来"), nil
			}
			if n := len([]rune(text)); n > maxExperienceRunes {
				return actool.Errorf(fmt.Sprintf("experience 过长(%d 字)，上限 %d 字：只留可复用的结论与命令", n, maxExperienceRunes)), nil
			}
			if t.ownerNode <= 0 {
				return actool.Errorf("write_experience 需要意图上下文（当前没有绑定意图）"), nil
			}
			if t.ts == nil {
				return actool.Errorf("write_experience 需要探索库（当前没有任务上下文）"), nil
			}
			prev, err := t.ts.SetIntentExperience(t.ownerNode, text)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			t.writes.Experience++
			return jsonResult(map[string]any{
				"ok":         true,
				"intent":     t.ownerNode,
				"chars":      len([]rune(text)),
				"replaced":   prev > 0,
				"prev_chars": prev,
			})
		},
	)
}

// readExperience searches this task's stored experience. The query is natural
// language; the tool picks candidates locally (no tokens), then makes ONE model
// call to select + compress them, then returns the digest.
func (t *ToolSet) readExperience() actool.CoreTool {
	return t.readExpTool(
		"read_experience",
		"检索本任务历史意图沉淀下来的经验。query 用自然语言说明你想找哪方面的经验"+
			"（例如「mini_httpd 认证绕过相关的经验」「有没有人试过固件升级入口」）。\n"+
			"内部会读取本任务全部经验，用模型筛出相关的并梳理压缩后返回；命令、路径、参数保留原文。\n"+
			"返回 {experiences:[{intent_id, summary, digest}], note}；没有相关经验时 experiences 为空，"+
			"note 会说明原因（含检索不可用时）。本工具只读本任务，不跨任务。",
		obj(map[string]any{
			"query": str("想找哪方面的经验，一句话自然语言即可"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query string `json:"query"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			query := strings.TrimSpace(a.Query)
			if query == "" {
				return actool.Errorf("query 不能为空：用一句话说你想要哪方面的经验"), nil
			}
			if t.ts == nil {
				return jsonResult(map[string]any{"experiences": []any{}, "note": "经验检索不可用（当前没有任务上下文）"})
			}
			if t.prov == nil {
				return jsonResult(map[string]any{"experiences": []any{}, "note": "经验检索不可用（未配置模型）"})
			}
			if t.expReads >= experienceReadsPerRun {
				return jsonResult(map[string]any{
					"experiences": []any{},
					"note":        fmt.Sprintf("本轮已达经验检索上限（%d 次），请按已获得的信息继续", experienceReadsPerRun),
				})
			}
			rows, err := t.ts.IntentExperiences(experienceCandidatesMax)
			if err != nil {
				log.Printf("[experience] 读取经验失败 exp=%d: %v", t.ts.ID(), err)
				return jsonResult(map[string]any{"experiences": []any{}, "note": "读取经验失败，请按当前上下文继续"})
			}
			if len(rows) == 0 {
				return jsonResult(map[string]any{"experiences": []any{}, "note": "本任务暂无经验（还没有意图写过经验）"})
			}
			key := experienceCacheKey(t.ts.ID(), query)
			if cached, ok := experienceCacheGet(key); ok {
				return actool.Text(cached), nil
			}
			cands := preselectExperience(rows, query, experienceCandidates)
			t.expReads++
			req := llm.CompletionRequest{
				System:    []string{experienceReadSystemPrompt},
				Messages:  []llm.Message{llm.UserText(buildExperienceReadInput(query, cands))},
				MaxTokens: 1500,
				Thinking:  "disabled", // retrieval is a lookup, not a reasoning step
			}
			rctx, cancel := context.WithTimeout(ctx, experienceReadTimeout)
			defer cancel()
			// Session id + lane: the provider is the llmrec-wrapped one, so this call
			// is metered into llm_usage and written to the task transcript on its own
			// lane instead of being mixed into the worker's own turns.
			rctx = transcript.WithSessionID(rctx, fmt.Sprintf("exp%d-experience-read", t.ts.ID()))
			if t.taskID > 0 {
				rctx = llmrec.WithTaskID(rctx, strconv.FormatInt(t.taskID, 10))
			}
			rctx = llmrec.WithWorker(rctx, experienceWorkerLane)
			msg, _, _, callErr := t.prov.Complete(rctx, req)
			if callErr != nil {
				log.Printf("[experience] 经验检索失败 exp=%d: %v", t.ts.ID(), callErr)
				return jsonResult(map[string]any{"experiences": []any{}, "note": "经验检索不可用，请按当前上下文继续"})
			}
			payload := buildExperienceDigest(msg.Text(), cands)
			body, mErr := json.Marshal(payload)
			if mErr != nil {
				return jsonResult(map[string]any{"experiences": []any{}, "note": "经验检索结果解析失败，请按当前上下文继续"})
			}
			experienceCachePut(key, string(body))
			return actool.Text(string(body)), nil
		},
	)
}

// experienceCache memoizes retrieval results per (task, normalized query). Two
// workers asking the same thing in the same task should not pay twice; the entries
// are tiny and expire, so this stays a bounded map with no eviction LRU.
type experienceCacheEntry struct {
	body   string
	expire time.Time
}

var experienceCache = struct {
	mu sync.Mutex
	m  map[string]experienceCacheEntry
}{m: map[string]experienceCacheEntry{}}

func experienceCacheKey(expID int64, query string) string {
	return strconv.FormatInt(expID, 10) + "|" + strings.ToLower(strings.Join(strings.Fields(query), " "))
}

func experienceCacheGet(key string) (string, bool) {
	experienceCache.mu.Lock()
	defer experienceCache.mu.Unlock()
	e, ok := experienceCache.m[key]
	if !ok || time.Now().After(e.expire) {
		if ok {
			delete(experienceCache.m, key)
		}
		return "", false
	}
	return e.body, true
}

func experienceCachePut(key, body string) {
	experienceCache.mu.Lock()
	defer experienceCache.mu.Unlock()
	if len(experienceCache.m) > 512 { // crude cap: retrieval results are disposable
		for k := range experienceCache.m {
			delete(experienceCache.m, k)
			break
		}
	}
	experienceCache.m[key] = experienceCacheEntry{body: body, expire: time.Now().Add(experienceCacheTTL)}
}

// experienceShingles turns text into检索用的 shingles: ASCII words (>=2 chars) and
// CJK bigrams. Chinese notes have no spaces, so word splitting alone would score
// every Chinese query as zero-overlap and always fall back to "newest N".
func experienceShingles(s string) map[string]struct{} {
	out := make(map[string]struct{})
	var word []rune
	var prevHan rune
	flush := func() {
		if len(word) >= 2 {
			out[string(word)] = struct{}{}
		}
		word = word[:0]
	}
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.Is(unicode.Han, r):
			flush()
			if prevHan != 0 {
				out[string([]rune{prevHan, r})] = struct{}{}
			}
			prevHan = r
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			prevHan = 0
			word = append(word, r)
		default:
			prevHan = 0
			flush()
		}
	}
	flush()
	return out
}

// preselectExperience ranks this task's notes against the query by shingle overlap
// and returns at most limit of them (newest first on ties / no signal at all).
// Pure local computation — it exists so the model never sees 200 notes at once.
func preselectExperience(rows []db.ExperienceRow, query string, limit int) []db.ExperienceRow {
	if limit <= 0 || limit > len(rows) {
		limit = len(rows)
	}
	q := experienceShingles(query)
	type scored struct {
		row   db.ExperienceRow
		score float64
	}
	out := make([]scored, 0, len(rows))
	for _, r := range rows {
		doc := experienceShingles(r.Summary + "\n" + r.Experience)
		hit := 0
		for t := range q {
			if _, ok := doc[t]; ok {
				hit++
			}
		}
		score := 0.0
		if len(q) > 0 {
			score = float64(hit) / float64(len(q))
		}
		out = append(out, scored{row: r, score: score})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].score > out[j].score })
	picked := make([]db.ExperienceRow, 0, limit)
	for _, s := range out[:limit] {
		picked = append(picked, s.row)
	}
	return picked
}

// buildExperienceReadInput renders the retrieval prompt: the query plus the
// preselected candidates, each truncated so 30 notes still fit a modest budget.
func buildExperienceReadInput(query string, cands []db.ExperienceRow) string {
	var b strings.Builder
	b.WriteString("【想找的经验】\n")
	b.WriteString(query)
	fmt.Fprintf(&b, "\n\n【本任务已沉淀的经验（候选 %d 条，按相关度排序）】\n", len(cands))
	for _, c := range cands {
		fmt.Fprintf(&b, "\n### intent #%d · %s\n", c.IntentID, strings.TrimSpace(c.Summary))
		b.WriteString(truncateRunes(c.Experience, experienceCandidateChar))
		b.WriteByte('\n')
	}
	return b.String()
}

// buildExperienceDigest turns the model's JSON answer into the tool result, and is
// where the hard caps live: unknown intent ids are dropped (the model may invent
// one), at most experienceDigestLimit entries survive, and the total body is capped.
// summaries come from the DB row, never from the model, so a hallucinated summary
// cannot masquerade as a real past intent.
func buildExperienceDigest(raw string, cands []db.ExperienceRow) map[string]any {
	byID := make(map[int64]db.ExperienceRow, len(cands))
	for _, c := range cands {
		byID[c.IntentID] = c
	}
	var parsed struct {
		Experiences []struct {
			IntentID int64  `json:"intent_id"`
			Digest   string `json:"digest"`
		} `json:"experiences"`
		Note string `json:"note"`
	}
	if err := json.Unmarshal([]byte(jsonPayload(raw)), &parsed); err != nil {
		return map[string]any{
			"experiences": []any{},
			"note":        "经验检索结果无法解析，请按当前上下文继续",
		}
	}
	out := make([]map[string]any, 0, experienceDigestLimit)
	total := 0
	for _, e := range parsed.Experiences {
		row, ok := byID[e.IntentID]
		if !ok {
			continue // hallucinated / out-of-window id: drop it
		}
		digest := strings.TrimSpace(e.Digest)
		if digest == "" {
			continue
		}
		// 预算按 rune 计：truncateRunes 也按 rune 截，单位必须一致，否则中文会超预算
		// 最多 3 倍（1 rune = 3 bytes）。
		if len(out) >= experienceDigestLimit || total >= experienceDigestRunes {
			break
		}
		digest = truncateRunes(digest, experienceDigestRunes-total)
		if strings.TrimSpace(digest) == "" { // 预算刚好耗尽：不塞空条目
			break
		}
		total += len([]rune(digest))
		out = append(out, map[string]any{
			"intent_id": row.IntentID,
			"node_id":   row.IntentID, // same node: worker can node_detail() for the raw note
			"summary":   strings.TrimSpace(row.Summary),
			"digest":    digest,
		})
	}
	note := strings.TrimSpace(parsed.Note)
	if len(out) == 0 {
		if note == "" {
			note = "无相关经验"
		}
		return map[string]any{"experiences": []any{}, "note": note, "candidates": len(cands)}
	}
	if len(parsed.Experiences) > len(out) {
		note = strings.TrimSpace(note + fmt.Sprintf("（还有 %d 条命中未返回，需要时缩小 query）", len(parsed.Experiences)-len(out)))
	}
	return map[string]any{"experiences": out, "note": note, "candidates": len(cands)}
}

// jsonPayload extracts the outermost JSON object from a model answer, tolerating
// code fences and leading prose ("```json {…} ```" is common even when asked not to).
func jsonPayload(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "{"); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndex(s, "}"); j >= 0 && j+1 <= len(s) {
		s = s[:j+1]
	}
	return s
}

// truncateRunes cuts s to at most n runes without splitting a multi-byte character.
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
