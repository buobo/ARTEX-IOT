package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
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
		t.insertComponents(), t.listComponents(), t.setComponentStatus(),
		// 跨 work 回看：worker 也可复用其他 work 的观察，避免重复劳动。
		// search_all_worker_traces：不必先知道 intent_id，按关键字全局捞命中步骤；
		// get_worker_trace：锁定某条 work 后列步骤/就地搜/取完整内容。
		t.searchAllWorkerTraces(), t.getWorkerTrace(),
		// node_detail：worker 拿到 intent_id/节点 id 后可查该节点完整详情（配合上面的回看）。
		t.nodeDetail(),
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
		t.addFinding(), t.recordFact(),
		t.addTaskScope(),
		// list_untested_components：按需查本任务范围内未测组件(类型+分页)，自行决定补测。
		t.listUntestedComponents(),
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
