package db

import (
	"encoding/json"
	"fmt"
	"sort"
)

// =====================================================================
// 漏洞 → 组件 的树
// =====================================================================
//
// 原实现是「公司 → 根域 → 子域 → 服务 → 端点」的资产树。资产下线后，树只剩两层：
// 组件类型 → 组件，每个组件节点带命中漏洞数。前端按同样结构渲染即可。

// FindingComponentNode 是树节点：kind=组件类型（分组）或 "component"（叶子）。
type FindingComponentNode struct {
	Key          string                  `json:"key"`
	Kind         string                  `json:"kind"`
	Label        string                  `json:"label"`
	ComponentID  int64                   `json:"component_id,omitempty"`
	Status       string                  `json:"status,omitempty"`
	Version      string                  `json:"version,omitempty"`
	FindingCount int                     `json:"finding_count"`
	Children     []*FindingComponentNode `json:"children,omitempty"`
}

// FindingComponentTree 是整棵树。
type FindingComponentTree struct {
	Nodes     []*FindingComponentNode `json:"nodes"`
	Total     int                     `json:"total"`
	Truncated bool                    `json:"truncated"`
}

// BuildFindingComponentTree 按筛选条件统计「漏洞 → 组件」分布。
func (d *DB) BuildFindingComponentTree(f FindingFilter) (*FindingComponentTree, error) {
	// where() 自带前缀 " WHERE ..."（无筛选时为空串），FROM 里必须给 findings 起别名 f，
	// 因为筛选条件用的是 f.status / t.id 这类带别名的列。
	where, args := f.where()
	rows, err := d.Query(`SELECT f.component_ids FROM findings f
LEFT JOIN tasks t ON t.id = f.task_id`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 先收集每条漏洞的组件 id，等组件表查完再判定「未关联」——引用了已删除组件的
	// 漏洞同样算未关联，跟列表页 component_none 筛选口径一致。
	var perFinding [][]int64
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ids []int64
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &ids)
		}
		kept := make([]int64, 0, len(ids))
		for _, id := range ids {
			if id > 0 {
				kept = append(kept, id)
			}
		}
		perFinding = append(perFinding, kept)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tree := &FindingComponentTree{}
	allIDs := map[int64]bool{}
	for _, ids := range perFinding {
		for _, id := range ids {
			allIDs[id] = true
		}
	}
	var comps []*Component
	if len(allIDs) > 0 {
		comps, err = d.Components().GetByIDs(mapKeys(allIDs))
		if err != nil {
			return nil, err
		}
	}
	live := make(map[int64]bool, len(comps))
	for _, c := range comps {
		live[c.ID] = true
	}
	counts := map[int64]int{}
	unassigned := 0
	for _, ids := range perFinding {
		matched := false
		for _, id := range ids {
			if live[id] {
				counts[id]++
				matched = true
			}
		}
		if !matched {
			unassigned++
		}
		tree.Total++
	}

	groups := map[string]*FindingComponentNode{}
	for _, c := range comps {
		g, ok := groups[c.Type]
		if !ok {
			g = &FindingComponentNode{Key: "t:" + c.Type, Kind: c.Type, Label: c.Type}
			groups[c.Type] = g
		}
		g.Children = append(g.Children, &FindingComponentNode{
			Key:          fmt.Sprintf("a:%d", c.ID),
			Kind:         "component",
			Label:        c.ComponentName,
			ComponentID:  c.ID,
			Status:       c.Status,
			Version:      c.Version,
			FindingCount: counts[c.ID],
		})
		g.FindingCount += counts[c.ID]
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := groups[k]
		sort.SliceStable(g.Children, func(i, j int) bool {
			if g.Children[i].FindingCount != g.Children[j].FindingCount {
				return g.Children[i].FindingCount > g.Children[j].FindingCount
			}
			return g.Children[i].Label < g.Children[j].Label
		})
		tree.Nodes = append(tree.Nodes, g)
	}
	if unassigned > 0 {
		tree.Nodes = append(tree.Nodes, &FindingComponentNode{
			Key:          "__none__",
			Kind:         "none",
			Label:        "未关联",
			FindingCount: unassigned,
		})
	}
	return tree, nil
}

// mapKeys 取 map[int64]bool 的键（给 GetByIDs 用）。
func mapKeys(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
