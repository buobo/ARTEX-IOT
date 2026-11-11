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
	where, args := f.where()
	rows, err := d.Query(`SELECT component_ids, status FROM findings WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[int64]int{}
	var total int
	for rows.Next() {
		var raw []byte
		var status string
		if err := rows.Scan(&raw, &status); err != nil {
			return nil, err
		}
		total++
		if status == "ignored" || status == "false_positive" {
			continue
		}
		var ids []int64
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &ids)
		}
		for _, id := range ids {
			if id > 0 {
				counts[id]++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tree := &FindingComponentTree{Total: total}
	if len(counts) == 0 {
		return tree, nil
	}

	ids := make([]int64, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	comps, err := d.Components().GetByIDs(ids)
	if err != nil {
		return nil, err
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
	return tree, nil
}
