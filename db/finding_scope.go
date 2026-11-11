package db

import (
	"strconv"
	"strings"
)

// componentIDContainments 把组件 id 列表转成 jsonb containment 片段：
// 组件 id 5 → "[5]"，用于 component_ids @> ANY($n::jsonb[])。
func componentIDContainments(ids []int64) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		out = append(out, "["+strconv.FormatInt(id, 10)+"]")
	}
	return out
}

// applyComponentScope 把前端的筛选节点 key 解析成组件 id 集：
//   __none__  只看未关联组件的漏洞
//   a:<id>    单个组件
//   t:<type>  某类组件（web/mqtt/…）
// 解析不到组件时置 componentMiss，保证结果为空而不是全量。
func (d *DB) applyComponentScope(f FindingFilter) (FindingFilter, error) {
	scope := strings.TrimSpace(f.ComponentScope)
	if scope == "" {
		return f, nil
	}
	if scope == "__none__" {
		f.componentNone = true
		return f, nil
	}
	if strings.HasPrefix(scope, "a:") {
		id, err := strconv.ParseInt(strings.TrimPrefix(scope, "a:"), 10, 64)
		if err != nil || id <= 0 {
			f.componentMiss = true
			return f, nil
		}
		f.componentIDs = []int64{id}
		return f, nil
	}
	if strings.HasPrefix(scope, "t:") {
		typ := strings.TrimPrefix(scope, "t:")
		rows, err := d.Query(`SELECT id FROM components WHERE type = $1`, typ)
		if err != nil {
			return f, err
		}
		defer rows.Close()
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return f, err
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			f.componentMiss = true
			return f, nil
		}
		f.componentIDs = ids
		return f, nil
	}
	// 旧格式（c:/r: 等资产节点）已无对应实体
	f.componentMiss = true
	return f, nil
}
