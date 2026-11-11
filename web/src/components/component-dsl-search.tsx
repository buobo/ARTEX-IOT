"use client";

import * as React from "react";

import { SearchIcon } from "lucide-react";

import { Input } from "@/components/ui/input";

// 组件 DSL 的字段表：与 db/component_dsl.go 的 known*Fields 一一对应。
// 用途只是补全/帮助，不承担校验——真校验在后端，写错字段后端会报错。
const DSL_FIELDS: { field: string; ops: string[]; note: string }[] = [
  { field: "component_name", ops: ["=", "==", "!="], note: "组件名（lighttpd / mosquitto / roscore），= 模糊、== 精确" },
  { field: "type", ops: ["=="], note: "组件类型，也可用左侧下拉过滤" },
  { field: "version", ops: ["=", "==", "!="], note: "版本号（只在确知时有值）" },
  { field: "vendor", ops: ["=", "=="], note: "厂商" },
  { field: "binary_path", ops: ["=", "=="], note: "可执行文件路径" },
  { field: "config_path", ops: ["=", "=="], note: "配置文件路径" },
  { field: "started_by", ops: ["=", "=="], note: "启动脚本（/etc/init.d/xxx）" },
  { field: "status", ops: ["==", "!="], note: "pending | running | completed | ignored" },
  { field: "firmware_sha256", ops: ["==", "="], note: "固件 sha256" },
  { field: "technology", ops: ["=", "=="], note: "依赖/特征（数组）" },
  { field: "port", ops: [">", ">=", "<", "<=", "=="], note: "主监听端口（整数）" },
];

export function ComponentDslSearch({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const [open, setOpen] = React.useState(false);
  const [draft, setDraft] = React.useState(value);

  React.useEffect(() => setDraft(value), [value]);

  const apply = () => {
    onChange(draft.trim());
    setOpen(false);
  };

  return (
    <div className="relative">
      <div className="flex items-center gap-2">
        <SearchIcon className="text-muted-foreground size-4 shrink-0" />
        <Input
          value={draft}
          placeholder={placeholder ?? "DSL 查询，如 component_name=lighttpd AND port==80"}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") apply();
          }}
          className="font-mono text-xs"
        />
        <button
          type="button"
          className="text-muted-foreground hover:text-foreground text-xs underline underline-offset-4"
          onClick={() => setOpen((o) => !o)}
        >
          字段
        </button>
      </div>

      {open && (
        <div className="bg-popover absolute top-full left-0 z-30 mt-2 w-full rounded-md border p-3 text-xs shadow-lg">
          <p className="text-muted-foreground mb-2">
            语法：<code>field=值</code> 模糊 / <code>field==值</code> 精确 / <code>field!=值</code> 排除；
            数字支持 <code>&gt; &gt;= &lt; &lt;=</code>；裸词全文模糊；AND 优先于 OR，可加括号。
          </p>
          <div className="grid gap-1">
            {DSL_FIELDS.map((f) => (
              <div key={f.field} className="flex items-baseline gap-2">
                <button
                  type="button"
                  className="hover:text-foreground font-mono text-[11px] text-sky-400"
                  onClick={() => setDraft((d) => (d ? `${d} AND ${f.field}==` : `${f.field}==`))}
                >
                  {f.field}
                </button>
                <span className="text-muted-foreground font-mono text-[11px]">{f.ops.join(" ")}</span>
                <span className="text-muted-foreground">{f.note}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
