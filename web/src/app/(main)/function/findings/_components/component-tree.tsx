"use client";

import * as React from "react";

import {
  ChevronRightIcon,
  CircleDashedIcon,
  ContainerIcon,
  NetworkIcon,
  PackageIcon,
  RefreshCwIcon,
  SearchIcon,
  TerminalIcon,
  WaypointsIcon,
  type LucideIcon,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import type { FindingComponentNode } from "@/lib/types";
import { cn } from "@/lib/utils";

// 组件类型 → 图标。跟组件库页保持一致的视觉语言。
const TYPE_ICON: Record<string, LucideIcon> = {
  web: NetworkIcon,
  mqtt: WaypointsIcon,
  ros: ContainerIcon,
  ssh: TerminalIcon,
  telnet: TerminalIcon,
  upnp: WaypointsIcon,
  onvif: NetworkIcon,
  rtsp: NetworkIcon,
  ftp: PackageIcon,
  other: PackageIcon,
};

const KIND_LABEL: Record<string, string> = {
  type: "组件类型",
  component: "组件",
  none: "未关联",
};

interface TreeNode extends FindingComponentNode {
  children: TreeNode[];
  depth: number;
}

// build 把后端返回的嵌套节点（type → component）补上深度，供缩进渲染。
function build(nodes: FindingComponentNode[], depth = 0): TreeNode[] {
  return nodes.map((n) => ({
    ...n,
    depth,
    children: build(n.children ?? [], depth + 1),
  }));
}

export function ComponentTree({
  nodes,
  selected,
  onSelect,
  loading,
  truncated,
  findingTotal,
  onRefresh,
}: {
  nodes: FindingComponentNode[];
  selected: string | null;
  onSelect: (key: string | null) => void;
  loading: boolean;
  truncated?: boolean;
  droppedKinds?: string[];
  findingTotal: number;
  onRefresh?: () => void;
}) {
  const [keyword, setKeyword] = React.useState("");
  const [collapsed, setCollapsed] = React.useState<Set<string>>(() => new Set());

  const tree = React.useMemo(() => build(nodes), [nodes]);

  const visible = React.useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    if (!kw) return tree;
    const match = (n: TreeNode): boolean =>
      n.label.toLowerCase().includes(kw) || n.children.some(match);
    return tree.filter(match);
  }, [tree, keyword]);

  const toggle = (key: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const rows: React.ReactNode[] = [];
  const push = (list: TreeNode[]) => {
    for (const node of list) {
      const open = !collapsed.has(node.key);
      rows.push(
        <Row
          key={node.key}
          node={node}
          open={open}
          selected={selected === node.key}
          onToggle={() => toggle(node.key)}
          onSelect={() => onSelect(selected === node.key ? null : node.key)}
        />,
      );
      if (open && node.children.length) push(node.children);
    }
  };
  push(visible);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex items-center gap-1">
        <InputGroup className="flex-1">
          <InputGroupInput
            type="search"
            value={keyword}
            onChange={(event) => setKeyword(event.target.value)}
            placeholder="过滤组件"
            aria-label="过滤组件"
          />
          <InputGroupAddon>
            <SearchIcon aria-hidden="true" />
          </InputGroupAddon>
        </InputGroup>
        {onRefresh && (
          <Button
            size="icon"
            variant="ghost"
            className="text-muted-foreground size-8 shrink-0"
            onClick={onRefresh}
            disabled={loading}
            aria-label="刷新组件树"
            title="刷新组件树"
          >
            <RefreshCwIcon className={cn("size-4", loading && "animate-spin")} />
          </Button>
        )}
      </div>

      <button
        type="button"
        onClick={() => onSelect(null)}
        className={cn(
          "flex items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-sm",
          selected === null ? "bg-accent font-medium" : "hover:bg-accent/50",
        )}
      >
        <span>全部组件</span>
        <span className="text-muted-foreground text-xs tabular-nums">{findingTotal}</span>
      </button>

      <div className="max-h-[24rem] min-h-0 flex-1 overflow-y-auto pr-2 lg:max-h-[calc(100vh-16rem)]">
        <div className="flex flex-col">
          {rows}
          {rows.length === 0 && (
            <p className="text-muted-foreground px-2 py-8 text-center text-xs">
              {loading ? "加载中…" : keyword ? "没有匹配的组件。" : "当前筛选下没有关联组件的发现。"}
            </p>
          )}
        </div>
      </div>

      {truncated && (
        <p className="text-muted-foreground px-1 text-xs">
          组件过多，已折叠部分层级（计数仍已计入上层）。用筛选或过滤框收窄可看到完整层级。
        </p>
      )}
    </div>
  );
}

function Row({
  node,
  open,
  selected,
  onToggle,
  onSelect,
}: {
  node: TreeNode;
  open: boolean;
  selected: boolean;
  onToggle: () => void;
  onSelect: () => void;
}) {
  const Icon = node.kind === "none" ? CircleDashedIcon : (TYPE_ICON[node.label.split(" ")[0]] ?? PackageIcon);
  const hasChildren = node.children.length > 0;
  return (
    <div
      className={cn(
        "group flex items-center gap-1 rounded-md pr-1 text-sm",
        selected ? "bg-accent" : "hover:bg-accent/50",
      )}
      style={{ paddingLeft: `${node.depth * 10}px` }}
    >
      {hasChildren ? (
        <button
          type="button"
          onClick={onToggle}
          className="text-muted-foreground hover:text-foreground flex size-5 shrink-0 items-center justify-center rounded"
          aria-label={open ? "折叠" : "展开"}
          aria-expanded={open}
        >
          <ChevronRightIcon className={cn("size-3.5 transition-transform", open && "rotate-90")} />
        </button>
      ) : (
        <span className="size-5 shrink-0" />
      )}
      <button
        type="button"
        onClick={onSelect}
        className="flex min-w-0 flex-1 items-center gap-1.5 py-1 text-left"
        title={`${KIND_LABEL[node.kind] ?? node.kind} · ${node.label}`}
      >
        <Icon className="text-muted-foreground size-3.5 shrink-0" aria-hidden="true" />
        <span className={cn("min-w-0 truncate", selected && "font-medium")}>{node.label}</span>
      </button>
      <span className="text-muted-foreground shrink-0 text-xs tabular-nums" title="命中漏洞数">
        {node.finding_count}
      </span>
    </div>
  );
}

// componentPathOf 返回从根到选中节点的路径（面包屑用）。
export function componentPathOf(nodes: FindingComponentNode[], key: string | null): FindingComponentNode[] {
  if (!key) return [];
  const walk = (list: FindingComponentNode[], trail: FindingComponentNode[]): FindingComponentNode[] | null => {
    for (const n of list) {
      const next = [...trail, n];
      if (n.key === key) return next;
      const hit = walk(n.children ?? [], next);
      if (hit) return hit;
    }
    return null;
  };
  return walk(nodes, []) ?? [];
}
