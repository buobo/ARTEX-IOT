"use client";

import * as React from "react";
import type { Graph as G6Graph } from "@antv/g6";
import {
  Boxes,
  Package,
  AppWindow,
  Building2,
  Globe,
  Link2,
  type LucideIcon,
  Radio,
  RefreshCw,
  Terminal,
  Server,
  Waypoints,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { api } from "@/lib/api";
import type { CoverageComponentRef, CoverageComponentRefs, CoverageGraphEdge, CoverageGraphNode } from "@/lib/types";
import { cn } from "@/lib/utils";

// 每个父节点下、同一类型的子节点默认展示的数量；超出折叠，"展示更多"每次再拉这么多。
const FOLD_LIMIT = 20;
const FOLD_STEP = 20;

// kind 是组件类型名（web/mqtt/...）或叶子 "component"。
type Kind = string;

type KindMeta = { label: string; icon: LucideIcon; iconBg: string; hex: string; size: number };

const LEAF_META: KindMeta = { label: "组件", icon: Package, iconBg: "bg-emerald-600", hex: "#059669", size: 26 };

// 分组节点按组件类型着色，跟组件库页的类型语义一致。
const TYPE_META: Record<string, KindMeta> = {
  web: { label: "Web 服务", icon: Globe, iconBg: "bg-sky-600", hex: "#0284c7", size: 40 },
  mqtt: { label: "MQTT", icon: Waypoints, iconBg: "bg-violet-600", hex: "#7c3aed", size: 40 },
  ros: { label: "ROS", icon: Boxes, iconBg: "bg-indigo-600", hex: "#4f46e5", size: 40 },
  ssh: { label: "SSH", icon: Terminal, iconBg: "bg-teal-600", hex: "#0d9488", size: 40 },
  telnet: { label: "Telnet", icon: Terminal, iconBg: "bg-lime-600", hex: "#65a30d", size: 40 },
  upnp: { label: "UPnP", icon: Radio, iconBg: "bg-cyan-600", hex: "#0891b2", size: 40 },
  onvif: { label: "ONVIF", icon: AppWindow, iconBg: "bg-fuchsia-600", hex: "#c026d3", size: 40 },
  rtsp: { label: "RTSP", icon: Link2, iconBg: "bg-rose-600", hex: "#e11d48", size: 40 },
  ftp: { label: "FTP", icon: Server, iconBg: "bg-amber-600", hex: "#d97706", size: 40 },
  other: { label: "其它", icon: Building2, iconBg: "bg-slate-600", hex: "#475569", size: 40 },
};

// metaOf 保证任何 kind 都有兜底，不再出现 undefined.label 的崩溃。
function metaOf(kind: string): KindMeta {
  if (kind === "component") return LEAF_META;
  return TYPE_META[kind] ?? { label: kind, icon: Boxes, iconBg: "bg-slate-500", hex: "#64748b", size: 36 };
}

// G6 节点图标用平台一致的 lucide 图标：把 lucide 的 SVG 路径（v1.22）渲染成白色描边的
// data URI，作为节点 iconSrc（白色在实色/灰色底上都清晰）。手写内嵌，避免 react-dom/server
// 在 React19/Next 客户端打包的问题。
function svgUri(inner: string, filled = false): string {
  const attrs = filled
    ? 'fill="#fff" stroke="none"'
    : 'fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" ${attrs}>${inner}</svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

const TYPE_ICON_SVG = svgUri(
  '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
);
const LEAF_ICON_SVG = svgUri(
  '<path d="M16 16h6"/><path d="M19 13v6"/><path d="M21 10V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l2-1.14"/>',
);
const KIND_ICON = (kind: string) => (kind === "component" ? LEAF_ICON_SVG : TYPE_ICON_SVG);

const FOLD_ICON = svgUri(
  '<circle cx="5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="19" cy="12" r="1.6"/>',
  true,
);

// ---------------------------------------------------------------------------
// Folding: full graph → currently-visible node/edge set (自顶向下级联折叠)。
// ---------------------------------------------------------------------------
type FoldNode = {
  fold: true;
  key: string;
  groupId: string;
  parentKey: string;
  kind: Kind;
  hidden: CoverageGraphNode[];
};
type AssetRenderNode = { fold: false; key: string; kind: Kind; node: CoverageGraphNode };
type RenderNode = AssetRenderNode | FoldNode;

function sortChildren(a: CoverageGraphNode, b: CoverageGraphNode): number {
  if (a.tested !== b.tested) return a.tested ? -1 : 1;
  return (a.label || "").localeCompare(b.label || "");
}

function computeVisible(
  nodes: CoverageGraphNode[],
  edges: CoverageGraphEdge[],
  expanded: Map<string, number>,
): { renderNodes: RenderNode[]; renderEdges: CoverageGraphEdge[] } {
  const byKey = new Map(nodes.map((n) => [n.key, n]));
  const parentOf = new Map<string, string>();
  const childrenOf = new Map<string, string[]>();
  for (const e of edges) {
    if (!byKey.has(e.src) || !byKey.has(e.dst)) continue;
    if (!parentOf.has(e.src)) parentOf.set(e.src, e.dst);
    const arr = childrenOf.get(e.dst);
    if (arr) arr.push(e.src);
    else childrenOf.set(e.dst, [e.src]);
  }

  const renderNodes: RenderNode[] = [];
  const visible = new Set<string>();
  const foldNodes: FoldNode[] = [];

  const queue: string[] = [];
  for (const n of nodes) {
    if (!parentOf.has(n.key)) {
      queue.push(n.key);
      visible.add(n.key);
    }
  }

  for (let qi = 0; qi < queue.length; qi++) {
    const parent = queue[qi];
    const kids = childrenOf.get(parent) ?? [];
    if (kids.length === 0) continue;
    const groups = new Map<Kind, CoverageGraphNode[]>();
    for (const ck of kids) {
      const cn = byKey.get(ck);
      if (!cn) continue;
      const g = groups.get(cn.kind);
      if (g) g.push(cn);
      else groups.set(cn.kind, [cn]);
    }
    for (const [kind, arr] of groups) {
      arr.sort(sortChildren);
      const groupId = `${parent}::${kind}`;
      const shown = expanded.get(groupId) ?? FOLD_LIMIT;
      const visibleChildren = arr.slice(0, shown);
      const hidden = arr.slice(shown);
      for (const c of visibleChildren) {
        if (!visible.has(c.key)) {
          visible.add(c.key);
          queue.push(c.key);
        }
      }
      if (hidden.length > 0) {
        foldNodes.push({ fold: true, key: `fold:${groupId}`, groupId, parentKey: parent, kind, hidden });
      }
    }
  }

  for (const n of nodes) {
    if (visible.has(n.key)) renderNodes.push({ fold: false, key: n.key, kind: n.kind, node: n });
  }
  const renderEdges: CoverageGraphEdge[] = edges.filter((e) => visible.has(e.src) && visible.has(e.dst));
  for (const f of foldNodes) {
    renderNodes.push(f);
    renderEdges.push({ src: f.key, dst: f.parentKey });
  }
  return { renderNodes, renderEdges };
}

// ---------------------------------------------------------------------------
// G6 数据映射。自定义字段放节点顶层（G6 v5 官方 force 示例约定：style/layout 回调直接读 d.<field>）。
// ---------------------------------------------------------------------------
type G6NodeDatum = {
  id: string;
  kind: Kind;
  fold: boolean;
  tested: boolean;
  inScope: boolean;
  lbl: string;
  size: number;
};

function trunc(s: string, n = 26): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

// 图里的节点文案：组件叶子用后端给的 label（组件名 + 版本），
// 类型分组用 TYPE_META 里的中文名（见 toG6Nodes）。
function graphLabel(n: CoverageGraphNode): string {
  return n.label;
}

function toG6Nodes(renderNodes: RenderNode[]): G6NodeDatum[] {
  return renderNodes.map((rn) => {
    if (rn.fold) {
      return {
        id: rn.key,
        kind: rn.kind,
        fold: true,
        tested: false,
        inScope: false,
        lbl: `还有 ${rn.hidden.length} 个${metaOf(rn.kind).label}`,
        size: 24,
      };
    }
    return {
      id: rn.key,
      kind: rn.kind,
      fold: false,
      tested: rn.node.tested,
      inScope: rn.node.in_scope,
      lbl: trunc(
        rn.node.kind === "component"
          ? graphLabel(rn.node) || metaOf(rn.kind).label
          : metaOf(rn.kind).label,
      ),
      size: metaOf(rn.kind).size,
    };
  });
}

// G6 的类型把自定义字段归在 data 下，但官方 force 示例（及运行时）按顶层读 d.<field>。
// 回调形参用 unknown 满足 G6 签名，内部用 nd() 强转回我们的顶层结构。
const nd = (d: unknown) => d as G6NodeDatum;

// 已测=实色高亮；范围内未测=灰；范围外/折叠=更淡的灰 + 虚线描边。
function nodeFill(d: G6NodeDatum): string {
  if (d.fold) return "#f1f5f9";
  if (!d.inScope) return "#e2e8f0";
  if (d.tested) return metaOf(d.kind).hex;
  return "#94a3b8";
}
function nodeStroke(d: G6NodeDatum): string {
  if (d.fold || !d.inScope) return "#94a3b8";
  if (d.tested) return "#0f766e";
  return "#64748b";
}

// ---------------------------------------------------------------------------
// 抽屉：组件节点看详情；折叠节点看隐藏列表 + "展示更多"。
// ---------------------------------------------------------------------------
function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  if (children === undefined || children === null || children === "") return null;
  return (
    <div className="flex items-start gap-3 py-1 text-sm">
      <span className="text-muted-foreground w-16 shrink-0">{label}</span>
      <span className="text-foreground min-w-0 flex-1 break-words">{children}</span>
    </div>
  );
}

function RefList({ title, items }: { title: string; items: CoverageComponentRef[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h4 className="text-muted-foreground mb-1 text-xs font-medium">
        {title}（{items.length}）
      </h4>
      <div className="flex flex-col gap-1">
        {items.map((r) => (
          <div
            key={`${r.kind}-${r.id}`}
            className="flex flex-wrap items-start gap-2 rounded-md bg-muted/50 px-2 py-1.5 text-xs"
          >
            <span className="shrink-0 font-mono text-muted-foreground">#{r.id}</span>
            {r.state && <span className="shrink-0 text-muted-foreground">{r.state}</span>}
            <span className="min-w-32 flex-1 break-words text-foreground">{r.summary || "—"}</span>
            {r.inherited && r.source_task_id && (
              <Badge variant="outline" className="shrink-0">
                来源 #{r.source_task_id} · 只读
              </Badge>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function AssetSheet({
  node,
  taskId,
  onOpenChange,
}: {
  node: CoverageGraphNode | null;
  taskId: string;
  onOpenChange: (open: boolean) => void;
}) {
  const meta = node ? metaOf(node.kind) : null;
  const Icon = meta?.icon;
  const raw = node ? JSON.stringify(node, null, 2) : "";
  const [refs, setRefs] = React.useState<CoverageComponentRefs | null>(null);

  React.useEffect(() => {
    setRefs(null);
    if (!node?.component_id) return;
    let cancelled = false;
    api
      .taskComponentRefs(taskId, node.component_id)
      .then((r) => {
        if (!cancelled) setRefs(r);
      })
      .catch(() => {
        /* 无关联或出错：不展示该区块 */
      });
    return () => {
      cancelled = true;
    };
  }, [node, taskId]);
  return (
    <Sheet open={node !== null} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 p-0 data-[side=right]:sm:max-w-md">
        {node && meta && Icon && (
          <>
            <SheetHeader className="border-b p-4">
              <div className="flex items-center gap-2.5 pr-8">
                <span className={cn("flex size-8 shrink-0 items-center justify-center rounded-lg shadow-sm", meta.iconBg)}>
                  <Icon className="size-4 text-white" />
                </span>
                <div className="min-w-0">
                  <SheetTitle className="leading-tight">{meta.label}</SheetTitle>
                  <span className="text-muted-foreground truncate font-mono text-xs" title={node.label}>
                    {node.kind === "component" ? node.label : `${meta.label}分组`}
                  </span>
                </div>
              </div>
            </SheetHeader>
            <ScrollArea className="min-h-0 flex-1">
              <div className="flex w-full min-w-0 flex-col gap-4 p-4">
                <section>
                  <h4 className="text-muted-foreground mb-1 text-xs font-medium">属性</h4>
                  <DetailRow label="类型">{meta.label}</DetailRow>
                  <DetailRow label="测试状态">
                    {node.in_scope ? (
                      node.tested ? (
                        <span className="text-emerald-600 dark:text-emerald-400">已测试</span>
                      ) : (
                        <span className="text-neutral-500">未测试</span>
                      )
                    ) : (
                      <span className="text-neutral-400">范围外（连接节点）</span>
                    )}
                  </DetailRow>
                  <DetailRow label="组件ID">
                    {node.component_id ? <span className="font-mono text-xs">{node.component_id}</span> : undefined}
                  </DetailRow>
                </section>
                {refs && (refs.intents.length > 0 || refs.facts.length > 0 || refs.findings.length > 0) && (
                  <section className="flex flex-col gap-3 border-t pt-3">
                    <RefList title="关联意图" items={refs.intents} />
                    <RefList title="关联事实" items={refs.facts} />
                    <RefList title="关联发现" items={refs.findings} />
                  </section>
                )}
                <section className="border-t pt-3">
                  <h4 className="text-muted-foreground mb-1.5 text-xs font-medium">原始数据</h4>
                  <pre className="bg-muted/50 text-foreground max-w-full overflow-hidden rounded-md border p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap">
                    {raw}
                  </pre>
                </section>
              </div>
            </ScrollArea>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function FoldSheet({
  fold,
  onOpenChange,
  onShowMore,
  onPick,
}: {
  fold: FoldNode | null;
  onOpenChange: (open: boolean) => void;
  onShowMore: (groupId: string) => void;
  onPick: (n: CoverageGraphNode) => void;
}) {
  const meta = fold ? metaOf(fold.kind) : null;
  const Icon = meta?.icon;
  return (
    <Sheet open={fold !== null} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 p-0 data-[side=right]:sm:max-w-md">
        {fold && meta && Icon && (
          <>
            <SheetHeader className="border-b p-4">
              <SheetTitle className="text-base">
                未展示的{meta.label}（{fold.hidden.length}）
              </SheetTitle>
              <p className="text-muted-foreground text-xs">已测优先展示。点「展示更多」把下一批拉进图里。</p>
            </SheetHeader>
            <ScrollArea className="min-h-0 flex-1">
              <div className="flex flex-col gap-1 p-3">
                {fold.hidden.map((n) => (
                  <button
                    key={n.key}
                    type="button"
                    onClick={() => onPick(n)}
                    className="hover:bg-accent flex items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm"
                  >
                    <span
                      className={cn(
                        "flex size-5 shrink-0 items-center justify-center rounded",
                        n.tested ? meta.iconBg : "bg-neutral-400 dark:bg-neutral-600",
                      )}
                    >
                      <Icon className="size-3 text-white" />
                    </span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs" title={n.label}>
                      {n.label}
                    </span>
                    {n.tested && <span className="size-1.5 shrink-0 rounded-full bg-emerald-500" />}
                  </button>
                ))}
              </div>
            </ScrollArea>
            <div className="border-t p-3">
              <Button className="w-full" variant="outline" onClick={() => onShowMore(fold.groupId)}>
                展示更多（+{FOLD_STEP}）
              </Button>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

// ---------------------------------------------------------------------------
function GraphInner({ taskId, coverageEnabled = true }: { taskId: string; coverageEnabled?: boolean }) {
  const [data, setData] = React.useState<{
    nodes: CoverageGraphNode[];
    edges: CoverageGraphEdge[];
  } | null>(null);
  const [expanded, setExpanded] = React.useState<Map<string, number>>(new Map());
  const [selectedComponent, setSelectedComponent] = React.useState<CoverageGraphNode | null>(null);
  const [selectedFoldId, setSelectedFoldId] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);

  const containerRef = React.useRef<HTMLDivElement>(null);
  const graphRef = React.useRef<G6Graph | null>(null);
  // click 处理需要最新的 key→RenderNode 映射（G6 事件回调闭包外读 ref）。
  const renderMapRef = React.useRef<Map<string, RenderNode>>(new Map());
  const gDataRef = React.useRef<{ nodes: G6NodeDatum[]; edges: { source: string; target: string }[] }>({
    nodes: [],
    edges: [],
  });

  const fetchGraph = React.useCallback(() => {
    setLoading(true);
    api
      .taskCoverageGraph(taskId)
      .then((g) => {
        // 组件覆盖度功能关闭(B1)：仍出图(范围内组件/company 关联依旧可见)，但抹平
        // tested 状态——不显示测试进度、不做已测高亮。
        const nodes = coverageEnabled ? (g.nodes ?? []) : (g.nodes ?? []).map((n) => ({ ...n, tested: false }));
        setData({ nodes, edges: g.edges ?? [] });
      })
      .catch(() => {
        /* 保留上一次数据 */
      })
      .finally(() => setLoading(false));
  }, [taskId, coverageEnabled]);

  React.useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  const { renderNodes, renderEdges } = React.useMemo(
    () =>
      data
        ? computeVisible(data.nodes, data.edges, expanded)
        : { renderNodes: [] as RenderNode[], renderEdges: [] as CoverageGraphEdge[] },
    [data, expanded],
  );

  // 结构签名：只在可见节点/边集合变化时重建图 + 重跑布局，避免无谓抖动。
  const sig = React.useMemo(
    () =>
      `${renderNodes.map((n) => `${n.key}:${n.fold ? "f" : n.node.tested ? "t" : "u"}`).sort().join(",")}|${renderEdges.length}`,
    [renderNodes, renderEdges],
  );

  // 维护 gDataRef + renderMapRef（供事件与图数据应用读取）。
  gDataRef.current = {
    nodes: toG6Nodes(renderNodes),
    edges: renderEdges.map((e) => ({ source: e.src, target: e.dst })),
  };
  const rmap = new Map<string, RenderNode>();
  for (const rn of renderNodes) rmap.set(rn.key, rn);
  renderMapRef.current = rmap;

  const applyData = React.useCallback(() => {
    const graph = graphRef.current;
    if (!graph || graph.destroyed) return;
    graph.setData(gDataRef.current);
    // render() 异步跑 d3-force 布局;若组件在布局落地前被卸载/销毁,g6 会在已清空的
    // context 上访问 transform 抛错(见 runtime/layout transformDataAfterLayout)。这是纯
    // teardown 竞态,吞掉它,不影响功能;真正的渲染错误(图未销毁)仍打日志。
    void graph.render().catch((err) => {
      if (!graph.destroyed) console.error("[coverage-graph] render:", err);
    });
  }, []);

  // 建图（一次）。动态 import 避开 SSR/静态导出期的 window 依赖。
  React.useEffect(() => {
    let destroyed = false;
    let graph: G6Graph | null = null;
    void (async () => {
      const { Graph } = await import("@antv/g6");
      if (destroyed || !containerRef.current) return;
      graph = new Graph({
        container: containerRef.current,
        autoResize: true,
        autoFit: "view",
        background: "#f0f2f7",
        node: {
          style: {
            size: (d: unknown) => nd(d).size,
            fill: (d: unknown) => nodeFill(nd(d)),
            stroke: (d: unknown) => nodeStroke(nd(d)),
            lineWidth: (d: unknown) => (nd(d).fold || !nd(d).inScope ? 1 : 1.5),
            lineDash: (d: unknown) => (nd(d).fold || !nd(d).inScope ? [3, 3] : [0]),
            iconSrc: (d: unknown) => (nd(d).fold ? FOLD_ICON : KIND_ICON(nd(d).kind)),
            iconWidth: (d: unknown) => Math.max(12, nd(d).size * 0.55),
            iconHeight: (d: unknown) => Math.max(12, nd(d).size * 0.55),
            labelText: (d: unknown) => nd(d).lbl,
            labelFontSize: 10,
            labelPlacement: "bottom",
            labelFill: "#475569",
            labelBackground: true,
            labelBackgroundFill: "rgba(255,255,255,0.75)",
            labelBackgroundRadius: 3,
            labelPadding: [1, 3],
          },
        },
        edge: {
          style: { stroke: "#cbd5e1", lineWidth: 1, endArrow: false },
        },
        layout: {
          type: "d3-force",
          collide: { radius: (d: unknown) => (nd(d).size ? nd(d).size : 20) + 8 },
          link: {
            distance: (edge: unknown) => {
              // 顶层（组件类型）离组件远一点，组件之间近一点。edge.source 可能是 id 或已解析节点。
              const s = (edge as { source: string | { id?: string } }).source;
              const srcId = typeof s === "string" ? s : (s?.id ?? "");
              const src = renderMapRef.current.get(srcId);
              const k = src && !src.fold ? src.kind : "component";
              return k === "type" ? 120 : 60;
            },
          },
          manyBody: {
            strength: (d: unknown) => (nd(d).kind === "component" || nd(d).fold ? -60 : -200),
          },
        },
        behaviors: ["drag-element-force", "drag-canvas", "zoom-canvas"],
      });
      graph.on("node:click", (evt: unknown) => {
        const id = (evt as { target?: { id?: string } }).target?.id;
        if (!id) return;
        const rn = renderMapRef.current.get(id);
        if (!rn) return;
        if (rn.fold) setSelectedFoldId(rn.key);
        else setSelectedComponent(rn.node);
      });
      graphRef.current = graph;
      applyData();
    })();
    return () => {
      destroyed = true;
      // 先停布局再销毁:尽量缩短"布局在飞、context 被清空"的竞态窗口。
      try {
        graph?.stopLayout();
      } catch {
        /* 图可能尚未建成或已无布局上下文 */
      }
      graph?.destroy();
      graphRef.current = null;
    };
  }, [applyData]);

  // 可见集合变化 → 重新灌数据 + 布局。sig 只作为重排触发器（applyData 读 gDataRef）。
  // biome-ignore lint/correctness/useExhaustiveDependencies: sig 是刻意的重排触发依赖
  React.useEffect(() => {
    applyData();
  }, [sig, applyData]);

  const showMore = React.useCallback((groupId: string) => {
    setExpanded((prev) => {
      const m = new Map(prev);
      m.set(groupId, (m.get(groupId) ?? FOLD_LIMIT) + FOLD_STEP);
      return m;
    });
  }, []);

  const selectedFold =
    selectedFoldId != null
      ? ((renderNodes.find((n) => n.fold && n.key === selectedFoldId) as FoldNode | undefined) ?? null)
      : null;
  React.useEffect(() => {
    if (selectedFoldId != null && !selectedFold) setSelectedFoldId(null);
  }, [selectedFoldId, selectedFold]);

  const presentKinds = React.useMemo(() => {
    const set = new Set<string>();
    let hasLeaf = false;
    for (const n of data?.nodes ?? []) {
      if (n.kind === "component") hasLeaf = true;
      else set.add(n.kind);
    }
    const list = Array.from(set);
    if (hasLeaf) list.push("component");
    return list;
  }, [data]);
  const total = data?.nodes.length ?? 0;
  const tested = data?.nodes.filter((n) => n.in_scope && n.tested).length ?? 0;
  const inScope = data?.nodes.filter((n) => n.in_scope).length ?? 0;

  return (
    <div className="relative h-full w-full">
      <div ref={containerRef} className="h-full w-full" />

      {/* 图例 + 统计 + 刷新（叠加层） */}
      <div className="bg-card/95 pointer-events-auto absolute top-3 left-3 flex max-w-[340px] flex-col gap-2.5 rounded-lg border p-3 text-xs shadow-sm backdrop-blur">
        <div className="flex items-center justify-between gap-3">
          {total > 0 ? (
            <span className="text-muted-foreground">
              范围内 <span className="text-foreground font-semibold tabular-nums">{inScope}</span>
              {coverageEnabled && (
                <>
                  {" "}
                  · 已测{" "}
                  <span className="font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">{tested}</span>
                </>
              )}
            </span>
          ) : (
            <span className="text-muted-foreground">{loading ? "加载中…" : "暂无范围内组件（先在组件页登记或让 agent 解包登记）"}</span>
          )}
          <Button variant="ghost" size="icon" className="size-6" onClick={fetchGraph} title="刷新">
            <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
          </Button>
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-1.5">
          {presentKinds.map((k) => {
            const m = metaOf(k);
            const Icon = m.icon;
            return (
              <span key={k} className="text-foreground inline-flex items-center gap-1.5">
                <span className={cn("flex size-4 items-center justify-center rounded", m.iconBg)}>
                  <Icon className="size-2.5 text-white" />
                </span>
                {m.label}
              </span>
            );
          })}
        </div>
        <div className="border-border/60 text-muted-foreground flex flex-wrap gap-x-3 gap-y-1.5 border-t pt-2">
          {coverageEnabled && (
            <>
              <span className="inline-flex items-center gap-1.5">
                <span className="size-3 rounded-full bg-emerald-500" /> 已测（高亮）
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="size-3 rounded-full bg-neutral-400" /> 未测
              </span>
            </>
          )}
          <span className="inline-flex items-center gap-1.5">
            <span className="size-3 rounded-full border border-dashed border-neutral-400 bg-neutral-200" /> 范围外
          </span>
        </div>
        <p className="text-muted-foreground/80 border-border/60 border-t pt-2 leading-relaxed">
          力导向布局，可拖拽节点、滚轮缩放；灰色「⋯」是折叠节点，点开可展开更多。
        </p>
      </div>

      <AssetSheet node={selectedComponent} taskId={taskId} onOpenChange={(o) => !o && setSelectedComponent(null)} />
      <FoldSheet
        fold={selectedFold}
        onOpenChange={(o) => !o && setSelectedFoldId(null)}
        onShowMore={showMore}
        onPick={(n) => {
          setSelectedFoldId(null);
          setSelectedComponent(n);
        }}
      />
    </div>
  );
}

export function CoverageGraphTab({ taskId, coverageEnabled = true }: { taskId: string; coverageEnabled?: boolean }) {
  return (
    <Card>
      <CardContent className="p-0">
        <div className="h-[72vh] w-full overflow-hidden rounded-xl">
          <GraphInner taskId={taskId} coverageEnabled={coverageEnabled} />
        </div>
      </CardContent>
    </Card>
  );
}
