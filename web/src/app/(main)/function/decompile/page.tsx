"use client";

import * as React from "react";

import { BinaryIcon, RefreshCwIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { Component, DecompileFunc, DecompileJob, DecompileStatus } from "@/lib/types";

import { DecompileCodePanel, type DecompileCodePanelHandle } from "@/components/decompile-code-panel";

const STATUS_LABEL: Record<DecompileStatus, string> = {
  pending: "排队中",
  running: "导出中",
  completed: "已完成",
  failed: "失败",
  canceled: "已取消",
};

const STATUS_CLASS: Record<DecompileStatus, string> = {
  pending: "bg-amber-500/15 text-amber-300",
  running: "bg-blue-500/15 text-blue-300",
  completed: "bg-emerald-500/15 text-emerald-300",
  failed: "bg-red-500/15 text-red-300",
  canceled: "bg-zinc-600/20 text-zinc-400",
};

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/**
 * 反编译浏览页（只给人看，不进 agent 工具集）。
 * 左：导出任务列表；中：函数列表；右：反汇编导出的 C 代码 + 调用关系跳转。
 */
export default function DecompilePage() {
  const [jobs, setJobs] = React.useState<DecompileJob[]>([]);
  const [jobId, setJobId] = React.useState<number | null>(null);
  const [funcs, setFuncs] = React.useState<DecompileFunc[]>([]);
  const [funcTotal, setFuncTotal] = React.useState(0);
  const [q, setQ] = React.useState("");
  const [loadingJobs, setLoadingJobs] = React.useState(false);
  const [loadingFuncs, setLoadingFuncs] = React.useState(false);
  const [loadingCode, setLoadingCode] = React.useState(false);
  // 三栏宽度（可拖拽）：默认 280 / 320，最小 160 / 200
  const [w1, setW1] = React.useState(280);
  const [w2, setW2] = React.useState(320);
  const [wide, setWide] = React.useState(false);
  const dragRef = React.useRef<{ which: 1 | 2; startX: number; startW: number } | null>(null);
  // 函数列表虚拟滚动
  const funcBoxRef = React.useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = React.useState(0);
  // ?task=<id>：任务内视图（只列本任务的组件/函数/代码，不混别的任务）
  const panelRef = React.useRef<DecompileCodePanelHandle | null>(null);
  const [codeAddr, setCodeAddr] = React.useState<string | null>(null);
  const [taskScope, setTaskScope] = React.useState<string | null>(null);
  const [comps, setComps] = React.useState<Component[]>([]);
  const [boxH, setBoxH] = React.useState(600);

  const job = jobs.find((j) => j.id === jobId) ?? null;

  // 首次进入：?job=<id> 直接选中（组件页行内图标跳过来）
  React.useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    const raw = sp.get("job");
    const id = raw ? Number(raw) : NaN;
    if (Number.isFinite(id) && id > 0) setJobId(id);
    const t = sp.get("task");
    if (t && t.trim()) setTaskScope(t.trim());
  }, []);

  const loadJobs = React.useCallback(async () => {
    setLoadingJobs(true);
    try {
      const { jobs: list } = await api.decompileJobs(taskScope ?? undefined);
      setJobs(list);
      setJobId((cur) => cur ?? null);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载导出任务失败");
    } finally {
      setLoadingJobs(false);
    }
  }, [taskScope]);

  // 任务内视图：把本任务登记过的二进制组件也列出来（未导出的可直接发起导出）
  const loadComps = React.useCallback(async () => {
    if (!taskScope) {
      setComps([]);
      return;
    }
    try {
      const r = await api.taskComponents(taskScope, "", "", "", 200, 0);
      setComps(r.components.filter((c) => !!c.binary_path));
    } catch {
      setComps([]);
    }
  }, [taskScope]);

  React.useEffect(() => {
    void loadComps();
  }, [loadComps]);

  // 未导出 → 发起导出（复用组件页同一个接口）
  const exportComponent = async (c: Component) => {
    if (!taskScope) return;
    try {
      const res = await api.decompileCreate(taskScope, { component_ids: [c.id] });
      const skipped = res.skipped?.length ? `，跳过 ${res.skipped.length} 个` : "";
      toast.success(`已加入导出队列（${res.jobs.length} 个${skipped}）`);
      await loadJobs();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "发起导出失败");
    }
  };

  React.useEffect(() => {
    void loadJobs();
  }, [loadJobs]);

  // 有排队/运行中的任务才轮询列表
  const active = jobs.some((j) => j.status === "pending" || j.status === "running");
  React.useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => void loadJobs(), 3000);
    return () => clearInterval(timer);
  }, [active, loadJobs]);

  const loadFuncs = React.useCallback(async (id: number, keyword: string) => {
    setLoadingFuncs(true);
    try {
      const res = await api.decompileFunctions(id, keyword, 1, 500);
      setFuncs(res.items);
      setFuncTotal(res.total);
    } catch (e) {
      setFuncs([]);
      setFuncTotal(0);
      toast.error(e instanceof Error ? e.message : "加载函数列表失败");
    } finally {
      setLoadingFuncs(false);
    }
  }, []);

  React.useEffect(() => {
    if (!job || job.status !== "completed") {
      setFuncs([]);
      setFuncTotal(0);
      return;
    }
    void loadFuncs(job.id, q.trim());
  }, [job, q, loadFuncs]);





  // 容器高度变化（窗口缩放/折叠侧栏）要重算可视窗口
  React.useEffect(() => {
    const el = funcBoxRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => setBoxH(el.clientHeight || 600));
    ro.observe(el);
    setBoxH(el.clientHeight || 600);
    return () => ro.disconnect();
  }, [job?.id]);


  // 完成态且还没选函数：自动打开列表第一个（首屏就有内容）
  React.useEffect(() => {
    if (codeAddr || !job || job.status !== "completed" || funcs.length === 0) return;
    panelRef.current?.open(funcs[0].addr);
  }, [codeAddr, job, funcs]);

  const cancelJob = async () => {
    if (!job) return;
    try {
      await api.decompileCancel(job.id);
      toast.success("已请求取消");
      await loadJobs();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "取消失败");
    }
  };

  const retryJob = async () => {
    if (!job) return;
    try {
      await api.decompileRetry(job.id);
      toast.success("已重新排队（已导出的函数会跳过，续跑）");
      await loadJobs();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "重试失败");
    }
  };

  const deleteJob = async () => {
    if (!job) return;
    if (!window.confirm(`删除导出记录并清理产物目录？\n${job.export_dir}`)) return;
    try {
      await api.decompileDelete(job.id);
      toast.success("已删除");
      setJobId(null);
      await loadJobs();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    }
  };

  // 左树按任务分组（文档 7.2 的「任务/组件树」）：同一任务下的二进制折叠在一起
  const groups = React.useMemo(() => {
    const map = new Map<number, DecompileJob[]>();
    for (const j of jobs) {
      const arr = map.get(j.task_id) ?? [];
      arr.push(j);
      map.set(j.task_id, arr);
    }
    const raw = [...map.entries()]
      .sort((a, b) => b[0] - a[0])
      .map(([taskId, list]) => ({ taskId, list, name: (list[0]?.task_name ?? "").trim() }));
    // 显示任务名；同名任务才在名字后面补编号，避免一串「任务 #111」
    const counts = new Map<string, number>();
    for (const g of raw) if (g.name) counts.set(g.name, (counts.get(g.name) ?? 0) + 1);
    return raw.map((g) => ({
      ...g,
      label: g.name
        ? (counts.get(g.name) ?? 0) > 1
          ? `${g.name}（#${g.taskId}）`
          : g.name
        : `任务 #${g.taskId}`,
    }));
  }, [jobs]);
  const [collapsed, setCollapsed] = React.useState<Record<number, boolean>>({});


  // 只有 lg 以上才分栏拖拽；窄屏仍是单列
  React.useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const on = () => setWide(mq.matches);
    on();
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);

  const startDrag = (which: 1 | 2) => (e: React.MouseEvent) => {
    e.preventDefault();
    dragRef.current = { which, startX: e.clientX, startW: which === 1 ? w1 : w2 };
    const move = (ev: MouseEvent) => {
      const d = dragRef.current;
      if (!d) return;
      const min = d.which === 1 ? 160 : 200;
      const next = Math.max(min, d.startW + (ev.clientX - d.startX));
      if (d.which === 1) setW1(next);
      else setW2(next);
    };
    const up = () => {
      dragRef.current = null;
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  // 虚拟滚动窗口：只渲染可视区 + 上下各 8 行缓冲
  const FUNC_ROW = 28;
  const visibleRows = Math.ceil(boxH / FUNC_ROW);
  const funcStart = Math.max(0, Math.floor(scrollTop / FUNC_ROW) - 8);
  const jobOfComp = (c: Component) =>
    jobs.find(
      (j) =>
        (j.component_id != null && j.component_id === c.id) ||
        (!!c.binary_path && j.binary_path === c.binary_path),
    ) ?? null;

  const funcEnd = Math.min(funcs.length, funcStart + visibleRows + 16);

  return (
    <div className="flex h-[calc(100vh-4rem)] min-h-0 flex-col gap-3 p-4">
      <header className="flex flex-wrap items-center gap-2">
        <BinaryIcon className="text-muted-foreground size-5" />
        <h1 className="text-lg font-semibold">反编译</h1>
        <span className="text-muted-foreground text-xs">
          IDA 无头导出，产物落任务目录；只供人工查阅，不进 Agent 工具集
        </span>
        <div className="ml-auto flex items-center gap-2">
          <Button variant="outline" size="sm" disabled={loadingJobs} onClick={() => void loadJobs()}>
            <RefreshCwIcon className={`size-4 ${loadingJobs ? "animate-spin" : ""}`} /> 刷新
          </Button>
        </div>
      </header>

      <div
        className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:gap-1"
        style={wide ? { gridTemplateColumns: `${w1}px 6px ${w2}px 6px 1fr` } : undefined}
      >
        <section className="flex min-h-0 flex-col overflow-hidden rounded-lg border">
          <div className="bg-muted/40 text-muted-foreground border-b px-3 py-2 text-xs">
            {taskScope ? `任务内组件（${comps.length}）` : `导出任务${jobs.length ? `（${jobs.length}）` : ""}`}
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {taskScope &&
              comps.map((c) => {
                const j = jobOfComp(c);
                const name = (c.binary_path ?? "").split("/").pop() || c.component_name;
                return (
                  <div
                    key={`comp-${c.id}`}
                    className={`flex w-full flex-col gap-1 border-b px-3 py-2 text-left text-sm ${
                      j && j.id === jobId ? "bg-muted/60" : ""
                    }`}
                  >
                    <button
                      type="button"
                      disabled={!j}
                      onClick={() => {
                        if (!j) return;
                        setJobId(j.id);
                        setQ("");
                      }}
                      className={`flex w-full items-center gap-2 text-left ${j ? "cursor-pointer hover:opacity-90" : ""}`}
                    >
                      <span className="truncate font-mono text-xs" title={c.binary_path}>
                        {name}
                      </span>
                      {j ? (
                        <Badge
                          variant="secondary"
                          className={`ml-auto shrink-0 text-[10px] ${STATUS_CLASS[j.status]}`}
                        >
                          {STATUS_LABEL[j.status]}
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="ml-auto shrink-0 text-[10px]">
                          未导出
                        </Badge>
                      )}
                    </button>
                    <span className="text-muted-foreground truncate font-mono text-[11px]">
                      {j
                        ? j.status === "completed"
                          ? `${j.func_done} 个函数`
                          : `${j.func_done} 个已导出`
                        : c.binary_path}
                    </span>
                    {!j && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="mt-0.5 h-7 self-start text-xs"
                        onClick={() => void exportComponent(c)}
                      >
                        <BinaryIcon className="size-3.5" /> 导出反编译
                      </Button>
                    )}
                  </div>
                );
              })}
            {taskScope && comps.length === 0 && (
              <p className="text-muted-foreground p-3 text-sm">本任务还没有登记可导出的二进制组件。</p>
            )}
            {!taskScope && jobs.length === 0 && (
              <p className="text-muted-foreground p-3 text-sm">
                {loadingJobs ? "加载中…" : "还没有导出任务。在任务详情的组件页勾选组件导出。"}
              </p>
            )}
            {!taskScope && groups.map(({ taskId, list, label }) => {
              const folded = !!collapsed[taskId];
              const running = list.some((j) => j.status === "running" || j.status === "pending");
              return (
                <div key={taskId}>
                  <button
                    type="button"
                    onClick={() => setCollapsed((c) => ({ ...c, [taskId]: !folded }))}
                    className="bg-muted/20 hover:bg-muted/40 flex w-full items-center gap-1 border-b px-2 py-1.5 text-left"
                  >
                    <span className="text-muted-foreground text-[11px]">{folded ? "▸" : "▾"}</span>
                    <span className="truncate text-xs font-medium" title={label}>
                      {label}
                    </span>
                    <span className="text-muted-foreground text-[10px]">（{list.length}）</span>
                    {running && <span className="ml-auto size-1.5 rounded-full bg-blue-400" />}
                  </button>
                  {!folded &&
                    list.map((j) => (
                      <button
                        key={j.id}
                        type="button"
                        onClick={() => {
                          setJobId(j.id);
                          setQ("");
                        }}
                        className={`hover:bg-muted/50 flex w-full flex-col gap-1 border-b px-3 py-2 pl-5 text-left text-sm ${
                          j.id === jobId ? "bg-muted/60" : ""
                        }`}
                      >
                        <span className="flex items-center gap-2">
                          <span className="truncate font-mono text-xs">{j.binary_path.split("/").pop()}</span>
                          <Badge
                            variant="secondary"
                            className={`ml-auto shrink-0 text-[10px] ${STATUS_CLASS[j.status]}`}
                          >
                            {STATUS_LABEL[j.status]}
                          </Badge>
                        </span>
                        <span className="text-muted-foreground truncate font-mono text-[11px]">
                          {j.status === "completed" ? `${j.func_done} 个函数` : `${j.func_done} 个已导出`}
                          {j.binary_path ? ` · ${j.binary_path}` : ""}
                        </span>
                        {j.status === "failed" && j.error && (
                          <span className="truncate text-[11px] text-red-400" title={j.error}>
                            {j.error}
                          </span>
                        )}
                      </button>
                    ))}
                </div>
              );
            })}
          </div>
        </section>

        {wide && (
          <div
            role="separator"
            aria-orientation="vertical"
            onMouseDown={startDrag(1)}
            className="hover:bg-sky-500/40 cursor-col-resize rounded bg-transparent"
            title="拖动调整栏宽"
          />
        )}

        <section className="flex min-h-0 flex-col overflow-hidden rounded-lg border">
          <div className="flex items-center gap-2 border-b px-3 py-2">
            <span className="text-muted-foreground text-xs">
              函数 {job?.status === "completed" ? `${funcTotal} 个` : "—"}
            </span>
            <div className="relative ml-auto w-40">
              <SearchIcon className="text-muted-foreground pointer-events-none absolute top-2 left-2 size-3.5" />
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="名字或地址"
                className="h-7 pl-7 text-xs"
                disabled={!job || job.status !== "completed"}
              />
            </div>
          </div>
          <div
            ref={funcBoxRef}
            onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
            className="min-h-0 flex-1 overflow-y-auto"
          >
            {!job && <p className="text-muted-foreground p-3 text-sm">左侧选一个导出任务。</p>}
            {job && job.status !== "completed" && (
              <p className="text-muted-foreground p-3 text-sm">
                {job.status === "running"
                  ? `导出中：已导出 ${job.func_done} 个函数（总数要导完才知道）`
                  : job.status === "pending"
                    ? "排队中：IDA 串行执行，前面还有任务。"
                    : job.status === "failed"
                      ? `导出失败：${job.error || "原因未知"}`
                      : "已取消。"}
              </p>
            )}
            {job?.status === "completed" && funcs.length === 0 && !loadingFuncs && (
              <p className="text-muted-foreground p-3 text-sm">没有匹配的函数。</p>
            )}
            {funcs.length > 0 && (
              <div style={{ height: funcs.length * FUNC_ROW, position: "relative" }}>
                <div style={{ transform: `translateY(${funcStart * FUNC_ROW}px)` }}>
                  {funcs.slice(funcStart, funcEnd).map((f) => (
                    <button
                      key={f.addr}
                      type="button"
                      style={{ height: FUNC_ROW }}
                      onClick={() => panelRef.current?.open(f.addr)}
                      className={`hover:bg-muted/50 flex w-full items-center gap-2 border-b px-3 text-left ${
                        codeAddr === f.addr ? "bg-muted/60" : ""
                      }`}
                    >
                      <span className="truncate font-mono text-xs">{f.name}</span>
                      <span className="text-muted-foreground ml-auto shrink-0 font-mono text-[10px]">
                        0x{f.addr} · {humanSize(f.size)}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>

        {wide && (
          <div
            role="separator"
            aria-orientation="vertical"
            onMouseDown={startDrag(2)}
            className="hover:bg-sky-500/40 cursor-col-resize rounded bg-transparent"
            title="拖动调整栏宽"
          />
        )}

        <DecompileCodePanel
          ref={panelRef}
          job={job}
          onAddrChange={setCodeAddr}
          onCancel={() => void cancelJob()}
          onRetry={() => void retryJob()}
          onDelete={() => void deleteJob()}
        />
      </div>
    </div>
  );
}
