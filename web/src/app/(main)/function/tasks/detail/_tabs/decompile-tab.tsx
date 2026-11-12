"use client";

// 任务详情「反编译」标签页：只看本任务的组件 → 函数 → 代码。
// 复用已有的反编译接口（/tasks/{id}/decompile、/decompile/jobs、functions、code），
// 不掺别的任务的导出产物。右侧代码面板与整页版 /function/decompile 共用同一个组件
// （DecompileCodePanel），配色、调用关系芯片、来源高亮、双击跳转、手型光标完全一致。

import * as React from "react";

import { BinaryIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { DecompileCodePanel, type DecompileCodePanelHandle } from "@/components/decompile-code-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { Component, DecompileFunc, DecompileJob, DecompileStatus } from "@/lib/types";

const STATUS_LABEL: Record<DecompileStatus, string> = {
  pending: "排队中",
  running: "运行中",
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

function baseName(p?: string) {
  return (p ?? "").split("/").pop() ?? "";
}

export function DecompileTab({ taskId }: { taskId: string }) {
  const [comps, setComps] = React.useState<Component[]>([]);
  const [jobs, setJobs] = React.useState<DecompileJob[]>([]);
  const [jobId, setJobId] = React.useState<number | null>(null);
  const [funcs, setFuncs] = React.useState<DecompileFunc[]>([]);
  const [total, setTotal] = React.useState(0);
  const [q, setQ] = React.useState("");
  const [codeAddr, setCodeAddr] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const panelRef = React.useRef<DecompileCodePanelHandle | null>(null);
  // 高度按"当前视口 − 本块顶部"实测，不写死 rem 常量（不同缩放/侧栏状态下都不会留白或多出滚动）
  const rootRef = React.useRef<HTMLDivElement | null>(null);
  const [boxH, setBoxH] = React.useState<number | null>(null);
  // 三栏宽度可拖拽（默认 260 / 300，最小 160 / 200）
  const [w1, setW1] = React.useState(260);
  const [w2, setW2] = React.useState(300);
  const [wide, setWide] = React.useState(false);
  const dragRef = React.useRef<{ which: 1 | 2; startX: number; startW: number } | null>(null);

  const job = jobs.find((j) => j.id === jobId) ?? null;

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
      const next = Math.max(d.which === 1 ? 160 : 200, d.startW + (ev.clientX - d.startX));
      if (d.which === 1) setW1(next);
      else setW2(next);
    };
    const up = () => {
      dragRef.current = null;
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      document.body.style.cursor = "";
    };
    document.body.style.cursor = "col-resize";
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  React.useEffect(() => {
    const measure = () => {
      const el = rootRef.current;
      if (!el) return;
      const top = el.getBoundingClientRect().top;
      // 底部只留 24px（含外层 p-4/p-6 的下内边距），既不贴边也不产生页面滚动
      setBoxH(Math.max(320, Math.round(window.innerHeight - top - 24)));
    };
    measure();
    const raf = requestAnimationFrame(measure);
    window.addEventListener("resize", measure);
    const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(measure) : null;
    if (ro && rootRef.current?.parentElement) ro.observe(rootRef.current.parentElement);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", measure);
      ro?.disconnect();
    };
  }, []);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [c, jn] = await Promise.all([
        api.taskComponents(taskId, "", "", "", 200, 0).catch(() => ({ components: [] as Component[] })),
        api.decompileTaskJobs(taskId).catch(() => ({ jobs: [] as DecompileJob[] })),
      ]);
      setComps(c.components.filter((x) => !!x.binary_path));
      setJobs(jn.jobs);
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    setJobId(null);
    setCodeAddr(null);
    setFuncs([]);
    setQ("");
    void load();
  }, [load]);

  const active = jobs.some((j) => j.status === "pending" || j.status === "running");
  React.useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => void load(), 3000);
    return () => clearInterval(timer);
  }, [active, load]);

  // 选中已完成的 job 才拉函数列表
  React.useEffect(() => {
    if (!job || job.status !== "completed") {
      setFuncs([]);
      setTotal(0);
      return;
    }
    let stop = false;
    api
      .decompileFunctions(job.id, q.trim(), 1, 500)
      .then((r) => {
        if (stop) return;
        setFuncs(r.items);
        setTotal(r.total);
      })
      .catch(() => {
        if (!stop) {
          setFuncs([]);
          setTotal(0);
        }
      });
    return () => {
      stop = true;
    };
  }, [job, q]);

  const cancelJob = async () => {
    if (!job) return;
    try {
      await api.decompileCancel(job.id);
      toast.success("已请求取消");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "取消失败");
    }
  };

  const retryJob = async () => {
    if (!job) return;
    try {
      await api.decompileRetry(job.id);
      toast.success("已重新排队（已导出的函数会跳过，续跑）");
      await load();
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
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    }
  };

  const exportComp = async (c: Component) => {
    try {
      const r = await api.decompileCreate(taskId, { component_ids: [c.id] });
      toast.success(`已加入导出队列（${r.jobs.length} 个）`);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "发起导出失败");
    }
  };

  const jobOfComp = (c: Component) =>
    jobs.find(
      (j) =>
        (j.component_id != null && j.component_id === c.id) ||
        (!!c.binary_path && j.binary_path === c.binary_path),
    ) ?? null;

  return (
    <div
      ref={rootRef}
      className="flex min-h-[320px] flex-col gap-2 overflow-hidden p-3"
      style={boxH ? { height: boxH } : undefined}
    >
      <div className="text-muted-foreground flex items-center gap-2 text-xs">
        <BinaryIcon className="size-4" />
        IDA 无头导出产物；只列本任务的组件，导出后点左侧看函数与代码
        <Button variant="outline" size="sm" className="ml-auto h-7" disabled={loading} onClick={() => void load()}>
          刷新
        </Button>
      </div>

      <div
        className={`grid min-h-0 flex-1 grid-cols-1 overflow-hidden ${wide ? "gap-0" : "gap-2"}`}
        style={wide ? { gridTemplateColumns: `${w1}px 6px ${w2}px 6px 1fr` } : undefined}
      >
        {/* 组件 */}
        <section className="flex min-h-0 flex-col overflow-hidden rounded-lg border">
          <div className="bg-muted/40 text-muted-foreground border-b px-2 py-1.5 text-[11px]">
            任务内组件（{comps.length}）
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {comps.length === 0 && (
              <p className="text-muted-foreground p-3 text-xs">
                {loading ? "加载中…" : "本任务还没有登记可导出的二进制组件。"}
              </p>
            )}
            {comps.map((c) => {
              const j = jobOfComp(c);
              return (
                <div
                  key={c.id}
                  className={`flex flex-col gap-1 border-b px-2 py-1.5 text-sm ${j && j.id === jobId ? "bg-muted/60" : ""}`}
                >
                  <button
                    type="button"
                    disabled={!j}
                    onClick={() => {
                      if (!j) return;
                      setJobId(j.id);
                      setQ("");
                    }}
                    className={`flex w-full items-center gap-1.5 text-left ${j ? "cursor-pointer" : ""}`}
                  >
                    <span className="min-w-0 truncate font-mono text-xs" title={c.binary_path}>
                      {baseName(c.binary_path) || c.component_name}
                    </span>
                    <Badge
                      variant="secondary"
                      className={`ml-auto shrink-0 text-[10px] ${j ? STATUS_CLASS[j.status] : ""}`}
                    >
                      {j ? STATUS_LABEL[j.status] : "未导出"}
                    </Badge>
                  </button>
                  <div className="text-muted-foreground flex items-center gap-1 text-[11px]">
                    <span className="min-w-0 truncate font-mono">
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
                        className="ml-auto h-6 shrink-0 px-1.5 text-[11px]"
                        onClick={() => void exportComp(c)}
                      >
                        导出
                      </Button>
                    )}
                  </div>
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

        {/* 函数 */}
        <section className="flex min-h-0 flex-col overflow-hidden rounded-lg border">
          <div className="flex items-center gap-1 border-b px-2 py-1.5">
            <SearchIcon className="text-muted-foreground size-3.5" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder={job?.status === "completed" ? "搜函数名/地址" : "先选一个已完成的导出"}
              className="h-7 px-2 text-xs"
              disabled={!job || job.status !== "completed"}
            />
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {job && job.status !== "completed" && (
              <p className="text-muted-foreground p-3 text-xs">
                {job.status === "failed" ? job.error || "导出失败" : "导出中，完成后可浏览函数。"}
              </p>
            )}
            {(!job || job.status === "completed") && funcs.length === 0 && (
              <p className="text-muted-foreground p-3 text-xs">{job ? "没有匹配的函数" : "还没有选中组件"}</p>
            )}
            {funcs.map((f) => (
              <button
                key={f.addr}
                type="button"
                onClick={() => panelRef.current?.open(f.addr)}
                className={`flex w-full cursor-pointer items-center gap-2 border-b px-2 py-1 text-left ${
                  codeAddr === f.addr ? "bg-muted/60" : "hover:bg-muted/40"
                }`}
              >
                <span className="min-w-0 truncate font-mono text-xs">{f.name}</span>
                <span className="text-muted-foreground ml-auto shrink-0 font-mono text-[10px]">0x{f.addr}</span>
              </button>
            ))}
          </div>
          <div className="text-muted-foreground border-t px-2 py-1 text-[10px] tabular-nums">
            {job ? `${funcs.length}/${total} 个函数` : "—"}
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

        {/* 代码：与整页版 /function/decompile 完全同一份实现 */}
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
