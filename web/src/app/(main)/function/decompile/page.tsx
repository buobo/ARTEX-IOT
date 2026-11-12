"use client";

import * as React from "react";

import {
  ArrowLeftIcon,
  BinaryIcon,
  ChevronDownIcon,
  CopyIcon,
  DownloadIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  SearchIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type {
  DecompileCode,
  DecompileFunc,
  DecompileJob,
  DecompileJobDetail,
  DecompileStatus,
} from "@/lib/types";

import { HighlightedCode } from "../tasks/detail/_tabs/poc-tab";

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
  const [code, setCode] = React.useState<DecompileCode | null>(null);
  const [loadingJobs, setLoadingJobs] = React.useState(false);
  const [loadingFuncs, setLoadingFuncs] = React.useState(false);
  const [loadingCode, setLoadingCode] = React.useState(false);
  // 调用关系跳转的返回栈（面包屑）
  const [history, setHistory] = React.useState<{ addr: string; name: string }[]>([]);
  // 刚从哪个函数跳过来：它会被提到 callers 第一位并高亮，点一下就能跳回去
  const [jumpFrom, setJumpFrom] = React.useState<{ addr: string; name: string } | null>(null);
  // 未完成的 job 只能看日志尾部
  const [logText, setLogText] = React.useState("");
  // 完成态的产物大小（状态条用）
  const [detail, setDetail] = React.useState<DecompileJobDetail | null>(null);
  // 三栏宽度（可拖拽）：默认 280 / 320，最小 160 / 200
  const [w1, setW1] = React.useState(280);
  const [w2, setW2] = React.useState(320);
  const [wide, setWide] = React.useState(false);
  const dragRef = React.useRef<{ which: 1 | 2; startX: number; startW: number } | null>(null);
  // callers/callees 默认只占一行，展开按钮看全部
  const [callsOpen, setCallsOpen] = React.useState(false);
  // 函数列表虚拟滚动
  const funcBoxRef = React.useRef<HTMLDivElement | null>(null);
  // 可跳转函数名集合：双击跳转 + 悬停手型光标都靠它
  const [fnNames, setFnNames] = React.useState<Set<string>>(new Set());
  // 代码滚动容器（换函数时回到顶部，否则跳转后停在上一段的滚动位置）
  const codeBoxRef = React.useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = React.useState(0);
  const [boxH, setBoxH] = React.useState(600);

  const job = jobs.find((j) => j.id === jobId) ?? null;

  // 首次进入：?job=<id> 直接选中（组件页行内图标跳过来）
  React.useEffect(() => {
    const raw = new URLSearchParams(window.location.search).get("job");
    const id = raw ? Number(raw) : NaN;
    if (Number.isFinite(id) && id > 0) setJobId(id);
  }, []);

  const loadJobs = React.useCallback(async () => {
    setLoadingJobs(true);
    try {
      const { jobs: list } = await api.decompileJobs();
      setJobs(list);
      setJobId((cur) => cur ?? null);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载导出任务失败");
    } finally {
      setLoadingJobs(false);
    }
  }, []);

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

  const openFunc = React.useCallback(
    async (id: number, addr: string, push = true) => {
      setLoadingCode(true);
      const prev = code;
      try {
        const c = await api.decompileCode(id, addr);
        if (push && prev && prev.addr !== c.addr) setHistory((h) => [...h, { addr: prev.addr, name: prev.name }]);
        if (prev && prev.addr !== c.addr) setJumpFrom({ addr: prev.addr, name: prev.name });
        setCode(c);
      } catch (e) {
        toast.error(e instanceof Error ? e.message : "读取函数失败");
      } finally {
        setLoadingCode(false);
      }
    },
    [code],
  );

  const goBack = () => {
    const last = history[history.length - 1];
    if (!last || !job) return;
    setHistory(history.slice(0, -1));
    void openFunc(job.id, last.addr, false);
  };

  // 双击代码里的函数名 → 跳到那个函数（索引里没有就静默不动，避免误报）
  const onCodeDoubleClick = React.useCallback(async () => {
    if (!job || !code || job.status !== "completed") return;
    const word = (window.getSelection()?.toString() ?? "").trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(word)) return;
    if (word === code.name) return;
    // 只对"被调用形态"的标识符跳转：双击变量名/关键字只是选词，别弹提示
    const called = new RegExp(`(^|[^A-Za-z0-9_])${word}\\s*\\(`).test(code.code);
    if (!called) return;
    try {
      // 精确匹配优先：接口按名字/地址模糊搜，这里再筛一次同名
      const res = await api.decompileFunctions(job.id, word, 1, 200);
      const hit =
        res.items.find((f) => f.name === word) ??
        res.items.find((f) => f.name.toLowerCase() === word.toLowerCase());
      if (!hit) {
        toast.info(`索引里没有 ${word}（外部库函数不导出）`);
        return;
      }
      await openFunc(job.id, hit.addr);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "跳转失败");
    }
  }, [job, code, openFunc]);

  // 未完成的 job：轮询日志尾部（进度可见，别让人以为卡死）
  React.useEffect(() => {
    if (!job || job.status === "completed" || job.status === "canceled") {
      setLogText("");
      return;
    }
    let stop = false;
    const tick = async () => {
      try {
        const r = await api.decompileLog(job.id);
        if (!stop) setLogText(r.log);
      } catch {
        /* 日志是辅助信息 */
      }
    };
    void tick();
    const timer = setInterval(() => void tick(), 3000);
    return () => {
      stop = true;
      clearInterval(timer);
    };
  }, [job]);

  // 完成态取一眼产物大小（单 job 接口才带 artifact_bytes）
  React.useEffect(() => {
    if (!job || job.status !== "completed") {
      setDetail(null);
      return;
    }
    let stop = false;
    api
      .decompileJob(job.id)
      .then((d) => {
        if (!stop) setDetail(d);
      })
      .catch(() => setDetail(null));
    return () => {
      stop = true;
    };
  }, [job]);

  // 容器高度变化（窗口缩放/折叠侧栏）要重算可视窗口
  React.useEffect(() => {
    const el = funcBoxRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => setBoxH(el.clientHeight || 600));
    ro.observe(el);
    setBoxH(el.clientHeight || 600);
    return () => ro.disconnect();
  }, [job?.id]);

  // 切 job：清空右侧代码与返回栈
  React.useEffect(() => {
    setCode(null);
    setHistory([]);
    setJumpFrom(null);
  }, [jobId]);

  // 完成态且还没选函数：自动打开列表第一个（首屏就有内容）
  React.useEffect(() => {
    if (code || !job || job.status !== "completed" || funcs.length === 0) return;
    void openFunc(job.id, funcs[0].addr);
  }, [code, job, funcs, openFunc]);

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
      setCode(null);
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

  // 代码面板里"cursor 变手型"的判定：优先用索引函数名；名字表还没到时，
  // 退化成「出现 name( 形态的标识符」，至少让调用点先有手型（双击再做真正的查表）
  const isJumpableToken = React.useCallback(
    (t: string) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(t)) return false;
      if (fnNames.size > 0) return fnNames.has(t);
      const src = code?.code;
      return !!src && new RegExp(`(^|[^A-Za-z0-9_])${t}\\s*\\(`).test(src);
    },
    [fnNames, code],
  );

  // callers 列表 = 「来源函数」（高亮、置顶、去重）+ 原有的 callers
  const callerAddrs = React.useMemo(() => {
    const base = code?.callers ?? [];
    if (!jumpFrom || jumpFrom.addr === code?.addr) return base;
    return [jumpFrom.addr, ...base.filter((a) => a !== jumpFrom.addr)];
  }, [code, jumpFrom]);

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

  // 换函数时 callers/callees 回到「一行」，代码滚回顶部
  React.useEffect(() => {
    setCallsOpen(false);
    if (codeBoxRef.current) codeBoxRef.current.scrollTop = 0;
  }, [code?.addr]);

  // 虚拟滚动窗口：只渲染可视区 + 上下各 8 行缓冲
  const FUNC_ROW = 28;
  const visibleRows = Math.ceil(boxH / FUNC_ROW);
  const funcStart = Math.max(0, Math.floor(scrollTop / FUNC_ROW) - 8);
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
            导出任务 {jobs.length ? `（${jobs.length}）` : ""}
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {jobs.length === 0 && (
              <p className="text-muted-foreground p-3 text-sm">
                {loadingJobs ? "加载中…" : "还没有导出任务。在任务详情的组件页勾选组件导出。"}
              </p>
            )}
            {groups.map(({ taskId, list, label }) => {
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
                      onClick={() => void openFunc(job!.id, f.addr)}
                      className={`hover:bg-muted/50 flex w-full items-center gap-2 border-b px-3 text-left ${
                        code?.addr === f.addr ? "bg-muted/60" : ""
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

        <section className="flex min-h-0 flex-col overflow-hidden rounded-lg border">
          <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
            {history.length > 0 && (
              <Button variant="ghost" size="sm" onClick={goBack} title={`返回 ${history[history.length - 1].name}`}>
                <ArrowLeftIcon className="size-4" />
              </Button>
            )}
            {code ? (
              <>
                <span className="font-mono text-sm font-medium">{code.name}</span>
                <span className="text-muted-foreground font-mono text-[11px]">0x{code.addr}</span>
                <span className="text-muted-foreground text-[11px]">{humanSize(code.size)}</span>
                {code.truncated && <Badge variant="secondary" className="text-[10px]">已截断</Badge>}
                <Button
                  variant="ghost"
                  size="sm"
                  title="复制这段代码"
                  onClick={() => {
                    void navigator.clipboard?.writeText(code.code).then(
                      () => toast.success("已复制"),
                      () => toast.error("复制失败"),
                    );
                  }}
                >
                  <CopyIcon className="size-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  title="下载为 .c 文件"
                  onClick={() => {
                    const blob = new Blob([code.code], { type: "text/plain;charset=utf-8" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `${code.name}.c`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  <DownloadIcon className="size-4" />
                </Button>
              </>
            ) : (
              <span className="text-muted-foreground text-xs">
                {job && job.status !== "completed" ? "导出未完成：只显示进度与日志" : "选中左侧函数查看代码"}
              </span>
            )}
            {job && (job.status === "running" || job.status === "pending") && (
              <Button variant="outline" size="sm" className="ml-auto" onClick={() => void cancelJob()}>
                取消导出
              </Button>
            )}
            {job && (job.status === "failed" || job.status === "canceled") && (
              <Button variant="outline" size="sm" className="ml-auto" onClick={() => void retryJob()}>
                <RotateCcwIcon className="size-4" /> 重试
              </Button>
            )}
            {job && job.status !== "running" && job.status !== "pending" && (
              <Button variant="ghost" size="sm" className="ml-auto text-red-400" onClick={() => void deleteJob()}>
                <Trash2Icon className="size-4" /> 删除
              </Button>
            )}
          </div>
          {job?.status === "completed" && (
            <div className="text-muted-foreground border-b px-3 py-1 text-[11px]">
              已完成 · {job.func_done} 个函数
              {job.finished_at ? ` · ${new Date(job.finished_at).toLocaleString()}` : ""}
              {detail?.artifact_bytes ? ` · ${humanSize(detail.artifact_bytes)}` : ""}
            </div>
          )}
          {code && (
            <div className="flex cursor-default select-none items-start gap-1 border-b px-3 py-1.5 text-[11px]">
              {/* 默认一行：装不下就裁掉，右侧「展开」把整组调用关系铺开，「收起」收回一行。
                  容器用 items-start，展开时按钮仍钉在顶上一行，不随内容变高而上下漂。 */}
              <div
                className={
                  callsOpen
                    ? "flex min-w-0 flex-1 flex-wrap items-center gap-1"
                    : "flex min-w-0 flex-1 items-center gap-1 overflow-hidden whitespace-nowrap"
                }
              >
                <span className="text-muted-foreground shrink-0">callers</span>
                {callerAddrs.length === 0 && <span className="text-muted-foreground/60">none</span>}
                {callerAddrs.map((a) => {
                  const from = jumpFrom && a === jumpFrom.addr;
                  return (
                    <button
                      key={`c-${a}`}
                      type="button"
                      title={from ? `返回 ${jumpFrom?.name}（刚从这跳过来）` : undefined}
                      className={
                        from
                          ? "shrink-0 cursor-pointer rounded bg-emerald-500/15 px-1.5 py-0.5 font-mono text-emerald-300 hover:bg-emerald-500/25"
                          : "shrink-0 cursor-pointer rounded bg-sky-500/15 px-1.5 py-0.5 font-mono text-sky-300 hover:bg-sky-500/25"
                      }
                      onClick={() => void openFunc(job!.id, a)}
                    >
                      {from ? `↩ 0x${a}` : `0x${a}`}
                    </button>
                  );
                })}
                <span className="text-muted-foreground ml-3 shrink-0">callees</span>
                {(code.callees ?? []).length === 0 && (
                  <span className="text-muted-foreground/60">none</span>
                )}
                {(code.callees ?? []).map((a) => (
                  <button
                    key={`d-${a}`}
                    type="button"
                    className="shrink-0 cursor-pointer rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-amber-300 hover:bg-amber-500/25"
                    onClick={() => void openFunc(job!.id, a)}
                  >
                    0x{a}
                  </button>
                ))}
              </div>
              {callerAddrs.length + (code.callees?.length ?? 0) > 0 && (
                <button
                  type="button"
                  onClick={() => setCallsOpen((v) => !v)}
                  aria-expanded={callsOpen}
                  className="text-muted-foreground hover:text-foreground flex shrink-0 items-center gap-0.5 self-start rounded border px-1.5 py-0.5"
                  title={
                    callsOpen
                      ? "收起到一行"
                      : `展开全部（callers ${callerAddrs.length} · callees ${code.callees?.length ?? 0}）`
                  }
                >
                  <ChevronDownIcon
                    className={`size-3 transition-transform ${callsOpen ? "rotate-180" : ""}`}
                  />
                  {callsOpen ? "收起" : "展开"}
                </button>
              )}
            </div>
          )}
          <div ref={codeBoxRef} className="min-h-0 flex-1 overflow-auto p-2">
            {job && job.status !== "completed" && (
              <>
                <p className="text-muted-foreground mb-2 px-1 text-xs">
                  {job.status === "running"
                    ? `导出中：已导出 ${job.func_done} 个函数。未完成不给看半成品，下面是 idat 日志尾部。`
                    : job.status === "pending"
                      ? "排队中：IDA 串行执行。下面是日志尾部。"
                      : `导出${STATUS_LABEL[job.status]}${job.error ? `：${job.error}` : ""}`}
                </p>
                <pre className="bg-muted/30 max-h-full overflow-auto rounded border p-2 font-mono text-[11px] leading-5 whitespace-pre-wrap">
                  {logText || "（还没有日志）"}
                </pre>
              </>
            )}
            {loadingCode && <p className="text-muted-foreground p-2 text-sm">读取中…</p>}
            {job?.status === "completed" && !code && !loadingCode && (
              <p className="text-muted-foreground p-2 text-sm">
                这里显示 IDA 导出的伪 C 代码，头部注释里的 callers / callees 可点击跳转。
              </p>
            )}
            {code && (
              <div onDoubleClick={() => void onCodeDoubleClick()} title="双击函数名跳转到该函数">
                <HighlightedCode
                  code={code.code}
                  name={`${code.name}.c`}
                  tokenHint={(t) =>
                    isJumpableToken(t)
                      ? "cursor-pointer hover:underline decoration-dotted"
                      : undefined
                  }
                />
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
