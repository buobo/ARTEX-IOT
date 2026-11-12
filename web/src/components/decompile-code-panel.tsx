"use client";

// 反编译「代码面板」：整页版 /function/decompile 与任务详情「反编译」页签共用同一份实现，
// 保证配色、调用关系芯片、来源高亮、双击跳转、手型光标、日志尾、状态条完全一致。
//
// 用法：ref 暴露 open(addr)；job 变了自动清空；onAddrChange 把当前函数地址回传父级做高亮。

import * as React from "react";

import { ArrowLeftIcon, ChevronDownIcon, CopyIcon, DownloadIcon, RotateCcwIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { DecompileCode, DecompileJob, DecompileJobDetail, DecompileStatus } from "@/lib/types";

import { HighlightedCode } from "@/app/(main)/function/tasks/detail/_tabs/poc-tab";

const STATUS_LABEL: Record<DecompileStatus, string> = {
  pending: "排队中",
  running: "运行中",
  completed: "已完成",
  failed: "失败",
  canceled: "已取消",
};

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export interface DecompileCodePanelHandle {
  open: (addr: string) => void;
  current: () => DecompileCode | null;
}

export interface DecompileCodePanelProps {
  job: DecompileJob | null;
  onAddrChange?: (addr: string | null) => void;
  onCancel?: () => void;
  onRetry?: () => void;
  onDelete?: () => void;
}

export const DecompileCodePanel = React.forwardRef<DecompileCodePanelHandle, DecompileCodePanelProps>(
  function DecompileCodePanel({ job, onAddrChange, onCancel, onRetry, onDelete }, ref) {
    const [code, setCode] = React.useState<DecompileCode | null>(null);
    const [history, setHistory] = React.useState<{ addr: string; name: string }[]>([]);
    const [jumpFrom, setJumpFrom] = React.useState<{ addr: string; name: string } | null>(null);
    const [callsOpen, setCallsOpen] = React.useState(false);
    const [loadingCode, setLoadingCode] = React.useState(false);
    const [logText, setLogText] = React.useState("");
    const [detail, setDetail] = React.useState<DecompileJobDetail | null>(null);
    const [fnNames, setFnNames] = React.useState<Set<string>>(new Set());
    const codeBoxRef = React.useRef<HTMLDivElement | null>(null);
    const codeRef = React.useRef<DecompileCode | null>(null);
    const notify = React.useRef(onAddrChange);
    notify.current = onAddrChange;

    const setBoth = (next: DecompileCode | null) => {
      codeRef.current = next;
      setCode(next);
      notify.current?.(next?.addr ?? null);
    };

    const open = React.useCallback(
      async (addr: string, push = true) => {
        if (!job) return;
        setLoadingCode(true);
        const prev = codeRef.current;
        try {
          const c = await api.decompileCode(job.id, addr);
          if (push && prev && prev.addr !== c.addr) {
            setHistory((h) => [...h, { addr: prev.addr, name: prev.name }]);
          }
          if (prev && prev.addr !== c.addr) setJumpFrom({ addr: prev.addr, name: prev.name });
          setBoth(c);
        } catch (e) {
          toast.error(e instanceof Error ? e.message : "读取函数失败");
        } finally {
          setLoadingCode(false);
        }
      },
      [job],
    );

    React.useImperativeHandle(ref, () => ({ open: (addr: string) => void open(addr), current: () => codeRef.current }), [
      open,
    ]);

    // 换 job：清空状态
    React.useEffect(() => {
      codeRef.current = null;
      setCode(null);
      setHistory([]);
      setJumpFrom(null);
      setCallsOpen(false);
      notify.current?.(null);
    }, [job?.id]);

    const goBack = () => {
      const last = history[history.length - 1];
      if (!last || !job) return;
      setHistory(history.slice(0, -1));
      void open(last.addr, false);
    };

    // 换函数：调用关系收回一行，代码滚回顶部
    React.useEffect(() => {
      setCallsOpen(false);
      if (codeBoxRef.current) codeBoxRef.current.scrollTop = 0;
    }, [code?.addr]);

    // 可跳转函数名（手型光标 + 双击跳转）
    React.useEffect(() => {
      if (!job || job.status !== "completed") {
        setFnNames(new Set());
        return;
      }
      let stop = false;
      api
        .decompileNames(job.id)
        .then(({ names }) => {
          if (!stop) setFnNames(new Set(names));
        })
        .catch(() => undefined);
      return () => {
        stop = true;
      };
    }, [job]);

    const isJumpableToken = React.useCallback(
      (t: string) => {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(t)) return false;
        if (fnNames.size > 0) return fnNames.has(t);
        const src = codeRef.current?.code;
        return !!src && new RegExp(`(^|[^A-Za-z0-9_])${t}\\s*\\(`).test(src);
      },
      [fnNames],
    );

    // 双击代码里的函数名跳到那个函数
    const onCodeDoubleClick = React.useCallback(async () => {
      if (!job || job.status !== "completed" || !codeRef.current) return;
      const cur = codeRef.current;
      const word = (window.getSelection()?.toString() ?? "").trim();
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(word)) return;
      if (word === cur.name) return;
      const called = new RegExp(`(^|[^A-Za-z0-9_])${word}\\s*\\(`).test(cur.code);
      if (!called) return;
      try {
        const res = await api.decompileFunctions(job.id, word, 1, 200);
        const hit =
          res.items.find((f) => f.name === word) ??
          res.items.find((f) => f.name.toLowerCase() === word.toLowerCase());
        if (!hit) {
          toast.info(`索引里没有 ${word}（外部库函数不导出）`);
          return;
        }
        await open(hit.addr);
      } catch (e) {
        toast.error(e instanceof Error ? e.message : "跳转失败");
      }
    }, [job, open]);

    // 未完成的 job：轮询日志尾
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

    // 完成态取产物大小
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

    const callerAddrs = React.useMemo(() => {
      const base = code?.callers ?? [];
      if (!jumpFrom || jumpFrom.addr === code?.addr) return base;
      return [jumpFrom.addr, ...base.filter((a) => a !== jumpFrom.addr)];
    }, [code, jumpFrom]);

    return (
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
              {code.truncated && (
                <Badge variant="secondary" className="text-[10px]">
                  已截断
                </Badge>
              )}
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
          {job && (job.status === "running" || job.status === "pending") && onCancel && (
            <Button variant="outline" size="sm" className="ml-auto" onClick={onCancel}>
              取消导出
            </Button>
          )}
          {job && (job.status === "failed" || job.status === "canceled") && onRetry && (
            <Button variant="outline" size="sm" className="ml-auto" onClick={onRetry}>
              <RotateCcwIcon className="size-4" /> 重试
            </Button>
          )}
          {job && job.status !== "running" && job.status !== "pending" && onDelete && (
            <Button variant="ghost" size="sm" className="ml-auto text-red-400" onClick={onDelete}>
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
            {/* 默认一行；「展开/收起」两向都在这条顶行上，展开时不随内容漂移 */}
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
                    onClick={() => void open(a)}
                  >
                    {from ? `↩ 0x${a}` : `0x${a}`}
                  </button>
                );
              })}
              <span className="text-muted-foreground ml-3 shrink-0">callees</span>
              {(code.callees ?? []).length === 0 && <span className="text-muted-foreground/60">none</span>}
              {(code.callees ?? []).map((a) => (
                <button
                  key={`d-${a}`}
                  type="button"
                  className="shrink-0 cursor-pointer rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-amber-300 hover:bg-amber-500/25"
                  onClick={() => void open(a)}
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
                <ChevronDownIcon className={`size-3 transition-transform ${callsOpen ? "rotate-180" : ""}`} />
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
                tokenHint={(t) => (isJumpableToken(t) ? "cursor-pointer hover:underline decoration-dotted" : undefined)}
              />
            </div>
          )}
        </div>
      </section>
    );
  },
);
