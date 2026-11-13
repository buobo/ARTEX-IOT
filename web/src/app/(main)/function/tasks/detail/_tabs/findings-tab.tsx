"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowDownIcon, ArrowUpIcon, ArrowUpRightIcon, ChevronRightIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { api } from "@/lib/api";
import { useStoredSortPreference } from "@/lib/sort-preference";
import { statusMeta } from "@/lib/status";
import type { AuditQueueStatus, Finding, FindingStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

type FindingSortField = "time";

const FINDING_SORT_FIELDS: readonly FindingSortField[] = ["time"];

// AUDIT_WINDOW_SECONDS 与后端 auditIdleWindow 保持一致：点击判重后等这么久才开批。
const AUDIT_WINDOW_SECONDS = 10;
const FINDING_SORT_PREFERENCE_KEY = "artex_task_findings_sort";

function findingLabel(finding: Finding): string {
  if (finding.name?.trim()) return finding.name;
  if (finding.vulnclass?.trim()) return finding.vulnclass;
  return "未分类";
}

const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function Row({
  f,
  contextTaskId,
  onStatus,
  onAudit,
  auditing,
}: {
  f: Finding;
  contextTaskId: string;
  onStatus: (f: Finding, next: FindingStatus) => void;
  onAudit: (f: Finding) => void;
  auditing: boolean;
}) {
  const [open, setOpen] = React.useState(false);
  return (
    <div className="border-b last:border-b-0">
      <div className="flex w-full items-center gap-3 px-4 py-3 text-sm hover:bg-accent/40">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex min-w-0 flex-1 items-center gap-3 text-left"
        >
          <ChevronRightIcon
            className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")}
          />
          <StatusBadge domain="severity" value={f.severity} dot />
          <div className="flex min-w-0 flex-1 flex-col gap-1">
            <div className="flex min-w-0 items-center gap-2">
              <span className="truncate font-medium">{findingLabel(f)}</span>
              {f.inherited && f.source_task_id && (
                <Badge variant="outline" className="shrink-0">
                  来源 #{f.source_task_id} · 只读
                </Badge>
              )}
            </div>
            <span className="truncate text-xs text-muted-foreground">{f.summary}</span>
          </div>
        </button>
        <Badge variant="outline">流量证据 {f.traffic_count ?? 0} 条</Badge>
        {f.components && f.components.length > 0 && (
          <div className="hidden shrink-0 flex-wrap justify-end gap-1 sm:flex">
            {f.components.slice(0, 2).map((a) => (
              <code
                key={a.id}
                className="max-w-[10rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                title={`${a.type} · ${a.label}`}
              >
                {a.label}
              </code>
            ))}
            {f.components.length > 2 && <span className="text-xs text-muted-foreground">+{f.components.length - 2}</span>}
          </div>
        )}
        {f.finding_id && !f.inherited ? (
          <Select value={f.status} onValueChange={(v) => onStatus(f, v as FindingStatus)}>
            <SelectTrigger size="sm" className="h-7 w-28 shrink-0 border-none px-1 shadow-none focus-visible:ring-0">
              <StatusBadge domain="finding" value={f.status} dot />
            </SelectTrigger>
            <SelectContent position="popper" align="end">
              <SelectGroup>
                {FINDING_STATUSES.map((st) => (
                  <SelectItem key={st} value={st}>
                    {statusMeta("finding", st).label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        ) : (
          <StatusBadge domain="finding" value={f.status} dot />
        )}
        <span className="hidden shrink-0 text-xs text-muted-foreground md:block">
          {new Date(f.ts).toLocaleString("zh-CN")}
        </span>
        {f.finding_id && (
          <button
            type="button"
            onClick={() => onAudit(f)}
            disabled={auditing}
            className="text-muted-foreground hover:text-primary inline-flex shrink-0 items-center gap-0.5 text-xs disabled:opacity-40"
            title="重新判重：让审计 Agent 复查这条漏洞是否与其他条目重复"
          >
            判重
          </button>
        )}
        {f.finding_id && (
          <Link
            href={
              f.inherited
                ? `/function/findings/detail?id=${f.finding_id}&context_task=${contextTaskId}`
                : `/function/findings/detail?id=${f.finding_id}`
            }
            className="text-muted-foreground hover:text-primary inline-flex shrink-0 items-center gap-0.5 text-xs"
            title="查看漏洞详情"
          >
            详情
            <ArrowUpRightIcon className="size-3" />
          </Link>
        )}
      </div>
      {open && (
        <div className="bg-muted/30 px-4 pb-4 pl-11">
          <div className="mb-1 text-xs font-medium text-muted-foreground">证据 / PoC</div>
          <pre className="overflow-auto rounded-md border bg-background p-3 font-mono text-xs whitespace-pre-wrap">
            {f.evidence}
          </pre>
        </div>
      )}
    </div>
  );
}

export function FindingsTab({ taskId }: { taskId: string }) {
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [sortPreference, setSortPreference] = useStoredSortPreference(
    FINDING_SORT_PREFERENCE_KEY,
    FINDING_SORT_FIELDS,
    "time",
    "desc",
  );

  React.useEffect(() => {
    let active = true;
    const load = () => {
      api
        .findings(taskId)
        .then((fs) => {
          if (active) setFindings(fs);
        })
        .catch(() => {
          // Keep the last successful snapshot during transient refresh failures.
        });
    };
    load();
    const t = setInterval(load, 3000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [taskId]);

  const [audit, setAudit] = React.useState<AuditQueueStatus | null>(null);
  const [auditing, setAuditing] = React.useState(false);
  // 静默窗口倒计时：轮询每 3 秒给一次 window_left，前端每秒自减，
  // 两次轮询之间秒数也在动（否则按钮上的秒数是死的）。
  // 点击判重时本地先把窗口置成 30，等下一次轮询再用后端值校准。
  const [windowLeft, setWindowLeft] = React.useState(0);
  React.useEffect(() => {
    const left = audit?.window_left;
    if (typeof left === "number") setWindowLeft(left);
  }, [audit?.window_left]);
  React.useEffect(() => {
    const tick = setInterval(() => setWindowLeft((n) => (n > 0 ? n - 1 : 0)), 1000);
    return () => clearInterval(tick);
  }, []);

  // 判重队列进度：只有「排队中 / 正在跑」才每 3 秒轮询，空闲时拉一次就停
  // （常开 interval 会让每个打开的任务详情页一直发请求）。
  const [auditEpoch, setAuditEpoch] = React.useState(0);
  React.useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const load = () => {
      api
        .auditTaskStatus(taskId)
        .then((st) => {
          if (!active) return;
          setAudit(st);
          if (st.running || st.pending > 0) {
            timer = setTimeout(load, 3000);
          }
        })
        .catch(() => {
          // 后端未就绪时静默，不打断页面。
        });
    };
    load();
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
  }, [taskId, auditEpoch]);

  const onAuditTask = React.useCallback(async () => {
    if (auditing) return;
    setAuditing(true);
    try {
      const r = await api.auditTaskFindings(taskId);
      if (r.queued > 0) {
        setWindowLeft(AUDIT_WINDOW_SECONDS); // 点了就刷新等待期
        toast.success(`已送审 ${r.queued} 条漏洞，最后一次点击后 ${AUDIT_WINDOW_SECONDS} 秒开始判重`);
      } else if (r.note) {
        toast.message(r.note);
      } else {
        toast.success("没有需要判重的漏洞");
      }
      setAuditEpoch((n) => n + 1); // 立刻拉一次进度，按钮随即进入「判重中」
    } catch (e) {
      toast.error("送审判重失败：" + (e as Error).message);
    } finally {
      setAuditing(false);
    }
  }, [auditing, taskId]);

  const onAuditOne = React.useCallback(
    async (f: Finding) => {
      if (!f.finding_id) return;
      const running = Boolean(audit?.running);
      const queued = (audit?.pending ?? 0) > 0;
      try {
        await api.auditFinding(f.finding_id);
        setWindowLeft(AUDIT_WINDOW_SECONDS); // 点了就刷新等待期，不用等下一次轮询
        toast.success(
          running
            ? `#${f.finding_id} 已排队：当前批次结束后会再判一次`
            : queued
              ? `#${f.finding_id} 已加入本批（最后一次点击后 ${AUDIT_WINDOW_SECONDS} 秒开跑，继续点会顺延）`
              : `#${f.finding_id} 已加入判重队列，${AUDIT_WINDOW_SECONDS} 秒后开跑`,
        );
        setAuditEpoch((n) => n + 1);
      } catch (e) {
        toast.error("送审判重失败：" + (e as Error).message);
      }
    },
    [audit],
  );

  const onStatus = React.useCallback(async (f: Finding, next: FindingStatus) => {
    if (f.inherited || !f.finding_id || next === f.status) return;
    const prev = f.status;
    setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: next } : x)));
    try {
      await api.setFindingStatus(f.finding_id, next);
      toast.success(`已标记为「${statusMeta("finding", next).label}」`);
    } catch (e) {
      setFindings((cur) => cur.map((x) => (x.id === f.id ? { ...x, status: prev } : x)));
      toast.error("更新失败：" + (e as Error).message);
    }
  }, []);

  const items = findings
    .filter((f) => f.task_id === taskId || f.inherited)
    .sort((a, b) => {
      const compared = Date.parse(a.ts) - Date.parse(b.ts);
      if (compared !== 0) return sortPreference.direction === "asc" ? compared : -compared;
      return b.id.localeCompare(a.id, undefined, { numeric: true });
    });

  return (
    <Card className="overflow-hidden py-0">
      <CardContent className="px-0">
        <div className="flex items-center border-b px-4 py-2 text-xs text-muted-foreground">
          <span className="min-w-0 flex-1">漏洞</span>
          <button
            type="button"
            className="inline-flex items-center gap-1 outline-none focus-visible:underline"
            aria-label={`发现时间当前${sortPreference.direction === "asc" ? "正序" : "倒序"}，点击切换排序方向`}
            onClick={() =>
              setSortPreference((current) => ({
                field: "time",
                direction: current.direction === "asc" ? "desc" : "asc",
              }))
            }
          >
            <span>发现时间</span>
            {sortPreference.direction === "asc" ? (
              <ArrowUpIcon className="size-3.5" />
            ) : (
              <ArrowDownIcon className="size-3.5" />
            )}
          </button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="ml-3 h-6 gap-1 px-1.5 text-xs"
            onClick={onAuditTask}
            disabled={auditing || (audit?.running ?? false)}
            title={
              audit?.running
                ? `判重进行中：第 ${audit?.batches_done ?? 1}/${audit?.batches_total ?? 1} 批，已处理 ${audit?.done ?? 0}/${audit?.total ?? 0} 条`
                : (audit?.pending ?? 0) > 0
                  ? `已排队 ${audit?.pending} 条，${windowLeft > 0 ? `约 ${windowLeft} 秒后开跑` : "即将开跑"}；现在继续点会顺延等待期`
                  : `把本任务所有在处理中的漏洞送进判重队列（重复的会被合并成一条）。点击后等 ${AUDIT_WINDOW_SECONDS} 秒才开跑，期间可继续追加`
            }
          >
            <RefreshCwIcon className={cn("size-3", (audit?.running || auditing) && "animate-spin")} />
            {audit?.running
              ? `判重中… ${audit?.done ?? 0}/${audit?.total ?? 0}`
              : (audit?.pending ?? 0) > 0
                ? windowLeft > 0
                  ? `判重排队 ${audit?.pending}（${windowLeft}s）`
                  : `判重排队 ${audit?.pending}（等待开跑）`
                : "整任务判重"}
          </Button>
        </div>
        {items.map((f) => (
          <Row
            key={f.id}
            f={f}
            contextTaskId={taskId}
            onStatus={onStatus}
            onAudit={onAuditOne}
            auditing={auditing}
          />
        ))}
        {items.length === 0 && (
          <p className="px-4 py-8 text-center text-sm text-muted-foreground">本任务及直接关联任务暂无确认发现。</p>
        )}
      </CardContent>
    </Card>
  );
}
