"use client";

import * as React from "react";

import { BinaryIcon, Loader2Icon, PackageIcon, RefreshCwIcon, RotateCcwIcon, UnlinkIcon } from "lucide-react";
import Link from "next/link";
import { toast } from "sonner";

import { ComponentDslSearch } from "@/components/component-dsl-search";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import {
  COMPONENT_STATUSES,
  COMPONENT_STATUS_LABELS,
  componentSourceLabel,
  componentTypeLabel,
} from "@/lib/task-components";
import type { Component, ComponentStatus, DecompileJob } from "@/lib/types";

const PAGE_SIZE = 50;

const STATUS_STYLE: Record<ComponentStatus, string> = {
  pending: "bg-slate-500/15 text-slate-300",
  running: "bg-blue-500/15 text-blue-300",
  completed: "bg-emerald-500/15 text-emerald-300",
  ignored: "bg-zinc-600/20 text-zinc-400",
};

/**
 * 任务里的组件：本任务登记的组件清单 + 挖到哪一步。
 * 组件本身是全局共享的（固件解包结果），这里只展示挂着 task_id 的那些。
 */
export function ComponentsTab({ taskId }: { taskId: string }) {
  const [rows, setRows] = React.useState<Component[]>([]);
  const [dsl, setDsl] = React.useState("");
  const [status, setStatus] = React.useState<"" | ComponentStatus>("");
  const [loading, setLoading] = React.useState(false);
  const [selected, setSelected] = React.useState<number[]>([]);
  const [batchStatus, setBatchStatus] = React.useState<"" | ComponentStatus>("");
  const [bulkSaving, setBulkSaving] = React.useState(false);
  // 状态计数走独立接口（不分页），避免只统计当前页。
  const [counts, setCounts] = React.useState<Record<ComponentStatus, number>>({
    pending: 0,
    running: 0,
    completed: 0,
    ignored: 0,
  });

  const totalAll = Object.values(counts).reduce((a, b) => a + b, 0);

  // 反编译导出状态：componentId → 最新 job。行内按钮据此显示进度/复用/重试。
  const [decompJobs, setDecompJobs] = React.useState<Record<number, DecompileJob>>({});
  const [decompBusy, setDecompBusy] = React.useState(false);

  const loadDecompJobs = React.useCallback(async () => {
    try {
      const { jobs } = await api.decompileTaskJobs(taskId);
      const map: Record<number, DecompileJob> = {};
      for (const j of jobs) if (j.component_id) map[j.component_id] = j;
      setDecompJobs(map);
    } catch {
      /* 导出状态只是辅助信息，失败不影响组件列表 */
    }
  }, [taskId]);

  React.useEffect(() => {
    void loadDecompJobs();
  }, [loadDecompJobs]);

  // 有排队/运行中的导出才轮询，避免空转。
  const decompActive = Object.values(decompJobs).some(
    (j) => j.status === "running" || j.status === "pending",
  );
  React.useEffect(() => {
    if (!decompActive) return;
    const timer = setInterval(() => void loadDecompJobs(), 2500);
    return () => clearInterval(timer);
  }, [decompActive, loadDecompJobs]);

  const exportDecompile = async (ids: number[]) => {
    if (ids.length === 0) return;
    setDecompBusy(true);
    try {
      const res = await api.decompileCreate(taskId, { component_ids: ids });
      const reused = res.jobs.filter((j) => j.reused).length;
      const fresh = res.jobs.length - reused;
      const skipped = res.skipped ?? [];
      if (fresh === 0 && skipped.length === 0) toast.success(`已导出过，直接复用 ${reused} 个结果`);
      else
        toast.success(
          `已建 ${fresh} 个导出任务${reused ? `，复用 ${reused} 个` : ""}，完成后点图标查看`,
        );
      if (skipped.length > 0) toast.warning(`${skipped.length} 个组件没有二进制路径，已跳过：${skipped.join("、")}`);
      await loadDecompJobs();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "导出失败");
    } finally {
      setDecompBusy(false);
    }
  };

  // 行内一格：没导出过 = 图标按钮；导出中/已完成 = 点进浏览页；失败/取消 = 重试按钮。
  const decompCell = (c: Component) => {
    const job = decompJobs[c.id];
    if (!job) {
      return (
        <Button
          variant="ghost"
          size="icon"
          className="text-muted-foreground size-7"
          title={c.binary_path ? "导出反编译（IDA 无头）" : "该组件未登记二进制路径，无法导出"}
          disabled={!c.binary_path || decompBusy}
          onClick={() => void exportDecompile([c.id])}
        >
          <BinaryIcon className="size-3.5" />
        </Button>
      );
    }
    const href = `/function/decompile?job=${job.id}`;
    if (job.status === "completed") {
      return (
        <Link
          href={href}
          title={`已导出 ${job.func_done} 个函数 · ${job.binary_path}`}
          className="inline-flex items-center gap-0.5 text-[11px] text-emerald-300 hover:underline"
        >
          <BinaryIcon className="size-3.5" />
          {job.func_done}
        </Link>
      );
    }
    if (job.status === "running" || job.status === "pending") {
      return (
        <Link
          href={href}
          title={`${job.status === "pending" ? "排队中" : "导出中"}：已导出 ${job.func_done} 个函数`}
          className="inline-flex items-center gap-0.5 text-[11px] text-blue-300"
        >
          <Loader2Icon className="size-3.5 animate-spin" />
          {job.func_done || "…"}
        </Link>
      );
    }
    return (
      <Button
        variant="ghost"
        size="icon"
        className="size-7 text-red-400"
        title={`${job.status === "failed" ? "导出失败" : "已取消"}：${job.error || ""}（点击重试）`}
        disabled={decompBusy}
        onClick={() => void exportDecompile([c.id])}
      >
        <RotateCcwIcon className="size-3.5" />
      </Button>
    );
  };

  const loadCounts = React.useCallback(async () => {
    try {
      const res = await api.componentStatusCounts(taskId);
      setCounts({
        pending: res.pending ?? 0,
        running: res.running ?? 0,
        completed: res.completed ?? 0,
        ignored: res.ignored ?? 0,
      });
    } catch {
      /* 计数只是辅助信息，失败不打断列表 */
    }
  }, [taskId]);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = dsl.trim()
        ? await api.searchTaskComponents(taskId, dsl.trim(), "", status, "", PAGE_SIZE, 0)
        : await api.taskComponents(taskId, "", status, "", PAGE_SIZE, 0);
      setRows(res.components);
      setSelected([]);
    } catch (err) {
      toast.error(`加载任务组件失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [taskId, dsl, status]);

  React.useEffect(() => {
    void load();
    void loadCounts();
  }, [load, loadCounts]);

  const changeStatus = async (c: Component, next: ComponentStatus) => {
    try {
      await api.setComponentStatus([c.id], next, taskId);
      setRows((prev) => prev.map((x) => (x.id === c.id ? { ...x, status: next } : x)));
      void loadCounts();
    } catch (err) {
      toast.error(`更新状态失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const detach = async (c: Component) => {
    try {
      await api.detachTaskComponent(taskId, c.id);
      toast.success(`已从本任务移除 ${c.component_name}`);
      await load();
      void loadCounts();
    } catch (err) {
      toast.error(`移除失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // ---- 批量：勾选后统一改状态 / 移除挂载 ----
  // 改状态复用组件库那条接口（POST /api/components/status），带 task_id 走任务守卫；
  // 移除挂载复用已有的单条 DELETE，不新增接口。
  const pageIDs = React.useMemo(() => rows.map((r) => r.id), [rows]);
  const selectedOnPage = selected.filter((id) => pageIDs.includes(id)).length;
  const allChecked = pageIDs.length > 0 && selectedOnPage === pageIDs.length;
  const someChecked = selectedOnPage > 0 && !allChecked;

  const toggleAll = () => setSelected(allChecked ? [] : pageIDs);
  const toggleOne = (id: number) =>
    setSelected((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));

  const applyBatchStatus = async () => {
    if (!batchStatus || selected.length === 0) return;
    setBulkSaving(true);
    try {
      const res = await api.setComponentsStatus(selected, batchStatus, taskId);
      const label = COMPONENT_STATUS_LABELS[batchStatus];
      toast.success(
        res.changed === res.requested
          ? `已把 ${res.changed} 个组件标为「${label}」`
          : `已把 ${res.changed} 个组件标为「${label}」，${res.requested - res.changed} 个未变`,
      );
      setBatchStatus("");
      setSelected([]);
      await load();
      void loadCounts();
    } catch (err) {
      toast.error(`批量改状态失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBulkSaving(false);
    }
  };

  const detachSelected = async () => {
    if (selected.length === 0) return;
    setBulkSaving(true);
    let ok = 0;
    const failed: string[] = [];
    for (const id of selected) {
      const row = rows.find((r) => r.id === id);
      try {
        await api.detachTaskComponent(taskId, id);
        ok++;
      } catch {
        failed.push(row?.component_name || String(id));
      }
    }
    setBulkSaving(false);
    if (failed.length === 0) {
      toast.success(`已从本任务移除 ${ok} 个组件`);
    } else {
      toast.error(`移除 ${ok} 个，失败 ${failed.length} 个：${failed.join("、")}`);
    }
    setSelected([]);
    await load();
    void loadCounts();
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <PackageIcon className="size-4" /> 组件（{totalAll}）
          </CardTitle>
          <CardDescription>
            本任务从固件里解出并登记的组件。状态即挖掘进度：待挖 → 挖掘中 → 已挖完 / 不挖。
          </CardDescription>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} /> 刷新
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant={status === "" ? "default" : "outline"}
            onClick={() => setStatus("")}
          >
            全部 {totalAll}
          </Button>
          {COMPONENT_STATUSES.map((st) => (
            <Button
              key={st}
              size="sm"
              variant={status === st ? "default" : "outline"}
              onClick={() => setStatus(st)}
            >
              {COMPONENT_STATUS_LABELS[st]} {counts[st]}
            </Button>
          ))}
          <div className="min-w-[240px] flex-1">
            <ComponentDslSearch
              value={dsl}
              onChange={setDsl}
              placeholder="在本任务内查组件，如 component_name=lighttpd"
            />
          </div>
        </div>

        {selected.length > 0 && (
          <div className="bg-muted/40 flex flex-wrap items-center gap-2 rounded-md border px-3 py-2">
            <span className="text-sm">
              已选 <b className="tabular-nums">{selected.length}</b> 项
            </span>
            <Button variant="ghost" size="sm" onClick={toggleAll}>
              {allChecked ? "取消本页全选" : "全选本页"}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setSelected([])}>
              清空
            </Button>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <Select value={batchStatus} onValueChange={(v) => setBatchStatus(v as ComponentStatus)}>
                <SelectTrigger className="h-8 w-32">
                  <SelectValue placeholder="改状态为…" />
                </SelectTrigger>
                <SelectContent>
                  {COMPONENT_STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {COMPONENT_STATUS_LABELS[s]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button size="sm" disabled={!batchStatus || bulkSaving} onClick={() => void applyBatchStatus()}>
                应用
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={decompBusy}
                onClick={() => void exportDecompile(selected)}
                title="对选中组件逐个导出反编译（IDA 无头，串行执行）"
              >
                <BinaryIcon className="size-4" /> 导出反编译（{selected.length}）
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={bulkSaving}
                onClick={() => void detachSelected()}
              >
                <UnlinkIcon className="size-4" /> 移除选中（{selected.length}）
              </Button>
            </div>
          </div>
        )}

        <div className="overflow-hidden rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">
                  <input
                    ref={(el) => {
                      if (el) el.indeterminate = someChecked;
                    }}
                    type="checkbox"
                    aria-label="全选本页"
                    checked={allChecked}
                    onChange={toggleAll}
                    className="size-4 cursor-pointer align-middle accent-sky-500"
                  />
                </TableHead>
                <TableHead className="w-20">类型</TableHead>
                <TableHead>组件名</TableHead>
                <TableHead className="w-24">版本</TableHead>
                <TableHead>二进制</TableHead>
                <TableHead className="w-28">状态</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-muted-foreground py-8 text-center text-sm">
                    {loading ? "加载中…" : "本任务还没有登记组件。"}
                  </TableCell>
                </TableRow>
              )}
              {rows.map((c) => {
                const st = (c.status || "pending") as ComponentStatus;
                return (
                  <TableRow key={c.id}>
                    <TableCell>
                      <input
                        type="checkbox"
                        aria-label={`选择 ${c.component_name}`}
                        checked={selected.includes(c.id)}
                        onChange={() => toggleOne(c.id)}
                        className="size-4 cursor-pointer align-middle accent-sky-500"
                      />
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-[11px]">
                        {componentTypeLabel(c.type)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="font-medium">{c.component_name || "—"}</div>
                      {c.task_source && (
                        <div className="text-muted-foreground mt-0.5 text-[11px]">
                          {componentSourceLabel(c.task_source)}
                          {c.task_source_summary ? ` · ${c.task_source_summary}` : ""}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{c.version || "—"}</TableCell>
                    <TableCell className="text-muted-foreground truncate font-mono text-xs">
                      {c.binary_path || "—"}
                    </TableCell>
                    <TableCell>
                      <select
                        className={`w-full rounded border-none bg-transparent px-1 py-0.5 text-xs ${STATUS_STYLE[st]}`}
                        value={st}
                        onChange={(e) => void changeStatus(c, e.target.value as ComponentStatus)}
                        aria-label="更新组件状态"
                      >
                        {COMPONENT_STATUSES.map((s) => (
                          <option key={s} value={s} className="bg-background text-foreground">
                            {COMPONENT_STATUS_LABELS[s]}
                          </option>
                        ))}
                      </select>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-0.5">
                        {decompCell(c)}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-muted-foreground size-7"
                          title="从本任务移除（不删组件本身）"
                          onClick={() => void detach(c)}
                        >
                          <UnlinkIcon className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
