"use client";

import * as React from "react";

import { ChevronLeftIcon, ChevronRightIcon, PackageIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { ComponentDslSearch } from "@/components/component-dsl-search";
import { COMPONENT_STATUSES, COMPONENT_STATUS_LABELS } from "@/lib/task-components";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { Component, ComponentStatus } from "@/lib/types";

const PAGE_SIZE = 50;

const TYPE_OPTIONS = ["web", "mqtt", "ros", "ssh", "telnet", "upnp", "onvif", "rtsp", "ftp", "other"];

const STATUS_LABELS: Record<ComponentStatus, string> = {
  pending: "待挖",
  running: "挖掘中",
  completed: "已挖完",
  ignored: "不挖",
};

const STATUS_STYLE: Record<ComponentStatus, string> = {
  pending: "bg-slate-500/15 text-slate-300",
  running: "bg-blue-500/15 text-blue-300",
  completed: "bg-emerald-500/15 text-emerald-300",
  ignored: "bg-zinc-600/20 text-zinc-400",
};

function statusOf(c: Component): ComponentStatus {
  return (c.status || "pending") as ComponentStatus;
}

export default function ComponentsPage() {
  const [rows, setRows] = React.useState<Component[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(1);
  const [type, setType] = React.useState("");
  const [status, setStatus] = React.useState("");
  const [firmware, setFirmware] = React.useState("");
  const [taskId, setTaskId] = React.useState(""); // 按任务筛选（空 = 全部）
  const [dsl, setDsl] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [selected, setSelected] = React.useState<number[]>([]);
  const [detail, setDetail] = React.useState<Component | null>(null);
  const [confirmDelete, setConfirmDelete] = React.useState(false);
  const [counts, setCounts] = React.useState<Record<string, number>>({});
  const [firmwareCounts, setFirmwareCounts] = React.useState<Record<string, number>>({});
  // 任务 id → 任务名（列表里显示名字，重名靠 id 兜底）
  const [taskNames, setTaskNames] = React.useState<Record<string, string>>({});
  // 固件 sha256 → 固件文件名（值取自 task_scope.kind=firmware 的 value）
  const [firmwareName, setFirmwareName] = React.useState<Record<string, string>>({});
  const scopeDone = React.useRef(false);
  // 表格列宽：先用现有自适应宽度量一次，之后交给 colgroup + 拖拽
  const headRowRef = React.useRef<HTMLTableRowElement | null>(null);
  const [colW, setColW] = React.useState<number[] | null>(null);
  const dragCol = React.useRef<{ idx: number; startX: number; startW: number } | null>(null);
  const [addOpen, setAddOpen] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [batchStatus, setBatchStatus] = React.useState<ComponentStatus | "">("");
  const [bulkSaving, setBulkSaving] = React.useState(false);
  const [form, setForm] = React.useState({
    type: "web",
    component_name: "",
    version: "",
    vendor: "",
    binary_path: "",
    config_path: "",
    started_by: "",
    port: "",
    notes: "",
  });

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const offset = (page - 1) * PAGE_SIZE;
      const kw = dsl.trim();
      const res = taskId
        ? kw
          ? await api.searchTaskComponents(taskId, kw, type, status, firmware, PAGE_SIZE, offset)
          : await api.taskComponents(taskId, type, status, firmware, PAGE_SIZE, offset)
        : kw
          ? await api.searchComponents(kw, type, status, firmware, PAGE_SIZE, offset)
          : await api.components(type, status, firmware, PAGE_SIZE, offset);
      setRows(res.components);
      setTotal(res.total);
      setSelected([]);
    } catch (err) {
      toast.error(`加载组件失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [page, type, status, firmware, dsl, taskId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  // 全量固件名：下拉要列所有固件，所以按任务列表把所有 scope 取一遍（sha256 → 固件文件名）
  React.useEffect(() => {
    if (scopeDone.current) return;
    scopeDone.current = true;
    void (async () => {
      try {
        const { tasks } = await api.tasks();
        const names: Record<string, string> = {};
        const fw: Record<string, string> = {};
        for (const t of tasks) names[String(t.id)] = (t.name || "").trim() || `#${t.id}`;
        setTaskNames(names);
        await Promise.all(
          tasks.map(async (t) => {
            try {
              const { scope } = await api.taskScope(String(t.id));
              for (const r of scope) {
                if (r.kind === "firmware" && r.sha256 && r.value) fw[r.sha256] = r.value;
              }
            } catch {
              /* 单个任务取不到不影响其他 */
            }
          }),
        );
        setFirmwareName(fw);
      } catch {
        /* 拉不到就退回只显示 sha 前缀 */
      }
    })();
  }, []);

  React.useEffect(() => {
    api
      .componentCounts()
      .then((c) => setCounts(c ?? {}))
      .catch(() => setCounts({}));
    api
      .componentFirmwareCounts()
      .then((c) => setFirmwareCounts(c ?? {}))
      .catch(() => setFirmwareCounts({}));
  }, []);

  // 首次渲染后量一次各列实际宽度（保持现在的观感），再切到固定列宽模式
  React.useLayoutEffect(() => {
    if (colW || rows.length === 0) return;
    const tr = headRowRef.current;
    if (!tr) return;
    const cells = Array.from(tr.querySelectorAll("th")) as HTMLElement[];
    if (cells.length !== 9) return;
    const widths = cells.map((c) => Math.round(c.getBoundingClientRect().width));
    if (widths.some((w) => w <= 0)) return;
    setColW(widths);
  });

  const startColDrag = (idx: number) => (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const startW = colW?.[idx] ?? 120;
    dragCol.current = { idx, startX: e.clientX, startW };
    const move = (ev: MouseEvent) => {
      const d = dragCol.current;
      if (!d) return;
      setColW((prev) => {
        const arr = [...(prev ?? [])];
        arr[d.idx] = Math.max(56, d.startW + (ev.clientX - d.startX));
        return arr;
      });
    };
    const up = () => {
      dragCol.current = null;
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      document.body.style.cursor = "";
    };
    document.body.style.cursor = "col-resize";
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
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
      const res = await api.setComponentsStatus(selected, batchStatus);
      const label = STATUS_LABELS[batchStatus];
      toast.success(
        res.changed === res.requested
          ? `已把 ${res.changed} 个组件标为「${label}」`
          : `已把 ${res.changed} 个组件标为「${label}」，${res.requested - res.changed} 个未变`,
      );
      setSelected([]);
      setBatchStatus("");
      await load();
      void api.componentCounts().then((c) => setCounts(c ?? {}));
    } catch (err) {
      toast.error(`批量改状态失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBulkSaving(false);
    }
  };

  const removeSelected = async () => {
    try {
      const res = await api.deleteComponents(selected);
      toast.success(`已删除 ${res.deleted} 个组件`);
      setConfirmDelete(false);
      await load();
    } catch (err) {
      toast.error(`删除失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const changeStatus = async (c: Component, status: ComponentStatus) => {
    try {
      await api.setComponentStatus([c.id], status);
      setRows((prev) => prev.map((x) => (x.id === c.id ? { ...x, status } : x)));
      if (detail?.id === c.id) setDetail({ ...detail, status });
    } catch (err) {
      toast.error(`更新状态失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const submitAdd = async () => {
    if (!form.component_name.trim()) {
      toast.error("组件名不能为空");
      return;
    }
    setSaving(true);
    try {
      const res = await api.insertComponents({
        components: [
          {
            type: form.type,
            component_name: form.component_name.trim(),
            version: form.version.trim() || undefined,
            vendor: form.vendor.trim() || undefined,
            binary_path: form.binary_path.trim() || undefined,
            config_path: form.config_path.trim() || undefined,
            started_by: form.started_by.trim() || undefined,
            port: form.port.trim() ? Number(form.port) : undefined,
            notes: form.notes.trim() || undefined,
          },
        ],
      });
      toast.success(`已登记：新增 ${res.inserted} / 更新 ${res.updated}`);
      setAddOpen(false);
      setForm({ ...form, component_name: "", version: "", binary_path: "", config_path: "", started_by: "", port: "", notes: "" });
      await load();
      void api.componentCounts().then((c) => setCounts(c ?? {}));
    } catch (err) {
      toast.error(`登记失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const typeSummary = React.useMemo(() => {
    const entries = Object.entries(counts).filter(([, n]) => n > 0);
    entries.sort((a, b) => b[1] - a[1]);
    return entries;
  }, [counts]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <PackageIcon className="size-5" /> 组件库
          </h1>
          <p className="text-muted-foreground mt-1 text-sm">
            固件解包出来的组件：一行 = 一个可指认组件（服务 / 二进制 / 配置 / 启动脚本）。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} /> 刷新
          </Button>
          <Button variant="outline" size="sm" onClick={() => setAddOpen(true)}>
            <PlusIcon className="size-4" /> 新增组件
          </Button>
        </div>
      </div>

      {selected.length > 0 && (
        <div className="bg-muted/40 flex flex-wrap items-center gap-2 rounded-lg border px-3 py-2 shadow-sm">
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
            <Select
              value={batchStatus}
              onValueChange={(v) => setBatchStatus(v as ComponentStatus)}
            >
              <SelectTrigger className="h-8 w-32">
                <SelectValue placeholder="改状态为…" />
              </SelectTrigger>
              <SelectContent>
                {COMPONENT_STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {STATUS_LABELS[s]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button size="sm" disabled={!batchStatus || bulkSaving} onClick={() => void applyBatchStatus()}>
              {bulkSaving ? <RefreshCwIcon className="size-4 animate-spin" /> : null} 应用
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setConfirmDelete(true)}
            >
              <Trash2Icon className="size-4" /> 删除选中（{selected.length}）
            </Button>
          </div>
        </div>
      )}

      {typeSummary.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-muted-foreground text-xs">类型分布：</span>
          {typeSummary.map(([k, n]) => (
            <Badge key={k} variant="secondary" className="font-mono text-xs">
              {k} {n}
            </Badge>
          ))}
        </div>
      )}

      <Card className="p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Select
            value={type || "__all__"}
            onValueChange={(v) => {
              setPage(1);
              setType(v === "__all__" ? "" : v);
            }}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="全部类型" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">全部类型</SelectItem>
              {TYPE_OPTIONS.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select
            value={status || "__all__"}
            onValueChange={(v) => {
              setPage(1);
              setStatus(v === "__all__" ? "" : v);
            }}
          >
            <SelectTrigger className="w-32">
              <SelectValue placeholder="全部状态" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">全部状态</SelectItem>
              {COMPONENT_STATUSES.map((st) => (
                <SelectItem key={st} value={st}>
                  {COMPONENT_STATUS_LABELS[st]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select
            value={firmware || "__all__"}
            onValueChange={(v) => {
              setPage(1);
              setFirmware(v === "__all__" ? "" : v);
            }}
          >
            <SelectTrigger className="w-[26rem] max-w-full">
              <SelectValue placeholder="全部固件" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">全部固件</SelectItem>
              {Object.entries(firmwareCounts)
                .filter(([sha]) => sha !== "")
                .map(([sha, n]) => (
                  <SelectItem key={sha} value={sha} title={`${firmwareName[sha] ?? "固件"} sha256: ${sha}`}>
                    {firmwareName[sha] ?? "固件"} · {sha.slice(0, 12)} ({n})
                  </SelectItem>
                ))}
            </SelectContent>
          </Select>
          <Select
            value={taskId || "__all__"}
            onValueChange={(v) => {
              setPage(1);
              setTaskId(v === "__all__" ? "" : v);
            }}
          >
            <SelectTrigger className="w-48">
              <SelectValue placeholder="全部任务" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">全部任务</SelectItem>
              {Object.entries(taskNames)
                .sort((a, b) => Number(b[0]) - Number(a[0]))
                .map(([id, name]) => (
                  <SelectItem key={id} value={id} title={`ID: ${id}`}>
                    {name}
                  </SelectItem>
                ))}
            </SelectContent>
          </Select>
          <div className="min-w-[160px] max-w-[320px] flex-1">
            <ComponentDslSearch
              value={dsl}
              onChange={(v) => {
                setPage(1);
                setDsl(v);
              }}
              placeholder="DSL 查询，如 component_name=lighttpd、status==pending AND type==web"
            />
          </div>
          <span className="text-muted-foreground w-24 shrink-0 text-right text-xs tabular-nums" aria-label="命中总数">
            共 <b className="text-foreground">{total}</b> 条
          </span>
        </div>
      </Card>

      <Card className="overflow-hidden p-0">
        <Table className={colW ? "table-fixed" : undefined}>
          {colW && (
            <colgroup>
              {colW.map((w, i) => (
                <col key={i} style={{ width: w }} />
              ))}
            </colgroup>
          )}
          <TableHeader>
            <TableRow ref={headRowRef}>
              <TableHead className="relative w-8">
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
                <div
                  role="separator"
                  aria-orientation="vertical"
                  onMouseDown={startColDrag(0)}
                  onClick={(e) => e.stopPropagation()}
                  title="拖动调整列宽"
                  className="hover:bg-sky-500/60 absolute top-0 right-0 z-10 h-full w-1.5 cursor-col-resize"
                />
              </TableHead>
              <TableHead className="relative w-20 text-left">
                类型
                <div
                  role="separator"
                  aria-orientation="vertical"
                  onMouseDown={startColDrag(1)}
                  onClick={(e) => e.stopPropagation()}
                  title="拖动调整列宽"
                  className="hover:bg-sky-500/60 absolute top-0 right-0 z-10 h-full w-1.5 cursor-col-resize"
                />

              </TableHead>
              <TableHead className="relative  text-left">
                组件名
                <div
                  role="separator"
                  aria-orientation="vertical"
                  onMouseDown={startColDrag(2)}
                  onClick={(e) => e.stopPropagation()}
                  title="拖动调整列宽"
                  className="hover:bg-sky-500/60 absolute top-0 right-0 z-10 h-full w-1.5 cursor-col-resize"
                />

              </TableHead>
              <TableHead className="relative w-36 text-left">
                任务
                <div
                  role="separator"
                  aria-orientation="vertical"
                  onMouseDown={startColDrag(3)}
                  onClick={(e) => e.stopPropagation()}
                  title="拖动调整列宽"
                  className="hover:bg-sky-500/60 absolute top-0 right-0 z-10 h-full w-1.5 cursor-col-resize"
                />

              </TableHead>
              <TableHead className="relative w-56 text-left">
                固件
                <div
                  role="separator"
                  aria-orientation="vertical"
                  onMouseDown={startColDrag(4)}
                  onClick={(e) => e.stopPropagation()}
                  title="拖动调整列宽"
                  className="hover:bg-sky-500/60 absolute top-0 right-0 z-10 h-full w-1.5 cursor-col-resize"
                />

              </TableHead>
              <TableHead className="relative w-32 text-left">
                二进制
                <div
                  role="separator"
                  aria-orientation="vertical"
                  onMouseDown={startColDrag(5)}
                  onClick={(e) => e.stopPropagation()}
                  title="拖动调整列宽"
                  className="hover:bg-sky-500/60 absolute top-0 right-0 z-10 h-full w-1.5 cursor-col-resize"
                />

              </TableHead>
              <TableHead className="relative w-24 text-left">
                版本
                <div
                  role="separator"
                  aria-orientation="vertical"
                  onMouseDown={startColDrag(6)}
                  onClick={(e) => e.stopPropagation()}
                  title="拖动调整列宽"
                  className="hover:bg-sky-500/60 absolute top-0 right-0 z-10 h-full w-1.5 cursor-col-resize"
                />

              </TableHead>
              <TableHead className="relative w-32 text-left">
                厂商
                <div
                  role="separator"
                  aria-orientation="vertical"
                  onMouseDown={startColDrag(7)}
                  onClick={(e) => e.stopPropagation()}
                  title="拖动调整列宽"
                  className="hover:bg-sky-500/60 absolute top-0 right-0 z-10 h-full w-1.5 cursor-col-resize"
                />

              </TableHead>
              <TableHead className="relative w-24 text-left">
                状态
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={9} className="text-muted-foreground py-10 text-center text-sm">
                  {loading ? "加载中…" : "没有组件。上传固件并让 agent 解包登记后，组件会出现在这里。"}
                </TableCell>
              </TableRow>
            )}
            {rows.map((c) => {
              const st = statusOf(c);
              return (
                <TableRow key={c.id} className="cursor-pointer" onClick={() => setDetail(c)}>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      aria-label={`选择 ${c.component_name}`}
                      checked={selected.includes(c.id)}
                      onChange={() => toggleOne(c.id)}
                      className="size-4 cursor-pointer align-middle accent-sky-500"
                    />
                  </TableCell>
                  <TableCell className="font-mono text-xs">{c.type}</TableCell>
                  <TableCell className="font-medium">{c.component_name || "—"}</TableCell>
                  <TableCell className="max-w-[9rem] text-xs">
                    <span className="block truncate" title={`ID: ${(c.task_ids ?? []).join(", ")}`}>
                      {(c.task_ids ?? []).length === 0
                        ? "—"
                        : (c.task_ids ?? [])
                            .map((tid) => taskNames[String(tid)] || `#${tid}`)
                            .join("、")}
                    </span>
                  </TableCell>
                  <TableCell className="max-w-[14rem] font-mono text-xs">
                    {(() => {
                      const fw = c.firmware_sha256 ? firmwareName[c.firmware_sha256] : undefined;
                      if (!c.firmware_sha256) return <span className="text-muted-foreground">—</span>;
                      return (
                        <span className="block truncate" title={`${fw ?? "固件"} sha256: ${c.firmware_sha256}`}>
                          {fw ?? "固件"}
                          <span className="text-muted-foreground"> · {c.firmware_sha256.slice(0, 12)}</span>
                        </span>
                      );
                    })()}
                  </TableCell>
                  <TableCell className="text-muted-foreground max-w-[8rem] truncate font-mono text-xs">
                    {c.binary_path || "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{c.version || "—"}</TableCell>
                  <TableCell className="text-xs">{c.vendor || "—"}</TableCell>
                  <TableCell>
                    <span className={`rounded px-2 py-0.5 text-xs ${STATUS_STYLE[st]}`}>
                      {STATUS_LABELS[st]}
                    </span>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Card>

      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">
          共 {total} 个组件（第 {page}/{pages} 页）
        </span>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            <ChevronLeftIcon className="size-4" /> 上一页
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= pages}
            onClick={() => setPage((p) => p + 1)}
          >
            下一页 <ChevronRightIcon className="size-4" />
          </Button>
        </div>
      </div>

      <AlertDialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除 {selected.length} 个组件？</AlertDialogTitle>
            <AlertDialogDescription>
              硬删除、作用于全局组件库（跨任务共享），不可撤销。漏洞上记录的组件引用会变成孤立 id。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction onClick={() => void removeSelected()}>删除</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Sheet open={addOpen} onOpenChange={(open) => !open && setAddOpen(false)}>
        <SheetContent className="w-[520px] overflow-y-auto sm:max-w-[520px]">
          <SheetHeader>
            <SheetTitle>新增组件</SheetTitle>
            <SheetDescription>
              手工登记一个固件里的可指认组件；同 (固件 sha256, 类型, 组件名, 版本) 会合并到同一行。
            </SheetDescription>
          </SheetHeader>
          <div className="mt-4 flex flex-col gap-3">
            <div className="grid grid-cols-2 gap-3">
              <label className="flex flex-col gap-1">
                <span className="text-muted-foreground text-xs">类型</span>
                <Select value={form.type} onValueChange={(v) => setForm({ ...form, type: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TYPE_OPTIONS.map((t) => (
                      <SelectItem key={t} value={t}>
                        {t}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-muted-foreground text-xs">组件名（必填）</span>
                <Input
                  value={form.component_name}
                  onChange={(e) => setForm({ ...form, component_name: e.target.value })}
                  placeholder="lighttpd"
                />
              </label>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <label className="flex flex-col gap-1">
                <span className="text-muted-foreground text-xs">版本</span>
                <Input value={form.version} onChange={(e) => setForm({ ...form, version: e.target.value })} placeholder="1.4.35" />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-muted-foreground text-xs">厂商</span>
                <Input value={form.vendor} onChange={(e) => setForm({ ...form, vendor: e.target.value })} placeholder="Xiaomi" />
              </label>
            </div>
            <label className="flex flex-col gap-1">
              <span className="text-muted-foreground text-xs">二进制路径</span>
              <Input value={form.binary_path} onChange={(e) => setForm({ ...form, binary_path: e.target.value })} placeholder="/usr/sbin/lighttpd" />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-muted-foreground text-xs">配置文件</span>
              <Input value={form.config_path} onChange={(e) => setForm({ ...form, config_path: e.target.value })} placeholder="/etc/lighttpd/lighttpd.conf" />
            </label>
            <div className="grid grid-cols-2 gap-3">
              <label className="flex flex-col gap-1">
                <span className="text-muted-foreground text-xs">启动脚本</span>
                <Input value={form.started_by} onChange={(e) => setForm({ ...form, started_by: e.target.value })} placeholder="/etc/init.d/lighttpd" />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-muted-foreground text-xs">主监听端口</span>
                <Input value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} placeholder="80" />
              </label>
            </div>
            <label className="flex flex-col gap-1">
              <span className="text-muted-foreground text-xs">备注</span>
              <Input value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} placeholder="busybox telnetd，默认无认证" />
            </label>
            <div className="mt-2 flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => setAddOpen(false)} disabled={saving}>
                取消
              </Button>
              <Button size="sm" onClick={() => void submitAdd()} disabled={saving}>
                {saving ? "保存中…" : "保存"}
              </Button>
            </div>
          </div>
        </SheetContent>
      </Sheet>

      <Sheet open={!!detail} onOpenChange={(open) => !open && setDetail(null)}>
        <SheetContent className="w-[520px] overflow-y-auto sm:max-w-[520px]">
          {detail && (
            <>
              <SheetHeader>
                <SheetTitle className="flex items-center gap-2">
                  <PackageIcon className="size-4" />
                  {detail.component_name || "未命名组件"}
                </SheetTitle>
                <SheetDescription>
                  <span className="font-mono text-xs">{detail.type}</span>
                  {detail.version ? ` · ${detail.version}` : ""}
                </SheetDescription>
              </SheetHeader>

              <div className="mt-4 flex flex-wrap items-center gap-2 px-4">
                {(Object.keys(STATUS_LABELS) as ComponentStatus[]).map((st) => (
                  <Button
                    key={st}
                    size="sm"
                    variant={statusOf(detail) === st ? "default" : "outline"}
                    onClick={() => void changeStatus(detail, st)}
                  >
                    {STATUS_LABELS[st]}
                  </Button>
                ))}
              </div>

              <dl className="mt-5 grid grid-cols-[110px_1fr] gap-x-3 gap-y-2 px-4 pb-2 text-sm">
                <Field label="二进制" value={detail.binary_path} mono />
                <Field label="配置" value={detail.config_path} mono />
                <Field label="启动脚本" value={detail.started_by} mono />
                <Field label="厂商" value={detail.vendor} />
                <Field label="主端口" value={detail.port ? String(detail.port) : ""} mono />
                <Field label="固件 sha256" value={detail.firmware_sha256} mono wrap />
                <Field label="依赖/特征" value={(detail.technologies ?? []).join(", ")} />
                <Field label="关联任务" value={(detail.task_ids ?? []).join(", ")} mono />
                <Field label="备注" value={detail.notes} wrap />
                <Field label="最后更新" value={detail.updated_at || detail.last_seen} />
              </dl>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function Field({
  label,
  value,
  mono,
  wrap,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  wrap?: boolean;
}) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={`${mono ? "font-mono text-xs" : "text-sm"} ${wrap ? "break-all" : "truncate"}`}>
        {value && value !== "" ? value : "—"}
      </dd>
    </>
  );
}
