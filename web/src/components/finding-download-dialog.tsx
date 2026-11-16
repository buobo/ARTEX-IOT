"use client";

import * as React from "react";

import { ChevronRightIcon, DownloadIcon, FileIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Spinner } from "@/components/ui/spinner";
import type { FindingArtifactFile, FindingArtifactKey, FindingArtifactSet } from "@/lib/api";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface FindingDownloadDialogProps {
  /** 要下载的 finding id：单条是 1 个，批量是多个（一个 finding 一个包）。 */
  findingIds: string[];
  /** 单条时显示的名字，便于确认下的是哪条。 */
  findingName?: string;
  onClose: () => void;
}

const ARTIFACT_ORDER: FindingArtifactKey[] = ["report", "poc", "video", "traffic", "evidence"];

function fmtBytes(bytes: number): string {
  if (bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function fmtDuration(ms?: number): string {
  if (!ms || ms <= 0) return "";
  const total = Math.round(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return m > 0 ? `${m}分${String(s).padStart(2, "0")}秒` : `${s}秒`;
}

interface Row {
  key: FindingArtifactKey;
  label: string;
  count: number;
  bytes: number;
  available: boolean;
  note: string;
  files: FindingArtifactFile[];
}

// 弹框打开即拉清单（format=manifest）。两档勾选：类别（报告/视频…）+ 类别里的每个文件；
// 文件级勾选换算成 items + files 传给后端，后端只接受清单里出现过的条目名。
export function FindingDownloadDialog({ findingIds, findingName, onClose }: FindingDownloadDialogProps) {
  const [sets, setSets] = React.useState<FindingArtifactSet[] | null>(null);
  const [error, setError] = React.useState("");
  const [pickedFiles, setPickedFiles] = React.useState<Set<string>>(new Set());
  const [open, setOpen] = React.useState<Set<FindingArtifactKey>>(new Set());
  const [downloading, setDownloading] = React.useState(false);
  const lock = React.useRef(false);
  // 用字符串做依赖：父组件每次 render 都会新建数组，直接依赖数组会反复重拉清单。
  const idKey = React.useMemo(() => findingIds.join(","), [findingIds]);

  React.useEffect(() => {
    let alive = true;
    api
      .findingArtifacts(idKey.split(","))
      .then((list) => {
        if (!alive) return;
        setSets(list);
        const files = new Set<string>();
        const expanded = new Set<FindingArtifactKey>();
        for (const key of ARTIFACT_ORDER) {
          for (const s of list) {
            const it = s.items.find((x) => x.key === key);
            if (!it?.available) continue;
            expanded.add(key);
            for (const f of it.files) files.add(f.name);
          }
        }
        setPickedFiles(files);
        setOpen(expanded);
      })
      .catch((e: unknown) => {
        if (!alive) return;
        setSets([]);
        setError((e as Error).message || "读取产物清单失败");
      });
    return () => {
      alive = false;
    };
  }, [idKey]);

  // 一项在任一条 finding 里可用就能勾选（批量时按并集，下载仍是一 finding 一包）。
  const rows = React.useMemo<Row[]>(() => {
    const list = sets ?? [];
    return ARTIFACT_ORDER.map((key) => {
      let label: string = key;
      let count = 0;
      let bytes = 0;
      let available = false;
      const notes: string[] = [];
      const files: FindingArtifactFile[] = [];
      for (const s of list) {
        const it = s.items.find((x) => x.key === key);
        if (!it) continue;
        label = it.label || label;
        if (it.available) {
          available = true;
          count += it.count;
          bytes += it.bytes;
          files.push(...it.files);
        } else if (it.note && !notes.includes(it.note)) {
          notes.push(it.note);
        }
      }
      return { key, label, count, bytes, available, note: notes.join("；"), files };
    });
  }, [sets]);

  const totalBytes = rows.reduce(
    (sum, row) => sum + row.files.reduce((s, f) => (pickedFiles.has(f.name) ? s + f.bytes : s), 0),
    0,
  );
  const pickedCount = pickedFiles.size;
  const huge = totalBytes > 500 * 1024 * 1024;

  function toggleFile(name: string, on: boolean) {
    setPickedFiles((prev) => {
      const next = new Set(prev);
      if (on) next.add(name);
      else next.delete(name);
      return next;
    });
  }

  function toggleItem(row: Row, on: boolean) {
    setPickedFiles((prev) => {
      const next = new Set(prev);
      for (const f of row.files) {
        if (on) next.add(f.name);
        else next.delete(f.name);
      }
      return next;
    });
  }

  function toggleOpen(key: FindingArtifactKey) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  async function download() {
    if (lock.current) return;
    lock.current = true;
    setDownloading(true);
    try {
      // 只发实际勾到的文件；items 由勾中的文件反推（后端两者都校验）。
      const files = [...pickedFiles];
      const items = rows.filter((row) => row.files.some((f) => pickedFiles.has(f.name))).map((row) => row.key);
      await api.downloadFindingArtifacts(findingIds, items, files);
      toast.success("已开始下载产物包");
      onClose();
    } catch (e) {
      toast.error((e as Error).message || "下载失败");
    } finally {
      lock.current = false;
      setDownloading(false);
    }
  }

  const loading = sets === null;
  const canDownload = !loading && !downloading && pickedCount > 0 && totalBytes > 0;

  return (
    <Dialog open onOpenChange={(next) => !next && !downloading && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>下载产物{findingIds.length > 1 ? `（${findingIds.length} 条漏洞）` : ""}</DialogTitle>
          <DialogDescription className="break-all">
            {findingIds.length > 1
              ? "每条漏洞一个独立压缩包，打包进一个外层 zip，内容互不混合。"
              : `只包含这条漏洞自身的产物${findingName ? `：${findingName}` : ""}`}
          </DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
            <Spinner /> 正在读取产物清单…
          </div>
        ) : error ? (
          <p className="py-4 text-sm text-destructive">{error}</p>
        ) : (
          <div className="max-h-[62vh] space-y-2 overflow-y-auto pr-1">
            {rows.map((row) => {
              const id = `artifact-${row.key}`;
              const expanded = open.has(row.key);
              const canExpand = row.files.length > 0;
              const pickedInRow = row.files.filter((f) => pickedFiles.has(f.name)).length;
              const allPicked = row.files.length > 0 && pickedInRow === row.files.length;
              const checked: boolean | "indeterminate" =
                allPicked ? true : pickedInRow > 0 ? "indeterminate" : false;
              const rowBytes = row.files.reduce((s, f) => (pickedFiles.has(f.name) ? s + f.bytes : s), 0);
              return (
                <div key={row.key} className="rounded-md border data-[off=true]:opacity-60" data-off={!row.available}>
                  <div className="flex items-start gap-3 px-3 py-2">
                    <Checkbox
                      id={id}
                      className="mt-0.5"
                      checked={checked}
                      disabled={!row.available}
                      onCheckedChange={(v) => toggleItem(row, v === true)}
                    />
                    <div className="min-w-0 flex-1">
                      <label htmlFor={id} className="flex cursor-pointer items-center justify-between gap-2 text-sm">
                        <span className="font-medium">{row.label}</span>
                        <span className="shrink-0 text-xs text-muted-foreground tabular-nums">
                          {row.available
                            ? `${pickedInRow}/${row.files.length} 个文件 · ${fmtBytes(rowBytes)}`
                            : "不可用"}
                        </span>
                      </label>
                      {!row.available && row.note ? (
                        <p className="mt-0.5 text-xs text-muted-foreground">{row.note}</p>
                      ) : null}
                    </div>
                    {canExpand ? (
                      <button
                        type="button"
                        onClick={() => toggleOpen(row.key)}
                        aria-expanded={expanded}
                        aria-label={expanded ? "收起文件列表" : "展开文件列表"}
                        className="mt-0.5 inline-flex shrink-0 items-center gap-1 rounded px-1 text-xs text-muted-foreground hover:text-foreground"
                      >
                        {expanded ? "收起" : "展开"}
                        <ChevronRightIcon
                          className={cn("size-3.5 transition-transform", expanded && "rotate-90")}
                        />
                      </button>
                    ) : null}
                  </div>

                  {/* 二级目录：每个文件单独可勾选（PoC 文件、每段视频、流量文件…） */}
                  {canExpand && expanded ? (
                    <ul className="space-y-1 border-t bg-muted/30 px-3 py-2">
                      {row.files.map((file) => {
                        const fid = `file-${row.key}-${file.name}`;
                        return (
                          <li key={file.name} className="flex items-center gap-2 text-xs">
                            <Checkbox
                              id={fid}
                              className="size-3.5"
                              checked={pickedFiles.has(file.name)}
                              disabled={!row.available}
                              onCheckedChange={(v) => toggleFile(file.name, v === true)}
                            />
                            <FileIcon className="size-3 shrink-0 text-muted-foreground" />
                            <label
                              htmlFor={fid}
                              className="min-w-0 flex-1 cursor-pointer truncate font-mono"
                              title={file.name}
                            >
                              {file.name}
                            </label>
                            <span className="shrink-0 text-muted-foreground tabular-nums">
                              {file.duration_ms ? `${fmtDuration(file.duration_ms)} · ` : ""}
                              {fmtBytes(file.bytes)}
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  ) : null}
                </div>
              );
            })}
            {rows.every((r) => !r.available) ? (
              <p className="pt-1 text-xs text-muted-foreground">这条漏洞还没有任何可下载产物。</p>
            ) : null}
          </div>
        )}

        <DialogFooter className="items-center gap-2 sm:justify-between">
          <span className="text-xs text-muted-foreground tabular-nums">
            已选 {pickedCount} 个文件 · 合计 {fmtBytes(totalBytes)}
            {huge ? <span className="ml-2 text-destructive">体积较大，下载可能较慢</span> : null}
          </span>
          <div className="flex items-center gap-2">
            <Button type="button" variant="ghost" onClick={onClose} disabled={downloading}>
              取消
            </Button>
            <Button type="button" onClick={download} disabled={!canDownload}>
              {downloading ? <Spinner data-icon="inline-start" /> : <DownloadIcon data-icon="inline-start" />}
              打包下载
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
