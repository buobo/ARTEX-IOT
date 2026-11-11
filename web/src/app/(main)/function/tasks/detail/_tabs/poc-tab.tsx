"use client";

import * as React from "react";
import Link from "next/link";
import { FileCode2Icon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { PocFileEntry } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function PocTab({ taskId }: { taskId: string }) {
  const [files, setFiles] = React.useState<PocFileEntry[]>([]);
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.taskPocFiles(taskId);
      setFiles(res.files);
    } catch (err) {
      toast.error(`加载 PoC 失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Button variant="outline" size="sm" onClick={() => void load()}>
          <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} /> 刷新
        </Button>
      </div>

      {files.length === 0 ? (
        <Card className="text-muted-foreground p-8 text-center text-sm">
          <FileCode2Icon className="mx-auto mb-2 size-6" />
          还没有 PoC。worker 复现成功后应当调用 save_poc 落盘。
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>文件名</TableHead>
                <TableHead className="w-24">大小</TableHead>
                <TableHead className="w-48">修改时间</TableHead>
                <TableHead>关联漏洞</TableHead>
                <TableHead className="w-32 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {files.map((f) => (
                <TableRow key={f.name}>
                  <TableCell className="font-mono text-xs">{f.name}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">{humanSize(f.size)}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {new Date(f.modified_at).toLocaleString("zh-CN")}
                  </TableCell>
                  <TableCell>
                    {f.referenced_by.length === 0 ? (
                      <span className="text-muted-foreground text-xs">未被漏洞引用</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {f.referenced_by.map((r) => (
                          <Link key={r.id} href={`/function/findings/detail?id=${r.id}`}>
                            <Badge variant="secondary" className="font-mono text-xs">
                              #{r.id} {r.name || ""}
                            </Badge>
                          </Link>
                        ))}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      <Button variant="ghost" size="sm" asChild>
                        <a href={api.taskPocFileUrl(taskId, f.name, true)} target="_blank" rel="noreferrer">
                          查看
                        </a>
                      </Button>
                      <Button variant="ghost" size="sm" asChild>
                        <a href={api.taskPocFileUrl(taskId, f.name, false)}>下载</a>
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  );
}
