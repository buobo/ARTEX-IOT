"use client";

import * as React from "react";
import Link from "next/link";
import { CheckIcon, CopyIcon, DownloadIcon, FileCode2Icon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { PocFileContent, PocFileEntry } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: "border-transparent bg-red-600 text-white hover:bg-red-600",
  high: "border-transparent bg-orange-500 text-white hover:bg-orange-500",
  medium: "border-transparent bg-amber-400 text-black hover:bg-amber-400",
  low: "border-transparent bg-slate-400 text-white hover:bg-slate-400",
};

// ---------------- 代码着色 ----------------
// PoC 主要是 py/sh/c/js/rb/http，自带一个小词法器够了，不引整包高亮库。

type TokClass = "comment" | "string" | "number" | "keyword" | "func" | "punct" | "plain";
type Tok = { cls: TokClass; text: string };
type Lang = "py" | "sh" | "c" | "js" | "rb" | "http" | "text";

const KEYWORDS: Record<Lang, string[]> = {
  py: "def class return if elif else for while in not and or import from as with try except finally raise pass break continue lambda yield global nonlocal assert del None True False async await".split(
    " ",
  ),
  sh: "if then else elif fi for while do done case esac function return export local readonly set unset shift exit echo printf cd curl wget nc ncat base64".split(
    " ",
  ),
  c: "int char void unsigned signed long short float double struct union enum typedef static const extern return if else for while do switch case break continue sizeof goto NULL include define".split(
    " ",
  ),
  js: "const let var function return if else for while do switch case break continue new class extends import from export default async await try catch finally throw typeof null undefined true false".split(
    " ",
  ),
  rb: "def end class module require return if elsif else unless while until do each puts print begin rescue ensure raise nil true false".split(
    " ",
  ),
  http: "GET POST PUT DELETE PATCH HEAD OPTIONS HTTP HTTPS".split(" "),
  text: [],
};

function langOf(name: string): Lang {
  const ext = (name.split(".").pop() || "").toLowerCase();
  if (ext === "py") return "py";
  if (ext === "sh") return "sh";
  if (ext === "c" || ext === "h") return "c";
  if (ext === "js") return "js";
  if (ext === "rb") return "rb";
  if (ext === "http") return "http";
  return "text";
}

const TOKEN_RE = new RegExp(
  String.raw`(#[^\n]*|\/\/[^\n]*|\/\*[\s\S]*?\*\/)` +
    String.raw`|("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')` +
    String.raw`|(\b\d[\d._]*\b)` +
    String.raw`|([A-Za-z_][A-Za-z0-9_]*)` +
    String.raw`|(\s+)` +
    String.raw`|([\s\S])`,
  "g",
);

function tokenize(code: string, lang: Lang): Tok[][] {
  const kw = new Set(KEYWORDS[lang]);
  const lines: Tok[][] = [[]];
  const push = (cls: TokClass, text: string) => {
    const parts = text.split("\n");
    parts.forEach((part, i) => {
      if (i > 0) lines.push([]);
      if (part !== "") lines[lines.length - 1].push({ cls, text: part });
    });
  };
  TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TOKEN_RE.exec(code))) {
    if (m[1]) {
      // C 的 #define/#include 是预处理指令，不当注释
      push(lang === "c" && m[1].startsWith("#") ? "keyword" : "comment", m[0]);
    } else if (m[2]) {
      push("string", m[0]);
    } else if (m[3]) {
      push("number", m[0]);
    } else if (m[4]) {
      if (kw.has(m[4])) push("keyword", m[0]);
      else if (code[TOKEN_RE.lastIndex] === "(") push("func", m[0]);
      else push("plain", m[0]);
    } else if (m[5]) {
      push("plain", m[0]);
    } else {
      push("punct", m[0]);
    }
  }
  return lines;
}

const TOK_CLASS: Record<TokClass, string> = {
  comment: "text-muted-foreground/70 italic",
  string: "text-emerald-600 dark:text-emerald-400",
  number: "text-amber-600 dark:text-amber-400",
  keyword: "text-violet-600 dark:text-violet-400 font-medium",
  func: "text-sky-600 dark:text-sky-400",
  punct: "text-muted-foreground",
  plain: "text-foreground",
};

const LANG_LABEL: Record<Lang, string> = {
  py: "Python",
  sh: "Shell",
  c: "C",
  js: "JavaScript",
  rb: "Ruby",
  http: "HTTP",
  text: "Text",
};

export function HighlightedCode({
  code,
  name,
  tokenHint,
}: {
  code: string;
  name: string;
  /** 可选：给命中的标识符追加样式（反编译页用它把可跳转函数打成手型光标）。 */
  tokenHint?: (text: string) => string | undefined;
}) {
  const lang = langOf(name);
  const lines = React.useMemo(() => tokenize(code, lang), [code, lang]);
  return (
    <div className="overflow-hidden rounded-lg border shadow-sm">
      <div className="bg-muted/50 text-muted-foreground flex items-center justify-between border-b px-3 py-1.5 text-[11px]">
        <span className="flex items-center gap-2">
          <span className="size-2 rounded-full bg-emerald-500/70" />
          <span className="font-mono tracking-wide">{LANG_LABEL[lang]}</span>
        </span>
        <span className="tabular-nums">{lines.length} 行</span>
      </div>
      <div className="bg-card overflow-x-auto">
        <pre className="font-mono text-xs leading-6">
          <code>
            {lines.map((toks, i) => (
              <div key={i} className="hover:bg-muted/40 flex min-h-6">
                <span className="bg-muted/30 text-muted-foreground/50 w-12 shrink-0 select-none border-r px-2 text-right tabular-nums">
                  {i + 1}
                </span>
                <span className="flex-1 whitespace-pre-wrap break-all pr-4 pl-3">
                  {toks.length === 0
                    ? " "
                    : toks.map((t, j) => (
                        <span
                          key={j}
                          className={`${TOK_CLASS[t.cls]} ${tokenHint?.(t.text) ?? ""}`}
                        >
                          {t.text}
                        </span>
                      ))}
                </span>
              </div>
            ))}
          </code>
        </pre>
      </div>
    </div>
  );
}

// ---------------- 关联漏洞 ----------------

function FindingChips({ refs }: { refs: PocFileEntry["referenced_by"] }) {
  if (refs.length === 0) {
    return <span className="text-muted-foreground text-xs">未关联漏洞</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {refs.map((r) => (
        <Link key={r.id} href={`/function/findings/detail?id=${r.id}`} title={r.severity || ""}>
          <Badge
            variant="outline"
            className={`text-xs ${SEVERITY_STYLE[(r.severity || "").toLowerCase()] ?? ""}`}
          >
            #{r.id} {r.name || ""}
          </Badge>
        </Link>
      ))}
    </div>
  );
}

// ---------------- 阅读弹框 ----------------

function PocViewer({
  taskId,
  file,
  onClose,
}: {
  taskId: string;
  file: PocFileEntry | null;
  onClose: () => void;
}) {
  const [data, setData] = React.useState<PocFileContent | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const [err, setErr] = React.useState("");

  React.useEffect(() => {
    if (!file) {
      setData(null);
      setErr("");
      return;
    }
    let alive = true;
    setLoading(true);
    setErr("");
    api
      .taskPocContent(taskId, file.name)
      .then((res) => {
        if (alive) setData(res);
      })
      .catch((e) => {
        if (alive) setErr(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [taskId, file]);

  const copy = async () => {
    if (!data?.content) return;
    try {
      await navigator.clipboard.writeText(data.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("复制失败，请手动选中文本");
    }
  };

  return (
    <Dialog open={!!file} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="flex max-h-[88vh] w-[min(1040px,94vw)] flex-col gap-0 p-0 sm:max-w-[1040px]">
        <DialogHeader className="from-muted/60 border-b bg-gradient-to-b to-transparent px-5 py-4">
          <DialogTitle className="flex items-center gap-2 font-mono text-base">
            <FileCode2Icon className="size-4 text-sky-500" />
            {file?.name}
            {data && (
              <span className="text-muted-foreground text-xs font-normal">· {humanSize(data.size)}</span>
            )}
          </DialogTitle>
          <DialogDescription asChild>
            <div className="flex flex-wrap items-center gap-2 pt-2">
              <span className="text-muted-foreground text-xs">关联漏洞：</span>
              <FindingChips refs={file?.referenced_by ?? []} />
            </div>
          </DialogDescription>
        </DialogHeader>

        <div className="min-h-0 flex-1 overflow-auto p-3">
          {loading && <div className="text-muted-foreground p-6 text-center text-sm">加载中…</div>}
          {!loading && err && <div className="text-destructive p-6 text-center text-sm">{err}</div>}
          {!loading && !err && data?.binary && (
            <div className="text-muted-foreground p-6 text-center text-sm">
              {data.note || "二进制文件，请下载后查看"}
            </div>
          )}
          {!loading && !err && data && !data.binary && (
            <HighlightedCode code={data.content} name={data.name} />
          )}
          {data?.truncated && (
            <div className="text-muted-foreground px-1 pt-2 text-xs">
              文件较大，仅显示前 512KB；完整内容请下载。
            </div>
          )}
        </div>

        <div className="bg-muted/30 flex items-center justify-end gap-2 border-t px-5 py-3">
          <Button variant="ghost" size="sm" onClick={() => void copy()} disabled={!data?.content}>
            {copied ? <CheckIcon className="size-4 text-emerald-500" /> : <CopyIcon className="size-4" />} 复制
          </Button>
          {file && (
            <Button variant="outline" size="sm" asChild>
              <a href={api.taskPocFileUrl(taskId, file.name, false)}>
                <DownloadIcon className="size-4" /> 下载
              </a>
            </Button>
          )}
          <Button size="sm" onClick={onClose}>
            关闭
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------- 列表 ----------------

export function PocTab({ taskId }: { taskId: string }) {
  const [files, setFiles] = React.useState<PocFileEntry[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [viewing, setViewing] = React.useState<PocFileEntry | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.taskPocFiles(taskId);
      // 未挂到任何漏洞上的 PoC 不展示（后端也已过滤，这里再兜一层）
      setFiles(res.files.filter((f) => f.referenced_by.length > 0));
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
      <div className="flex items-center justify-end">
        <Button variant="outline" size="sm" onClick={() => void load()}>
          <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} /> 刷新
        </Button>
      </div>

      {files.length === 0 ? (
        <Card className="text-muted-foreground p-8 text-center text-sm">
          <FileCode2Icon className="mx-auto mb-2 size-6" />
          还没有关联到漏洞的 PoC。
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>文件名</TableHead>
                <TableHead className="w-24">大小</TableHead>
                <TableHead className="w-44">修改时间</TableHead>
                <TableHead>关联漏洞</TableHead>
                <TableHead className="w-32 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {files.map((f) => (
                <TableRow key={f.name}>
                  <TableCell>
                    <button
                      type="button"
                      className="font-mono text-xs underline-offset-4 hover:underline"
                      onClick={() => setViewing(f)}
                    >
                      {f.name}
                    </button>
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">{humanSize(f.size)}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {new Date(f.modified_at).toLocaleString("zh-CN")}
                  </TableCell>
                  <TableCell>
                    <FindingChips refs={f.referenced_by} />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      <Button variant="ghost" size="sm" onClick={() => setViewing(f)}>
                        查看
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

      <PocViewer taskId={taskId} file={viewing} onClose={() => setViewing(null)} />
    </div>
  );
}
