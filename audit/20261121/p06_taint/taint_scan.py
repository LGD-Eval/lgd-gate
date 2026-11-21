# -*- coding: utf-8 -*-
"""P1-6 提案：AST + 污点分析原型（Python/JS/Shell），带跨文件与间接调用

定位：现有 skillgate 以正则为主，抓不到「动态拼接后再执行」「跨文件转发到 sink」
「编码后再执行」。本原型用 AST（Python）+ 轻量词法（JS/Shell）做源→汇传播，
并用标注语料量化漏报率/误报率。

仅为审计提案，未进入任何仓库。
"""
from __future__ import annotations

import ast
import re

# ---------- Python ----------
SOURCES = {
    "input", "raw_input", "sys.argv", "sys.stdin.read",
    "os.environ", "os.getenv", "os.environ.get", "getpass.getpass",
}
SINKS_EXEC = {"exec", "eval", "compile"}
SINKS_PROC = {
    "os.system", "os.popen", "os.spawnl", "os.spawnv",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
}
SINKS_FS_DESTRUCT = {"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree"}
SINKS_NET = {"requests.get", "requests.post", "requests.put", "urllib.request.urlopen",
             "socket.socket.connect", "socket.create_connection"}
SINKS_DESER = {"pickle.loads", "marshal.loads", "yaml.unsafe_load"}


def _dotted(node):
    """把 a.b.c 还原为 'a.b.c'。"""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        inner = _dotted(node.func)
        return inner if inner else None
    return None


class PyTaint(ast.NodeVisitor):
    def __init__(self, forwarders=None):
        self.tainted = set()
        self.findings = []
        self.forwarders = forwarders or {}   # func_name -> set(param indexes that reach sink)

    # --- 污点判定 ---
    def is_src(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted or node.id in SOURCES
        if isinstance(node, ast.Attribute):
            d = _dotted(node)
            return bool(d) and (d in SOURCES or d.split(".")[0] in self.tainted
                                or any(d.startswith(s + ".") for s in ("request", "flask", "sys"))
                                and d.split(".")[0] in self.tainted)
        if isinstance(node, ast.Subscript):
            return self.is_src(node.value)
        if isinstance(node, ast.Call):
            d = _dotted(node.func)
            if d in SOURCES:
                return True
            # base64/urllib 解码也算"编码后再执行"的载体
            if d in {"base64.b64decode", "codecs.decode", "urllib.parse.unquote",
                     "bytes.decode", "json.loads"}:
                return True
            return False
        if isinstance(node, ast.BinOp):
            return self.is_src(node.left) or self.is_src(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(self.is_src(v) for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.FormattedValue):
            return self.is_src(node.value)
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(self.is_src(e) for e in node.elts)
        if isinstance(node, ast.IfExp):
            return self.is_src(node.body) or self.is_src(node.orelse)
        return False

    def visit_Assign(self, node):
        if self.is_src(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.tainted.add(t.id)
                elif isinstance(t, (ast.Tuple, ast.List)):
                    for e in t.elts:
                        if isinstance(e, ast.Name):
                            self.tainted.add(e.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None and self.is_src(node.value) and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        d = _dotted(node.func) or ""
        args_tainted = any(self.is_src(a) for a in node.args) or any(
            self.is_src(k.value) for k in node.keywords)
        kind = None
        if d in SINKS_EXEC:
            kind = "code-exec"
        elif d in SINKS_PROC:
            kind = "process-exec"
            # subprocess 用 list 传常量时不算
            if d.startswith("subprocess") and not args_tainted:
                kind = None
        elif d in SINKS_FS_DESTRUCT:
            kind = "destructive-fs"
        elif d in SINKS_NET:
            kind = "network-egress"
        elif d in SINKS_DESER:
            kind = "unsafe-deserialization"
        elif d == "open" and args_tainted:
            modes = [k.value for k in node.keywords if k.arg == "mode"]
            if len(node.args) > 1:
                modes.append(node.args[1])
            if any(isinstance(m, ast.Constant) and set(str(m.value)) & set("wax+") for m in modes):
                kind = "write-to-tainted-path"
        elif d.split(".")[-1] in self.forwarders and args_tainted:
            kind = "indirect-via-forwarder"

        if kind and (args_tainted or kind == "code-exec"):
            if d in SINKS_EXEC and not args_tainted:
                self.generic_visit(node)
                return
            self.findings.append({
                "line": node.lineno, "sink": d, "kind": kind,
                "tainted_args": args_tainted,
            })
        self.generic_visit(node)


def collect_forwarders(tree):
    """函数体里把参数送进 sink 的 → 记为转发器（供跨文件/间接调用判定）。"""
    fwd = {}
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        params = {a.arg for a in fn.args.args}
        hits = []
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
            d = _dotted(call.func) or ""
            if d in SINKS_EXEC | SINKS_PROC | SINKS_DESER | SINKS_NET | SINKS_FS_DESTRUCT:
                for i, a in enumerate(call.args):
                    if isinstance(a, ast.Name) and a.id in params:
                        hits.append(i)
        if hits:
            fwd[fn.name] = set(hits)
    return fwd


# ---------- JS / TS ----------
JS_SOURCE_HINT = re.compile(r"(req\.(body|query|params|headers)|process\.argv|process\.env|"
                            r"event\.target|location\.(search|hash)|prompt\()")
JS_SINKS = [
    (re.compile(r"\beval\s*\("), "code-exec"),
    (re.compile(r"new\s+Function\s*\("), "code-exec"),
    (re.compile(r"child_process[^\n]*"), "process-exec-module"),
    (re.compile(r"\b(exec|execSync|spawn|spawnSync|execFile)\s*\("), "process-exec"),
    (re.compile(r"\.writeFile(Sync)?\s*\("), "write-file"),
    (re.compile(r"\brequire\s*\(\s*[A-Za-z_$][\w$]*\s*\)"), "dynamic-require"),
    (re.compile(r"\bfetch\s*\(\s*[A-Za-z_$][\w$]*\s*\)"), "network-egress"),
]
JS_SUPPRESS = re.compile(r"// *(lgd|skillgate)[: ] *ignore")


def scan_js(text):
    out = []
    lines = text.splitlines()
    # 先收集被污染的标识符
    taints = set()
    for ln in lines:
        m = re.match(r"\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.*)", ln)
        if m and JS_SOURCE_HINT.search(m.group(2)):
            taints.add(m.group(1))
        m2 = re.match(r"\s*([A-Za-z_$][\w$]*)\s*=\s*(.*)", ln)
        if m2 and any(t in m2.group(2) for t in taints):
            taints.add(m2.group(1))
    for i, ln in enumerate(lines, 1):
        if JS_SUPPRESS.search(ln):
            continue
        for rx, kind in JS_SINKS:
            if rx.search(ln):
                hit = rx.search(ln).group(0)
                # 参数里是否出现污染变量
                argtxt = ln[ln.find("(", ln.find(hit)) + 1:] if "(" in ln else ln
                tainted = any(re.search(r"\b%s\b" % re.escape(t), argtxt) for t in taints)
                # 常量实参（引号字面量）降级为低置信
                const_arg = bool(re.search(r"(^|[(,])\s*(['\"`])", argtxt))
                out.append({"line": i, "rule": kind, "snippet": hit.strip()[:40],
                            "tainted": tainted, "const_arg": const_arg})
    return out


# ---------- Shell ----------
SH_RULES = [
    (re.compile(r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)"), "remote-pipe-exec"),
    (re.compile(r"\beval\s+[\"']?\$"), "eval-var"),
    (re.compile(r"rm\s+-[rf]{1,2}[a-z]*\s+\$"), "destructive-rm-var"),
    (re.compile(r"chmod\s+777\s+\$"), "chmod-777-var"),
    (re.compile(r":\s*\(\s*\)\s*\{.*:\s*\|\s*:"), "fork-bomb"),
]


def scan_sh(text):
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        for rx, kind in SH_RULES:
            if rx.search(ln):
                out.append({"line": i, "rule": kind, "snippet": ln.strip()[:50]})
    return out


def scan_file(path, forwarders=None):
    text = open(path, encoding="utf-8", errors="replace").read()
    if path.endswith(".py"):
        tree = ast.parse(text)
        fwd = dict(forwarders or {})
        fwd.update(collect_forwarders(tree))
        v = PyTaint(fwd)
        v.visit(tree)
        return [{"line": f["line"], "rule": f["kind"], "snippet": f["sink"],
                 "tainted": f["tainted_args"]} for f in v.findings]
    if path.endswith((".js", ".ts", ".mjs", ".cjs")):
        return [x for x in scan_js(text) if not (x["const_arg"] and not x["tainted"])]
    if path.endswith((".sh", ".bash", ".ps1")):
        return scan_sh(text)
    return []
