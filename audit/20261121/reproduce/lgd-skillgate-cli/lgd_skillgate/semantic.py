"""语义审阅层（可选）：调用本地/自建 LLM 补充静态规则看不到的语义风险。

设计约束（重要）：
1. 本层是**可选增强**，不替代静态规则；默认不启用。
2. 模型输出的每条发现必须携带 evidence_quote，且该引文必须能在被扫描文本中**逐字找到**，
   回填 文件:行号 后才保留，否则丢弃（防幻觉）。
3. 结果是**非确定性**的：同一输入多次运行可能不同，输出里固定标注 deterministic=false。
4. 纯标准库（urllib），不引入第三方依赖；可指向本机 Ollama，也可指向任何 OpenAI 兼容端点。
"""

import json
import os
import re
import sys
import hashlib
import urllib.request
from pathlib import Path

TEXT_SUFFIX = {".md", ".markdown", ".txt", ".py", ".sh", ".js", ".ts", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}
MAX_CHARS = 24000

CATEGORIES = ["credential_access", "data_exfiltration", "destructive_action",
              "privilege_escalation", "prompt_injection", "supply_chain", "obfuscation"]

PROMPT = """你是安全审阅助手。读下面的 skill 文本，找出**静态规则难以覆盖的语义风险**。

只允许输出严格 JSON 数组，不要解释、不要 markdown 代码块。每个元素：
{"category": 以下之一 %s, "severity": "CRITICAL|HIGH|MEDIUM|LOW", "evidence_quote": 从原文逐字复制的一段（20-200字符，不得改写）, "why": 一句话说明风险}

规则：
- evidence_quote 必须是原文的连续片段，一字不改，否则该条会被程序丢弃。
- 只报确有语义风险的段落；没有就输出 []。
- 不要因为出现某个词就报；要看它在指令中的实际作用。

文本如下：
---
%s
---
""" % (json.dumps(CATEGORIES, ensure_ascii=False), "%s")


def _collect(root):
    """收集文本并建立 行号 -> (文件, 行) 映射，用于回填行号。"""
    files = []
    for p in sorted(Path(root).rglob("*")):
        if p.is_file() and p.suffix.lower() in TEXT_SUFFIX:
            try:
                if p.stat().st_size <= 400000:
                    files.append(p)
            except OSError:
                pass
    chunks, index = [], []  # index: (file, lineno, line_text)
    total = 0
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = os.path.relpath(p, root)
        block = "\n# ==== FILE: %s ====\n" % rel + text
        if total + len(block) > MAX_CHARS:
            break
        chunks.append(block)
        total += len(block)
        for i, line in enumerate(text.splitlines(), 1):
            if line.strip():
                index.append((rel, i, line))
    return "\n".join(chunks), index


def _locate(quote, index):
    """在原文索引里找引文，返回 文件:行号；找不到返回 None（丢弃该条）。"""
    q = quote.strip()
    if len(q) < 12:
        return None
    norm = re.sub(r"\s+", " ", q)
    for rel, lineno, line in index:
        if norm in re.sub(r"\s+", " ", line):
            return {"file": rel, "line": lineno}
    # 跨行引文：取首行片段定位
    first = norm.split(" ")[0]
    if len(first) >= 12:
        for rel, lineno, line in index:
            if first in line:
                return {"file": rel, "line": lineno}
    return None


def _call(endpoint, model, prompt, timeout, retries=2):
    body = json.dumps({
        "model": model, "stream": False, "think": False,
        "options": {"temperature": 0.0, "num_ctx": 12288, "num_predict": 800},
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(endpoint.rstrip("/") + "/api/chat", data=body,
                                         headers={"Content-Type": "application/json"})
            d = json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8"))
            msg = d.get("message", {})
            return (msg.get("content") or msg.get("thinking") or "").strip(), None
        except Exception as e:
            last = "%s: %s" % (type(e).__name__, str(e)[:120])
            if attempt < retries:
                import time as _t
                _t.sleep(2 * (attempt + 1))
    return "", last


def _parse_array(text):
    i, j = text.find("["), text.rfind("]")
    if i < 0 or j <= i:
        return []
    try:
        v = json.loads(text[i:j + 1])
        return v if isinstance(v, list) else []
    except Exception:
        return []


def review(root, model="qwen3.5:4b", endpoint="http://127.0.0.1:11434", timeout=600):
    text, index = _collect(root)
    if not text.strip():
        return {"skill": os.path.basename(os.path.abspath(root)), "findings": [],
                "note": "无可读文本", "deterministic": False}
    raw, err = _call(endpoint, model, PROMPT % text, timeout)
    items = _parse_array(raw)

    kept, dropped = [], 0
    for it in items:
        if not isinstance(it, dict):
            dropped += 1
            continue
        cat = it.get("category")
        sev = str(it.get("severity", "")).upper()
        quote = it.get("evidence_quote") or ""
        why = it.get("why") or ""
        if cat not in CATEGORIES or sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            dropped += 1
            continue
        loc = _locate(quote, index)
        if not loc:
            dropped += 1          # 引文无法在原文定位 → 视为幻觉，丢弃
            continue
        kept.append({"category": cat, "severity": sev, "file": loc["file"],
                     "line": loc["line"], "evidence_quote": quote, "why": why,
                     "source": "semantic:%s" % model})

    return {
        "skill": os.path.basename(os.path.abspath(root)),
        "model": model, "endpoint": endpoint,
        "deterministic": False,
        "llm_error": err,
        "text_bytes": len(text.encode("utf-8")),
        "raw_items": len(items),
        "kept": len(kept), "dropped_unverifiable": dropped,
        "input_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
        "findings": kept,
        "boundary": "语义层为可选增强且非确定性；结果不用于替代静态规则，不构成质量认证。",
    }


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="lgd-skillgate semantic",
                                 description="语义审阅层（可选，调用本地/自建 LLM）")
    ap.add_argument("skill_dir")
    ap.add_argument("--model", default="qwen3.5:4b")
    ap.add_argument("--endpoint", default="http://127.0.0.1:11434")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--format", choices=["json", "terminal"], default="terminal")
    a = ap.parse_args(argv)
    r = review(a.skill_dir, a.model, a.endpoint, a.timeout)
    if a.format == "json":
        print(json.dumps(r, ensure_ascii=False, indent=1))
    else:
        print("语义审阅: %s  model=%s  deterministic=false" % (r["skill"], r["model"]))
        print("保留 %d 条 / 丢弃 %d 条（引文无法定位）" % (r["kept"], r["dropped_unverifiable"]))
        for f in r["findings"]:
            print("  [%s] %s:%s  %s\n      %s" % (f["severity"], f["file"], f["line"], f["category"], f["why"]))
    return 0 if r["kept"] == 0 else 1
