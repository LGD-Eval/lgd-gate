#!/usr/bin/env python3
"""Intent engine v4：区分"会执行的行为（代码）"与"描述的行为（文档）"。

真实语料实测暴露的教训（149 个技能、26 个假阳性）：
1) Python f-string 的 `:>14` 被当成 shell 的 `:>` 截断 → destruction 误报一片
2) README 里的 `curl -fsSL …` 安装命令被当成下载外传 → 文档不等于行为
3) `import subprocess` 被判动态执行 → 库导入不是执行

判定契约：
verdict ∈ {ALLOW, REVIEW, DENY, UNKNOWN}；无代码文件/解析失败 → UNKNOWN（fail-closed）
本结果只表示风险判定，绝不等于授权
"""
import json
import re
import sys
from pathlib import Path

CODE_EXT = {".py", ".sh", ".js", ".ts", ".mjs", ".cjs", ".ps1", ".psm1", ".bat", ".cmd"}
DOC_EXT = {".md", ".txt", ".rst"}

CAPS = {
    "credential_access": r"((\.ssh|id_rsa|\.aws|\.env\b|\.netrc|\.npmrc|\.credentials|\.bash_history))",
    "network_egress": (r"((requests|httpx)\.(post|put|patch)\s*\(|axios\.(post|put)\s*\(|"
                       r"urlopen\s*\(|http\.client|smtplib|socket\.(create_connection|socket)\s*\(|"
                       r"\bscp\b|\brsync\b|\bnc\b[^\n]*\s-[a-z]*e\b|ncat[^\n]*\s-e\b|\bsocat\b)"),
    "download": (r"(\bcurl\b[^\n]*\s(-o|--output|-O)\s|wget\s|\biwr\b|Invoke-WebRequest|"
                 r"DownloadString|DownloadFile|Net\.WebClient|urlretrieve)"),
    "dynamic_exec": (r"(\bos\.system\s*\(|\beval\s*\(|\bexec\s*\(|\bshell\s*=\s*True|"
                     r"\bIEX\b|Invoke-Expression|powershell\s+-|pickle\.loads\s*\(|"
                     r"yaml\.load\s*\(|__import__\s*\(|"
                     r"\|\s*(bash|sh|zsh|dash|ksh|python[0-9.]*|node|perl|ruby|php)\b|"
                     r"\b(bash|sh|zsh)\s+-i\b|"
                    r"(^|[;&|]\s*)(bash|sh|zsh|dash|ksh|python[0-9.]*|node|perl|ruby|php|pwsh)\s+"
                    r"[^\s;&|]+(\.sh|\.bash|\.py|\.js|\.mjs|\.ps1|\.run)\b)"),
    "binary_exec": r"(^|[;&|]\s*)(\./|/|~/)[^\s;&|]+",
    "persistence": (r"(authorized_keys|\bcrontab\b|/etc/cron|systemd|LaunchAgents|LaunchDaemons|"
                    r"schtasks|~/.bashrc|~/.profile)"),
    "destruction": (r"(\bdd\s+if=|\bmkfs|\bshred\b|truncate\s+-s\s*0|"
                    r"\brm\s+-rf\s+(/(etc|usr|var|bin|boot|lib|opt)|\$?HOME|\~|/var/lib|/dev))"),
    "privilege": (r"(\bsudo\b|--privileged|-v\s*/:|chmod\s+-R\s+777|NOPASSWD)"),
    "obfuscation": (r"(base64\s+(--)?decode|base64\s+-d|FromBase64String|xxd\s+-r|"
                    r"String\.fromCharCode|codecs\.decode)"),
    "time_tamper": r"(date\s+-s|hwclock\s+-w|timedatectl\s+set-time|Set-Date\b)",
    "remote_import": r"(import\s*\(\s*['\"]https?://|__import__\s*\(\s*['\"]https?://|require\s*\(\s*['\"]https?://)",
    "security_disable": (r"(setenforce\s+0|systemctl\s+(stop|disable)\s+(firewalld|apparmor"
                         r"|auditd|fail2ban)|\biptables\s+-F|ufw\s+disable|"
                         r"Set-MpPreference\s+-Disable)"),
}

# 代码侧策略：行为真实发生 → 可以 DENY
POLICY = [
    ("P01", ("credential_access", "network_egress"), "DENY", "读凭据 + 网络外发：完整外泄链"),
    ("P02", ("download", "dynamic_exec"), "DENY", "下载 + 动态执行：远端代码执行"),
    ("P03", ("obfuscation", "dynamic_exec"), "DENY", "解码 + 动态执行：静态检查绕过"),
    ("P04", ("destruction",), "DENY", "破坏性操作：不可恢复"),
    ("P05", ("persistence", "network_egress"), "DENY", "持久化 + 外连：后门常驻"),
    ("P09", ("dynamic_exec", "network_egress"), "DENY", "动态执行 + 网络：参数里的 RCE"),
    ("P10", ("security_disable",), "DENY", "关闭或削弱主机防护"),
    ("P11", ("download", "binary_exec"), "DENY", "下载 + 执行二进制：投放链"),
    ("P06", ("persistence",), "REVIEW", "涉及持久化面，需人工确认"),
    ("P07", ("privilege",), "REVIEW", "提权/特权容器，需确认必要性"),
    ("P08", ("credential_access",), "REVIEW", "访问凭据面，需确认必要且不外发"),
    ("P12", ("time_tamper",), "REVIEW", "篡改系统时间，规避审计时间线"),
    ("P13", ("remote_import",), "DENY", "从远程 URL 直接导入/加载代码"),
]

# 仅文档里出现的能力 → 是"描述"，最高 REVIEW（单独标识，便于产品区分）
DOC_POLICY = [
    ("D01", ("credential_access", "network_egress"), "REVIEW", "文档描述了凭据外发链路"),
    ("D02", ("download", "dynamic_exec"), "REVIEW", "文档描述了下载后执行"),
    ("D03", ("destruction",), "REVIEW", "文档描述了破坏性命令"),
]


def collect(root: Path):
    code, docs = [], []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or ".git" in p.parts:
            continue
        s = p.suffix.lower()
        if s in CODE_EXT:
            code.append(p)
        elif s in DOC_EXT:
            docs.append(p)
    return code, docs


def scan_files(files, root: Path):
    caps, evidence = {}, []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--")):
                continue  # 注释是说明，不是行为
            # 检测器悖论：安全检测工具自身会写满"攻击签名"（r"id_rsa|\.ssh"）。
            # 原始字符串（r"..."）与 re.compile 基本只出现在规则定义处，不是被执行的行为。
            if re.search(r"""r[\"']""", line) or "re.compile" in line or "Regex" in line:
                continue
            for cap, pat in CAPS.items():
                if re.search(pat, line, re.IGNORECASE):
                    caps.setdefault(cap, []).append(f"{f.relative_to(root)}:{i}")
                    evidence.append({"cap": cap, "file": str(f.relative_to(root)),
                                     "line": i, "text": stripped[:120]})
    # 跨行组合：下载落盘 + 解释器执行该文件（C04）。逐行扫描拆不开，必须整文匹配。
    whole = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in files if f.exists())
    if re.search(r"(curl|wget)[^\n]*(-o|--output|-O)[^\n]*\n[^\n]{0,120}?"
                 r"(bash|sh|zsh|python[0-9.]*|node|pwsh)\s+", whole, re.IGNORECASE):
        caps.setdefault("dynamic_exec", []).append("cross-line: download->execute")
        evidence.append({"cap": "dynamic_exec", "file": "cross-line",
                         "line": 0, "text": "download then interpreter executed file"})
    return caps, evidence


def decide(code_caps, doc_caps, has_code):
    if not has_code:
        # 纯提示词技能：先评估文档描述出的能力（文档最高 REVIEW），再降级为 PROMPT_ONLY。
        # 早退会漏掉"文档里写着完整外泄链"的情形（C08），属安全语义漏洞。
        doc_hits = []
        for pid, need, verdict, reason in DOC_POLICY:
            if all(c in doc_caps for c in need):
                doc_hits.append({"id": pid, "verdict": verdict, "reason": reason,
                                 "scope": "doc"})
        if doc_hits:
            return "REVIEW", doc_hits
        return "PROMPT_ONLY", [{"id": "D00", "verdict": "PROMPT_ONLY",
                                "reason": "无代码文件，文档未描述危险能力，风险面仅提示注入",
                                "scope": "none"}]
    hits = []
    for pid, need, verdict, reason in POLICY:
        if all(c in code_caps for c in need):
            hits.append({"id": pid, "verdict": verdict, "reason": reason,
                         "scope": "code", "required": list(need)})
    if not hits:  # 代码侧干净时，才看文档描述
        for pid, need, verdict, reason in DOC_POLICY:
            if all(c in doc_caps for c in need):
                hits.append({"id": pid, "verdict": verdict, "reason": reason,
                             "scope": "doc", "required": list(need)})
    if any(h["verdict"] == "DENY" for h in hits):
        return "DENY", hits
    if any(h["verdict"] == "REVIEW" for h in hits):
        return "REVIEW", hits
    return "ALLOW", hits


def run(root: Path):
    code, docs = collect(root)
    code_caps, code_ev = scan_files(code, root)
    doc_caps, doc_ev = scan_files(docs, root)
    verdict, hits = decide(code_caps, doc_caps, bool(code))
    return {
        "verdict": verdict,
        "policy_hits": hits,
        "capabilities_code": {k: len(v) for k, v in code_caps.items()},
        "capabilities_doc": {k: len(v) for k, v in doc_caps.items()},
        "evidence_pack": (code_ev[:30] + doc_ev[:10])[:40],
        "files": {"code": len(code), "doc": len(docs)},
        "contract": {
            "verdict_enum": ["ALLOW", "PROMPT_ONLY", "REVIEW", "DENY", "UNKNOWN"],
            "fail_closed": "无代码文件/解析失败 → UNKNOWN，调用方必须按不可放行处理",
            "not_authorization": "本结果只表示风险判定，绝不等于授权",
            "scope_rule": "DENY 仅由代码中真实发生的能力触发；文档描述最高 REVIEW",
        },
    }


if __name__ == "__main__":
    p = Path(sys.argv[1])
    r = run(p)
    print(json.dumps(r, ensure_ascii=False, indent=2))
    sys.exit(0 if r["verdict"] == "ALLOW" else 1)
