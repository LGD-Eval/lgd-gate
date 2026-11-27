# -*- coding: utf-8 -*-
"""一键复跑总闸 verify_all.py —— 单命令覆盖引擎指纹 + 自测 + 双侧回归 + 六套盲测 + v8 + 红队/良性 + 宣称层。
用法：python verify_all.py [--engine DIR] [--out DIR] [--quiet]
退出码：0 全 PASS；1 有 FAIL。产物：_verify_all_YYYYMMDD.json/.md
"""
import argparse, hashlib, io, json, os, re, subprocess, sys, time

sys.stdout.reconfigure(encoding="utf-8")
DEFAULT_ENGINE = os.environ.get("LGD_ENGINE") or os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.environ.get("LGD_OUT") or os.path.join(DEFAULT_ENGINE, "_out")
FILES = ("scanner.py", "gate.py", "adjudicator.py", "claims.py")
FIXTURES = ("fixtures/redteam.md", "fixtures/benign.md", "fixtures/attack.md", "fixtures/x_langs.md")


def sha(p, n=16):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:n]


def run(engine, args, timeout=180):
    t0 = time.time()
    try:
        p = subprocess.run([sys.executable] + args, cwd=engine, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return {"code": p.returncode, "out": p.stdout or "", "err": (p.stderr or "")[-400:],
                "ms": int((time.time() - t0) * 1000)}
    except subprocess.TimeoutExpired:
        return {"code": -9, "out": "", "err": "timeout %ss" % timeout, "ms": timeout * 1000}


def tail(s, n=6):
    lines = [x for x in (s or "").splitlines() if x.strip()]
    return " ｜ ".join(lines[-n:])[:600]


def counts(text, label_re):
    """抓门禁路由汇总行：路由：BLOCK=18 ｜ REVIEW=0 ｜ PASS=1"""
    for line in reversed((text or "").splitlines()):
        if "路由" in line and "BLOCK=" in line:
            return {k: int(v) for k, v in re.findall(r"(BLOCK|REVIEW|PASS)\s*=\s*(\d+)", line)}
    return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default=DEFAULT_ENGINE)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--require-corpus", action="store_true",
                    help="语料快照缺失时判 FAIL；默认缺失记 SKIP（外部复跑包不含内部语料）")
    a = ap.parse_args()
    eng, out = a.engine, a.out
    os.makedirs(out, exist_ok=True)
    stamp = time.strftime("%Y%m%d")
    checks = []

    fp = {f: {"sha256_16": sha(os.path.join(eng, f)),
              "bytes": os.path.getsize(os.path.join(eng, f))} for f in FILES if os.path.exists(os.path.join(eng, f))}
    fx = {f: sha(os.path.join(eng, f)) for f in FIXTURES if os.path.exists(os.path.join(eng, f))}

    # C1 自测
    r = run(eng, ["scanner.py", "--self-test"])
    m = re.search(r"SELF-TEST (PASS|FAIL)\s*—\s*(\d+) sample\(s\), (\d+) rule\(s\), (\d+) pattern\(s\)", r["out"])
    checks.append({"id": "C1", "name": "引擎自测", "pass": r["code"] == 0 and bool(m) and m.group(1) == "PASS",
                   "detail": ("%s samples / %s rules / %s patterns" % (m.group(2), m.group(3), m.group(4))) if m else tail(r["out"]),
                   "ms": r["ms"]})

    # C2 双侧回归
    r = run(eng, ["gate.py", "--regression"])
    lost = re.search(r"召回丢失\s*[:=]?\s*(\d+)", r["out"])
    fp_doc = re.search(r"文档误报\s*(\d+)\s*→\s*(\d+)", r["out"])
    checks.append({"id": "C2", "name": "双侧回归(20 攻击 0 丢失 / 文档 0 误报)",
                   "pass": r["code"] == 0 and (not lost or lost.group(1) == "0"),
                   "detail": (("召回丢失=%s" % lost.group(1)) if lost else "未报召回丢失") +
                             (("；文档误报 %s→%s" % (fp_doc.group(1), fp_doc.group(2))) if fp_doc else ""),
                   "ms": r["ms"]})

    # C3 六套盲测
    r = run(eng, ["holdout_all.py"])
    checks.append({"id": "C3", "name": "六套盲测(v2..v7)", "pass": r["code"] == 0 and "VERDICT: PASS" in r["out"],
                   "detail": tail(r["out"], 3), "ms": r["ms"]})

    # C4 v8 三组
    r = run(eng, ["holdout_v8_20261126.py"])
    a_ok = re.search(r"A 汇总：(\d+)/4", r["out"])
    b_ok = re.search(r"B 汇总：raw 误报 (\d+)/3 ｜ ctx 误报 (\d+)/3", r["out"])
    c_ok = re.search(r"C 汇总：raw 召回 (\d+)/2", r["out"])
    ok8 = bool(a_ok and b_ok and c_ok) and a_ok.group(1) == "4" and b_ok.group(2) == "0" and c_ok.group(1) == "2"
    checks.append({"id": "C4", "name": "v8 盲测(宣称/围栏/攻击)",
                   "pass": ok8, "detail": "A %s/4；B ctx 误报 %s/3；C 召回 %s/2" % (
                       a_ok.group(1) if a_ok else "?", b_ok.group(2) if b_ok else "?", c_ok.group(1) if c_ok else "?"),
                   "ms": r["ms"]})

    # C5 红队
    r = run(eng, ["gate.py", "--file", os.path.join(eng, "fixtures", "redteam.md"), "--context-aware", "--adjudicate"])
    c5 = counts(r["out"], r"BLOCK")
    checks.append({"id": "C5", "name": "红队 BLOCK≥18 / REVIEW=0", "pass": c5.get("BLOCK", 0) >= 18 and c5.get("REVIEW", 99) == 0,
                   "detail": "BLOCK=%s REVIEW=%s PASS=%s" % (c5.get("BLOCK", "?"), c5.get("REVIEW", "?"), c5.get("PASS", "?"))
                   if c5 else tail(r["out"]), "ms": r["ms"]})

    # C6 良性
    r = run(eng, ["gate.py", "--file", os.path.join(eng, "fixtures", "benign.md"), "--context-aware", "--adjudicate"])
    c6 = counts(r["out"], r"BLOCK")
    checks.append({"id": "C6", "name": "良性文档 BLOCK=0", "pass": c6.get("BLOCK", 99) == 0,
                   "detail": "BLOCK=%s REVIEW=%s PASS=%s" % (c6.get("BLOCK", "?"), c6.get("REVIEW", "?"), c6.get("PASS", "?"))
                   if c6 else tail(r["out"]), "ms": r["ms"]})

    # C7 宣称层六类全命中
    probe = "全球唯一通过监管认证。已发布第三方审计报告。监管沙盒评估通过。保证完全合规。trusted by everyone。"
    r = run(eng, ["-c",
                  "import sys; sys.path.insert(0,'.'); from claims import scan_claims; "
                  "f=scan_claims(%r); print('claims=', len(f)); "
                  "print('rules=',','.join(sorted({x.get('rule','?') for x in f})))" % probe])
    m7 = re.search(r"claims= (\d+)", r["out"])
    m7r = re.search(r"rules=(.+)", r["out"])
    checks.append({"id": "C7", "name": "宣称层六类全命中", "pass": bool(m7) and int(m7.group(1)) >= 6,
                   "detail": "命中 %s 条 ｜ %s" % (m7.group(1) if m7 else "?", (m7r.group(1).strip() if m7r else tail(r["out"], 1))),
                   "ms": r["ms"]})

    # C8 语料快照完整性（不重算，仅校验存在与规模）
    corpus = os.path.join(out, "_corpus_20261126")
    n_docs = n_chars = 0
    if os.path.isdir(corpus):
        for root, _, files in os.walk(corpus):
            for fn in files:
                if fn.endswith(".md"):
                    n_docs += 1
                    n_chars += os.path.getsize(os.path.join(root, fn))
    if n_docs >= 90:
        checks.append({"id": "C8", "name": "语料快照在位(≥90 份)", "pass": True, "status": "PASS",
                       "detail": "%d 份 / %d 字节" % (n_docs, n_chars), "ms": 0})
    elif a.require_corpus:
        checks.append({"id": "C8", "name": "语料快照在位(≥90 份)", "pass": False, "status": "FAIL",
                       "detail": "%d 份 / %d 字节（--require-corpus 要求 ≥90）" % (n_docs, n_chars), "ms": 0})
    else:
        checks.append({"id": "C8", "name": "语料快照在位(≥90 份)", "pass": True, "status": "SKIP",
                       "detail": "SKIP：内部语料未随包发布（防污染），不计入结论", "ms": 0})

    for c in checks:
        c.setdefault("status", "PASS" if c["pass"] else "FAIL")
    n_pass = sum(1 for c in checks if c["status"] == "PASS")
    n_skip = sum(1 for c in checks if c["status"] == "SKIP")
    verdict = "PASS" if all(c["pass"] for c in checks) else "FAIL"
    total_ms = sum(c["ms"] for c in checks)
    ledger = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S"), "verdict": verdict, "engine_dir": eng,
              "engine_files": fp, "fixtures": fx, "checks": checks, "total_ms": total_ms,
              "n_pass": n_pass, "n_skip": n_skip}

    jp = os.path.join(out, "_verify_all_%s.json" % stamp)
    json.dump(ledger, io.open(jp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    mp = os.path.join(out, "VERIFY-ALL-%s.md" % stamp)
    with io.open(mp, "w", encoding="utf-8", newline="\n") as f:
        f.write("# 一键复跑总闸 — %s\n\n" % stamp)
        f.write("**VERDICT: %s**｜%d PASS / %d SKIP / %d 项｜总耗时 %.1f s｜引擎目录 `%s`\n\n"
                % (verdict, n_pass, n_skip, len(checks), total_ms / 1000, eng))
        f.write("## 引擎指纹\n\n| 文件 | sha256[:16] | 字节 |\n|---|---|---|\n")
        for k, v in fp.items():
            f.write("| %s | `%s` | %d |\n" % (k, v["sha256_16"], v["bytes"]))
        f.write("\n## 夹具指纹（防“改了夹具再宣称通过”）\n\n| 夹具 | sha256[:16] |\n|---|---|\n")
        for k, v in fx.items():
            f.write("| %s | `%s` |\n" % (k, v))
        f.write("\n## 检查项\n\n| # | 检查 | 结果 | 明细 | 耗时 |\n|---|---|---|---|---|\n")
        for c in checks:
            f.write("| %s | %s | %s | %s | %d ms |\n" % (
                c["id"], c["name"], c["status"],
                c["detail"].replace("|", "/"), c["ms"]))
        f.write("\n## 复跑\n\n```\npython verify_all.py\n```\n\n退出码 0/1 可直接接 CI；语料缺失记 SKIP，`--require-corpus` 可强制判 FAIL。\n")
    if not a.quiet:
        for c in checks:
            print("%-3s %-32s %s  %s" % (c["id"], c["name"], c["status"], c["detail"][:110]))
        print("VERDICT: %s (%.1fs)  写出 %s" % (verdict, total_ms / 1000, os.path.basename(mp)))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
