"""授权记录（authorization record）：谁、给了什么、到什么时候、凭什么。

设计上的一处硬决定：**evaluate.py 不读这个文件。**
评测器只产出结论，授权是另一次动作、由另一条命令裁决。把两者放在同一支流程里，
就是审计第一条 P0 的复发——一个工具同时打分和发许可证。

所以这里只做三件事：
  1. 生成一份可审计的记录（new）
  2. 校验这份记录是否成立（validate）
  3. 打印它说的是什么（show）

校验不追求"防伪造"（本地文件无从防），追求的是**伪造会留下痕迹**：
授予人、范围、有效期、依据四项缺一不可，且第三方复核必须有可访问的依据。

用法：
  python3 authorization_record.py new --grantor "Steven Zhao" --subject <tree_sha256> \
      --scope "production deploy: skill-x" --days 90 --provenance third_party \
      --evidence https://... -o auth.json
  python3 authorization_record.py validate auth.json --tree <tree_sha256>
"""
import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys

VERSION = "lgd-auth/1"

# 这些名字不接受：它们不是"一方"，无法承担后果
_NON_PERSONS = {"auto", "automated", "bot", "ci", "system", "none", "n/a", "-"}

PROVENANCE = ("maintainer_self", "automated", "third_party")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_URL = re.compile(r"^https?://\S+$")


def _norm_subject(value):
    """evaluate.py 的 --evidence-json 把树哈希写成 "sha256:<hex>"，两种写法都收。"""
    s = str(value or "").strip().lower()
    if s.startswith("sha256:"):
        s = s[len("sha256:"):]
    return s


def _today(now=None):
    return (now or _dt.date.today()).isoformat()


def _parse_date(value, field):
    try:
        return _dt.date.fromisoformat(str(value))
    except ValueError:
        raise ValueError("%s 不是合法日期（要 YYYY-MM-DD）：%r" % (field, value))


def new_record(grantor, subject, scope, days, provenance, evidence, now=None,
               justification=""):
    """构造一份记录。这里不做校验——由 validate 统一裁决，避免两套规则。"""
    start = _parse_date(_today(now), "granted_at")
    rec = {
        "version": VERSION,
        "subject_tree_sha256": (subject or "").strip().lower(),
        "grantor": (grantor or "").strip(),
        "scope": (scope or "").strip(),
        "granted_at": start.isoformat(),
        "expires_at": (start + _dt.timedelta(days=int(days))).isoformat(),
        "provenance": (provenance or "").strip(),
        "evidence": list(evidence or []),
        "justification": (justification or "").strip(),
    }
    rec["record_id"] = hashlib.sha256(
        json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]
    return rec


def validate(rec, tree=None, now=None):
    """返回 (ok, [问题...])。所有问题一次报全，不逐条挤牙膏。"""
    problems = []

    if not isinstance(rec, dict):
        return False, ["记录不是 JSON 对象"]

    if rec.get("version") != VERSION:
        problems.append("version 必须是 %s（实际 %r）" % (VERSION, rec.get("version")))

    subject = _norm_subject(rec.get("subject_tree_sha256"))
    if not _HEX64.match(subject):
        problems.append("subject_tree_sha256 必须是 64 位小写十六进制")
    elif tree and subject != _norm_subject(tree):
        problems.append(
            "记录针对的是另一棵树：记录 %s…，被测 %s…"
            % (subject[:12], str(tree).strip().lower()[:12]))

    grantor = str(rec.get("grantor") or "").strip()
    if not grantor:
        problems.append("grantor 不能为空：授权必须有一方署名")
    elif grantor.lower() in _NON_PERSONS:
        problems.append("grantor %r 不是一方，无法承担后果" % grantor)

    if not str(rec.get("scope") or "").strip():
        problems.append("scope 不能为空：不写范围等于授权到任何地方")

    try:
        granted = _parse_date(rec.get("granted_at"), "granted_at")
        expires = _parse_date(rec.get("expires_at"), "expires_at")
    except ValueError as exc:
        problems.append(str(exc))
        granted = expires = None

    if granted and expires:
        if expires <= granted:
            problems.append("expires_at 必须晚于 granted_at")
        as_of = _parse_date(_today(now), "as_of")
        if expires < as_of:
            problems.append("记录已过期（%s < %s）" % (expires.isoformat(), as_of.isoformat()))

    prov = str(rec.get("provenance") or "").strip()
    if prov not in PROVENANCE:
        problems.append("provenance 必须是 %s 之一" % "/".join(PROVENANCE))

    evidence = rec.get("evidence") or []
    if not isinstance(evidence, list):
        problems.append("evidence 必须是数组")
        evidence = []
    evid_urls = [e for e in evidence if isinstance(e, str) and _URL.match(e)]
    if prov == "third_party" and not evid_urls:
        problems.append(
            "声明了 third_party 却没有任何可访问的依据：第三方复核必须留证据")
    if prov in ("maintainer_self", "automated") and not str(
            rec.get("justification") or "").strip():
        problems.append("自评或自动授权必须写 justification：为什么这样也够")

    return (not problems), problems


def describe(rec):
    return ("AUTHORIZATION: %s\n"
            "  grantor   : %s\n"
            "  scope     : %s\n"
            "  valid     : %s → %s\n"
            "  subject   : %s\n"
            "  provenance: %s\n"
            "  record_id : %s"
            % ("VALID" if validate(rec)[0] else "INVALID",
               rec.get("grantor"), rec.get("scope"),
               rec.get("granted_at"), rec.get("expires_at"),
               str(rec.get("subject_tree_sha256"))[:16] + "…",
               rec.get("provenance"), rec.get("record_id")))


def main(argv=None):
    ap = argparse.ArgumentParser(description="LGD 授权记录：生成 / 校验 / 打印")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_new = sub.add_parser("new", help="生成一份授权记录")
    p_new.add_argument("--grantor", required=True)
    p_new.add_argument("--subject", required=True, help="被测目录的 tree_sha256")
    p_new.add_argument("--scope", required=True, help="授权的范围，例如 production deploy: skill-x")
    p_new.add_argument("--days", type=int, default=90)
    p_new.add_argument("--provenance", default="maintainer_self", choices=PROVENANCE)
    p_new.add_argument("--evidence", action="append", default=[], help="可重复：依据 URL")
    p_new.add_argument("--justification", default="")
    p_new.add_argument("-o", "--out", default="")

    p_val = sub.add_parser("validate", help="校验一份授权记录")
    p_val.add_argument("path")
    p_val.add_argument("--tree", default=None, help="被测目录的 tree_sha256，用于核对记录是否针对这棵树")

    p_show = sub.add_parser("show", help="打印记录内容与结论")
    p_show.add_argument("path")

    args = ap.parse_args(argv)

    if args.cmd == "new":
        rec = new_record(args.grantor, args.subject, args.scope, args.days,
                         args.provenance, args.evidence,
                         justification=args.justification)
        ok, problems = validate(rec)
        if not ok:
            sys.stderr.write("记录本身不成立：\n" + "\n".join("  - " + p for p in problems) + "\n")
            return 2
        payload = json.dumps(rec, ensure_ascii=False, indent=2) + "\n"
        if args.out:
            with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(payload)
            print("已写入 %s（record_id=%s）" % (args.out, rec["record_id"]))
        else:
            print(payload, end="")
        return 0

    try:
        with open(args.path, encoding="utf-8") as f:
            rec = json.load(f)
    except OSError as exc:
        # 找不到文件不该是 traceback：这是使用者会犯的普通错误
        sys.stderr.write("读不到记录 %s：%s\n" % (args.path, exc))
        return 2
    except ValueError as exc:
        sys.stderr.write("记录不是合法 JSON（%s）：%s\n" % (args.path, exc))
        return 2
    ok, problems = validate(rec, tree=getattr(args, "tree", None))
    if args.cmd == "show":
        print(describe(rec))
        for p in problems:
            print("  - " + p, file=sys.stderr)
        return 0 if ok else 2
    for p in problems:
        print("  - " + p, file=sys.stderr)
    print("AUTHORIZATION: %s" % ("VALID" if ok else "INVALID"))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
