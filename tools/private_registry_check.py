"""A-34c 私有包名 registry 占用核对（只读、可预审）。

它回答一个问题：给定一份私有包清单，这些名字现在是否已被**他人**发布在
公开 registry 上。它不判断"这个包安不安全"，只报"名字被占了几次、谁是发布者、
最早什么时候发布"。

设计上的三条硬约束：
  1) 只读。只有 GET，没有 PUT/POST/DELETE，不带任何写凭据。
  2) 默认不联网。必须显式给 --live 才发起请求；不给就只做本地自检，
     并把"未联网核对"写进结论——沉默的跳过比失败更危险。
  3) 不猜。registry 返回格式变了、字段缺了、请求失败，一律报 UNKNOWN，
     绝不把"查不到"写成"没被占用"。

用法（离线自检，不联网）：
    python private_registry_check.py --selfcheck

用法（真实核对，需批准）：
    python private_registry_check.py --live --inventory private-packages.json
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

NPM_URL = "https://registry.npmjs.org/%s"
PYPI_URL = "https://pypi.org/pypi/%s/json"
UA = "lgd-gate-private-name-check/1.0 (+read-only)"


def fetch(url, timeout=10):
    """唯一的网络出口。只 GET，不带凭据。"""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def probe(name, ecosystem, fetcher=fetch):
    """返回 (state, detail)。state ∈ {TAKEN, FREE, UNKNOWN}。

    FREE 只表示"registry 明确回了 404"；任何其他情况都是 UNKNOWN。
    """
    url = (NPM_URL if ecosystem == "npm" else PYPI_URL) % name
    try:
        data = fetcher(url)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "FREE", "registry 返回 404（该名字当前无人发布）"
        return "UNKNOWN", "HTTP %s，无法判定" % e.code
    except Exception as e:  # 网络、解析、超时
        return "UNKNOWN", "%s: 无法判定" % type(e).__name__
    if not isinstance(data, dict):
        return "UNKNOWN", "返回结构非对象，无法判定"
    if ecosystem == "npm":
        maintainers = data.get("maintainers") or []
        who = ", ".join(m.get("name", "?") if isinstance(m, dict) else str(m)
                        for m in maintainers) or "未知"
        when = (data.get("time") or {}).get("created", "未知")
    else:
        info = data.get("info") or {}
        who = (info.get("author") or info.get("maintainer") or "未知")
        when = "未知"
        releases = data.get("releases") or {}
        if releases:
            when = min((v[0].get("upload_time_iso_8601", "") for v in releases.values()
                        if isinstance(v, list) and v and isinstance(v[0], dict)
                        and v[0].get("upload_time_iso_8601")), default="未知")
    return "TAKEN", "发布者=%s；最早发布=%s" % (who, when)


def load_inventory(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    names = [str(n).strip() for n in data.get("names", []) if str(n).strip()]
    scopes = [str(s).strip() for s in data.get("scopes", []) if str(s).strip()]
    return names, scopes


def run(names, ecosystems=("PyPI", "npm"), fetcher=fetch, live=False):
    rows = []
    for n in names:
        for eco in ecosystems:
            if not live:
                rows.append({"name": n, "ecosystem": eco, "state": "NOT CHECKED",
                             "detail": "未联网（需 --live 且经批准）"})
                continue
            state, detail = probe(n, eco, fetcher=fetcher)
            rows.append({"name": n, "ecosystem": eco, "state": state, "detail": detail})
    return rows


def verdict(rows):
    """把逐行结果压成一句结论。关键在于未核对不能算通过。"""
    if not rows:
        return "EMPTY", "清单为空，未核对任何名字"
    states = {r["state"] for r in rows}
    if "TAKEN" in states:
        return "AT RISK", "至少一个私有名已被他人发布，需人工确认发布者身份"
    if "NOT CHECKED" in states:
        return "NOT VERIFIED", "存在未核对条目；未核对不等于安全"
    if "UNKNOWN" in states:
        return "PARTIAL", "存在无法判定条目，需重试或人工核对"
    return "CLEAR", "所有私有名在公开 registry 上均返回 404（当前无人发布）"


def _stub(url):
    """离线桩：只为验证解析与判定路径，不代表任何 registry 的真实状态。"""
    if "npmjs" in url:
        if "acme-utils" in url:
            return {"maintainers": [{"name": "someone-else"}],
                    "time": {"created": "2024-01-02T00:00:00.000Z"}}
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
    if "acme-utils" in url:
        return {"info": {"author": "stranger"}, "releases": {"1.0.0": [{"upload_time_iso_8601": "2023-05-06T00:00:00Z"}]}}
    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


def selfcheck():
    """不联网的行为自检：确认 TAKEN/FREE 两条路径与 verdict 都按预期工作。"""
    rows = run(["acme-utils", "acme-internal-api"], fetcher=_stub, live=True)
    for r in rows:
        print("  %-10s %-6s %-8s %s" % (r["name"], r["ecosystem"], r["state"], r["detail"]))
    code, msg = verdict(rows)
    print("  verdict=%s  %s" % (code, msg))
    assert any(r["state"] == "TAKEN" for r in rows)
    assert code == "AT RISK"
    rows2 = run(["acme-utils"], fetcher=_stub, live=False)
    assert verdict(rows2)[0] == "NOT VERIFIED", verdict(rows2)
    print("  selfcheck OK（离线桩，未访问任何 registry）")
    return 0


def main():
    ap = argparse.ArgumentParser(description="私有包名 registry 占用核对（只读）")
    ap.add_argument("--inventory", help="private-packages.json 路径")
    ap.add_argument("--live", action="store_true", help="真的联网（需批准）")
    ap.add_argument("--selfcheck", action="store_true", help="离线桩自检，不联网")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    a = ap.parse_args()
    if a.selfcheck:
        return selfcheck()
    if not a.inventory:
        ap.print_help()
        return 2
    names, scopes = load_inventory(a.inventory)
    rows = run(names, fetcher=fetch, live=a.live)
    code, msg = verdict(rows)
    if a.json:
        print(json.dumps({"verdict": code, "message": msg, "rows": rows},
                         ensure_ascii=False, indent=2))
    else:
        for r in rows:
            print("%-24s %-5s %-12s %s" % (r["name"], r["ecosystem"], r["state"], r["detail"]))
        print("verdict=%s  %s" % (code, msg))
    return 0 if code in ("CLEAR", "AT RISK") else 3


if __name__ == "__main__":
    sys.exit(main())
