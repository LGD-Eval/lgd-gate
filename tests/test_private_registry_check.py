"""A-34c 只读核对脚本的行为测试：全部离线，不访问任何 registry。

被测的核心不是"能不能联网"，而是三条判定纪律：
  · 只有 404 才算 FREE；其他一切异常都是 UNKNOWN
  · 未核对不等于安全（NOT CHECKED → NOT VERIFIED）
  · 结论不静默：任何跳过都要出现在结论里
"""
import importlib.util
import json
import os
import sys
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = importlib.util.spec_from_file_location(
    "prc", os.path.join(ROOT, "tools", "private_registry_check.py"))
prc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prc)


def _taken(url):
    return {"maintainers": [{"name": "stranger"}], "time": {"created": "2024-01-01"}}


def _404(url):
    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


def _500(url):
    raise urllib.error.HTTPError(url, 500, "Server Error", {}, None)


def _boom(url):
    raise TimeoutError("slow")


def test_404_is_the_only_free_signal():
    rows = prc.run(["acme"], fetcher=_404, live=True)
    assert all(r["state"] == "FREE" for r in rows)
    assert prc.verdict(rows)[0] == "CLEAR"


def test_http_500_is_unknown_not_free():
    """把 500 当成"没被占用"，就是拿故障当结论。"""
    rows = prc.run(["acme"], fetcher=_500, live=True)
    assert all(r["state"] == "UNKNOWN" for r in rows)
    assert prc.verdict(rows)[0] == "PARTIAL"


def test_timeout_is_unknown():
    rows = prc.run(["acme"], fetcher=_boom, live=True)
    assert all(r["state"] == "UNKNOWN" for r in rows)


def test_offline_run_is_not_verified_never_clear():
    """不联网的一轮，结论必须是 NOT VERIFIED —— 这是最容易被糊弄成"通过"的地方。"""
    rows = prc.run(["acme"], live=False)
    assert all(r["state"] == "NOT CHECKED" for r in rows)
    assert prc.verdict(rows)[0] == "NOT VERIFIED"


def test_occupied_name_is_at_risk():
    rows = prc.run(["acme"], fetcher=_taken, live=True)
    assert prc.verdict(rows)[0] == "AT RISK"


def test_at_risk_outranks_unverified_and_unknown():
    """混合清单的优先级：已经确认被占，不能因为还有没核到的就降级成 NOT VERIFIED。

    真实场景：一轮 20 个名字，5 个联网核到被占、15 个因限流没核。
    若结论落到 NOT VERIFIED，读的人会以为"只是没查"，而事实上已经有人抢注了。
    """
    taken = prc.run(["acme"], fetcher=_taken, live=True)
    unchecked = prc.run(["other"], live=False)
    unknown = prc.run(["third"], fetcher=_500, live=True)
    for extra in (unchecked, unknown):
        verdict, _ = prc.verdict(taken + extra)
        assert verdict == "AT RISK", "已确认被占时不得降级为 %s" % verdict


def test_empty_inventory_is_empty_not_clear():
    assert prc.verdict([])[0] == "EMPTY"


def test_inventory_loader_reads_names_and_scopes(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps({"names": ["a", " b ", ""], "scopes": ["@acme"]}), encoding="utf-8")
    names, scopes = prc.load_inventory(str(p))
    assert names == ["a", "b"] and scopes == ["@acme"]


def test_selfcheck_runs_offline():
    """selfcheck 用离线桩，不该碰到网络。"""
    assert prc.selfcheck() == 0
