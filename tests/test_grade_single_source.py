"""等级刻度只能有一个来源，且版本号不得各写一遍。

由来：这条线走到第四站时发现，同一个"等级"在仓里有四份实现——
evaluate.py 的 grade_for、skillgate.py 的 grade_from_score、lgd_web.py 的 grade_of、
eval_mcp.py 的 grade_of。实测 13 个边界分数上四者今天恰好一致，
**但一致不等于同源**：评测器改一次刻度，其余三份不动，Web / MCP 就会继续发旧字母，
而且没有任何测试会红。

更实的两处已在本次修掉：
  1) eval_mcp 把 🏆/🥇/🥈/🥉 拼进等级字符串，下游 grade == "C" 必然失配；
  2) Web / MCP 的 health 报 version 1.0.0，而评测器是 1.1.0——一个当下就错的对外数字。

这个测试把四件事钉住：刻度一致、等级是裸字母、版本同源、输出带引擎与口径。
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import evaluate as ev            # noqa: E402
import skillgate as sg           # noqa: E402
import lgd_web as web            # noqa: E402
import eval_mcp as mcp           # noqa: E402

SCORES = [0, 10, 39, 40, 59, 60, 69, 70, 79, 80, 89, 90, 100]
LETTERS = {"A+", "A", "B", "C", "D", "F"}


def test_all_grade_tables_agree_on_boundaries():
    for s in SCORES:
        e = ev.grade_for(s)[0]
        g = sg.grade_from_score(s)
        w = web.grade_of(s)
        m = mcp.grade_of(s)
        assert e == g == w == m, "分数 %d 上四份刻度不一致：%r" % (s, (e, g, w, m))


def test_grades_are_bare_letters():
    for s in SCORES:
        for name, fn in (("evaluate", lambda x: ev.grade_for(x)[0]),
                         ("skillgate", sg.grade_from_score),
                         ("web", web.grade_of), ("eval_mcp", mcp.grade_of)):
            g = fn(s)
            assert g in LETTERS, "%s 的等级 %r 不是裸字母（不要拼 emoji）" % (name, g)


def test_web_does_not_redefine_the_scale():
    """Web 的 grade_of 必须委托评测器，不能自己写一张表。"""
    src = open(os.path.join(HERE, "lgd_web.py"), encoding="utf-8").read()
    assert "from evaluate import grade_for" in src, "lgd_web 必须从评测器取等级"


def test_versions_come_from_one_source():
    assert ev.ENGINE_VERSION, "评测器必须有 ENGINE_VERSION"
    src_web = open(os.path.join(HERE, "lgd_web.py"), encoding="utf-8").read()
    src_mcp = open(os.path.join(HERE, "lgd_mcp_server.py"), encoding="utf-8").read()
    assert '"version": "1.0.0"' not in src_web, "Web health 不得写死一个版本号"
    assert '"version": "1.0.0"' not in src_mcp, "MCP serverInfo 不得写死一个版本号"
    assert "ENGINE_VERSION" in src_web and "ENGINE_VERSION" in src_mcp


def test_results_carry_engine_and_scale():
    """两个引擎输出形状相同，必须各自标明是谁、哪把尺子。"""
    text = ("---\nname: t\ndescription: d\n---\n# t\n\n## When to Use\n- a\n- b\n- c\n")
    r = web.evaluate_text(text)
    assert r["engine"] and r["scale"].startswith("技能五维")
    assert r["grade"] in LETTERS
    assert r["authorization_status"] == "NOT_GRANTED"

    src = open(os.path.join(HERE, "lgd_mcp_server.py"), encoding="utf-8").read()
    assert '"scale": _mcp_mod.SCALE' in src, "evaluate_mcp 的结果必须带自己的口径"
    assert mcp.SCALE.startswith("MCP Server 五维")


def test_eval_mcp_json_carries_engine_and_scale():
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(HERE, "eval_mcp.py"), HERE, "--json"],
                       capture_output=True, text=True, encoding="utf-8", cwd=HERE)
    payload = json.loads(r.stdout)
    assert payload["engine"] == "eval_mcp.py"
    assert payload["scale"] == mcp.SCALE
    assert payload["grade"] in LETTERS


def test_mcp_skill_tool_returns_engine_not_tuple():
    """evaluate_skill 的返回值从 5 个变 6 个时，MCP 端曾整段崩掉。

    这里直接走真实调用路径：tools/call → evaluate_skill，必须返回带引擎字段的 JSON，
    而不是 ValueError: too many values to unpack。
    """
    import lgd_mcp_server as srv
    res = srv.call_tool("evaluate_skill", {"path": HERE})
    payload = json.loads(res["content"][0]["text"])
    assert payload["engine"] == "evaluate.py"
    assert 0 <= payload["score"] <= 100
    assert payload["grade"] in LETTERS
    assert payload["authorization_status"] == "NOT_GRANTED"


def test_score_never_leaves_the_0_100_scale():
    """实测出现过 -87/100：扣分项叠加能超出刻度，而对外只有一个 0–100 的分数。

    刻度破了，比较就失去意义（-87 与 0 都印 F，但不是同一件事）。
    """
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(HERE, "evaluate.py"), HERE, "--ascii"],
                       capture_output=True, text=True, encoding="utf-8", cwd=HERE)
    out = r.stdout or ""
    m = __import__("re").search(r"Trust Score: (-?\d+)/100", out)
    assert m, "没有产出分数行：%r" % out[-300:]
    score = int(m.group(1))
    assert 0 <= score <= 100, "分数越界：%d（应恒在 0–100）" % score


def test_badge_line_requires_breaching_threshold():
    """三律齐备不等于够格：分数很低时不得再印"可申请认证徽章"。"""
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(HERE, "evaluate.py"), HERE, "--ascii"],
                       capture_output=True, text=True, encoding="utf-8", cwd=HERE)
    out = r.stdout or ""
    if "可申请 LGD 认证徽章" in out:
        assert "分数达标" in out, "徽章结论未与分数挂钩：%r" % out[-200:]
