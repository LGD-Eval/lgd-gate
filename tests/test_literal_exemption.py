"""字面量豁免必须"只收窄误报，不放宽真阳性"。

由来：同一个仓库，skillgate 报 93 A+，evaluate 报 0 F —— 因为 skillgate 早就豁免
"规则定义行"，evaluate 没豁免，于是扫描器被自己的规则表与说明文字打穿。
修法是加豁免，但豁免是最容易变成"静默放行"的地方，所以这里钉三件事：
  1. 真凭证（不在 tests/ 里）必须照报；
  2. 豁免必须打印出来，不许静默；
  3. 本仓自扫不得再出现凭证/TLS 类命中。
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL = os.path.join(HERE, "evaluate.py")
CRED = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # 36 位，形状合法


def _run(path):
    r = subprocess.run([sys.executable, EVAL, path, "--ascii"],
                       capture_output=True, text=True, encoding="utf-8", cwd=HERE)
    return r.stdout or ""


def _mk(tmp, rel, body):
    p = os.path.join(tmp, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(p) else None
    with open(p, "w", encoding="utf-8") as f:
        f.write(body)
    return p


def test_real_credential_outside_tests_is_still_reported():
    with tempfile.TemporaryDirectory() as td:
        _mk(td, "scripts/leak.py", 'TOKEN = "%s"\n' % CRED)
        out = _run(td)
        assert "硬编码凭证" in out, "真凭证必须照报，豁免不得吃掉它：%r" % out[-400:]


def test_exemption_is_announced_not_silent():
    out = _run(HERE)
    assert "豁免" in out, "发生了豁免就必须打印，静默放行是这套工具最不能犯的错"


def test_self_scan_has_no_credential_or_tls_hits():
    out = _run(HERE)
    for bad in ("硬编码凭证", "TLS 校验被关闭", "私钥块"):
        assert bad not in out, "本仓自扫仍被自己的规则表打穿：%s" % bad


def test_fixture_sample_is_exempt_but_counted():
    """夹具里的样例命中会被豁免——这是刻意的，且必须记在账上。

    如果哪天有人把真凭证写进 tests/，这里的行为就是"放过"；所以这条测试的
    价值不是断言"放过"，而是让"放过"这件事一旦改变就必须显式改测试。
    """
    with tempfile.TemporaryDirectory() as td:
        _mk(td, "tests/sample.py", 'TOKEN = "%s"\n' % CRED)
        out = _run(td)
        assert "豁免" in out, "夹具豁免也必须落账"
        assert "tests/sample.py" in out


def test_exempted_hits_are_listed_one_by_one():
    """外部席当场问了这一条：夹具里的真凭证会不会被吞掉、且看不出来。

    答案是"会被豁免"。既然豁免不取消，就让它**看得见**：每一条被豁免的命中
    都要带 file:line 与规则号逐条列出，末尾还要写"这条路下真凭证不会报错"。
    条数不够看不是理由——看不见才是。
    """
    with tempfile.TemporaryDirectory() as td:
        _mk(td, "tests/sample.py", 'TOKEN = "%s"\n' % CRED)
        out = _run(td)
        assert "tests/sample.py:1" in out, "被豁免的命中必须带行号逐条列出：%r" % out[-300:]
        assert "R-SEC-01" in out, "列出时必须带规则号，否则人无法判断该不该放过"
        assert "不会报错" in out, "必须在清单后明写这条路的风险，不许让读者以为彻底安全"
