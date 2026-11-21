"""两个引擎都必须自报身份与版本。

缘由：lgd-gate 仓里有两个引擎——skillgate.py（规则命中口径）与 evaluate.py（五维口径）
——都会打印 `Trust Score: N/100`。一份被引用的分数如果不写引擎与版本，就无法核验，
甚至在出问题时连"是哪一版给的结论"都答不出来。README 早就要求"引用须标注引擎 +
rule_version"，但输出里没有这两项，这条要求此前谁也无法执行。

这里把它变成可执行断言：跑两个 CLI，检查输出里必须有身份与版本，
且 skillgate 打印的版本必须等于它自己 JSON 里的 rule_version（单一来源）。
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(HERE, "examples")


def _run(args):
    return subprocess.run([sys.executable] + args, capture_output=True, text=True,
                          encoding="utf-8", cwd=HERE)


def _sample_dir():
    for name in os.listdir(SAMPLE) if os.path.isdir(SAMPLE) else []:
        d = os.path.join(SAMPLE, name)
        if os.path.isdir(d):
            return d
    return HERE


def test_skillgate_prints_engine_and_rule_version():
    r = _run(["skillgate.py", "scan", _sample_dir()])
    out = r.stdout or ""
    assert "skillgate.py" in out, "报告头必须写明引擎身份"
    m = re.search(r"[vV]\d+\.\d+\.\d+", out)
    assert m, "报告头必须写明规则版本（rule_version）"


def test_skillgate_stdout_version_matches_json():
    """终端与 JSON 不能各说一套：版本只有一个来源。"""
    d = _sample_dir()
    txt = _run(["skillgate.py", "scan", d]).stdout or ""
    js = _run(["skillgate.py", "scan", d, "--format", "json"])
    payload = json.loads(js.stdout)
    ver = payload.get("rule_version", "")
    assert ver.startswith("v"), "JSON 里必须有 rule_version"
    assert ver in txt, "终端打印的版本 %r 必须在 JSON 里出现，实际终端：%r" % (ver, txt[:200])
    assert payload.get("engine") == "skillgate.py"


def test_evaluator_prints_engine_and_authorization_state():
    r = _run(["evaluate.py", _sample_dir(), "--ascii"])
    out = r.stdout or ""
    assert "evaluate.py" in out and "1.1.0" in out, "评测报告头必须写引擎与版本"
    assert "NOT_GRANTED" in out, "评测报告头必须写明授权状态恒为 NOT_GRANTED"


def test_evaluator_evidence_json_carries_identity():
    import tempfile
    tmp = tempfile.mkdtemp()
    out = os.path.join(tmp, "ev.json")
    _run(["evaluate.py", _sample_dir(), "--evidence-json", out, "--ascii"])
    payload = json.load(open(out, encoding="utf-8"))
    assert payload["engine"] == "evaluate.py"
    assert payload["engine_version"] == "1.1.0"
    assert payload["authorization_status"] == "NOT_GRANTED"
