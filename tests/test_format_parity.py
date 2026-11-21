"""六种出口必须说同一件事：分数、阈值、是否拦住。

修复前（audit2/probe_format_parity.py + 手工复核）：
· JUnit XML 硬编码 `threshold 80`，完全不看 `--fail-under`
  —— 分 85 + 门槛 90，进程 exit 1（拦住），XML 写 failures=0，
     读 JUnit 的 CI（GitHub Test Reporter、IDE）看到一片绿。
· SARIF 里根本没有分数与阈值，只有 findings 条数
  —— 同一份扫描，JSON 出口说"85/100、被门槛 90 拦住"，SARIF 出口什么都不说。
· JUnit 的 failures 数是 `critical+high` 估出来的，不是写出的 failure 元素数
  —— 非计分披露若被算进来，披露会变成"测试失败"。

守卫用真 CLI（子进程）验证，因为读这些出口的是 CI，不是函数调用者。
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = str(ROOT / "skillgate.py")
SKILL_MD = "---\nname: demo\ndescription: format parity guard skill\n---\n\n# demo\n"
LOW_BODY = "import tempfile\np = tempfile.mkdtemp()\n"


def _build(tmp_path, n_low):
    d = tmp_path / "skill"
    (d / "scripts").mkdir(parents=True)
    (d / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    for i in range(n_low):
        (d / "scripts" / ("f%02d.py" % i)).write_text(LOW_BODY, encoding="utf-8")
    return d


def _run(d, fmt, fail_under=None):
    cmd = [sys.executable, GATE, "scan", str(d), "--format", fmt]
    if fail_under is not None:
        cmd += ["--fail-under", str(fail_under)]
    p = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return p.stdout, p.returncode


def test_junit_follows_cli_threshold(tmp_path):
    """分 85 + 门槛 90：退出码必须 1，JUnit 必须记 failure（不能一片绿）。"""
    d = _build(tmp_path, 15)  # 100 − 15 = 85
    out, rc = _run(d, "junit", 90)
    assert rc == 1, "门槛 90 下 85 分没有拦住"
    fails = re.search(r'failures="(\d+)"', out)
    assert fails and int(fails.group(1)) >= 1, "JUnit 报 failures=0 却已拦住"
    assert "threshold 90" in out, "JUnit 里的阈值不是命令行给的 90"


def test_junit_does_not_red_when_cli_passes(tmp_path):
    """反向：分 85 + 门槛 60，退出码 0 —— JUnit 不得自造失败。"""
    d = _build(tmp_path, 15)
    out, rc = _run(d, "junit", 60)
    assert rc == 0
    fails = re.search(r'failures="(\d+)"', out)
    assert fails and int(fails.group(1)) == 0, "退出码说放行，JUnit 却报失败"


def test_sarif_carries_score_and_threshold(tmp_path):
    d = _build(tmp_path, 15)
    out, _ = _run(d, "sarif", 90)
    doc = json.loads(out)
    props = doc["runs"][0]["properties"]
    assert props["trust_score"] == 85
    assert props["fail_under"] == 90
    assert props["blocked"] is True, "SARIF 没说出'被拦住'这件事"


def test_all_formats_agree_on_blocking(tmp_path):
    """同一份扫描：六个出口的"拦不拦"必须一致。"""
    d = _build(tmp_path, 15)
    codes = {}
    for fmt in ("terminal", "json", "markdown", "agent", "sarif", "junit"):
        _, rc = _run(d, fmt, 90)
        codes[fmt] = rc
    assert all(c == 1 for c in codes.values()), "出口之间对'拦不拦'不一致: %r" % (codes,)
