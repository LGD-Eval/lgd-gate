"""门槛边界：score 与 --fail-under 的比较必须是"达到即通过"，不能差一。

分数是门禁的嘴，退出码是门禁的手。边界差一，CI 就会在该拦的时候绿。
用子进程跑真正的 CLI，不走函数——exit code 才是 CI 看的东西。
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = str(ROOT / "skillgate.py")
SKILL_MD = "---\nname: demo\ndescription: threshold edge guard skill\n---\n\n# demo\n"
LOW_BODY = "import tempfile\np = tempfile.mkdtemp()\n"


def _build(tmp_path, n_low):
    d = tmp_path / "skill"
    (d / "scripts").mkdir(parents=True)
    (d / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    for i in range(n_low):
        (d / "scripts" / ("f%02d.py" % i)).write_text(LOW_BODY, encoding="utf-8")
    return d


def _run(d, fail_under):
    p = subprocess.run([sys.executable, GATE, "scan", str(d),
                        "--fail-under", str(fail_under), "--format", "json"],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    j = json.loads(p.stdout) if p.stdout.strip().startswith("{") else {}
    return j.get("trust_score"), p.returncode


def test_score_equal_to_threshold_passes(tmp_path):
    """12 条 LOW → 88 分；门槛 88 必须放行，门槛 89 必须拦住。"""
    d = _build(tmp_path, 12)
    s, rc = _run(d, 88)
    assert s == 88, "分数与文档不符：%r" % (s,)
    assert rc == 0, "分数等于门槛时被拦住（>= 应为通过）"
    s2, rc2 = _run(d, 89)
    assert s2 == 88
    assert rc2 != 0, "分数低于门槛时被放行"


def test_above_threshold_passes(tmp_path):
    d = _build(tmp_path, 8)  # 92 分
    s, rc = _run(d, 90)
    assert s == 92 and rc == 0
