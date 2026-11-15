"""同一个标签不许挂两套刻度：`Trust Score` 只属于评测器。

由来（2026-11-15，把 README 命令逐条实跑时才看见）：`lgd_audit.py` 也印
`Trust Score: N/100`，但那是 18 维完整性分——同一个最小技能，评测器给 61/C、
审计器给 1/100。两个数字并排放着，读者只会得出"这工具太严"或"这工具坏了"。
README 里还写着 lgd_audit"不评总分"，与代码不符：它确实算分，并把分用在退出码上。

这个文件钉两件：
  1. `Trust Score` 这个对外标签只许出现在 evaluate.py / skillgate.py 的输出与文档里；
  2. lgd_audit 的输出必须写清"完整性审计分、不是 Trust Score、不可互比"。
"""
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(name):
    return open(os.path.join(HERE, name), encoding="utf-8").read()


def test_audit_does_not_borrow_the_trust_score_label():
    src = _src("lgd_audit.py")
    assert 'f"  Trust Score: {self.score}/100"' not in src, (
        "lgd_audit 又把审计分印成了 Trust Score——同一个标签两套刻度")
    assert "完整性审计分" in src, "审计分必须有独立的名字"
    assert "不可与评测器分数互比" in src, "必须在输出里明写两者不可互比"


def test_audit_run_prints_its_own_scale_and_engine():
    import subprocess
    import sys
    sample = os.path.join(os.environ.get("TEMP", "."), "lgd_g3_sample", "my-skill")
    if not os.path.isdir(sample):
        os.makedirs(sample, exist_ok=True)
        open(os.path.join(sample, "SKILL.md"), "w", encoding="utf-8").write(
            "---\nname: my-skill\ndescription: sample\nauthor: reviewer\nversion: 0.1.0\n---\n")
    out = subprocess.run([sys.executable, os.path.join(HERE, "lgd_audit.py"), sample],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", cwd=HERE, timeout=120).stdout or ""
    assert "完整性审计分" in out, "审计器的输出没有标自己的刻度：%r" % out[-200:]
    assert "Trust Score" not in out.split("完整性审计分")[0][-200:], (
        "审计器输出里先出现了 Trust Score 标签（会被误读成对外分数）")
