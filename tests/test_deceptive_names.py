"""名字本身就是伪装：读内容永远读不出来的三种形态。

由来（audit2/probe_name_coverage.py 实测）：
  ① invoice\\u202Efdp.exe —— 双向控制符。资源管理器/审批弹窗显示成 `invoiceexe.pdf`，
     修复前只在真被 .exe 落进"二进制披露"时才露面，**名字伪装本身一句不提**
  ② pay\\u200Bload.py —— 零宽字符。与 payload.py 肉眼无差，按后缀分派还会错位 → 修复前 0 命中
  ③ report.pdf.exe —— 双扩展名。Windows 默认隐藏已知扩展名，用户只看到 report.pdf

为什么必须查名字：所有"读文件内容再匹配"的规则都看不见名字。
而审批界面给用户看的正是名字——"点这个 pdf 吧"与"点下去跑的是 exe"之间的差距，
就是这个洞的全部价值。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import skillgate as sg

SKILL_MD = "---\nname: demo\ndescription: demo\n---\n\n# demo\n"


def _mk(tmp_path, name, fname):
    d = tmp_path / name
    d.mkdir()
    (d / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    (d / fname).write_text("print('x')\n", encoding="utf-8")
    return sg.scan_skill(str(d)).findings


def _obf(findings):
    return [f for f in findings if f.category == "obfuscation"]


def test_bidi_in_filename_is_high(tmp_path):
    f = _obf(_mk(tmp_path, "rlo", "invoice\u202Efdp.exe"))
    assert f and f[0].severity == "HIGH", "双向控制符文件名未报 HIGH"


def test_zero_width_in_filename_is_reported(tmp_path):
    f = _obf(_mk(tmp_path, "zw", "pay\u200Bload.py"))
    assert f, "零宽字符文件名未报"


def test_double_extension_is_reported(tmp_path):
    f = _obf(_mk(tmp_path, "de", "report.pdf.exe"))
    assert any("双扩展名" in x.message for x in f), "report.pdf.exe 未被识别为双扩展名"


def test_normal_names_are_quiet(tmp_path):
    """反噪：正常 ASCII 名字一个都不能报（否则这条规则会被当噪音关掉）。"""
    d = tmp_path / "clean"
    d.mkdir()
    (d / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    for n in ("run.py", "notes.md", "data.csv", "tool.exe"):
        (d / n).write_text("print('x')\n", encoding="utf-8")
    assert not _obf(sg.scan_skill(str(d)).findings)


def test_chinese_filenames_are_not_flagged(tmp_path):
    """中文文件名不是伪装——只查控制符/零宽，不查"非 ASCII"。"""
    f = _obf(_mk(tmp_path, "cn", "说明文档.md"))
    assert not f, "中文文件名被误报：%s" % [x.message for x in f]
