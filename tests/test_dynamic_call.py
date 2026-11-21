# -*- coding: utf-8 -*-
"""名字拆开还算不算危险调用（§3av 守卫）。

修复前实测（audit2/probe_dynamic_call.py）：
  getattr(os, "sys" + "tem")("id")                 → 100/A+，一条不报
  subprocess.__dict__["run"]("id", shell=True)     → 100/A+（连 shell=True 都没看见）
  __import__("o" + "s").system("id")               → 只有 MEDIUM 96/A
对照组：同一件事写成 os.system("id") 是 CRITICAL 49/D。
被拦的是写法，不是行为——这就是"例通过、类没通过"。
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import skillgate as sg  # noqa: E402

SKILL_MD = "---\nname: demo\ndescription: dynamic call guard skill\n---\n\n# demo\n"


def _scan(tmp_path, body, name="dyn"):
    d = tmp_path / name
    (d / "scripts").mkdir(parents=True)
    (d / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    (d / "scripts" / "run.py").write_text(body, encoding="utf-8")
    return sg.scan_skill(str(d))


def test_literal_baseline_is_critical(tmp_path):
    """基线：字面写法必须是 CRITICAL，否则下面几条没有参照。"""
    r = _scan(tmp_path, 'import os\nos.system("id")\n')
    assert r.trust_score <= 49


def test_getattr_with_concatenated_name_is_flagged(tmp_path):
    r = _scan(tmp_path, 'import os\ngetattr(os, "sys" + "tem")("id")\n')
    assert any(f.severity in ("HIGH", "CRITICAL") for f in r.findings), \
        "getattr 拼名字取到 os.system 未报"
    assert r.trust_score <= 69, "绕开字面规则后仍能拿 A 以上"


def test_dunder_import_dangerous_module_is_flagged(tmp_path):
    r = _scan(tmp_path, 'm = __import__("o" + "s")\nm.system("id")\n')
    assert any(f.severity == "HIGH" for f in r.findings), "__import__ 拼模块名未升级"


def test_dict_subscript_dangerous_attr_is_flagged(tmp_path):
    r = _scan(tmp_path, 'import subprocess\nsubprocess.__dict__["run"]("id", shell=True)\n')
    assert any("__dict__" in f.message for f in r.findings), "__dict__ 下标取用未报"


def test_globals_subscript_dangerous_attr_is_flagged(tmp_path):
    r = _scan(tmp_path, 'globals()["eval"]("1+1")\n')
    assert any("globals" in f.message for f in r.findings), "globals() 下标取用未报"


# ---------- 反例：正常动态取用必须干净 ----------
def test_normal_getattr_is_clean(tmp_path):
    r = _scan(tmp_path, (
        'class C:\n    name = "x"\n'
        'c = C()\nprint(getattr(c, "name", None))\n'
        'print(getattr(c, "missing", "default"))\n'
        'obj = object()\nprint(getattr(obj, "timeout", 30))\n'))
    assert r.trust_score == 100, "正常 getattr 被误报: %r" % [
        (f.severity, f.message[:40]) for f in r.findings]


def test_normal_dict_and_import_are_clean(tmp_path):
    r = _scan(tmp_path, (
        'import json\n'
        'd = {"items": 1}\n'
        'print(d.__dict__) if hasattr(d, "__dict__") else None\n'
        'print(vars(d))\n'
        'mod = __import__("json")\n'))
    assert not [f for f in r.findings if f.severity in ("CRITICAL", "HIGH")], \
        "正常 __dict__/__import__ 被误报: %r" % [
            (f.severity, f.message[:40]) for f in r.findings]
