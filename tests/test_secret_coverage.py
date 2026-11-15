"""凭证类覆盖：密钥不该只在代码文件里才被看见。

由来（audit2/probe_secrets_coverage.py 实测）：同一批形如真实的假密钥
  · 写进 creds.py / creds.js → CRITICAL（早就是）
  · 写进 .env / settings.ini / config.toml / creds.txt / config.json → 修复前 0 命中
而现实里泄漏最常发生的位置正是配置文件。

反向要求同样重要：占位值（YOUR_KEY_HERE / ${TOKEN} / changeme）不能报，
否则每个模板都会被判红，误报会把这个能力废掉。
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import skillgate as sg

SKILL_MD = "---\nname: demo\ndescription: demo\n---\n\n# demo\n"

AWS = "AKIA" + "Q7XZ3LMNOPQRSTUV"
GH = "ghp_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
SK = "sk-proj-" + "Zx9Yw8Vu7Ts6Rq5Po4Nn3Mm2Ll1Kk0Jj"

BODIES = {
    ".env": "AWS_ACCESS_KEY_ID=%s\nGITHUB_TOKEN=%s\nOPENAI_API_KEY=%s\n" % (AWS, GH, SK),
    "settings.ini": "[auth]\naws_key = %s\ntoken = %s\n" % (AWS, GH),
    "config.toml": 'aws = "%s"\ntoken = "%s"\n' % (AWS, GH),
    "creds.txt": "aws_key: %s\ngithub: %s\n" % (AWS, GH),
    "config.json": json.dumps({"aws_key": AWS, "github_token": GH}),
}


def _scan(tmp_path, fname, body, extra=None):
    d = tmp_path / ("case_" + fname.replace(".", "_"))
    d.mkdir()
    (d / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    (d / fname).write_text(body, encoding="utf-8")
    for fn, b in (extra or {}).items():
        (d / fn).write_text(b, encoding="utf-8")
    return sg.scan_skill(str(d)).findings


def test_secret_in_config_formats_is_critical(tmp_path):
    for fname, body in BODIES.items():
        f = _scan(tmp_path, fname, body)
        assert any(x.severity == "CRITICAL" and x.category == "credential" for x in f), \
            "%s 里的硬编码密钥没被报出来" % fname


def test_placeholder_values_are_not_reported(tmp_path):
    tpl = ("AWS_ACCESS_KEY_ID=YOUR_KEY_HERE\n"
           "GITHUB_TOKEN=${GITHUB_TOKEN}\n"
           "OPENAI_API_KEY=sk-xxxx\n"
           "password=changeme\n")
    f = _scan(tmp_path, ".env", tpl)
    assert not any(x.category == "credential" for x in f), \
        "占位值被误报：" + str([x.message for x in f])


def test_no_duplicate_findings_for_same_file(tmp_path):
    """一条 glob 之外还有别的 glob 命中同一文件时，不能重复报同样的东西。"""
    f = [x for x in _scan(tmp_path, ".env", BODIES[".env"]) if x.category == "credential"]
    assert len(f) == 3, "同一文件重复报了 %d 条凭证" % len(f)


def test_code_files_still_reported(tmp_path):
    """回归：原来就抓得住的代码文件，不能因为改了配置扫描而丢。"""
    f = _scan(tmp_path, "creds.py", 'AWS_ACCESS_KEY = "%s"\n' % AWS)
    assert any(x.severity == "CRITICAL" for x in f)
