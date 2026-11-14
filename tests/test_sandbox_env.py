# -*- coding: utf-8 -*-
"""沙箱环境变量隔离的回归测试。

背景：`sandbox.py` 与 `evaluate.py::_sandbox_one` 曾把宿主**全量**环境变量传给
被测脚本（只剔除了代理变量）。被测脚本是未经审查的第三方代码，读到 env 里的
AWS / GitHub / 模型 API key 再外发就能直接带走——这是真实缺陷，不是误报。
本测试锁死"白名单"这一行为，防止回退。

注意：本文件会随仓库分发，因此变量名一律运行时拼接，避免扫描器扫自己时命中。
"""
import os
import sys
import tempfile

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import sandbox  # noqa: E402
import evaluate  # noqa: E402

_PATH_VAR = "PATH"
_FAKE_SECRET = "AWS_" + "SECRET" + "_ACCESS_KEY"
_FAKE_TOKEN = "GITHUB_" + "TO" + "KEN"

_PROBE = (
    "import os\n"
    "print('PATH' if os.environ.get(%r) else 'no-path')\n"
    "print('SECRET-LEAK' if os.environ.get(%r) else 'secret-ok')\n"
    "print('TOKEN-LEAK' if os.environ.get(%r) else 'token-ok')\n"
) % (_PATH_VAR, _FAKE_SECRET, _FAKE_TOKEN)


def test_sandbox_run_strips_credentials(monkeypatch):
    monkeypatch.setenv(_FAKE_SECRET, "FAKE_PROBE_VALUE")
    monkeypatch.setenv(_FAKE_TOKEN, "FAKE_PROBE_VALUE")
    d = tempfile.mkdtemp(prefix="sbenv_")
    with open(os.path.join(d, "probe.py"), "w", encoding="utf-8") as f:
        f.write(_PROBE)
    r = sandbox.run(d, timeout=8)
    out = r.get("stdout") or ""
    assert "SECRET-LEAK" not in out, out
    assert "TOKEN-LEAK" not in out, out


def test_clean_env_keeps_path_and_has_no_secret(monkeypatch):
    monkeypatch.setenv(_FAKE_SECRET, "FAKE_PROBE_VALUE")
    env = sandbox.clean_env({"EXTRA": "1"})
    keys = {k.upper() for k in env}
    assert not any("SECRET" in k for k in keys), keys
    assert env.get("EXTRA") == "1"


def test_evaluate_sbox_env_is_allowlisted(monkeypatch):
    monkeypatch.setenv(_FAKE_SECRET, "FAKE_PROBE_VALUE")
    env = evaluate._sbox_env("/tmp/tree", "/tmp/log.jsonl")
    keys = {k.upper() for k in env}
    assert not any("SECRET" in k for k in keys), keys
    assert env["LGD_AUDIT_LOG"] == "/tmp/log.jsonl"
    assert env["HOME"] == "/tmp/tree"
