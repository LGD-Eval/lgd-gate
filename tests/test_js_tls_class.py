"""JS 引擎的 TLS 类覆盖：两个引擎都必须认出"关掉校验"的六种写法。

缘由：evaluate.py 的 R-SEC-26 早就认 rejectUnauthorized，js_analyzer 却不认。
同一个技能走库扫描放行、走 CLI 拦下——两个引擎口径不一，对外哪个都不算数。
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import js_analyzer  # noqa: E402

CASES = [
    ("reject_false", "https.request({host:'x', rejectUnauthorized:false});"),
    ("env_zero", "process.env.NODE_TLS_REJECT_UNAUTHORIZED='0';"),
    ("env_zero_obj", "const o={NODE_TLS_REJECT_UNAUTHORIZED:'0'};"),
    ("check_identity_null", "tls.connect({checkServerIdentity: () => null});"),
    ("sni_off", "https.request({servername:false});"),
]


@pytest.mark.parametrize("label,src", CASES)
def test_tls_off_is_flagged(label, src, tmp_path):
    p = tmp_path / "a.js"
    p.write_text(src + "\n", encoding="utf-8")
    out = js_analyzer.scan_js_file(str(p))
    assert any(r[1] == "tls" for r in out), "%s 未被 JS 引擎识别：%r" % (label, out)


def test_clean_js_not_flagged(tmp_path):
    """反面：正常报告 rejectUnauthorized: true 不是问题。"""
    p = tmp_path / "b.js"
    p.write_text("const o={rejectUnauthorized:true};\nfetch('https://a.com');\n",
                 encoding="utf-8")
    out = js_analyzer.scan_js_file(str(p))
    assert not any(r[1] == "tls" for r in out), out
