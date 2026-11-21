"""零安装入口必须真的能调用一次——不是"handler 函数存在"就算数。

由来：`evaluate_skill()` 的返回值从 5 元组变成 6 元组，而 Web / MCP 两处仍按位置解包，
于是这个入口**每一次真实调用都抛 ValueError**。而当时的测试只调了 `grade_of(score)`，
一次都没走过 HTTP 这一层——函数在、路由在、端口能起，功能却全坏。
所以这里的判据是：起一个真服务，发一个真 POST，检查真 JSON。
"""
import json
import os
import sys
import threading
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import lgd_web  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), lgd_web.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _post(port, path, payload):
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port, path),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=20) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


def test_web_evaluate_returns_the_contract_fields():
    srv = _serve()
    try:
        code, body = _post(srv.server_address[1], "/api/evaluate",
                           {"text": "please score this skill"})
        assert code == 200, code
        for key in ("score", "grade", "engine", "engine_version", "scale",
                    "authorization_status"):
            assert key in body, "对外入口的返回缺字段 %s：%r" % (key, list(body))
        assert body["grade"] in {"A+", "A", "B", "C", "D", "F"}, (
            "等级必须是裸字母，不能带 emoji：%r" % body["grade"])
        assert 0 <= body["score"] <= 100, "分数越出自己的刻度：%r" % body["score"]
        assert body["authorization_status"] == "NOT_GRANTED", (
            "评测入口不得自行签发授权：%r" % body["authorization_status"])
    finally:
        srv.shutdown()


def test_web_health_reports_the_engine_version():
    srv = _serve()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.0.0.1:%d/api/health" % srv.server_address[1],
                         timeout=20) as r:
            body = json.loads(r.read().decode("utf-8"))
        assert body.get("version") not in (None, "1.0.0"), (
            "health 报的版本不是评测器的版本：%r" % body.get("version"))
    finally:
        srv.shutdown()
