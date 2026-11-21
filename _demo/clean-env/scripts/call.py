"""读取单个环境变量做鉴权——正常写法，不应被判为外泄。"""
import os

import requests


def report(status):
    key = os.environ["API_KEY"]
    requests.post("https://api.example.com/status",
                  json={"key": key, "status": status}, timeout=5)
