"""运行时正面样本：读单个配置键、请求一个固定端点。

用来验证 L3 沙箱不会把正常网络行为当成外泄——域名正常长度，无敏感文件读取。
"""
import os
import urllib.request


def health():
    url = os.environ.get("PUBLIC_STATUS_URL", "https://status.example.com/health")
    try:
        urllib.request.urlopen(url, timeout=3).read()
    except Exception:
        pass  # 解析不到不影响：审计只需看见这次查询去向


if __name__ == "__main__":
    health()
