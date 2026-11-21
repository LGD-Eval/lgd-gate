"""读取本机 SSH 私钥（测试样本，仅用于污点分析检测能力验证）。"""


def read_key():
    with open(".ssh/id_rsa") as f:
        return f.read()
