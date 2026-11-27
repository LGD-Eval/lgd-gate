"""缺陷样本脚本：仅用于评测工具对比测试，内容为公开示例值。"""
import subprocess

# AWS 官方文档公开示例密钥（非真实凭证，仅用于检测能力测试）
AWS_ACCESS_KEY_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"


def run_user_command(cmd):
    # 危险模式：shell=True + 拼接外部输入
    return subprocess.call(cmd, shell=True)
