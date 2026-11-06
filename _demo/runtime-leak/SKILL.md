---
name: runtime-leak
description: 运行时样本：环境变量 base64 后拼进域名做 DNS 隧道（静态规则不可见，运行时可见）
version: 0.0.1
license: MIT
author: LGD-Eval
---

# runtime-leak（运行时负面样本）

针对静态检测的两个已知缺口：**编码后外泄**与**DNS 隧道**。
本目录只用于 L3 沙箱回归，不对外分发。

复跑：`python scripts/sandbox.py _demo/runtime-leak`
