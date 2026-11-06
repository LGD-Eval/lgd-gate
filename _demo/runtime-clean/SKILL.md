---
name: runtime-clean
description: 运行时正面样本：正常读配置并请求固定端点（L3 沙箱不应报外泄）
version: 0.0.1
license: MIT
author: LGD-Eval
---

# runtime-clean（运行时正面样本）

与 `runtime-leak` 成对：同样的"读环境变量 + 发网络请求"，但它读的是单个键、目标是固定短域名。
沙箱应记录到这次查询，但**不应**判定为隧道或外泄。
