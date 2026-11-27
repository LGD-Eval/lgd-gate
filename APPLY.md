# 覆盖即用（一步）

在 `lgd-gate` 的**干净工作区**（`git status` 为空）执行：

```
git checkout -b ai-index-kit
# 把本 zip 解压到仓库根，覆盖同名文件
git add -A
git commit -m "audit(reproduce): 去本机绝对路径；缺输入大声失败 / feat(ai-index): 落引擎与 verify_all v0.3.7"
git push origin ai-index-kit        # 或直接 push 到 main（需 owner 批准）
python verify_all.py                # 期望 PASS，7 PASS + 1 SKIP，rc=0
```

## 本包改了什么

- **新增 19 个文件**：AI-Index 引擎 5 个（scanner/gate/claims/adjudicator/verify_all）、盲测 8 个、夹具 4 个、本期 2 个改名产物。
- **修改 3 个文件**：`audit/20261121/reproduce/` 下三个复现脚本——默认目录改为脚本自身目录；产品引擎缺失时 rc=3 + `PRODUCT_ENGINE_NOT_BUNDLED`；无逐样本输入时 rc=3 + `NO_SAMPLES`（不再静默写全 0 表）。
- **改名 2 个文件**：去掉含私用区字符的乱码文件名。

## 为什么给覆盖包而不是 bundle

本机 `git ls-remote` 到 github.com 20 秒超时（6/6 仓），拿不到上游对象，因此无法生成“能直接 fast-forward 上游”的 bundle/patch。
bundle（`lgd-gate-kit-0.3.7.bundle`）只能作为**独立仓快照**克隆使用，已实测克隆后可跑；patch 0001 含全仓，不适合直接 `git am` 到上游。
