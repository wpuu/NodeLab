# NL-REVIEW-019 — 手动 Linux 本机验收工作流

日期：2026-09-28。承接审计 018；本轮没有再次下载 Python/Mihomo，没有推送、创建 PR 或触发 GitHub Actions。

## 目的与实现

当前沙箱运行时阻塞尚未解除。新增 `.github/workflows/linux-local-acceptance.yml`，将已经实现的离线双摘要准备入口和三套真实 gate 接入手动 GitHub 托管 Linux runner 路径，而不是增加协议替身或放宽验收前置条件。

工作流约束：

- 只有无输入的 `workflow_dispatch`；无 push、PR、定时任务、节点或凭据参数。
- Ubuntu 24.04、Python 3.12，安装项目测试依赖并检查 openssl 命令。
- `contents: read`，checkout 的 `persist-credentials: false`；没有引用仓库 secrets。
- actions 完整 SHA 固定。本轮通过 `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` 获取 commit 类型对象：checkout v4=`11d5960a326750d5838078e36cf38b85af677262`；setup-python v5=`a26af69be951a213d495a4c3e4e4022e16d87065`；upload-artifact v4=`ea165f8d65b6e75b540449e92b4886f43607fa02`。读取 ref 不等于审计这些 actions 全部源码。
- 仅 HTTPS 下载固定官方 Mihomo v1.19.31 Linux amd64 compatible gzip；连接/下载有时限，准备目录使用 umask 077。调用审计 018 的离线准备器，同时验证压缩包与解压后二进制摘要后才进入验收。
- 分别运行 session（11）、Trojan TCP（4）、VLESS TCP（4）gate；报告生成、精确数量、零 skip、binary pin 和协议范围沿用现有 gate，不在 YAML 中重实现。
- 使用显式 bash（Actions 的 `-e -o pipefail`），不使用 continue-on-error。任一 gate 非零时 job 失败；准备/依赖成功且未取消时，仍尝试其余 gate。
- artifact 只允许四个固定 JSON 文件，保留 7 天；不上传原始日志、配置、证书、二进制、pytest XML 或运行目录。
- 同分支不自动取消正在运行的任务；20 分钟 runner 超时/人工取消仍可能中断清理，不属于清理通过证据。托管 runner 销毁不替代应用级进程所有权与回收验收。

更新 `docs/Linux-local-acceptance.md`：说明新 workflow 通常须先进入默认分支注册手动入口，才能针对已推送的会话分支使用 `--ref`。本轮没有改变当前分支或执行发布操作。

## 验证

新增 `tests/test_linux_acceptance_workflow.py` 七项静态测试，覆盖触发方式、权限、SHA pin、下载/验证入口、三套 gate 的失败传播与 artifact 白名单。对所有 run 脚本执行 `bash -n` 均通过。这些仅证明本地配置约束和 shell 语法，不证明 GitHub 表达式调度、托管 runner 环境或真实 Mihomo 运行成功。

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
637 passed, 37 skipped in 29.90s

git diff --check
通过
```

## 未完成与边界

没有 workflow run ID、远端 PASS、真实 Mihomo 握手或 controller 路由证明。37 项 skip 未减少，本机 Python 3.11.2 和缺少固定二进制的限制未解决。远端是否能下载官方资源必须由后续实际运行确认；完整依赖未锁定，不能声称可重复构建。

下一步为审阅并发布/注册工作流，在获准的目标 revision 上执行，检查三份完整 gate JSON 和实际 job 结论。若失败，应排查真实错误，而非放宽 pin、版本或 skip 门禁。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`。即使工作流未来通过，也只是本机 fixture 范围，不能自动授权外部节点、扩展传输或 Windows 验收；无 P0 CLOSED 结论。
