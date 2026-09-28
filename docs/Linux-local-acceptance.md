# Linux 本机真实引擎验收准备

范围：Linux amd64、本机 fixture，不使用外部节点或真实凭据。文件准备成功不等于运行时、协议或路由验收通过，任何步骤都不开放真实节点门禁。

## 1. 准备官方 Mihomo 压缩包

固定资源：

- 仓库：MetaCubeX/mihomo
- 标签：`v1.19.31`
- 文件：`mihomo-linux-amd64-compatible-v1.19.31.gz`
- 官方 URL：<https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/mihomo-linux-amd64-compatible-v1.19.31.gz>
- GitHub release asset ID：`563462721`
- 压缩包 SHA-256：`04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc`
- 解压后二进制 SHA-256：`b341a765412c192685264e038a6aad2ac1c67c12b8aceeb5c6f64955cf43f5ed`

若当前环境无法下载，可在能连接官方 URL 的环境下载后传入工作区。不要关闭 TLS 校验、使用未知镜像、改 pin 或把 API JSON 元数据当作压缩包。上述摘要是字节/来源固定值，不是上游签名；压缩包摘要与可执行文件摘要不可混用。

从仓库根目录执行，替换压缩包的绝对路径：

```sh
mkdir -p tools/mihomo
python3 scripts/prepare_mihomo_linux.py \
  --archive /absolute/path/to/mihomo-linux-amd64-compatible-v1.19.31.gz \
  --destination "$PWD/tools/mihomo/mihomo"
```

准备脚本可在本项目目前的 Python 3.11 环境运行，不依赖第三方包；它不下载、不运行二进制、不查找 PATH、不接受自定义 pin、不覆盖已有目的文件。父目录必须已存在、不经过符号链接且不能被组或其他用户写入；输入文件必须是普通文件。

脚本先将输入复制为有大小限制的私有快照并校验压缩包摘要，再从该快照有限解压、校验二进制摘要，以权限 `0700` 和不覆盖的 hard link 发布。成功 JSON 为 `PREPARED / PINNED_BYTES_PREPARED`，`binary_executed=false`，`runtime_acceptance=NOT_RUN`。

错误时退出码为 2，并只输出固定错误码，不回显路径。`DESTINATION_EXISTS` 时保留原文件，不要自动删除它；先确认所有权及内容。`CANCELLED_REVIEW_DESTINATION` 或进程被杀后须检查目的文件和暂存目录：可能已经发布已校验文件。脚本不是崩溃恢复或敌对并发文件系统的安全边界，不保证断电持久性；父路径不得被其他进程并发替换。

## 2. 准备受支持 Python 和测试依赖

验收仍要求 **Python 3.12+**。准备脚本能在 3.11 运行不放宽这个要求。使用可信来源的现有 Python 3.12+ 创建隔离环境，例如：

```sh
python3.12 -m venv tools/runtime/acceptance
tools/runtime/acceptance/bin/python -m pip install -e . pytest
```

本机协议测试还需要 `openssl` 命令生成临时测试证书。这里不提供未知来源 Python 安装器，也不修改主机信任库。`tools/` 已被 Git 忽略，不提交运行时、压缩包、二进制或环境依赖。

## 3. 逐套执行 gate

```sh
tools/runtime/acceptance/bin/python scripts/f2_session_gate.py \
  --suite session --exe "$PWD/tools/mihomo/mihomo"
tools/runtime/acceptance/bin/python scripts/f2_session_gate.py \
  --suite trojan-tcp --exe "$PWD/tools/mihomo/mihomo"
tools/runtime/acceptance/bin/python scripts/f2_session_gate.py \
  --suite vless-tcp --exe "$PWD/tools/mihomo/mihomo"
```

- `session`：精确 11 个用例通过且零 skip；合成会话范围，不是实际代理协议证明。
- `trojan-tcp`：精确 4 个用例通过且零 skip；实际本机 Trojan/TLS/TCP。
- `vless-tcp`：精确 4 个用例通过且零 skip；实际本机 VLESS v0/零 addons/TLS/TCP。
- 所有 gate 都要求固定二进制校验；不会接受环境变量提供的自定义摘要作为验收替代。
- 即使协议 gate 通过，范围也仅为 `LOCAL_FIXTURE_ONLY`；不覆盖外部节点、Vision/WS/gRPC/Reality、Windows 或普通短请求的采样可靠性。

当前执行状态见审计 018：尚无可用官方二进制或受支持 Python；三套 gate 均被 Python 版本前置条件阻塞，真实互操作未执行。

## 4. 可选：手动 GitHub Actions 验收

`.github/workflows/linux-local-acceptance.yml` 提供另一条运行路径，避免依赖当前沙箱的下载网络：

- 仅 `workflow_dispatch`，没有 push/PR/schedule 触发，也没有节点、凭据或下载 URL 输入。
- GitHub 托管 Ubuntu 24.04 runner，Python 3.12；官方 actions 固定到完整 commit SHA，仓库权限只读，checkout 不持久化 token。
- 下载固定官方资源，调用同一个双摘要离线准备脚本，再分别执行 session、Trojan TCP、VLESS TCP gate。
- 任一 gate 的非零退出码都会使 job 失败；使用 bash pipefail，不让 `tee` 隐藏失败。准备成功后，即使前一套 gate 失败，也继续运行其余独立 gate。
- 仅上传 `preparation.json`、`session.json`、`trojan-tcp.json`、`vless-tcp.json`，保留 7 天；不上传原始 pytest/引擎日志、配置、证书、二进制、Junit XML 或运行目录。
- 固定 20 分钟 job 上限。取消/超时不是通过或清理完成证据，不能替代进程回收验收；不自动取消同分支正在运行的任务。
- 项目/pytest 依赖按当前项目约束安装，尚非全依赖锁定的可重复构建。网络下载、托管 runner 和 actions 自身也可能失败，workflow 配置存在不保证执行成功。

**本轮没有推送或触发远端工作流。** 新增的 `workflow_dispatch` 工作流通常需要先出现在仓库默认分支，GitHub 才会注册手动触发入口；指定 `--ref` 不会绕过这一条件。待工作流注册、目标分支已推送且获准执行后，可使用：

```sh
gh workflow run linux-local-acceptance.yml --ref arena/01a0e60c-nodelab
gh run list --workflow linux-local-acceptance.yml --branch arena/01a0e60c-nodelab
# 使用实际返回的 run ID：
# gh run view RUN_ID
# gh run download RUN_ID --dir tools/acceptance-results
```

检查具体 run 的 commit、结论和所有三个 gate 的 JSON，不以 artifact 存在或 preparation 成功替代验收。即使全部通过，也仍仅限本机 fixture 范围，`real_node_test_allowed` 必须为 false。静态 YAML/测试检查不属于 GitHub runner 执行证据。
