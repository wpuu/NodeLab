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
tools/runtime/acceptance/bin/python scripts/f2_session_gate.py \
  --suite full --exe "$PWD/tools/mihomo/mihomo"
```

- `session`：精确 11 个用例通过且零 skip；合成会话范围，不是实际代理协议证明。
- `trojan-tcp`：精确 4 个用例通过且零 skip；实际本机 Trojan/TLS/TCP。
- `vless-tcp`：精确 4 个用例通过且零 skip；实际本机 VLESS v0/零 addons/TLS/TCP。
- `full`：当前精确 737 个 testcase，要求 734 passed，只允许三个指定 Windows 测试以 pytest.skip 跳过；不是任意三个 skip。失败诊断仅发布源码白名单中的测试函数标识，不包含参数或异常文本。增减测试时须审阅并更新 `FULL_EXPECTED_CASES`。
- 所有 gate 都要求固定二进制校验；不会接受环境变量提供的自定义摘要作为验收替代。
- 即使协议 gate 通过，范围也仅为 `LOCAL_FIXTURE_ONLY`；不覆盖外部节点、Vision/WS/gRPC/Reality、Windows 或普通短请求的采样可靠性。

最新远端执行状态见审计 025：完整 Linux 回归为 734 passed、3 个指定 Windows skip；三套独立 gate 为 11/4/4 个通过且零 skip。当前沙箱本身仍缺少受支持 Python 和可用官方二进制；不要混淆本地与远端结果。

## 4. 可选：显式启用 GitHub Actions 验收

`.github/workflows/linux-local-acceptance.yml` 提供另一条运行路径，避免依赖当前沙箱的下载网络：

- 提供 `workflow_dispatch`，以及标签启用的 `pull_request` 入口。PR 必须来自同仓库、目标为 main、带有 `run-local-acceptance` 标签；只响应 labeled/synchronize/reopened。没有 push/schedule 或 `pull_request_target`，也没有节点、凭据或下载 URL 输入。
- 标签代表允许在该 PR 的后续提交上持续运行本机验收；移除标签后，后续事件不再运行此 job。移除标签不会取消已经启动的任务。Fork PR 即使带标签也不会运行此 job。
- GitHub 托管 Ubuntu 24.04 runner，Python 3.12；官方 actions 固定到完整 commit SHA，仓库权限只读，checkout 不持久化 token。
- 下载固定官方资源，调用同一个双摘要离线准备脚本，再分别执行 session、Trojan TCP、VLESS TCP 与 full gate。
- 任一 gate 的非零退出码都会使 job 失败；使用 bash pipefail，不让 `tee` 隐藏失败。准备成功后，即使前一套 gate 失败，也继续运行其余独立 gate。
- 仅上传 `preparation.json`、`session.json`、`trojan-tcp.json`、`vless-tcp.json`、`full.json`，保留 7 天；不上传原始 pytest/引擎日志、配置、证书、二进制、Junit XML 或运行目录。
- 固定 20 分钟 job 上限。取消/超时不是通过或清理完成证据，不能替代进程回收验收；不自动取消同分支正在运行的任务。
- 项目/pytest 依赖按当前项目约束安装，尚非全依赖锁定的可重复构建。网络下载、托管 runner 和 actions 自身也可能失败，workflow 配置存在不保证执行成功。

草稿 PR 为 [#2](https://github.com/wpuu/NodeLab/pull/2)，会话分支为 `arena/01a0e60c-nodelab`。新增的 `workflow_dispatch` 工作流通常需要先出现在默认分支，GitHub 才会注册手动触发入口；指定 `--ref` 不会绕过这一条件。

为避免仅为注册入口而合并未验收代码，可由维护者给同仓库 PR 添加 `run-local-acceptance` 标签，使用 PR merge revision 上的工作流直接运行，不必先修改 main。此入口会执行 PR 代码，因此只应对可信、已获准运行的同仓库分支启用；job 条件不是抵御能修改工作流代码的恶意仓库写入者的安全边界。它不使用特权的 `pull_request_target`。

```sh
gh pr edit 2 --add-label run-local-acceptance
gh run list --branch arena/01a0e60c-nodelab
```

实际 run 的 commit 与 PR head/merge revision 都需要核对；标签、草稿状态和绿色的 skipped job 均不是验收证据。手动入口在默认分支注册后，也可使用：

```sh
gh workflow run linux-local-acceptance.yml --ref arena/01a0e60c-nodelab
gh run list --workflow linux-local-acceptance.yml --branch arena/01a0e60c-nodelab
# 使用实际返回的 run ID：
# gh run view RUN_ID
# gh run download RUN_ID --dir tools/acceptance-results
```

检查具体 run 的 commit、结论和所有三个 gate 的 JSON，不以 artifact 存在或 preparation 成功替代验收。即使全部通过，也仍仅限本机 fixture 范围，`real_node_test_allowed` 必须为 false。静态 YAML/测试检查不属于 GitHub runner 执行证据。

### 历史远端运行：基础设施阻塞（已被后续成功运行取代）

PR #2 的标签入口已经实际触发：[run 36399985871](https://github.com/wpuu/NodeLab/actions/runs/36399985871)，head `5f7f80871273592a8f92b934f42bf68ad94be587`。GitHub 因账户付款失败或支出额度限制阻止 job 启动；`steps=[]`、artifact 数量为 0。没有执行任何 gate，此 failure 不是测试失败，也不是验收通过。

已暂时移除 `run-local-acceptance` 标签。账户维护者需先检查 GitHub 的 Billing & plans / Actions 支付与额度，之后再添加标签以验证最新 revision；不要通过修改 gate 或反复 rerun 绕过基础设施阻塞。详见审计 020。无需提供任何账单信息或凭据给本工具。

### 最新远端运行：三套 gate 通过

用户将仓库公开后，run 36402330033 和 [run 36402531966](https://github.com/wpuu/NodeLab/actions/runs/36402531966) 均成功。后者 head 为 `a10c1dbe661bca8f2408fedfbdf54540e09c97fa`，已通过 check annotations API 核对：session 11 passed、Trojan TCP 4 passed、VLESS TCP 4 passed，全部零 skip。双摘要官方 Mihomo 准备成功，真实协议 gate 范围仅 `LOCAL_FIXTURE_ONLY`，真实节点使用/授权仍为 false。

当前沙箱无法下载 Actions blob 附件，因此工作流新增同一份固定字段 JSON 的 check notices；可通过 `gh api repos/wpuu/NodeLab/check-runs/108863525420/annotations` 读取。不会发布原始引擎日志或测试凭据。审计 021 记录证据和限制。

本轮已移除 opt-in 标签，避免文档更新重复触发；后续代码验收仍可重新添加。无需为此次本机验收调整支出预算。公共仓库运行成功不等于账户账单状态全面正常，也不等于所有平台或生产探测通过。

### 最新补充：受支持 Python 上的全量回归

[run 36403873841](https://github.com/wpuu/NodeLab/actions/runs/36403873841)，head `1325490ce9ae1212b6b7bb8647a575d837af89c4`：`LINUX_FULL_REGRESSION / PASS / FULL_REGRESSION_OK`，**685 passed、3 skipped**。三个 skip 身份已由 gate 严格核对为 Windows 专属测试。session/Trojan/VLESS 也再次通过。结果通过 check `108868158025` 的 annotations API 读回核实。

具体证据、统计边界和限制见审计 022。full 覆盖已有独立 gate 的用例，不把重复执行计为更多独立用例。opt-in 标签已在完成验收后移除；后续代码变更仍需重新验收。

### Controller 严格解析后的复验

审计 023 修复重复 JSON 键静默覆盖与非有限数值被接受的问题。新增 19 项后，全量预期总数为 707。

[run 36405427124](https://github.com/wpuu/NodeLab/actions/runs/36405427124)，head `c5b6fce3c6fa478e30c39a806137ab958aa4aaf9`：完整回归 **704 passed、3 个指定 Windows skip**，三套独立 gate 分别 11/4/4 通过且零 skip。通过 check `108872893313` 的 annotations API 核实；本轮未增加外部探测或修改授权门禁。

### 启动期逐请求所有权复核后的验收

审计 024 为启动器每次 controller HTTP 增加前后存活/端口归属检查，避免持续复用初始 readiness 结果；不是原子 socket 身份证明。新增 18 项负控后，full 总数为 725。

[run 36408708687](https://github.com/wpuu/NodeLab/actions/runs/36408708687)，head `d952a565a0b90d273d8d6ef1045bec65037081a8`：完整回归 **722 passed、3 个指定 Windows skip**，三套独立 gate 分别 11/4/4 通过且零 skip。check `108883489374` 的固定 annotations 已读回核对。共享 deadline、单所有者清理和生产门禁保持不变。

### 清理异常边界加固后的验收

审计 025 使停止子进程中的意外异常/取消不再跳过私有 YAML 删除尝试；清理未知统一固定失败，不误报 closed，不暴露先前异常文本。删除本身失败仍可能留下明文，这不是断电/强制终止恢复保证。

[run 36410716164](https://github.com/wpuu/NodeLab/actions/runs/36410716164)，head `d044cccdeb5cd303a9fa42a4f8bf92b9faac6648`：完整回归 **734 passed、3 个指定 Windows skip**，三套独立 gate 分别 11/4/4 通过且零 skip；check `108889982043` 的固定 annotations 已核对。新增 12 项后 full 总数为 737，生产授权门禁不变。
