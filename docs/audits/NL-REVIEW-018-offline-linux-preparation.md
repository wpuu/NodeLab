# NL-REVIEW-018 — Linux 离线准备入口与真实验收阻塞复核

日期：2026-09-28。承接审计 017，优先检查真实引擎验收环境，没有扩展协议 fixture 或放宽 gate。

## 实际环境检查

- 当前 `.venv` 为 Python 3.11.2；没有找到可用的 Python 3.12/3.13、uv 或 Go。
- 官方 GitHub API 能返回 Mihomo asset `563462721` 和 python-build-standalone asset `294829449` 的元数据；本轮未将元数据当作二进制。
- python.org 的 Python 3.12.11 tarball HEAD 请求发生 `SSL_ERROR_SYSCALL`。
- 官方 Mihomo gzip URL 的实际下载在 `release-assets.githubusercontent.com` 发生 `SSL_ERROR_SYSCALL`。
- 对官方 python-build-standalone asset 的 octet-stream API 请求重定向后发生 EOF。没有取得可用 Python 或 Mihomo 文件。
- 没有关闭 TLS 校验、使用未知镜像、修改主机信任库或伪造版本条件。

与上一轮相比：本轮实际重查了上述渠道，但运行时阻塞没有解除。元数据中的 archive digest 不是新验证的 executable digest。

## 新增离线准备能力

`scripts/prepare_mihomo_linux.py` 接收明确的本机压缩包路径和目的文件路径，不负责下载，不执行任何二进制，不查找 PATH。它在现有 Python 3.11 环境即可运行，验收对 Python 3.12+ 的要求不变。

- 仅 Linux amd64，固定 `v1.19.31` compatible gzip 资源。
- 固定压缩包 SHA-256 `04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc`，来自本轮官方 release asset 元数据。
- 固定二进制 SHA-256 `b341a765412c192685264e038a6aad2ac1c67c12b8aceeb5c6f64955cf43f5ed`，沿用现有 `engine_binary.KNOWN_DIGESTS`；本轮未取得真文件重新验证它。
- 只读取普通文件；最终输入组件用 `O_NOFOLLOW | O_NONBLOCK` 打开，拒绝链接路径，避免 FIFO 阻塞。
- 私有暂存目录内形成最大 64 MiB 的压缩包快照；校验快照后从相同快照解压，避免校验后重新打开输入路径。
- 解压最大 128 MiB，再校验二进制摘要，权限设为 `0700`。
- 用同文件系统 hard link 以不覆盖方式发布；目的文件预先存在或发布时出现都拒绝，不删除旧文件。
- 不接收任意摘要覆盖参数；固定 JSON 不打印路径、内容或异常原文。
- 成功只报告 `PREPARED / PINNED_BYTES_PREPARED`；`binary_executed=false`、`runtime_acceptance=NOT_RUN`、`route_proof=NOT_RUN`、`real_node_test_allowed=false`。

这些是来源/字节固定值，不是上游签名。父路径不被并发替换是前提；这不是敌对文件系统或断电恢复边界。中断可能发生在已发布之后，`CANCELLED_REVIEW_DESTINATION` 要求人工检查目的文件，不自动删除。未承诺跨崩溃回滚或目录 fsync 持久性。

## 测试与实际命令

新增 `tests/test_prepare_mihomo_linux.py` **27 项通过**，以合成 payload 和测试期 monkeypatch pin 检查安装机制，不是真实官方资源证据。覆盖双摘要、压缩包/解压大小及边界、坏包与截断、输入变更后继续使用已校验快照、权限、FIFO、链接、相对路径、缺失父目录、可写父目录、已有目的文件、发布竞争、fsync 失败、架构限制、参数脱敏，以及发布前后中断。

实际对缺失下载文件调用准备脚本：`BLOCKED / PREPARATION_IO_FAILED`，退出码 2；未产生可执行文件。

实际运行三套 gate：

| suite | gate | status/code | exit |
| --- | --- | --- | --- |
| session | F2_LINUX_SESSION | BLOCKED / PYTHON_VERSION_UNSUPPORTED | 2 |
| trojan-tcp | F3_LINUX_TROJAN_TCP | BLOCKED / PYTHON_VERSION_UNSUPPORTED | 2 |
| vless-tcp | F3_LINUX_VLESS_TCP | BLOCKED / PYTHON_VERSION_UNSUPPORTED | 2 |

各项均 `passed=0`、`skipped=0`、`route_proof=NOT_RUN`。这些是前置条件阻塞，并非运行测试后失败或通过；也不代表后续前置条件满足。

全量回归：

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
630 passed, 37 skipped in 30.44s

git diff --check
通过
```

## 操作交接与未完成事项

新增 `docs/Linux-local-acceptance.md`，记录固定资源、双摘要、离线准备、隔离 Python 环境以及三套 gate 的实际命令和证据范围。压缩包/二进制/运行时仍放在被忽略的 `tools/`，不加入 Git。

仍需从官方渠道取得可校验 Mihomo 和受支持 Python，再运行真实本机验收。没有真实 Mihomo 握手、TLS CA 加载或 controller 路由证明的新增通过结果；37 项 skip 未减少。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；没有外部节点探测、生产集成、Windows 验收或 P0 CLOSED 结论。
