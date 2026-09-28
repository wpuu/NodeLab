# NL-REVIEW-021 — 公开仓库后的真实 Linux 本机验收通过

日期：2026-09-28。用户自行将仓库公开后，GitHub API 确认 `wpuu/NodeLab` 为 public。本轮没有修改仓库可见性、付费设置或 main；PR #2 仍为草稿。

## 真实执行结果

重新添加 `run-local-acceptance` 标签后，run [36402330033](https://github.com/wpuu/NodeLab/actions/runs/36402330033) 成功（head `385d07c5c62ae4c8cfdba75a1d88b0daa257bd5f`）。官方下载、双摘要准备和三套 gate 步骤都执行成功，job 53 秒。之前的 runner billing 阻塞本次没有复现；这不证明账户账单状态已全面修复。

当前沙箱下载该 run 的 artifact 和日志分别在 Azure blob / results-receiver 连接处 EOF，无法读回附件正文。没有将下载失败当作测试失败，也没有仅凭附件元数据推断具体通过数量。

提交 `a10c1dbe661bca8f2408fedfbdf54540e09c97fa` 增加固定 JSON check notices：仅发布 preparation/session/trojan-tcp/vless-tcp 四个既有报告，不发布原始日志、配置或凭据。增加一项静态测试。随后 PR synchronize 触发第二次运行：

- run：[36402531966](https://github.com/wpuu/NodeLab/actions/runs/36402531966)
- head SHA：`a10c1dbe661bca8f2408fedfbdf54540e09c97fa`
- event：`pull_request`（workflow 默认 checkout PR merge revision；head SHA 指事件的 PR head）
- job/check ID：`108863525420`
- job：success，54 秒
- Ubuntu 24.04、setup-python 3.12、固定 Mihomo v1.19.31 官方 Linux amd64 compatible 资源

本轮通过 GitHub check annotations API 读回并程序化核对 head SHA、run conclusion 和精确报告字段，结果如下：

| gate | status / code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| F2_LINUX_SESSION | PASS / SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | PASS / LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | PASS / LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

全部 `real_node_used=false`、`real_node_test_allowed=false`、`windows_acceptance=NOT_RUN`。准备报告为 `PREPARED / PINNED_BYTES_PREPARED`；准备器本身不执行 binary，后续 gate 才执行固定摘要/版本校验和真实引擎实验。

## 证据范围变化

首次获得三套真实 gate 的通过结果，不再仅是 Python fixture 或静态 CI 配置证据：

- 固定版 Mihomo 在受支持的远端 Python 环境中运行了 11 个会话实验。
- Trojan 与基本 VLESS 各执行成功握手、错误凭据、错误 SNI、不可信 CA 四项实验。
- 正向用例验证本机协议转发、两个本机 HTTPS 来源、未经改写的已认证 controller 观测、NODE→PROBE 链、私有候选判断与清理。
- 负向用例要求协议/TLS fixture 确实拒绝，没有转发或候选结果，不能仅由启动失败让负控通过。

这不是外部节点或普通短请求采样可靠性的证明；来源正文仍被保持至观测完成。它不覆盖 Vision/flow、WS/gRPC/Reality 的真实握手，不覆盖 Windows、崩溃恢复或硬实时 deadline。不能据此宣称 P0 全部关闭。

## 本地回归与限制

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
638 passed, 37 skipped in 30.23s
```

这是当前沙箱 Python 3.11.2 的独立本地结果。远端 19 个真实 gate 用例通过，不应直接与本地统计相加，也不代表远端执行了完整回归。当前沙箱的 Python/下载限制与 37 项本地 skip 仍存在。

远端还提示固定的 actions 使用已弃用的 Node 20 目标、被平台强制在 Node 24 运行；本次仍成功。后续应单独审阅并升级 actions pin，不在本轮未经验证地替换。

结果已核对后移除 opt-in 标签，避免仅更新文档再次运行。此后文档提交的 head 不应冒充上述已验收 head；后续代码变更仍需重新启用并验收。PR 保持草稿，未合并 main。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`。下一步可进行受支持 Python 上的完整回归及剩余风险审阅，Windows 和生产授权仍需独立验收。
