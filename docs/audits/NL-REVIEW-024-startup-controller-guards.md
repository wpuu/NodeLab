# NL-REVIEW-024 — 启动期每次 controller HTTP 前后复核所有权

日期：2026-09-28。承接审计 023，继续检查启动预检的身份边界。未开放真实节点探测或修改 main。

## 复现与修复范围

此前启动器只在 HTTP 预检开始前确认一次 controller 端口归属。后续未经认证探测、错误 token、正确 token 以及 configs/proxies/rules 请求复用这份旧结论；部分调用之间缺少及时的子进程退出检查。

新增六个 HTTP 阶段 × 两种故障（端口接管/子进程退出）的合成负控，旧实现结果为 **10 失败、2 通过**：六个阶段的端口接管均未触发预期拒绝；子进程在未经认证/错误 token/configs/proxies 阶段退出后，仍可能发送后续 HTTP 请求。负控中的返回值模拟成功响应，用于确认不能让表面正确的结果掩盖失去所有权。

这是合成时序复现，不是已观测到真实攻击者接管端口，也不声称 token 曾真实泄露。

在 `start_verified_engine` 内增加共享 `controller_guard/controller_step`：

- 每次 controller HTTP 前后检查本次 Popen 是否仍存活、端口是否由该 PID 以 loopback 监听、查询过程中子进程是否退出。
- 覆盖未经认证重试、错误/正确 token、configs/proxies/rules 六类调用。
- 初次等待监听建立的行为保留；一旦建立后的复核发现丢失/其他进程所有/非 loopback/不可验证，即拒绝，不等待端口重新出现后继续发送凭据。
- 后置复核失败时丢弃响应，不再发送后续请求，不返回成功 handle。
- 新增查询全部计入原启动绝对 deadline，不为每次复核分配新预算。正常无重试路径为 1 次初始 readiness + 6×2 次复核，共 13 次 controller 归属查询。
- 失败仍走既有单所有者清理；只停止自己持有的子进程，不按端口杀进程。已退出的进程不再 terminate/kill。

## 本地验证

新增 18 项测试：12 个分阶段接管/退出负控、4 个首次 HTTP 前丢失 controller 的拒绝类型、1 个归属查询期间退出、1 个最后后置复核耗尽总 deadline。既有正常事件顺序和共享预算测试同步强化，没有删除负控。

```text
controller isolation + launch deadline + runtime routing
112 passed in 8.79s

PYTHONPATH=src .venv/bin/python -m pytest -ra
688 passed, 37 skipped in 32.33s
```

full gate 总数随新增 18 项由 707 更新为 **725**，仍只允许三个指定 Windows skip。代码提交：`d952a565a0b90d273d8d6ef1045bec65037081a8`。提交差异检查通过。

## 远端验收

- run：[36408708687](https://github.com/wpuu/NodeLab/actions/runs/36408708687)
- 已验收 head：`d952a565a0b90d273d8d6ef1045bec65037081a8`
- job/check ID：`108883489374`，job success，2 分 13 秒
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- event 为 pull_request，默认 checkout PR merge revision；上述 SHA 是事件的 PR head。

通过 GitHub API 读回 run 元数据及 check annotations，程序化核对 head、success 与固定结果字段：

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 722 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

全部 status=PASS、real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。仅三个指定 Windows 测试跳过；本地/远端结果和独立 gate/full 的重复用例不能累加。

此复验确认真实本机正常路径未被加固破坏；故障时序的拒绝证据来自合成负控，未把它冒充真实攻击复现。结果核对后已移除 opt-in 标签，避免后续文档提交重复运行。PR #2 保持草稿，文档 head 不冒充上述已验收代码 head。

## 未消除的限制

端口查询与 HTTP 建连/发送仍不原子，查询完成后仍可能发生短暂变更；后置复核也不能收回已发送的字节。没有新增 OS 原子 socket/PID attestation，没有声称彻底消除 token 发送竞态。

本轮不重构启动后的配置变更监测、崩溃恢复或 Windows 所有权实现。Windows 上多次查询的成本需独立实测，不能由 Linux 结果代替。协作 deadline 仍不能硬中断所有系统调用。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；无 P0 全部关闭结论。
