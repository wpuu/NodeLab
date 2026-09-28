# NL-REVIEW-036 — Linux 每次恢复信号前重核身份

日期：2026-09-29。承接审计 035，避免 TERM/KILL 持续复用首次身份结果；不声明原子进程映像绑定。

## 复现与实现

旧实现只在绑定 pidfd 后核对一次身份，之后可能在 TERM 与 KILL 之间发生 exec、身份变为不可读或查询不一致。先加入 TERM/KILL 两阶段、五种变化的 10 项负控，旧实现全部失败：会继续发送该阶段信号。

Linux 恢复现在每次发送 TERM 或 KILL 之前：

1. 检查共享预算和绑定 pidfd 是否已 ready；若内核已确认退出则不再查询/发送。
2. 重新读取身份，要求合法且与原始记录的 PID、创建时间、完整 executable 路径指纹完全相等。不会采用允许缺指纹的宽松 matches 规则。
3. 变化、缺失或不一致不能重新授权信号；仅再次查询同一 pidfd 是否 ready。未确认退出时返回 False，保留既有失败清理语义和恢复依据。
4. 身份读取后再次核对同一个 deadline；读取耗尽预算也不能发送信号，不重置预算、不追加最小等待。

仍只通过原 pidfd 发信号，无数字 PID fallback。绑定之后的新创建时间也不直接被作为绑定任务退出证明。Windows 和正常持有 Popen 的清理分支不变。

## 测试

新增 `tests/test_recovery_signal_guards.py` **16 项**：

- TERM/KILL 前不可读、exec 变化、创建时间变化、查询 PID 不同、缺指纹共 10 项负控。
- 两阶段身份查询耗尽预算、两阶段查询异常。
- 查询过程中退出只以绑定 pidfd ready 为依据。
- **真实 TERM→exec**：测试自有 Python child 安装 TERM handler，收到真实 pidfd TERM 后 exec 为 `/bin/sh` 并等待受控管道。确认 PID/创建时间不变、指纹改变，恢复在 KILL 前返回 False，只发送过 TERM、未发 KILL，child 仍活。最后由测试自有 Popen 清理。

既有 pidfd 用例更新首次绑定加 pre-TERM 的调用次数断言，继续检查无数字 PID 信号；没有删除既有预算、未知身份或 KILL 正向测试。

```text
signal guards + pidfd + exec recovery
56 passed in 3.21s

PYTHONPATH=src .venv/bin/python -m pytest -ra
879 passed, 37 skipped in 38.47s
```

本地 Python 3.11.2 为补充证据；34 个固定引擎用例及三个 Windows 用例跳过。full 总数 **916**，要求 **913 passed + 三个指定 Windows skip**。代码 head：`fe236ceb87ec1d5bc55b84c79b8c753b4623f6ec`。

## 远端验收

- run：[36449845409](https://github.com/wpuu/NodeLab/actions/runs/36449845409)
- job/check：`109021471280`，success，2 分 25 秒
- 已核对事件 head：`fe236ceb87ec1d5bc55b84c79b8c753b4623f6ec`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交明确区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 913 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对运行成功、精确 head、固定结果及安全字段。全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；五条 notice，无 warning/failure。准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加，不把 annotations 核对冒充 artifact ZIP 内容核对。验收后移除 opt-in 标签，PR #2 保持草稿，未合并 main。

## 限制

查询之后、发送之前仍存在竞态，pidfd 绑定进程生命周期而非冻结 executable。实际验证的是可观察到的身份变化阻止后续信号，不是所有 exec 都绝不会接到信号。路径指纹也不是执行文件内容摘要。

deadline 是合作式预算：慢查询/系统调用本身仍可能超过预算，本轮只禁止查询后继续发送过期信号。没有增加硬实时截止或整个恢复事务的原子性。

未知 PID 自动找回、记录认证、敌对父目录替换、断电/主机重启、Windows 及生产授权仍未完成。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR 保持草稿，不合并 main，不改支付设置，不声明 P0 CLOSED。
