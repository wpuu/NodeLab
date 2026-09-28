# NL-REVIEW-027 — Linux 恢复终止必须绑定 pidfd

日期：2026-09-28。审阅崩溃恢复的 `terminate_verified_process`，不改变持有 Popen 的正常子进程停止路径。

## 复现

原 Linux 恢复路径存在三类过宽行为：

- pidfd API 不存在、pidfd_open 失败、或 pidfd_send_signal 不存在时，退回 `os.kill(expected.pid, ...)`。记录身份查询与按 PID 发信号之间仍可能发生 PID 重用。
- `_linux_identity` 的 None 同时代表进程消失与不可读取；原来把它作为身份不匹配，可能直接报告 True。
- 匹配的 PID/创建时间在缺少可执行文件指纹时仍可触发信号；恢复预算也未验证输入，并通过最小 0.1 秒等待扩展耗尽的预算。

先执行新测试的初始 21 项，在旧实现上 **17 失败、4 通过**。随后补充更多负控，最终新增 31 项。这是合成 API 故障与真实自有 Python 子进程实验，不是已观测到实际误杀事件。

## 修改

- 公共入口拒绝不合格的记录身份与无效预算；返回 False，不执行终止。
- Linux 要求 pidfd_open 和 pidfd_send_signal 同时存在。打开失败（除内核明确 ESRCH）、不支持或权限受限都返回 False，绝不退回数字 PID 信号。
- 获取 pidfd 后先检查是否已退出；若 /proc 身份不可核实，只允许 pidfd 就绪证明退出，不以 None 猜测。
- 可核实的不同身份不发送信号；True 在此表示记录身份已经不匹配，不代表当前 PID 下的新进程被停止。
- 只有 PID/创建时间匹配且两边都有合格、匹配的执行文件路径指纹时才发信号。TERM 与必要时的 KILL 均发送给同一个 pidfd。
- 发送后只使用 pidfd 就绪或内核 ESRCH 确认退出；不再用后续 /proc 读取失败推断死亡。
- TERM/KILL 等待共用同一个 deadline，耗尽时不再发起新的升级或附加最小等待。文件系统/身份读取仍是协作预算，不是硬中断。
- pidfd 在 finally 关闭；不枚举进程，不按名称匹配，不终止外部监听器。

安全兼容性变化：缺少 pidfd 能力的旧 Linux/Python 不再自动恢复终止，会返回失败；正常 owner/Popen 清理不受该能力要求影响。恢复调用方仍可能按既有策略删除私有文件并报告 PROCESS_STOP_FAILED，而不是保证保留完整孤儿恢复材料。

Windows 句柄分支的内部终止/等待逻辑本轮未重构；公共输入验证并非 Windows 真实验收，也不代表它的未知身份处理问题已解决。

## 本地测试

新增 `tests/test_recovery_pidfd.py`，31 项覆盖 API 缺失、EPERM/ENOSYS/EMFILE、未知身份、指纹缺失、已知身份变化、pidfd 就绪/ESRCH、无效记录与预算、预算耗尽、TERM→KILL、发信号被拒绝、发信号后身份不可读，以及真实自有子进程终止且独立外部进程存活。

```text
pidfd 新测试 + 既有 P0 safety：64 passed in 3.38s

PYTHONPATH=src .venv/bin/python -m pytest -ra
731 passed, 37 skipped in 31.64s
```

full gate 总数由 737 随新增 31 项更新为 **768**，三个指定 Windows skip 不变。代码 head：`0ce612017f20141a010a33054d91d949ac494e0e`，提交差异检查通过。

## 远端验收

- run：[36413400189](https://github.com/wpuu/NodeLab/actions/runs/36413400189)
- 已验收 head：`0ce612017f20141a010a33054d91d949ac494e0e`
- job/check ID：`108898701420`，job success，2 分 13 秒
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- event 为 pull_request，默认 checkout PR merge revision；上述 SHA 是事件 head。

通过 GitHub API 程序化核对 head、success 与固定 JSON check annotations：

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 765 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

全部 status=PASS、real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。只有三个指定 Windows 测试跳过；check annotations 为五条 notice，无 warning/failure。独立 gate 与 full 重复用例不累加。

结果核对后已移除 opt-in 标签，避免文档提交重复运行。PR #2 保持草稿，不合并 main；文档 head 不冒充上述已验收 head。

## 未关闭

本轮不解决 marker 写入与进程创建之间的崩溃窗口、marker 未绑定 boot ID 的跨重启身份碰撞、路径指纹不等于执行文件内容摘要，以及停止失败后已删除 marker 的恢复材料缺口。同进程可伪造 Python handle/记录也不是认证边界。

socket 查询与 token 发送非原子、Windows 验收和生产授权仍未关闭。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；无 P0 全部关闭结论。
