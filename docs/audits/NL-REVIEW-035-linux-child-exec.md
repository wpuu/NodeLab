# NL-REVIEW-035 — Linux child 可执行文件变化不是退出证明

日期：2026-09-28。承接审计 032 的 owner 判定与 034 的启动意图，继续收紧 child 恢复的成功条件。

## 复现

Linux `terminate_verified_process` 原先把 `expected.matches(current)` 为 False 统一视为原 child 已退出。但同 PID、同创建时间、不同 executable 路径指纹，可能是原 child 执行了 exec，进程仍活着。原实现不向这种进程发信号是保守的，但返回 True 会使上层把停止视为已确认，删除恢复依据。

先加入“同生命周期 executable 变化”和“查询结果 PID 不一致”两项负控，旧实现 **2 failed**。后一种结果也不能被当作可靠的 PID 复用证明。

## Linux 新规则

保持稳定 pidfd、完整身份要求和共享停止预算；仅修改首次身份查询后的判定：

- 查询的 PID 与请求 PID 不一致：不能推断退出，仅再次检查绑定 pidfd 是否 ready。
- 同 PID、已知不同创建时间：原生命周期已不再占用此 PID，不发信号，保留既有退出结论。
- 同 PID/创建时间但 executable 路径指纹变化或缺失：不发信号，不根据该变化返回成功；只有绑定 pidfd ready 才能证明退出。
- 完整身份匹配时仍走原 pidfd TERM/KILL 路径；ESRCH 和 pidfd readiness 的退出证明不变。

因此已观察到 exec 但 child 仍活着时，恢复返回 PROCESS_STOP_FAILED，尝试删除 YAML/非恢复负载，保留原 marker 供复核（审计 030），重复恢复不销毁记录。不把 marker 改绑到新 executable。

Windows 恢复终止分支不变，未获得 Windows 验收。直接持有 Popen 的内存所有者仍可通过自己的 Popen 停止其 child；本轮不把记录恢复的限制误套到该所有权路径。

## 新增测试

`tests/test_recovery_exec.py` **9 项**：

- 两项旧实现负控；所有 Mock 分支禁止 pidfd 或数字 PID 发信号，并核对描述符关闭。
- 指纹缺失/变化时的再次 pidfd ready 正向证据、不同创建时间、再次 poll 错误。
- **真实 exec**：测试自己的 Python child 通过受控管道握手后 exec 为 `/bin/sh`，确认 PID/创建时间不变、路径指纹改变；恢复终止返回 False 且 child 仍活。随后仅由测试自有 Popen 发送终止，独立 pidfd 确认退出后恢复函数才返回 True。
- **恢复集成**：真实 child exec 后模拟 stale owner；连续两次恢复返回 PROCESS_STOP_FAILED、不发信号、marker 原始字节保持、YAML 删除，child 仍活。最终通过原内存 owner 的 Popen 清理自身 fixture。

```text
exec + pidfd + evidence + owner recovery
76 passed in 0.39s

PYTHONPATH=src .venv/bin/python -m pytest -ra
863 passed, 37 skipped in 34.09s
```

本地 Python 3.11.2 为补充证据；34 个固定引擎用例与三个 Windows 用例跳过。full 总数由 891 增至 **900**，要求 **897 passed + 三个指定 Windows skip**。代码 head：`7a53b1e9539449bd5ece88f468a6ed273bd05930`。

## 远端验收

- run：[36445073974](https://github.com/wpuu/NodeLab/actions/runs/36445073974)
- job/check：`109005145141`，success，2 分 13 秒
- 已核对事件 head：`7a53b1e9539449bd5ece88f468a6ed273bd05930`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交明确区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 897 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对运行成功、精确 head、固定结果及安全字段。全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；五条 notice，无 warning/failure。准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加，不把 annotations 核对冒充 artifact ZIP 内容核对。验收后移除 opt-in 标签，PR #2 保持草稿，未合并 main。

## 未解决的边界

本轮针对的是**首次查询已经观察到**的 executable 变化；没有让查询与后续信号原子化，也没有冻结 exec。匹配检查之后、发送信号之前或 TERM/KILL 之间仍可能发生状态变化，不能称为完整进程映像绑定。

路径指纹不是可执行文件内容摘要；同路径的内容变化不由此检测。可信 proc/marker、创建时间粒度及私有目录前提不变。未知 PID 自动找回、敌对父目录替换、实际断电/重启、Windows 及生产授权仍未解决。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`。保持草稿 PR，不合并 main，不改支付设置，不声明 P0 CLOSED。
