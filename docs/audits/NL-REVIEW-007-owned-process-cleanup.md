# NL-REVIEW-007｜F2b 进程清理失败硬阻断

日期：2026-09-28。承接 NL-REVIEW-006；不是 P0 CLOSED 证明。

## 本轮修改

- `start_verified_engine` 失败时改用统一 `stop_owned_process`，不再吞掉 kill/wait 失败。无法确认退出则抛出固定 `EngineLaunchError("PROCESS_STOP_FAILED")`，优先于此前的预检错误或取消。
- `LaunchedEngine` 增加 `close()` 与上下文管理协议。`with start_verified_engine(...) as engine:` 在正常退出、异常与取消时清理所持有的 exact Popen。清理成功保留正文异常；清理失败优先报告固定清理错误。重复 close 不重复终止已退出的 child。
- 引擎 stdout/stderr 改为 DEVNULL，避免旧实现的无人读取 PIPE 被填满、阻塞 child，也不落盘保存可能含秘密的日志。
- `stop_owned_process` 验证正且有限的数值预算，拒绝 bool、字符串、NaN 与 Infinity。terminate、kill 与取消后的兜底 wait 共用同一 deadline，预算耗尽后使用零等待，不再重新授予 0.1 秒最低等待时间。
- 既有模拟 child 测试改为模拟 terminate 导致退出，避免把“不验证是否真的退出”的旧行为继续写成测试预期。

## 验证

`PYTHONPATH=src .venv/bin/python -m pytest -ra`：Linux / Python 3.11.2，**196 passed, 18 skipped**。本轮新增 21 项。

覆盖非法预算、虚拟时钟下 0.25/5 秒共享预算、取消后的 kill、无法确认退出、成功上下文、正文异常、清理异常优先级、失败启动与取消的清理阻断、DEVNULL 配置。

另外使用两个真实本机 Python 替身 child 验证正常上下文结束和 KeyboardInterrupt：只停止被拥有的 child，独立外部进程仍存活。既有真实忽略 SIGTERM 的替身测试也通过。没有真实节点或 Mihomo 网络请求。

## 明确限制与后续

- 本轮只收紧**停止进程的等待预算**，不是端到端探测总 deadline。同步系统调用、进程创建与操作系统调度也不能被解释为严格墙钟上限。
- 引擎句柄上下文只拥有进程，**不负责私有 YAML 的删除或恢复 marker**。统一 RunContext 的单所有者启动/清理集成仍待实现，不能把两个上下文随意叠加当作完成。
- binary 检查、HTTP 请求、Windows listener helper 等启动步骤仍待共享剩余时间预算。
- 清理硬失败会报告风险，不保证无法终止的 child 已经消失；调用方不得报告成功。
- Python ≥3.12、固定 Mihomo binary 与 Windows 仍未复验；15 项真实 binary 测试、3 项 Windows 测试跳过。
- `PROBE_GATE_OPEN=False`，`REAL_NODE_TEST_ALLOWED_NOW=NO`。未宣称 route proof 或任何 P0 CLOSED。
