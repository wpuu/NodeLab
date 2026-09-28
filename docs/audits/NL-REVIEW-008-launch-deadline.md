# NL-REVIEW-008｜F2b 启动共享 deadline

日期：2026-09-28。承接 NL-REVIEW-007；不启用真实节点探测。

## 问题与修改

旧启动 deadline 在 binary 校验后才创建，HTTP 固定 3 秒、Windows listener helper 固定 20 秒，各阶段还可能在前一步已过期后继续发出请求。

本轮新增内部 monotonic deadline 工具，并将一个绝对 deadline 从 binary 校验前传递到全部启动预检阶段：

- 启动预算只接受正、有限数值；bool、字符串、NaN、Infinity 等在 binary 校验与进程创建之前被拒绝，返回固定 `INVALID_DEADLINE`。
- 摘要计算在读取前、各块和结束时检查 deadline；`-v` 的 subprocess timeout 为 `min(10s, remaining)`。超时返回固定 `BINARY_TIMEOUT`，在启动边界映射为 `LAUNCH_TIMEOUT`。
- controller 请求连接 timeout 为 `min(3s, remaining)`；Windows listener helper 为 `min(20s, remaining)`。
- 每次调用前后检查预算。晚返回的成功结果不能启动后续步骤或生成成功句柄。
- 监听与未鉴权请求的轮询 sleep 不超过剩余预算；到期立即 `LAUNCH_TIMEOUT`。
- 已创建的 child 即使 Popen 返回时已经过期也进入清理；清理失败仍以 `PROCESS_STOP_FAILED` 优先报告。
- 控制器正文以 read1 分块读取、块间检查 deadline，设置 1 MiB 上限，拒绝无效 UTF-8 与无效 JSON。不将正文或动态异常文本对外返回。

兼容原内部调用：不传 deadline 的 binary/helper 使用既有单操作 timeout。真实探测 CLI 仍关闭。

## 验证

命令：`PYTHONPATH=src .venv/bin/python -m pytest -ra`

Linux / Python 3.11.2：**224 passed, 18 skipped**，本轮新增 28 项测试。`git diff --check` 通过。

新增测试包括：非法预算无副作用；九个阶段晚返回不被接受；绝对 deadline 一致与剩余预算递减；短预算轮询；binary 版本检查的 timeout；摘要计算到期后不打开文件；Windows helper 参数透传（仅模拟）；HTTP 参数透传；分块读取中到期；Popen 晚返回清理；清理失败优先级；过大、无效 UTF-8、无效 JSON 正文。

## 不得夸大的边界

这是**启动工作共享预算与晚结果拒绝**，不是严格端到端墙钟保证，也不是探测全流程 deadline 已关闭：

- `Popen`、文件系统操作和操作系统调度不能在当前同步实现中被强制中断。
- urllib timeout 是阻塞 I/O 的超时，不是整个事务的硬截止时间；慢响应头和单次底层读取仍可能越过剩余墙钟预算。分块检查能拒绝晚结果，不能宣称硬性取消已实现。
- 清理保留独立的最多 5 秒等待预算，不因工作 deadline 到期而跳过。
- `config_test(-t)` 不在当前 `start_verified_engine` 链路，本轮未改变其独立 timeout；统一 RunContext 生命周期集成时仍须纳入。
- Windows helper 的本轮测试只是 Linux 上参数注入，不构成 Windows PID/NTFS 验收。
- Python ≥3.12 尚未复验；15 项真实 Mihomo binary 与 3 项 Windows 测试跳过。

下一步仍需私有 RunContext 的单所有者启动集成、配置测试与恢复 marker 的完整生命周期；严格可取消 I/O 与端到端 deadline 还需后续实现/验收。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`，未宣称 P0 CLOSED 或逐请求 route proof。
