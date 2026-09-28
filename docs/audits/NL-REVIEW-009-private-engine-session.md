# NL-REVIEW-009｜F2 内部私有引擎会话

日期：2026-09-28。承接 NL-REVIEW-008；不是 P0 CLOSED 或真实探测开闸。

## 本轮实现

新增 `engine_session.private_engine_session` 内部上下文管理入口。它按顺序执行：

1. 创建共享启动 deadline、生成随机 controller secret、构造严格引擎配置。
2. 验证 pinned binary，失败时不创建私有目录。
3. 进入唯一 RunContext，安全写入 probe.yaml。
4. RunContext 创建并立即持有配置检查 `-t` 的 Popen；记录可核验 child identity。
5. 在剩余预算内等待检查结束，非零退出/超时拒绝。成功后 reap、清除检查进程 marker，再允许启动 runtime。
6. 启动器重新验证 binary，使用同一 RunContext 创建 runtime 并执行已有鉴权、端口归属和规则预检。
7. 成功返回的句柄 close 委托 RunContext；正常、异常和取消路径均由该 owner 统一停止进程、删除 YAML/目录及释放锁。

`LaunchedEngine` 原独立使用方式不变；新增 `_owner` / `_deadline` 仅供内部会话组合使用。绑定 owner 时启动器不再另行清理同一个 child。CLI、probe verdict 和探测开关没有接入该内部入口。

RunContext 新增内部固定命令启动方法，不接受任意 URI/argv；Popen 返回后首先保留 raw_child，然后建立 wrapper、核验 identity、更新 marker。即使后续 marker 失败，退出会话仍有可清理的子进程。活着但身份无法核验的 child 被拒绝；已退出的短命 -t 可以没有活动 identity。运行中禁止重写其 YAML；marker 写后 flush/fsync。marker 清除失败保持固定码，阻止 runtime 启动。

## 验证

`PYTHONPATH=src .venv/bin/python -m pytest -ra`：Linux / Python 3.11.2，**240 passed, 18 skipped**；本轮新增 16 项。`git diff --check` 通过。

集成测试使用真实本机 Python 替身子进程，真实 POSIX 私有目录、权限、进程 identity 与清理；mock 了 binary 验证和 controller 行为，**不是 Mihomo 协议握手**。

覆盖：两个 child 串行归属、私有 marker 与 YAML 权限、同一 deadline、重复 close、check/runtime spawn 失败、-t 非零/超时、正文异常/取消、运行时预检失败、marker 写入与清除失败、活 child 无法核验、binary 拒绝无私有文件、配置写入失败、清理失败删除 YAML 且覆盖此前错误、独立外部进程存活、运行中配置不可重写。

## 边界与下一步

- 本轮未运行真实 Mihomo；15 项固定 binary 测试和 3 项 Windows 测试仍跳过，Python ≥3.12 未复验。
- 短时 `-v` 仍由 binary verifier 的 subprocess.run 管理，并非登记到 RunContext 的恢复 marker。本轮统一的是包含 YAML 的 `-t` 与 runtime 生命周期，不宣称所有辅助进程都已有持久恢复记录。
- marker 写入不是原子替换；进程创建至持久 marker 更新之间仍有硬崩溃窗口。fsync 不等于完整 crash consistency 验收。异常后不明残留仍须默认拒绝、人工恢复审核，不能自动按名称扫杀。
- 停止无法确认时仍为 `SECRET_CLEANUP_FAILED`，不保证 orphan 已消失；保留 owner 状态供确定性重试。本轮没有放宽清理失败硬阻断。
- 共享 deadline 仍受 NL-REVIEW-008 的同步系统调用/urllib 边界限制；不是严格端到端墙钟截止实现。
- 内部 session 不抓取出口 IP、不生成 PASS，也不是生产使用授权。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`。

后续应在支持的 Python 与固定引擎上复验完整 session，再推进 F3 的原始请求连接级证据；Windows W1/W2 与本地握手 fixture 仍是独立验收门槛。
