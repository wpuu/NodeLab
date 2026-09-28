# NL-REVIEW-028 — Linux 恢复记录绑定启动实例

日期：2026-09-28。承接审计 027 的跨重启身份碰撞限制；未改动 main、付费设置或生产门禁。

## 风险与兼容性决策

Linux 进程创建时间使用启动后的计时值。系统重启后 PID、计时和可执行文件路径指纹可能重复，旧 marker 不能仅凭这三项授权当前进程终止。本轮收紧自动恢复条件，而非尝试猜测旧记录是否恰好来自当前启动。

先执行六项旧版/不同/不合格绑定负控，旧实现全部失败。测试模拟记录内容或 boot reader 变化，不实际重启机器，也不声称已观测到现实中的跨重启误杀。

**兼容性变化：Linux 旧 marker 没有 boot 绑定时返回 RECOVERY_REVIEW_REQUIRED，保留运行目录与 YAML，不查询/终止记录中的进程，也不自动补写当前 boot 值。** 因此旧残留可能继续阻塞新运行，需要人工审阅，不应删除证据或改 marker 来绕过门禁。

## 实现

- 有界读取 `/proc/sys/kernel/random/boot_id`（最多读取 65 字节，超过 64 即拒绝），只接受规范 UUID。
- marker 新增 `linux_boot_fingerprint`，为带用途前缀的 SHA-256 摘要，不存储原始 boot UUID 或文件路径。
- 初次 marker 写入前必须取得当前启动指纹；无法读取则进入失败，不能写入私有 YAML。每次更新 marker 都核对本 RunContext 已绑定的值，不能悄悄改绑。
- 恢复读 marker 时要求规范 64 位小写十六进制指纹且等于当前值；缺失、格式错误、不可读取或不同启动实例均拒绝，发生在 owner/child 身份查询与目录删除前。
- marker JSON 重复字段也拒绝，不能通过最后值覆盖选择有利 boot 绑定。损坏 JSON 返回不可验证 marker。
- 同启动实例的合法陈旧记录继续走既有目录/锁/身份/pidfd 校验；boot 匹配本身不授权终止。
- 子进程生成后若 marker 更新遇到绑定变化，现有 owner 仍清理自己持有的子进程和私有目录。

Windows 不写入此 Linux 字段，不将 Linux boot 验证称为 Windows 支持。低层 `terminate_verified_process(ProcessIdentity)` 本身未增加 boot 参数；本轮绑定施加于应用的 marker 恢复入口，不能把任意手构 ProcessIdentity 当成 boot 证明。

## 测试与本地结果

新增 `tests/test_recovery_boot.py` 19 项，覆盖旧 marker、其他启动/坏格式、原始 UUID 不落 marker、当前 boot 不可读、同启动恢复、禁止运行中改绑、reader 有界/坏编码、双向重复字段及 child marker 更新失败清理。拒绝测试同时核对 marker/YAML 字节不变、身份查询和终止函数未调用。

```text
boot binding + P0 safety + private cleanup faults
64 passed in 3.49s

PYTHONPATH=src .venv/bin/python -m pytest -ra
750 passed, 37 skipped in 32.29s
```

full 总数由 768 随新增 19 项更新为 **787**，三个指定 Windows skip 不变。代码 head：`9884f59b40d464b7b6c12cf2db258df267cb126f`，提交差异检查通过。

## 远端验收

- run：[36414504335](https://github.com/wpuu/NodeLab/actions/runs/36414504335)
- 已验收 head：`9884f59b40d464b7b6c12cf2db258df267cb126f`
- job/check ID：`108902279375`，job success，2 分 14 秒
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- event 为 pull_request，默认 checkout PR merge revision；上述 SHA 是事件 head。

通过 GitHub API 读回并程序化核对 head、success 与固定 JSON check annotations：

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 784 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

全部 status=PASS、real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。只跳过三个指定 Windows 测试；五条 notice，无 warning/failure annotation。既有真实孤儿恢复用例继续通过，但未实际重启主机测试跨启动拒绝。

结果核对后移除 opt-in 标签，避免文档更新重复运行；PR #2 保持草稿，未合并 main。文档提交不是上述已验收 head，独立 gate 与 full 的重复用例不累加。

## 未关闭的边界

这降低了把旧启动实例记录误用于当前进程的风险，不是记录认证或全面崩溃一致性。仍依赖可信的本机 proc 视图、私有文件权限；能任意改写记录的同身份进程也能伪造 boot 字段，摘要不是签名。

进程创建与 marker 写入之间的窗口、停止失败但已删 marker 的材料缺口、路径指纹非内容摘要、socket/PID 查询与 token 发送非原子等限制仍在。没有实际主机重启验收、Windows W1/W2 或生产节点验收。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；不宣称 P0 全部关闭。
