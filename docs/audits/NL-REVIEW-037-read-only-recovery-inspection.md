# NL-REVIEW-037 — Linux 只读残留检查与独立脱敏输出

日期：2026-09-29。承接审计 034–036 的“未知状态保留现场”，提供非破坏性观察入口，不扩大恢复授权。

## 实现

新增 `nodelab recover --inspect`，与 `--confirm` 互斥。Linux-only `inspect_private_runs` 不调用恢复、不创建根目录/恢复锁、不查询 PID/owner/child、不探测 flock、不读取 YAML，也不修改运行文件。

按固定原因区分启动意图、marker 暂存、缺失/不合法记录、非预期内容、锁文件和需进一步恢复核验的记录。静态 marker 读取复用现有有界/非链接/权限/boot/child 形状检查，但不调用 owner 或 child 进程核验。锁文件只用 lstat 描述，PRESENT_UNCHECKED 不声称 live/stale。

扫描用 scandir 限制每目录 256 个入口；没有用可能先 materialize listdir 的 Path.iterdir 再截断。超限整体返回固定错误，不输出伪完整的截断结果。记录读取沿用既有上限。

独立 `redacted_recovery_inspection` 重建公开 JSON：固定 mode/status，行只允许顺序号及原因/锁状态枚举。路径、PID、原始 JSON、凭据和未知字段不公开；非法字段拒绝整份结果。cleanup_performed、process_signals_sent、process_identity_checked、recovery_authorized 永远 false。没有绕过原 CLI 脱敏器输出原始文件内容，也不改变原节点结果 schema。

操作说明见 `docs/Linux-recovery-inspection.md`。退出码 0/COMPLETE 只表示观察完成，不是 cleanup PASS；非 Linux 返回固定 unsupported，不猜测 Windows 行为。

## 测试

新增 `tests/test_recovery_inspection.py` **22 项**。首个 CLI 用例在旧实现失败（尚不支持 --inspect），不是旧实现破坏性安全故障的声称。

覆盖：禁止调用恢复/身份核验/锁获取或探测；只读打开标志；记录/启动意图分类；不读 YAML；目录不存在不创建；互斥参数/相对路径；非 Linux 不扫描；根/子目录超限；软链接不遍历；锁不移除；原始文件字节保留；异常固定输出；独立脱敏器拒绝任意字符串/非法行并丢弃额外秘密/授权字段；真实自有活 child 检查后仍活且文件不变。

```text
inspection + P0 safety
55 passed in 3.65s

PYTHONPATH=src .venv/bin/python -m pytest -ra
901 passed, 37 skipped in 38.10s
```

本地 Python 3.11.2 是补充证据，34 个固定引擎及三个 Windows 用例跳过。full 总数 **938**，要求 **935 passed + 三个指定 Windows skip**。代码 head：`ed86eee6f6398c09841f2ac78c6a5a4d8f3ee9f2`。

## 远端验收

- run：[36451360873](https://github.com/wpuu/NodeLab/actions/runs/36451360873)
- job/check：`109026653084`，success，2 分 24 秒
- 已核对事件 head：`ed86eee6f6398c09841f2ac78c6a5a4d8f3ee9f2`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交明确区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 935 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对运行成功、精确 head、固定结果及安全字段。全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；五条 notice，无 warning/failure。准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加，不把 annotations 核对冒充 artifact ZIP 内容核对。验收后移除 opt-in 标签，PR #2 保持草稿，未合并 main。

## 限制

不把“外观正常/静态 marker 可解析”叫作可安全恢复，不判断锁实际占用。扫描不持锁，不是原子快照或授权租约；读取可能更新 atime。原始路径/父目录可信前提和竞争变化风险不变。

检查不解除残留阻塞、不补全未知 PID、不重写/迁移记录，也不保证 YAML 已删除。Windows、未知 child 自动找回、完整文件系统防护、硬截止、断电重启与生产授权仍需独立处理。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR 保持草稿，不合并 main，不改支付设置，不声明 P0 CLOSED。
