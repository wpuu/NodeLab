# NL-REVIEW-041 — Linux 目录恢复期间持续持有 run 锁

日期：2026-09-29。接续 039/040，将 Linux 完整恢复入口的 run 锁持有范围扩展到目录恢复本体；不是文件系统回滚事务。

## 复现与修复

此前目录恢复仅在 `recover_dir` 前探测 missing/stale，未持有 run 锁。三项初始负控在旧实现 **3 failed in 0.05s**：已有 stale 锁和缺失锁的目录恢复体均未持锁；过期 stale 观察还会让恢复体处理已被重新持有的锁对应的目录。

新增 `_recover_linux_dir_locked`，只供 Linux 完整恢复入口使用：

- 分类与动作前的状态检查保留，但不是授权；必须额外打开/取得对应 run 锁并完成 039 的锁后 fd/路径核验，获取失败不进入恢复体。
- 同一 fd/flock 持续覆盖 `recover_dir` 的 owner 核验、child 处理、负载清理和目录删除。
- 完全成功后，持锁核对并删除锁；不再探测自己的锁并把它误认成外部 live 锁。
- 失败、复核或异常时关闭描述符但保留锁及既有证据策略。成功后释放错误可能发生在目录已被删除之后，不能声称回滚。
- 非 Linux 分支不迁移；`recover --inspect` 不打开或获取锁。

### 缺失锁的行为变化

目录存在但 run 锁缺失时，恢复会创建安全的空锁作为本次持锁依据。若目录不能恢复，该新锁保留为 stale；再次恢复仍需重新取锁和验证。复核流程因此不保证根目录完全不变，但不会凭新建锁跳过 marker/owner/child 检查。原持有者已放弃 fd 后不能假装仍拥有这把锁；测试 harness 在清完自有目录后显式恢复孤立锁，而不是盲删。

## 测试

新增 `tests/test_recovery_run_transaction.py` **14 项**：已有/缺失锁的恢复体持锁、过期判断不得进入恢复体、两种初始状态下的复核/停止失败/I/O 错误/取消与 fd 释放、释放时路径替换保留、真实竞争进程被排除及恢复结束后可获取、实际目录恢复的 owner/child/tree 三阶段锁检查。

真实竞争用例执行独立 Python 进程尝试 flock，恢复体内必须竞争失败，恢复返回后必须成功；subprocess 等待有超时。owner/child 三阶段用例用注入身份结果和合成 child 记录检查调用期间持锁，不冒充真实 child 终止证明；既有真实 child 回归继续执行。

```text
transaction + P0 safety: 47 passed in 3.51s
local full: 962 passed, 37 skipped in 36.21s
```

本地 Python 3.11.2，仅补充证据；34 个引擎用例和三个 Windows 用例跳过。full 总数 **999**，远端须 **996 passed + 三个指定 Windows skip**。代码 head：`2f4cc3ad7435fe41f1248d39b0cf982e7d517799`。

## 远端验收

- run：[36463508748](https://github.com/wpuu/NodeLab/actions/runs/36463508748)
- job/check：`109067716960`，success，2 分 29 秒
- 事件 head：`2f4cc3ad7435fe41f1248d39b0cf982e7d517799`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 996 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对精确 head、成功状态、五条 notice 与全部固定字段，无 warning/failure。四套 gate 均 PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；准备为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加；annotations 验证不冒充 artifact ZIP 内容核验。opt-in 标签已移除，PR #2 保持草稿。

## 未关闭边界

这是协作进程遵守锁时的持锁临界区，不是目录描述符绑定、原子路径事务或回滚机制。恶意同身份进程可以不遵守 flock，也可能替换路径；逐次检查与 unlink/目录操作仍有敌对并发窗口。私有辅助 `recover_dir` 自身不获取锁，完整入口必须经过持锁包装。

新运行的 root 扫描与后续新 run 创建尚未和根恢复锁组成共同的准入协议；不同 run-id 的启动/恢复竞态仍需独立审查。身份查询→信号并非原子，未知 PID、硬截止、实际重启/断电、Windows 与生产授权未完成。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR #2 保持草稿，不合并 main，不修改支付设置，不声明 P0 CLOSED。
