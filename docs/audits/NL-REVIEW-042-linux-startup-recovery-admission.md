# NL-REVIEW-042 — Linux 启动发布与恢复共用根锁准入

日期：2026-09-29。接续 041，处理新运行初始扫描到 run 锁/目录/marker 发布期间，恢复可能同时进入的问题。

## 复现与修复

三个确定性负控在旧实现 **3 failed in 0.06s**：初始扫描后恢复取得根锁但启动仍继续；初始 marker 发布时根锁未持有、恢复可进入；初始扫描后出现残留但启动未复核。

Linux `RunContext.__enter__` 在既有根目录验证/初始扫描之后：

- 通过 O_CREAT|O_EXCL 排他创建 `.recover.lock`，复用安全 fd 元数据、flock 和锁后路径/inode 核验。
- **启动不接管已有根锁**：不论 live/stale，均拒绝并要求复核；显式恢复仍使用既有直接锁住 stale inode 的协议。
- 取得根锁后再次分类根目录，仅忽略自己持有的 `.recover.lock`。任何新残留阻止启动，已有 live run 可共存。
- 根锁持续覆盖 run-id 分配、run 锁取得、目录创建/验证和初始 marker 发布；退出准入区时核对路径并释放根锁，run 锁继续由运行持有。
- 发布失败走既有未完成初始化清理；Linux KeyboardInterrupt/SystemExit 等异常也清理已取得的 run 资源，不因新增根锁 finally 掩盖已知取消路径。清理仍是尽力而为，不声称可恢复任意内核 syscall 中断。

两个同时开始的新启动可能有一个即时拒绝，而不是排队等待；活跃运行本身仍能共存。调用者不能靠删除根锁重试，必须确认竞争已结束或执行明确的残留复核/恢复。非 Linux 使用空上下文，不迁移 Windows 协议；inspection 保持只读、不取锁。

## 测试

新增 `tests/test_startup_recovery_admission.py` **12 项**：三个初始竞态负控、迟到 stale 根锁不接管、I/O/格式/取消/退出异常清理、释放时替代根锁保留、live run 共存与恢复跳过、真实恢复子进程竞争、第二次启动不破坏首次发布。

真实子进程在初始 marker 发布期间调用完整 `recover_stale_runs`，必须拒绝；发布后同样调用成功且不触碰仍持 run 锁的运行。子进程等待设有超时。注入发布点控制交错，不声称覆盖所有内核调度。

```text
admission suite: 12 passed in 0.21s
local full: 974 passed, 37 skipped in 36.28s
```

本地 Python 3.11.2，仅作补充；34 个固定引擎测试和三个 Windows 测试跳过。full 总数更新为 **1011**，远端要求 **1008 passed + 三个指定 Windows skip**。

代码 head：`2938684cceb8f21ab57020f2e7ce5292935aa27b`。

## 远端验收

- run：[36464656369](https://github.com/wpuu/NodeLab/actions/runs/36464656369)
- job/check：`109071585492`，success，2 分 23 秒
- 事件 head：`2938684cceb8f21ab57020f2e7ce5292935aa27b`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 1008 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对精确 head、成功状态、五条 notice 与全部固定字段，无 warning/failure。四套 gate 均 PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；准备为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加；annotations 验证不冒充 artifact ZIP 内容核验。opt-in 标签已移除，PR #2 保持草稿。

## 未关闭边界

该协议约束使用当前实现的协作启动/恢复者，不约束旧版本、绕过锁的同身份进程或敌对父目录/锁路径替换。根扫描也不是冻结所有 owner 生命周期：其他 owner 在扫描后退出或崩溃仍可能产生新残留。

根锁释放失败可能发生在初始 marker 已发布之后，启动将报错并尝试清理，而非宣称发布从未发生。现有失败初始化清理对 run 目录所有权的依据仍需单独审查，随机 run-id 不是敌对并发环境的所有权证明。扫描上界、路径描述符绑定、身份查询→信号原子性、未知 PID 自动恢复、硬截止和断电/重启仍未完全解决。

Windows、生产/外部节点未验收。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR #2 保持草稿，不合并 main，不改支付设置，不声明 P0 CLOSED。
