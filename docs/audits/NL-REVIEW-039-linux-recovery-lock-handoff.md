# NL-REVIEW-039 — Linux stale 恢复锁的描述符持有接管

日期：2026-09-29。限定于 Linux `.recover.lock` 的恢复入口；不改变普通 run 锁的契约，不迁移 Windows 分支。

## 复现与修正

此前先用 `_lock_state` 探测 stale，再 unlink/recreate。探测释放锁之后，其他恢复者可能已经持有原 inode；此时删除原锁并新建文件会让两个恢复者各持不同 inode，失去互斥。

两项负控在旧实现得到 **2 failed in 0.06s**：实际持锁后注入过期 stale 观察仍能进入恢复；对未锁住但保留打开引用的 stale 文件接管时 inode 被替换。前者是确定性过期观察注入，不声称靠调度随机复现竞态。

Linux 恢复现在使用独立 acquisition/release：

- O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK，绝不先删除已有 stale 锁；不截断或改写已有文件。
- 已打开 fd 须符合当前 UID、0600、普通文件、单硬链接、长度零；再取得非阻塞排他 flock。
- **取得 flock 后**再次验证 fd 和当前路径的元数据及 `(st_dev, st_ino)` 一致。旧持有者 unlink 后才获得旧 inode 的打开者不能据此进入恢复。
- fd 持续持有到恢复体结束；竞争、未知系统错误、路径消失或替换均拒绝，关闭本次 fd，不删除失败候选现场。
- 释放前再次检查路径仍对应所持 fd；发现替换不删除替代文件，报 `RECOVERY_REVIEW_REQUIRED`，finally 关闭描述符。恢复体抛错也执行释放。

只读 inspection 仍只观察、不打开/取得锁；现存异常锁不自动迁移或盲删。

## 测试

新增 `tests/test_recovery_lock_handoff.py` **15 项**：过期观察、stale inode 连续性、取得 flock 后路径替换/消失、释放遇到替代锁、异常内容/权限/硬链接/FIFO/软链接、获取错误及 KeyboardInterrupt/SystemExit 的 fd 关闭、恢复体异常、真实双子进程竞争。

真实竞争用例让两个独立 Python 进程从同一个 stale 锁开始，通过管道同时放行；胜者保持恢复体直到父进程确认另一方被拒绝，然后释放。检查恰好一个进入、原 inode 未变、正常退出及最终锁清理。等待有超时，finally 终止并回收测试子进程。这不是无限调度探索或 hostile-filesystem 证明。

```text
handoff suite: 15 passed in 0.15s
local full: 935 passed, 37 skipped in 38.89s
```

本地 Python 3.11 结果仅作补充；34 个引擎用例与三个 Windows 用例跳过。full 总数更新为 **972**，远端要求 **969 passed + 三个指定 Windows skip**，不接受任意 skip/xfail 替代。

代码 head：`2aaaa3a96cbfa080837b06e78b450da8f6287ce8`。

## 远端验收

- run：[36460029019](https://github.com/wpuu/NodeLab/actions/runs/36460029019)
- job/check：`109055995826`，success，2 分 16 秒
- 事件 head：`2aaaa3a96cbfa080837b06e78b450da8f6287ce8`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 969 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对成功状态、精确 head、五条 notice 和全部固定报告字段，无 warning/failure。四套 gate 均 PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加；这里是 check annotations 核对，不冒充 artifact ZIP 内容核对。验收后已移除 opt-in 标签，PR #2 仍为草稿。

## 边界与后续

此修复只处理协作恢复者的根恢复锁接管。普通 run 锁的探测与后续 run 目录操作仍不是持锁事务；运行启动与恢复之间的竞态没有因此全部解决。路径复核与 unlink 也不是原子操作，不保证敌对同身份写入、父目录替换或不遵守 flock 的进程安全。

释放失败发生在恢复体之后：可能已经执行清理或进程动作，报错不表示回滚或“未发生清理”。崩溃仍可能留下 stale 锁；下次必须重新取得 fd/flock 并验证，而不是凭静态 inspection 授权。

未知 PID 恢复、非原子身份查询→信号、硬截止、断电/重启、Windows、生产/外部节点授权与 P0 closure 仍未完成。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR #2 保持草稿，不合并 main，不改支付设置。
