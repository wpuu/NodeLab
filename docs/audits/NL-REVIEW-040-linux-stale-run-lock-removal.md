# NL-REVIEW-040 — Linux stale run 锁删除前取得实际所有权

日期：2026-09-29。接续 039，限定修复普通 run 锁的删除窗口，不宣称整个 run 目录恢复已成为持锁事务。

## 复现与变化

此前孤立 `<run_id>.lock` 的处理，以及目录恢复后的 `_remove_stale_lock`，都可能在探测 stale、释放探测锁后直接 unlink。另一个进程若在间隙持有该 inode，过期观察仍能删除它的锁路径。

两个确定性负控在旧实现 **2 failed in 0.05s**：实际持有 run 锁，注入过期 stale 判断，分别调用辅助删除入口和完整恢复入口。旧代码删除了仍被持有的锁；这不是依赖随机调度的复现。

Linux 删除现在复用 039 的描述符获取/核验/释放流程：

- `create=False`，绝不为了清除残留而创建一个原本不存在的 run 锁。
- 打开现有文件后验证安全元数据，取得非阻塞排他 flock，锁后核对路径与 fd 的设备/inode。
- 持有该 fd 直到删除；释放前再次验证路径，替代对象不因已知替换而被删除。
- 打开时路径不存在可作无事可做；**打开后**消失必须复核，不能混同成功处理缺失文件。
- 竞争、异常元数据、路径替换及系统错误返回 `RECOVERY_REVIEW_REQUIRED`，关闭 fd 并保留仍在的现场。
- 完整恢复的孤立锁分支不再根据 stale 字符串直接 unlink；目录恢复后的锁清理也使用同一辅助入口。

分类阶段已经看到 live 的孤立锁仍跳过；分类 stale 但实际获取时竞争则明确要求复核。非 Linux 路径不变，只读 inspection 不获取锁。

## 测试

新增 `tests/test_recovery_orphan_lock.py` **13 项**：两个过期判断入口、缺失不创建、删除瞬间实际持锁和 fd 关闭、锁后替换/消失/删除错误、内容/权限/硬链接/FIFO/软链接异常、真实子进程持锁与释放后的恢复。

真实子进程用管道报告已取得 flock，父进程在其仍活且持锁时注入 stale 判断并执行完整恢复，确认拒绝且原 inode 保留；子进程释放后再次恢复成功。等待有界，finally 回收测试子进程；没有使用外部节点或向非测试进程发送信号。

```text
orphan-lock suite: 13 passed in 0.07s
local full: 948 passed, 37 skipped in 37.11s
```

本地 Python 3.11.2 仅为补充结果；34 个固定引擎测试及三个 Windows 测试跳过。full 总数更新为 **985**，远端要求 **982 passed + 三个指定 Windows skip**。

代码 head：`4e04e3fe846dc50826607eca7ac97d98830c55a5`。

## 远端验收

- run：[36461036856](https://github.com/wpuu/NodeLab/actions/runs/36461036856)
- job/check：`109059335909`，success，2 分 24 秒
- 事件 head：`4e04e3fe846dc50826607eca7ac97d98830c55a5`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 982 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已验证精确 head、成功状态、五条 notice 及固定报告全部字段，无 warning/failure。四套 gate 均 PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；准备为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 重叠用例不累加；annotations 验证不等于 artifact ZIP 内容验证。验收标签已移除，PR #2 保持草稿。

## 未关闭边界

普通 run 目录的 `recover_dir` 本体仍依赖先前锁探测，尚未在整个身份查询、信号和目录删除期间持有对应 run 锁；启动与恢复之间的协调也未完整解决。**本轮只让锁文件本身的删除取得实际锁，不倒推授权此前目录操作。**

释放/删除错误可能发生在目录已经处理之后；复核错误不代表回滚或“没有发生动作”。路径核对→unlink 仍不是敌对同身份写入/父目录替换下的原子事务，flock 只约束协作方。

不扩展 Windows、断电/主机重启、未知 PID 自动恢复、硬截止、外部节点或生产验收。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR #2 保持草稿，不合并 main，不修改支付设置，不声明 P0 CLOSED。
