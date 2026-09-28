# NL-REVIEW-038 — Linux 锁文件核验与未知状态拒绝

日期：2026-09-29。使只读检查与实际恢复对锁文件的外观要求一致，收紧 unknown 与 live/stale 的区分。

## 复现与变化

原 Linux `_lock_state` 仅预先拒绝软链接，打开后直接 flock：异常类型、权限、硬链接或有内容的文件也可能被判 stale；任意 flock OSError 都被判 live。

初始七项负控（四种异常文件与三个后端错误）在旧实现全失败。本轮：

- 锁路径预检查及已打开 fd 的 fstat 均要求普通文件、当前 UID、0600、单硬链接且长度为零。
- Linux 打开增加 NONBLOCK，保留 NOFOLLOW/CLOEXEC；核验后被换为 FIFO 等对象也在 flock 前拒绝。
- 只有 EAGAIN/EWOULDBLOCK 锁竞争按 live 处理；权限、资源、不支持等其他错误为 unsafe。解锁错误也不能声称成功探明 stale。
- 恢复扫描后的分类不是授权：处理 run 目录之前再次确认锁为 missing/stale；unsafe 或新近 live 则要求复核，不查询进程、不删 YAML。
- 只读 inspection 复用相同的元数据条件，但仍不打开或探测锁。

非 Linux 的既有锁分支不迁移；未获得 Windows 验收。旧的非空或权限不符锁文件可能阻塞新运行/恢复，不自动迁移、不盲删。

## 测试

新增 `tests/test_recovery_lock_validation.py` **19 项**：异常锁、后端错误及权限错误、正常竞争、解锁错误、打开时类型/权限变化和 fd UID 不符、fd 关闭、真实 missing/live/stale 生命周期、恢复前锁变为 live/unsafe、不安全记录保留 YAML/marker、未知后端阻塞新运行、inspection 同规则。

```text
lock validation + inspection + P0 safety
74 passed in 3.57s

PYTHONPATH=src .venv/bin/python -m pytest -ra
920 passed, 37 skipped in 37.64s
```

full 总数 **957**，要求 **954 passed + 三个指定 Windows skip**。代码 head：`d5b9a28e4f418e8779d7295a6a581aaceca3f8e4`。

## 验收结果

本地 Python 3.11.2 仅为补充证据，34 个固定引擎及三个 Windows 用例跳过。

- run：[36454765941](https://github.com/wpuu/NodeLab/actions/runs/36454765941)
- job/check：`109038168013`，success，2 分 27 秒
- 已核对事件 head：`d5b9a28e4f418e8779d7295a6a581aaceca3f8e4`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交明确区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 954 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对运行成功、精确 head、固定结果及安全字段。全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；五条 notice，无 warning/failure。准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加，不把 annotations 核对冒充 artifact ZIP 内容核对。验收后移除 opt-in 标签，PR #2 保持草稿，未合并 main。

## 仍未关闭

flock 探测随后会释放，检查与后续文件/进程动作不是原子事务。仍未完整处理 stale 恢复锁的并发接管、检查后路径替换和 unlink/recreate 竞态；不得把元数据核验称为稳定锁所有权转移。

可信私有目录/proc 前提、未知 PID 自动恢复、硬截止、断电/主机重启、Windows 和生产授权仍未完成。只读检查保持不改变现场、不授权恢复。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR 保持草稿，不合并 main，不改支付设置，不声明 P0 CLOSED。
