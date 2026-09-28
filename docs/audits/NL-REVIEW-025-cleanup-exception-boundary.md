# NL-REVIEW-025 — 清理异常不能跳过明文删除尝试

日期：2026-09-28。承接审计 024，检查 `RunContext.close` 的异常边界；未开放外部节点或修改 main。

## 复现问题

原 `close` 顺序调用 `_stop_child()`、`_remove_private_tree()`。虽然两个 helper 通常返回 bool，但意外 wrapper RuntimeError 或未在 helper 中处理的 KeyboardInterrupt/SystemExit 会越过这条顺序链，导致明文删除步骤未被尝试。另有：

- helper 返回整数 1 等 truthy 值也可能被当作清理确认。
- `_drop_lock` 的意外异常可能原样冒出。
- 既有 `SECRET_CLEANUP_FAILED` 未显式 suppress context，可能在格式化异常时带出含敏感文本的先前 body exception。

先添加 10 项故障注入测试，在旧实现上全部失败；随后修复并再补两项边界测试。测试使用真实私有文件、OS 锁与自己持有的 Python 子进程，但故障为注入，不冒充真实操作系统崩溃。

## 修改

- `close` 在 try/finally 中分别尝试停止与删除；未预期异常或取消不能让停止阶段直接绕过删除尝试。
- 两项均只有 `is True` 才算明确确认。任一未知/失败都不释放所有权锁、不设置 closed，不把可能存活的子进程标为已停止。
- 错误统一为 `PrivateRunError("SECRET_CLEANUP_FAILED") from None`，不回显原始异常或先前 body exception。
- 锁释放异常也报告固定失败，不标记 closed；若释放已经部分完成，不声称锁一定仍持有。
- 没有再发起第二轮停止来重置预算，没有按 PID/端口猜测或杀其他进程。正常 body 异常/取消在清理成功时仍由原 context manager 传播。
- 故障撤销后同一所有者可重试 close；测试不以本次删除失败后手工删文件来伪造首次成功。

## 测试

新增 `tests/test_private_cleanup_faults.py` 共 12 项：停止/删除的 RuntimeError、KeyboardInterrupt、SystemExit，两个 helper 的 truthy 非 bool 返回，锁释放前/完成后的异常，先前 body 异常脱敏，以及停止/删除同时异常仍各尝试一次。

检查实际 YAML 是否删除、子进程是否仍存活、锁是否仍归属、closed/active 标志与故障撤销后的重试。测试 fixture 最终停止自己的子进程，不遗留后台任务。

```text
新增故障测试：12 passed in 0.29s

PYTHONPATH=src .venv/bin/python -m pytest -ra
700 passed, 37 skipped in 31.32s
```

full gate 总数由 725 随新增 12 项更新为 **737**；只允许三个指定 Windows skip 的规则不变。代码 head：`d044cccdeb5cd303a9fa42a4f8bf92b9faac6648`。提交差异检查通过。

## 远端验收

- run：[36410716164](https://github.com/wpuu/NodeLab/actions/runs/36410716164)
- 已验收 head：`d044cccdeb5cd303a9fa42a4f8bf92b9faac6648`
- job/check ID：`108889982043`，job success，2 分 15 秒
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- event 为 pull_request，默认 checkout PR merge revision；上述 SHA 是事件的 PR head。

通过 GitHub API 读回并核对 head、success 与固定 check annotations：

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 734 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。只跳过三个指定 Windows 测试。真实引擎正常路径再次通过；故障注入不冒充真实 OS 崩溃。独立 gate 与 full 的重复测试不能累加。

核对后已移除 opt-in 标签，避免文档更新重复触发。PR #2 保持草稿，不合并 main；后续文档提交不是上述已验收 head。

## 未关闭的风险

删除本身失败时，明文可能仍存在；本轮只能尝试并报告失败，不能保证所有异常下文件必定删除。强制杀进程/断电无法由 Python finally 保证。

停止失败但删除成功时，活子进程仍由当前内存中的 owner 持有；此时 marker 也已随目录移除，不能据此宣称所有者随后崩溃时有完整 orphan 恢复证据。锁释放的任意 OS 部分失败、敌对并发文件系统及 Windows 语义仍需独立审阅/验收。

历史 socket/PID 非原子竞态、协作 deadline 和运行中配置变更等限制保持。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；不宣称 P0 全部关闭。
