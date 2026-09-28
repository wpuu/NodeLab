# NL-REVIEW-029 — Linux 恢复记录原子发布

日期：2026-09-28。承接审计 028，缩小 marker 更新时破坏上一份完整记录的风险；不改变生产授权或 main。

## 复现与实现

原 `_write_marker` 使用 w 模式截断 `.owner.json` 再写入。先加入序列化失败、文件 fsync 失败两项负控，旧实现均失败：未能保持之前完整记录。

Linux 路径现在：

1. 核对运行目录及既有 marker 的私有权限/非链接条件。
2. 在同目录用 mkstemp 排他创建 0600 的 `.owner-*.tmp` 文件；验证权限后才写入不含凭据的恢复元数据。
3. 完成 JSON 序列化、flush、文件 fsync，再关闭文件。
4. `os.replace` 原子替换 `.owner.json`；之后重新验证 marker 权限并 fsync 所在目录。
5. finally 关闭尚未移交的描述符、清除自己未发布的临时文件。发布后绝不把新 marker 当临时文件删除。

序列化/文件同步等发布前失败保留旧记录；发布后目录同步失败仍报告错误，新记录保持完整，不假装回滚。初次发布不先创建空 marker，失败进入既有 failed-enter 清理。

Windows 和其他非 Linux 路径保留原来的 ACL 创建/写入实现；没有用 Linux 原子替换声称 Windows ACL/持久性等价。

## 故障与恢复规则

活 owner 仍负责自己创建的临时文件和私有树。强制终止可能留下 `.owner-*.tmp`：**没有扩展自动恢复文件白名单**，带临时文件的目录仍返回 RECOVERY_REVIEW_REQUIRED，保留现场、不查询或终止记录中的进程。

这有意选择审阅而不是从旧/新/部分临时记录中猜测恢复身份。可能增加人工复核需求，不以删除临时文件或改写 marker 自动解除阻塞。

## 测试

新增 `tests/test_atomic_marker.py` 共 11 项，覆盖：序列化/文件 fsync 失败、成功发布顺序与 0600 权限、replace 前/后的异常、目录 fsync 失败、KeyboardInterrupt/SystemExit、fdopen 失败不泄露描述符、残留临时文件拒绝自动恢复，以及初次发布失败不进入 YAML 写入阶段。

```text
atomic marker + engine session + boot recovery + P0 safety
79 passed in 4.13s

PYTHONPATH=src .venv/bin/python -m pytest -ra
761 passed, 37 skipped in 32.96s
```

full 总数随新增 11 项由 787 更新为 **798**，三个具名 Windows skip 不变。代码 head：`98b8d6c9bfab1c041f3cc2e20b56111dc55fa657`。提交差异检查通过。

## 远端验收

- run：[36417115761](https://github.com/wpuu/NodeLab/actions/runs/36417115761)
- 已验收 head：`98b8d6c9bfab1c041f3cc2e20b56111dc55fa657`
- job/check ID：`108910796275`，job success，2 分 20 秒
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- event 为 pull_request，默认 checkout PR merge revision；上述 SHA 为事件 head。

通过 GitHub API 读回并核对 head、success 与固定 JSON check annotations：

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 795 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。只跳过三个指定 Windows 测试；五条 notice，无 warning/failure annotation。原子发布未破坏本次真实引擎会话/协议和既有孤儿恢复用例；不把注入 I/O 错误等价为掉电测试。

结果核对后移除 opt-in 标签，避免文档提交重复运行；PR #2 保持草稿，未合并 main。后续文档 head 不冒充上述已验收 head；独立 gate 与 full 的重复用例不累加。

## 未关闭

原子可见性与 fsync 调用不等于实际断电持久性验收；没有执行掉电、主机重启或敌对并发目录替换实验。仍依赖私有目录不被同身份进程恶意替换，路径操作不是完整 dirfd 隔离边界。

子进程创建到首次 child marker 的窗口仍存在；停止失败但 marker 随目录删除的恢复材料缺口仍在。Windows、运行中配置变化、socket 身份非原子竞态和生产授权仍需独立推进。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；无全面崩溃恢复或 P0 CLOSED 结论。
