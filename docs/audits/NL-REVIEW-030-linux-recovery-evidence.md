# NL-REVIEW-030 — Linux 停止失败时保留恢复依据

日期：2026-09-28。承接审计 029。修正 Linux 停止失败仍删除 marker 的已知缺口，不改变生产授权或 main。

## 复现与行为变更

原 owned close 和显式 stale recovery 即使没有确认子进程终止，也会尝试删除整个私有目录。明文清理优先级是正确的，但同时删掉 marker，会在 owner 随后退出时丢失已记录的子进程身份。

先加入两项负控（owned 停止失败、恢复停止失败后重试），旧实现均失败：YAML 虽已删除，恢复 marker 也不存在。

现在 Linux 在停止未确认时：

- 仍尝试删除 `probe.yaml` 及其他非恢复负载，包括引擎缓存目录；不会为了 marker 而保留 YAML。
- 保留应用写出的 `.owner.json` 和 `.owner-*.tmp` 原始字节，以及私有运行目录。
- 保留临时 marker 是为了不把未完成发布伪装成可选用旧记录的成功发布。显式恢复仍拒绝带临时文件的目录，不扩大白名单。
- owned close 报 `SECRET_CLEANUP_FAILED`，不设置 closed 或 private_tree_removed，保持当前锁/进程所有权；后续确认停止才删除全树、释放锁。
- 显式恢复只有返回值 **is True** 才把停止视为确认。False、None、truthy 非布尔值和 Linux 停止异常/取消均保留记录，负载清理成功则报 `PROCESS_STOP_FAILED`。
- 恢复负载清理若失败则仍报 `SECRET_CLEANUP_FAILED`；不把 YAML 未删除误报为成功。
- Linux 恢复失败也不主动移除该 run 的 stale lock；成功恢复才移除。

owner 退出后的 stale 残留会阻塞新运行，需后续恢复或人工复核；不能为了解除阻塞而盲删 marker。普通成功停止仍走原全树清理。

非 Linux 不切换为保留 marker 的清理策略，也不引入 Linux 的恢复停止异常吞并规则；精确布尔确认规则适用于恢复调用。Windows 仍未验收。

## 安全边界

清理前仍拒绝链接/重解析树，不删除外部目标。元数据不导出：应用 marker 仅有 opaque 目录/启动/可执行指纹、PID 和创建时间等，不含凭据或控制器 token，仍留在私有目录中。

这不是 marker 真实性证明，也不保证被同身份恶意进程改写过的文件不含秘密。失败的子进程可能仍持有内存中的秘密或再次写文件；无终止确认时仍是 FAIL。文件系统错误或不安全目录也可能阻止明文删除，不宣称必然清除。

## 新增测试与实际进程证据

`tests/test_recovery_evidence.py` 新增 14 项：

- owned 停止失败保留原 marker/锁且删 YAML，随后成功重试。
- 恢复停止失败后，保留同一真实 Python child 的 marker，再经真实身份/pidfd 路径停止。
- None、1、字符串不算停止成功；OSError/RuntimeError/KeyboardInterrupt/SystemExit 不使记录丢失，输出仅固定码。
- 临时 marker 保留、非恢复缓存移除；重复失败保留字节并阻塞新运行。
- 负载删除错误不报成功、外部链接目标不受影响。
- **独立真实 owner 进程**在注入停止失败后 `os._exit(0)`：YAML 已删、child 仍活、锁转 stale；再次注入恢复停止失败后，marker/锁仍在且稳定 pidfd 尚未 ready。恢复真实停止路径后，固定结果成功、原 child 的 pidfd ready、目录和锁均消失。

同步更新既有 fault/P0 断言：Linux 停止失败现在应保留目录/marker，但必须继续验证 YAML 删除、固定错误码、活 child 和后续重试，未删除或弱化这些失败检查。

```text
recovery evidence + private cleanup faults + P0 safety
59 passed in 3.71s

PYTHONPATH=src .venv/bin/python -m pytest -ra
775 passed, 37 skipped in 32.19s
```

full 总数从 798 增至 **812**，要求 **809 passed + 三个指定 Windows skip**；独立 session/Trojan/VLESS 用例不与 full 累加。

代码 head：`be17ca75378cca7e43684702f43ff0df444f9fdd`。

## 验收状态

- run：[36419262286](https://github.com/wpuu/NodeLab/actions/runs/36419262286)
- job/check：`108917763864`，success，2 分 26 秒
- 已核对事件 head：`be17ca75378cca7e43684702f43ff0df444f9fdd`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；上述 SHA 为事件 head，不把后续文档提交当作已验收代码。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 809 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

通过 GitHub API 读回并断言成功结论、精确 head、报告数值/固定码及安全字段。全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。共五条 notice，无 warning/failure；准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。没有以 annotation 核对冒充 artifact ZIP 内容核对。

验收后移除 opt-in 标签，PR #2 保持草稿，未合并 main。

## 仍未关闭

本轮覆盖的是**已成功记录身份之后**的停止失败与 owner 退出。子进程创建到 marker 首次发布、marker 更新失败时尚未记录新 child 的窗口仍存在；缺少/损坏/旧启动记录或临时文件歧义依然需要人工复核。

没有实际掉电或系统重启；不是恶意同身份进程、并发路径替换或全部文件系统场景的安全证明。Windows、严格硬截止、非原子 socket/PID/token 检查及生产授权仍需独立处理。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；不宣布 P0 CLOSED，不改支付设置，不合并 main。
