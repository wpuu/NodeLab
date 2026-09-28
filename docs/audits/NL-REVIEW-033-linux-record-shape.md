# NL-REVIEW-033 — Linux 缺失及不完整恢复记录拒绝

日期：2026-09-28。承接审计 032。缩小不完整记录被解释为没有 child 的误清理风险，不改变生产授权。

## 旧实现负控

原恢复用 `data.get()` 取 child 三个字段，缺键与显式 null 混同。child_pid 为空但仍有创建时间/可执行指纹时，可能跳过 child 停止直接删除目录。缺 marker 的目录（包括只含 YAML 的目录）也会绕过 owner 退出证明直接删除。

先加入缺 child 字段、部分身份、无 marker 的空/含 YAML 目录共 **11 项负控**，旧实现全部失败。测试使用合成数据及 mock 终止器，不向任意记录 PID 发信号。

## Linux 新规则

- 恢复 run 目录必须有 `.owner.json`，即使目录为空也不能用名称/权限代替 owner 依据。缺 marker 返回 RECOVERY_REVIEW_REQUIRED，保留目录及内容。
- child_pid、child_create_time、child_exe_fingerprint 三个键必须全部存在。
- 接受两个记录形状：三字段全部显式 null，或正整数 PID、正整数创建时间、32 位小写十六进制 executable 路径指纹。布尔值不是整数。
- 部分 null、缺键、零/负数、指纹为空/长度不符/大写/非十六进制均不能构成有效 Linux marker。
- 记录形状检查发生在 owner/child 身份查询或终止之前；失败保留 YAML 和 marker 原始字节。重复恢复不改变此结果。
- 全部 null 仍须取得 owner 退出证明；完整 child 身份仍须经过既有 pidfd 终止核验。形状有效本身不是自动删除授权。

非 Linux 保持既有缺 marker 和 child 字段处理分支，Windows 未因此获得验收。

## 兼容性与秘密清理边界

旧的不完整记录（包括 PID/stamp 已写出但 executable 指纹缺失）现在要求人工复核，不再先删除 YAML。缺 marker 的准备期空目录也可能阻塞新运行。这是有意更严格的恢复规则：不明确的记录不能授权修改现场；不要自行补 null、填指纹或盲删目录来绕过。

当前 owner 在内存中持有运行上下文的正常 close/失败清理不变。有效完整记录的停止失败仍按审计 030 尝试删除负载、保留恢复依据；不要将该规则扩展到未通过记录校验的目录。

## 测试

新增 `tests/test_recovery_record_shape.py` **26 项**，覆盖缺键、缺 marker、部分身份、非法字段、全部键省略、显式 null/完整身份正向流程及残留阻塞新运行。拒绝测试重复调用恢复并核对文件字节和目录保留，禁止 owner/child 查询/停止。

```text
record shape + owner + boot + evidence recovery + P0 safety
114 passed in 3.79s

PYTHONPATH=src .venv/bin/python -m pytest -ra
839 passed, 37 skipped in 32.33s
```

本地 Python 3.11.2 是补充证据，34 项真实引擎与三个 Windows 用例跳过。full 总数由 850 增至 **876**，要求 **873 passed + 三个指定 Windows skip**。代码 head：`e70093bdd593e47125c2d6465feca4c367f04e74`。

## 远端验收

- run：[36440387947](https://github.com/wpuu/NodeLab/actions/runs/36440387947)
- job/check：`108989022640`，success，2 分 10 秒
- 已核对事件 head：`e70093bdd593e47125c2d6465feca4c367f04e74`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交明确区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 873 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对运行成功、精确 head、固定结果及安全字段。全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；五条 notice，无 warning/failure。准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加，不把 annotations 核对冒充 artifact ZIP 内容核对。验收后移除 opt-in 标签，PR #2 保持草稿，未合并 main。

## 未关闭

三字段全 null 表示格式上的空 child 记录，**不证明进程创建到 child marker 发布之间没有出现崩溃**。本轮没有增加创建意图记录，也没有消除创建/更新 marker 窗口，不能声称所有孤儿都会自动恢复。

记录不是签名，可信 proc/私有目录前提不变；父目录替换、同身份恶意改写、非原子 socket/PID/token 校验、主机重启/断电以及 Windows 验收仍未解决。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`。保持草稿 PR，不合并 main，不改支付设置，不声明 P0 CLOSED。
