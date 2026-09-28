# NL-REVIEW-034 — Linux 创建前启动意图与未接管状态

日期：2026-09-28。承接审计 033，给 child 创建到身份发布之间的未知状态留下可见阻塞证据；不承诺找回所有未知 PID。

## 实现

Linux 的真实引擎路径（config-test/runtime）和 synthetic 路径在 Popen 前执行：

1. 核对私有目录，排他创建 0600、NOFOLLOW/CLOEXEC 的 `.owner-launch.tmp`。
2. 只写固定 `{"state":"launch_pending"}`，不含 YAML、凭据、端点、token 或命令行。
3. flush + 文件 fsync + 目录 fsync 完成后，才标记内存中的 launch-unclaimed 并调用 Popen。
4. Popen 返回后立即保存 raw_child，再解除未接管状态、建立包装器并获取身份。
5. 完整 child marker 发布成功（包括其文件/目录同步）后，才 unlink 启动意图并同步目录。

短暂 child 的身份不可读时，只有 Popen 已观察到退出才允许写显式空 child；仍活着的不可验证 child 不会通过清除意图伪装成没有 child。

文件名属于既有 `.owner-*.tmp` 元数据保留范围，但**不加入恢复白名单**。因此意图残留导致 RECOVERY_REVIEW_REQUIRED，在 owner/child 查询之前保留整个现场；不根据旧 marker 的全 null 字段猜测没有进程，也不解析意图来猜 PID。

## 错误语义与兼容性

- 意图同步失败发生于调用 Popen 之前：不启动 child，内存 owner 仍能正常清理自己的目录。
- 构造器可能创建 child 后才抛错/取消；没有返回 Popen 就保持 launch-unclaimed。close 不把 raw_child=None 当作停止成功，仍尝试删除 YAML/非恢复负载，保留 marker/意图和锁，报告 SECRET_CLEANUP_FAILED。不能在同一上下文重试启动或写入新 YAML。
- Popen 已保存后，无论包装、身份、marker、意图移除还是最后目录同步出错，仍有精确 Popen 所有权供原清理路径停止 child。退出已确认后可以删除整个私有树。
- 初次 Popen 抛错的会话现在可能由 PROCESS_START_FAILED 变为 SECRET_CLEANUP_FAILED，且不再保证空目录；即使某次错误实际上发生在创建之前，也不会仅凭异常类型推定没有 child。
- 构造器未知状态没有自动清除或重置接口。不要盲删意图文件来允许恢复。

Windows 不写此意图文件，没有迁移其持久化协议；通用 synthetic 内存防重入条件同时收紧，未宣称 Windows 验收。

## 新增测试与真实中断证据

新增 `tests/test_launch_intent.py` **15 项**：

- 首先两项 synthetic/engine 创建前意图负控在旧实现均失败；修复后检查 0600、无测试秘密、Popen 前存在以及 child marker 后清除。
- 文件/目录 fsync 失败不调用 Popen；fdopen 错误关闭不可继承的 fd。
- 构造器在真实 child 创建后抛 OSError/RuntimeError/KeyboardInterrupt/SystemExit：运行上下文没有拿到 Popen，不把停止记为成功，删 YAML、保留意图、拒绝重试/新 YAML。测试 harness 保留自己的真实 Popen 做最终终止，不让生产代码猜测该 PID。
- 已接管 child 后 marker/意图移除/身份查询失败仍能通过原始 Popen 清理；最终目录同步失败保留完整 child 记录和所有权。
- 同步顺序明确为意图文件→目录→spawn→child marker 文件→目录→意图 unlink 后目录。
- **真实独立 owner**在构造器创建 child 之后、返回 Popen 之前 `os._exit(0)`：旧 marker 的 child_pid 仍为 null，意图及 YAML 保留；恢复拒绝且不改变文件，实际 child 仍活着。测试 harness 通过自己另外记录的完整身份/pidfd 做最终清理；恢复模块没有获得或使用这份旁路身份。

既有 engine-session/P0 构造器失败断言同步更新，继续证明 YAML 删除和固定错误文本。只有明确知道 fixture 在创建前抛错的测试 teardown 才清理其模拟未接管状态；这不是生产恢复能力。

```text
launch intent + engine session + recovery evidence + P0 safety
78 passed in 4.40s

PYTHONPATH=src .venv/bin/python -m pytest -ra
854 passed, 37 skipped in 31.27s
```

本地 Python 3.11.2 为补充证据；34 个固定引擎用例与三个 Windows 用例跳过。full 总数从 876 增至 **891**，要求 **888 passed + 三个指定 Windows skip**。代码 head：`bcdad0b9d14dc592e411c2a4099192f54ecfc007`。

## 远端验收

- run：[36442505342](https://github.com/wpuu/NodeLab/actions/runs/36442505342)
- job/check：`108996326066`，success，2 分 3 秒
- 已核对事件 head：`bcdad0b9d14dc592e411c2a4099192f54ecfc007`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交明确区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 888 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对运行成功、精确 head、固定结果及安全字段。全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；五条 notice，无 warning/failure。准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加，不把 annotations 核对冒充 artifact ZIP 内容核对。验收后移除 opt-in 标签，PR #2 保持草稿，未合并 main。

## 尚未证明

本轮将创建期不确定性从“可能像空记录”改为“有明确残留、必须复核”，**没有自动发现或终止尚未记录 PID 的 child**，也没有使进程创建与磁盘记录成为一个原子事务。

真实 owner 直接退出没有机会执行 close 时，YAML 可能仍在私有目录；显式恢复因意图残留保留现场，需要人工处理。构造器未知错误也可能保留 live 锁直到 owner 退出，不可冒充成功关闭。

fsync 调用及 owner 退出实验不是实际掉电/主机重启验收；可信私有目录/proc 的前提、敌对父目录替换、非原子 socket/PID/token 检查和硬截止问题仍在。旧版本在没有写过意图的创建期崩溃，不能因此补回证据。Windows、外部节点与生产授权未开放。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；保持草稿 PR，不合并 main，不改支付设置，不声明 P0 CLOSED。
