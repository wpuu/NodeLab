# NL-REVIEW-044 — Linux 正常 close 的目录身份绑定

日期：2026-09-29。接续 043，将目录 inode 依据保留到正常运行清理；不把路径核验描述成原子删除事务。

## 复现与修复

两个初始负控在旧实现 **2 failed in 0.08s**：运行目录被重命名并在原路径放置另一目录后，正常停止分支删除替代目录；停止未确认分支删除替代目录中的负载。

Linux 成功初始化现通过 `os.dup` 保留初始目录 fd 的同一 inode，而非重新打开路径。dup 默认不可继承；043 的临时初始化 fd 仍关闭。复制失败沿用失败初始化清理，不发布成功上下文。

- 正常目录清理验证所持 fd 与当前路径均为当前 UID/0700 目录，设备/inode 相同；树安全检查前后均核验，再执行删除。
- 停止未确认时的负载清理也先核验该绑定；不因仍有 run 锁或路径名字相同就删除替代负载。
- 路径缺失、软链接、替换、权限变化或 fd 核验失败均不授予删除权限，close 报 SECRET_CLEANUP_FAILED。
- 失败保留目录 pin 和原 run 锁以支持安全重试；成功停止、清理及锁释放后关闭 pin。正常运行因此多持有一个目录 fd；未成功 close 的实例仍占有资源直到重试或进程退出。
- child 停止规则不变：已知自有 child 可以先被停止，随后目录核验失败仍须报告清理失败，不误报全部完成。

非 Linux 不保留此 pin；只读 inspection 不增加动作。

## 测试

新增 `tests/test_owned_directory_binding.py` **12 项**：两条替代目录负控、两种停止状态下的权限变化、pin 生命周期/不可继承、dup 失败、停止失败后保留 pin 并重试、树检查后替换、软链接/缺失路径、真实自有 child 停止但替代目录保留、fstat 错误。

真实 child 用例启动项目既有合成 Python 子进程，移动原目录后执行 close，确认 child 已停止、替代目录与移走目录的合成 YAML 均保留。测试 harness 恢复自己创建的路径后再次 close；该操作不是产品自动搜索/找回目录的功能。

```text
owned directory binding suite: 12 passed in 0.10s
local full: 998 passed, 37 skipped in 37.40s
```

本地 Python 3.11.2 仅补充证据；34 个固定引擎测试与三个 Windows 测试跳过。full 总数 **1035**，远端要求 **1032 passed + 三个指定 Windows skip**。代码 head：`2b108df70433b153761834c2f6a6fb04c3111f00`。

## 远端验收

- run：[36467835941](https://github.com/wpuu/NodeLab/actions/runs/36467835941)
- job/check：`109082271477`，success，2 分 17 秒
- 事件 head：`2b108df70433b153761834c2f6a6fb04c3111f00`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 1032 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对精确 head、成功状态、五条 notice 与全部固定字段，无 warning/failure。四套 gate 均 PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；准备为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加；annotations 验证不冒充 artifact ZIP 内容核验。opt-in 标签已移除，PR #2 保持草稿。

## 边界与剩余工作

本轮保证已观察到目录绑定不一致时拒绝清理，不保证核验→rmtree/unlink 之间没有替换；负载辅助函数内部也未把每次文件操作绑定为原子目录事务。根父路径绑定、恢复流程目录 fd、正常 run 锁释放路径和凭据写入仍需独立审查。

原目录被移动时不会自动定位其新路径或盲目通过 fd 擦除；该处明文可能继续存在，报错不能当作秘密已清除。mkdir→首次目录打开、同身份恶意写入、任意 syscall 中断/close 错误、实际断电与主机重启仍有边界。

Windows、未知 PID 自动恢复、硬截止、生产/外部节点未验收。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR #2 保持草稿，不合并 main，不改支付设置，不声明 P0 CLOSED。
