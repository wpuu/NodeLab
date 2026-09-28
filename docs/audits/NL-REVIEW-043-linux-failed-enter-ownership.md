# NL-REVIEW-043 — Linux 初始化失败清理的目录所有权依据

日期：2026-09-29。限定 `RunContext.__enter__` 失败路径与其后续 `close()`，不宣称正常运行期间所有路径操作都已绑定描述符。

## 复现与变化

旧实现只要 `run_dir` 已赋值且路径当前是目录，就在初始化异常时 rmtree。两个确定性负控在旧实现 **2 failed in 0.04s**：mkdir 遭遇已存在目录仍删除它；成功创建后目录路径被换成另一个目录，发布异常时删除替代目录。

Linux 初始化现在：

- 仅在 `mkdir` 成功后，以 O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC 打开目录并保持描述符，直到初始化与根准入释放全部完成。
- 失败清理要求该 fd 存在，fstat 为当前 UID/0700 的目录，路径通过既有私有目录核验，且路径 lstat 的设备/inode 与 fd 一致。
- mkdir 冲突、无法打开目录、路径消失或替换时，不递归删除当前路径；原目录被重命名时也不搜索它的新位置。
- 失败初始化释放 run 锁时核对持有 fd 与路径，不盲删替代锁，关闭已持描述符。
- 记录失败初始化的终态：只有已确认清理的失败实例可以无动作 close；否则固定报 SECRET_CLEANUP_FAILED。后续 close 不再进入普通路径清理或进程处理，不能绕过失败时的所有权拒绝。
- 失败实例不可重新进入，包括尚未设置 run_dir 就失败的实例；调用者需要新建上下文，避免保留的失败状态影响未来 close。

成功初始化仍释放临时目录 pin，长期持有的 run 锁协议不变。非 Linux 清理分支未迁移；inspection 不增加动作。

## 测试

新增 `tests/test_failed_enter_ownership.py` **12 项**：mkdir 冲突、目录重命名后被替换、四种发布异常的已创建目录清理与 fd 关闭、软链接/缺失替换、打开目录失败、失败上下文不可复用、run 锁替换保留、成功初始化 pin 关闭且 run 锁继续持有。

用例使用真实本地 mkdir/rename/symlink 和目录 fd，并注入失败点；不是实际断电、敌对并发调度穷举或 Windows 证明。原有真实进程与协议回归继续执行。

```text
failed-enter ownership suite: 12 passed in 0.05s
local full: 986 passed, 37 skipped in 36.62s
```

本地 Python 3.11.2 仅补充证据；34 个固定引擎测试和三个 Windows 测试跳过。full 总数 **1023**，远端要求 **1020 passed + 三个指定 Windows skip**。代码 head：`db925dffa7ce6e91831e984c6e83b41168ea49e1`。

## 远端验收

- run：[36466831952](https://github.com/wpuu/NodeLab/actions/runs/36466831952)
- job/check：`109078907886`，success，2 分 27 秒
- 事件 head：`db925dffa7ce6e91831e984c6e83b41168ea49e1`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 1020 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对精确 head、成功状态、五条 notice 与全部固定字段，无 warning/failure。四套 gate 均 PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；准备为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加；annotations 验证不冒充 artifact ZIP 内容核验。opt-in 标签已移除，PR #2 保持草稿。

## 兼容性与未关闭边界

无法取得目录 pin 或无法确认路径时，可能留下空目录/部分 marker；这是保留未知现场，不是成功清理。后续 close 不再自动重试删除，需显式复核/恢复；不应靠补 marker 或删除陌生路径绕过。

mkdir→首次 open 仍是非原子窗口，同身份恶意进程若在首次打开前替换目录，不在本轮完整防护范围。核对 inode→rmtree 也不是原子操作，父目录替换、不遵守协议的写入与任意 syscall 中断仍有边界。

正常初始化成功后目录 pin 即释放；正常 close 的目录/负载删除、恢复目录操作及根路径的描述符绑定仍需独立审查。本轮不为这些路径扩大所有权声明。文件系统错误可导致保留现场，清理不是回滚。

Windows、主机重启/断电、未知 PID 自动恢复、硬截止、生产/外部节点未验收。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR #2 保持草稿，不合并 main，不改支付设置，不声明 P0 CLOSED。
