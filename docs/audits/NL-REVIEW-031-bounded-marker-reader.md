# NL-REVIEW-031 — Linux marker 描述符核验与有界读取

日期：2026-09-28。承接审计 030，收紧恢复读取边界，不开启生产探测。

## 旧实现负控

旧 `read_marker` 先按路径检查普通文件/权限/大小，再调用 `Path.read_text()` 整文件读取。两个操作之间如果目标变化，前面的核验不等于实际读取对象已核验，文件变大也可能绕过 4096 字节限制。

先加入三个受控替换测试：在路径核验完成后改变权限、追加内容使其超限、替换为指向外部合成记录的软链接。旧实现均返回可解析 marker 而不是拒绝，**3 failed**。这是注入竞态的复现，不是已发现实际外部攻击或实际泄漏。

## Linux 读取变化

保留原路径预检查，新增 `_read_linux_marker`：

1. `os.open` 使用 O_RDONLY / O_NOFOLLOW / O_NONBLOCK / O_CLOEXEC。
2. 用返回的同一 fd 执行 fstat，要求普通文件、当前 UID、0600、单一硬链接、大小不超过 4096 字节。
3. 实际读取只调用 `os.read(fd, 4097)`，读到超限即拒绝；不是先 stat 后无界读。即使 fstat 后文件变大，读取请求仍有上限。
4. 严格 UTF-8 解码，所有路径在 finally 关闭描述符；读取/打开/验证失败不产生有效 marker。
5. JSON 解析的 RecursionError 与格式/编码错误一样返回不可验证记录，不向后继续身份查询。

O_NONBLOCK 用于使被替换的 FIFO 能在等待写端之前接受 fstat 检查并被拒绝；不是普遍文件系统硬截止保证。硬链接 marker 现在也需要人工复核，不尝试自动迁移。

非 Linux 保持原来的文件读取方式；JSON 深度错误的固定拒绝同时生效。不声称 Windows 描述符/ACL 读取已验收。

## 测试

新增 `tests/test_marker_reader.py` **16 项**：

- 三种核验后路径变化的旧实现负控。
- FIFO 被非阻塞打开、在读取前拒绝，且 fd 不可继承并被关闭。
- fstat 后实际增长仍只请求 4097 字节；4096/4097 边界。
- 硬链接、已打开对象的 UID 不符在读取前拒绝。
- 空记录、错误编码、截断 JSON、过深 JSON 不进行 owner/child 身份查询或停止，保留 YAML 和 marker。
- fstat/read 异常不泄露 fd，不改动文件。
- fstat 后替换路径，读取来自已验证的原 fd，不重新打开新路径。

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
791 passed, 37 skipped in 32.86s
```

本地 Python 3.11.2，仅是补充证据；34 个固定引擎用例与 3 个 Windows 用例跳过。full gate 由 812 增至 **828**，期望 **825 passed + 三个指定 Windows skip**。代码 head：`373e0c8cb7c9a4bde47ec5620e1a6bdeb779a367`。

## 远端验收

- run：[36437457557](https://github.com/wpuu/NodeLab/actions/runs/36437457557)
- job/check：`108978955993`，success，2 分 16 秒
- 已核对事件 head：`373e0c8cb7c9a4bde47ec5620e1a6bdeb779a367`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交明确区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 825 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

已通过 GitHub API 核对运行成功、精确 head、固定结果及安全字段。全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；五条 notice，无 warning/failure。准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

没有把 annotations 核对冒充 artifact ZIP 内容核对；独立 gate 与 full 的重复用例不相加。验收后移除 opt-in 标签，PR #2 保持草稿，未合并 main。

## 限制仍在

O_NOFOLLOW 只限制最终路径分量；没有实现完整 dirfd 路径绑定，也没有证明父目录被敌对替换时的安全性。已打开普通文件仍可能被同身份进程原地修改；本轮证明的是对象检查和实际读取使用同一 fd、读取量有界，不是文件内容认证或完全原子快照。

单一硬链接是读取时的检查，不是永久条件。路径预检查发生 I/O 故障仍可能返回既有固定清理失败码；都不能授权删除或停止。

子进程创建到 marker 首次/更新发布的窗口、恢复 owner 身份查询中未知与退出的区分、socket/PID/token 非原子核验、实际重启/断电与 Windows 独立验收仍需推进。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`。不声明完整敌对文件系统防护、全面崩溃恢复或 P0 CLOSED。
