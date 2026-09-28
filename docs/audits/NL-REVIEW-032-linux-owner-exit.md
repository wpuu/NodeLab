# NL-REVIEW-032 — Linux 恢复前确认原 owner 已退出

日期：2026-09-28。承接审计 031 中明确保留的 owner 判断缺口，不改变生产授权。

## 旧实现负控

恢复原先调用 `owner.matches(process_identity(owner_pid))`。返回不匹配即继续处理 child 和目录，但不匹配也可能来自身份不可读、同进程 exec 导致可执行文件指纹改变；缺少 owner 创建时间则跳过检查。

先加入三项保留现场负控（不可读、同创建时间但 executable 变化、缺创建时间），旧实现 **3 failed**。这些是受控状态注入，不声称已发生实际误杀。

## 新规则

Linux 恢复在任何 child 查询/终止或文件删除之前，必须取得 `linux_owner_gone` 的精确 True：

- 先验证记录中的 PID/创建时间等字段；缺失、不合法则拒绝。
- 打开只用于查询的 pidfd。内核 ESRCH 确认不存在才可认为原 owner 已不在；API 不可用、权限不足或其他错误不能等价退出。
- 稳定 pidfd ready 可证明退出，包括尚未由父进程回收的进程。
- pidfd 尚未 ready 时读取实际身份；有效的同 PID、不同创建时间可证明记录中的原 owner 已不再占用该 PID。
- 相同创建时间、不同 executable 可能是 exec，不认定退出。身份不可读、缺 executable 或不合法身份也不能单独证明退出；只再查询同一个 pidfd 是否 ready。
- 关闭描述符，不调用 os.kill 或 pidfd_send_signal，也不向 owner 发信号。

未取得肯定结论时，返回 **RECOVERY_REVIEW_REQUIRED**，保留 YAML/marker，不尝试 child 停止。不以删除凭据优先原则越过仍可能存活的其他 owner。成功证明原 owner 不在之后，仍执行既有 boot、目录、child pidfd 和失败保留证据规则。

非 Linux 保持既有 owner 判断分支，Windows 仍待独立验收。旧内核/API 不支持时，即便实际 owner 已死，也可能需要人工复核；没有降级为 os.kill(pid, 0) 探测或数字 PID 发信号。

## 测试

新增 `tests/test_recovery_owner.py` **22 项**，包括：

- 三项旧实现负控；固定复核码、所有文件字节保留、禁止调用 child 停止。
- 不可读身份、缺指纹、同 stamp 的不同 executable、非法身份/不同 PID 不产生退出结论。
- 已知不同创建时间、初次或再次 pidfd ready，以及 ESRCH 正向证据。
- 权限/通用/溢出错误、API 缺失、缺失/零/负数/布尔 stamp、poll 错误与描述符关闭。
- Mock 负控禁止所有 owner 信号；真实自有 Python 子进程存活时返回 False，终止后通过独立 pidfd 确认退出，再在尚未回收时验证返回 True。测试只通过自身 Popen 终止自己的子进程。

```text
owner + boot + evidence recovery + P0 safety
88 passed in 3.84s

PYTHONPATH=src .venv/bin/python -m pytest -ra
813 passed, 37 skipped in 33.42s
```

本地 Python 3.11.2，仅作为补充；34 个固定引擎用例与三个 Windows 用例跳过。full 总数 **850**，要求 **847 passed + 三个指定 Windows skip**。代码 head：`c1ca762a42af4ec48b21bf04d68d66133652c999`。

## 远端验收

- run：[36438792012](https://github.com/wpuu/NodeLab/actions/runs/36438792012)
- job/check：`108983540257`，success，2 分 20 秒
- 已核对事件 head：`c1ca762a42af4ec48b21bf04d68d66133652c999`
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- pull_request 默认 checkout PR merge revision；事件 head 与后续文档提交明确区分。

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 847 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

GitHub API 已核对运行成功、精确 head、固定结果及安全字段。全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN；五条 notice，无 warning/failure。准备报告为 PREPARED/PINNED_BYTES_PREPARED、binary_executed=false。

独立 gate 与 full 用例不累加，不把 annotations 核对冒充 artifact ZIP 内容核对。验收后移除 opt-in 标签，PR #2 保持草稿，未合并 main。

## 未解决的边界

该判断依赖可信 marker、当前 boot 绑定和可信 proc 视图，不是记录认证；无法抵御同身份恶意改写或伪造创建时间。创建时间的内核粒度/身份模型不因此成为密码学唯一标识。pidfd 就绪证明的是被绑定进程的退出，并不构成整体文件系统事务。

仍未消除 child 创建到首次/更新 marker 发布的窗口；父目录替换、原地恶意改写、非原子 socket/PID/token 校验、主机重启/断电以及 Windows 验收仍需处理。不得据此开启生产节点测试。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`。PR 保持草稿，不合并 main，不改支付设置，不声明 P0 CLOSED。
