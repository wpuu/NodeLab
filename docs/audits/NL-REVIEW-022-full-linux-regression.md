# NL-REVIEW-022 — Python 3.12 / 固定 Mihomo 全量 Linux 回归通过

日期：2026-09-28。承接审计 021，补跑三套独立 gate 以外的测试，未修改付费设置或合并 main。

## 全量 gate

`scripts/f2_session_gate.py --suite full` 新增 `LINUX_FULL_REGRESSION`：

- 与既有 gate 共用 Linux/Python 3.12+、明确二进制路径和依赖前置检查。
- 子进程设置固定 executable，移除自定义摘要和 pytest 参数/插件覆盖，关闭第三方插件自动加载。
- 当前显式固定预期总数为 **688**，不是从本次 pytest 报告推导预期值。以后新增/删减测试须同时审阅并更新该常量。
- 要求每个 testcase 身份非空、不重复，精确总数，无 failure/error，pytest 退出码为 0。
- 只允许 `tests.test_windows_safety_gate` 中以下三个具体用例以 `pytest.skip` 类型跳过：
  - `test_windows_e_volume_dacl_before_and_during_private_yaml`
  - `test_windows_exact_pid_and_external_listening_port_untouched`
  - `test_windows_real_junction_is_not_deleted_through`
- 少测、多测、重复身份、额外 skip、同数量不同身份 skip、xfail、预期 Windows skip 缺失都不能通过。既有 session/Trojan/VLESS gate 仍要求零 skip。
- full gate 失败诊断仅输出源码 AST 白名单中的模块/测试函数名；去除参数 ID，不输出异常文本、路径或原始 JUnit。未知项为固定 `UNCLASSIFIED`。
- full 的 `route_proof=NOT_RUN` 表示汇总 gate 不单独授予路由证明；具体协议证明仍由对应协议 gate 给出 `LOCAL_FIXTURE_ONLY`。

新增 12 个 gate/脱敏测试，工作流参数化校验增加 1 项。GitHub workflow 加入完整回归步骤，并将 `full.json` 加入既有固定报告白名单与 check notices；不上传原始 pytest XML 或引擎日志。

## 实际远端证据

- 已验收 head：`1325490ce9ae1212b6b7bb8647a575d837af89c4`
- run：[36403873841](https://github.com/wpuu/NodeLab/actions/runs/36403873841)
- event：pull_request，默认 checkout PR merge revision；上述 head 是 PR 事件 head。
- job/check ID：`108868158025`
- job：success，2 分 8 秒
- 环境：Ubuntu 24.04、setup-python 3.12、官方固定 Mihomo v1.19.31 compatible，压缩包和二进制双摘要准备通过。

通过 GitHub API 读回 run 元数据和 check annotations，并程序化核对 head、success、精确计数及所有门禁字段：

| gate | status / code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | PASS / FULL_REGRESSION_OK | 685 | 3 | NOT_RUN |
| F2_LINUX_SESSION | PASS / SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | PASS / LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | PASS / LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

各报告均 `real_node_used=false`、`real_node_test_allowed=false`、`windows_acceptance=NOT_RUN`。独立 gate 和 full 内重复覆盖的用例不能累加为独立测试总数。

添加标签与 PR head 更新事件有短暂先后差：还触发了旧 head `6617b71` 的 run `36403867017`，但它不是本轮全量验收依据。未为抢占队列而中断已有任务；工作流依照既有 concurrency 串行运行。

## 本地回归

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
651 passed, 37 skipped in 30.50s

git diff --check
通过
```

本地 Python 3.11.2 仍缺少可用固定二进制，37 个 skip 不变。远端在相同本轮测试集合中执行了其中 34 个真实二进制/配置/启动/会话/协议测试，仅保留 3 个 Windows skip；不能把本地与远端数量相加。

## 剩余边界与交接

本轮移除 opt-in 标签后再记录文档，避免文档提交重复运行。后续文档 head 不应冒充已验收 head；PR #2 仍为草稿。actions 的 Node 20 目标被平台强制 Node 24 的警告仍存在，后续可单独升级 pin 并复验。

Linux 全量与实际本机协议验收已有证据；尚不证明 Windows、普通短请求采样可靠性、崩溃恢复、严格硬 deadline、Vision/WS/gRPC/Reality 实际握手或生产探测安全性。进程身份绑定等历史审计风险仍需审阅。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；不宣称 P0 全部关闭。下一步可优先审阅累计实现与剩余风险，再安排 Windows 验收或 CI 运行时维护，而不是开放外部节点测试。
