# NL-REVIEW-023 — 拒绝 controller 歧义 JSON

日期：2026-09-28。承接审计 022 的安全风险审阅；本轮定位并修复一个具体输入解析缺口，没有开放生产探测或修改 main。

## 可复现问题与范围

`engine_launch._controller_json` 原来使用 Python 默认 `json.loads`：

- 重复键保留最后一个值。例如 `{"mode":"direct","mode":"rule"}` 会被静默归一化为 rule。
- 嵌套 `chains`、PROBE.now、rule.proxy 等字段也会覆盖；一个先含 DIRECT、后含 NODE→PROBE 的重复 chains 字段，解析后可能只留下后者。
- NaN、Infinity、-Infinity 被接受；JSON 数值 `1e400` / `-1e400` 也会溢出为 Python 非有限浮点值。

先加入 13 个拒绝测试，在旧实现上全部失败，确认不是仅依据代码推测。它们是合成响应复现，不代表已观测到固定 Mihomo 产生歧义数据，更不证明攻击者能绕过既有 controller 认证和 socket/PID 检查。本轮修复属于证据入口的 fail-closed 加固，不将其夸大为已证实的远程攻击路径。

## 修复

在原有 1 MiB 字节上限、严格 UTF-8、HTTP 200、无代理环境/重定向、deadline 和响应关闭逻辑之内：

- `object_pairs_hook` 拒绝任意深度的重复键，包括相同值重复和 Unicode escape 解码后的同名键。
- `parse_constant` 拒绝 NaN 和正负 Infinity。
- `parse_float` 校验有限值，拒绝指数溢出；普通有限浮点、完整精度整数和含有 `NaN` 字样的字符串不受影响。
- 异常仍由既有 `_controller_json` 边界返回 None，不回显键名、JSON 正文、token 或原始异常。
- 同名键出现在不同对象里仍然合法；没有把所有键做跨对象去重。

没有新增 HTTP 调用、重试或运行时授权，也没有改变 router matcher 或生产输出 schema。

## 新增测试与本地回归

新增 19 项：13 个歧义/非有限数负控、3 个正常数据保留测试、3 个实际 loopback HTTP 用例（重复键拒绝、非有限数拒绝、合法 null 接受）。构造数据和认证 token 均为测试生成；不使用真实节点凭据。

```text
controller isolation + bound reader + deadline 定向测试
102 passed in 8.30s

PYTHONPATH=src .venv/bin/python -m pytest -ra
670 passed, 37 skipped in 31.08s
```

全量 gate 预期总数由 688 随新增 19 项明确更新至 **707**。只允许三个具名 Windows skip 的规则未放宽。提交差异检查通过。

## 真实远端复验

- 已验收 head：`c5b6fce3c6fa478e30c39a806137ab958aa4aaf9`
- run：[36405427124](https://github.com/wpuu/NodeLab/actions/runs/36405427124)
- job/check ID：`108872893313`
- event：pull_request（默认 checkout PR merge revision；上述 SHA 是事件 head）
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- job success，2 分 19 秒

通过 GitHub API 读回并核对 head、success 和固定字段 check annotations：

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 704 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。严格 JSON 解析没有破坏本轮真实引擎 controller/会话/本机协议实验。全量与独立 gate 重复用例不累加。

## 剩余边界

本轮未消除 socket/PID 查询与 token 发送间的非原子竞态、运行中配置变更、崩溃恢复或协作 deadline 的限制。未执行 Windows 验收、普通短请求采样或更广传输握手。固定 actions 的 Node 20 目标警告仍待独立维护。

结果核对后已移除 opt-in 标签，避免文档提交重复运行。PR #2 保持草稿，不合并 main。文档提交不是上述已验收 head。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；无 P0 全部关闭结论。
