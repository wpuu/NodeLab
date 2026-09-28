# NL-REVIEW-011｜F3 连接证据匹配候选（纯函数）

日期：2026-09-28。F2 真实 session gate 仍受 NL-REVIEW-010 所述环境阻塞。本轮仅推进可独立验证的 F3 纯函数，不绕过真实引擎/Windows 验收门。

## 实现

新增 `src/nodelab/route_evidence.py`：

- 私有 `RequestWindow` 描述本地分配的 run ID、来源代号、原始 CONNECT Host/port、mixed port、本地 source port 和 UTC 纳秒请求窗口。
- 私有 `ConnectionSnapshot` 带采集器标记的 run ID、本地采集起止窗口及未公开 controller JSON。
- `match_connection` 要求采集窗口完全位于原请求窗口内；匹配 loopback 源/入站地址、三个端口、目标 Host、TCP/HTTPS 类型；唯一连接 ID、非 baseline/已消费 ID；引擎 `start` 处于原请求至采集完成之间；`Match` 规则、空 payload、严格 `[NODE, PROBE]` 链。
- `match_pair` 要求 EXIT_A/EXIT_B、同一 run、不同目标、顺序非重叠窗口、不同连接 ID；两源必须分别匹配，不能拿 A 的连接证明 B。
- 输入异常、缺字段、空快照、窗口错配、重放、歧义、错误链分别返回固定代号；不输出原始 metadata 或动态异常，不修改输入。
- `repr` 固定；连接 ID 仅留在私有匹配结果。无网络、无落盘、无 PASS 状态、无 confirmed_exit_ip，也不修改 probe/CLI/redaction 的生产 gate。

本阶段**强制要求本地 source port**，不实现合同允许的“读不到 source port 时的唯一 host+port 降级”。读不到就拒绝，不能猜测或降低标准。

## 固定版本事实

本轮通过 GitHub API 读取官方 v1.19.31 源码：

- [constant/metadata.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/constant/metadata.go)：sourcePort、destinationPort、inboundPort 使用 `uint16` 的 JSON `,string` 序列化；network 为 `tcp`，CONNECT 入站类型为 `HTTPS`。
- [adapter/inbound/https.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/inbound/https.go)：CONNECT metadata 从实际连接的远端/本地地址填充 source/inbound。
- [tunnel/statistic/tracker.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/tunnel/statistic/tracker.go)：id、start、metadata、chains、rule、rulePayload；start 是 Go time.Time，可带纳秒。实现使用整数纳秒，避免微秒截断把过期连接变成有效证据。
- [tunnel/statistic/manager.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/tunnel/statistic/manager.go)：活动连接集合；零连接可以序列化为 null，不能当作历史日志。
- [adapter/outbound/base.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/base.go) 与 [adapter/outboundgroup/selector.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outboundgroup/selector.go)：先追加出站 NODE，再追加 selector PROBE，顺序不得反置。

## 测试

新增 `tests/test_route_evidence.py`，**74 项**全部使用合成 JSON/随机 UUID。

覆盖正确形状；错误 Host/端口/入站/源地址/类型；字符串端口不隐式转换；DIRECT/REJECT/额外跳/倒序链；错误规则；过期、未来、非法时区/日期与纳秒边界；无效本地事实；畸形/过大/空快照；跨 run；重复/歧义连接；baseline/消费 ID 重放；无关连接不冒充目标；双源串行与独立关联；私有 repr。

全量：`PYTHONPATH=src .venv/bin/python -m pytest -ra` → **328 passed, 29 skipped**（Linux / Python 3.11.2）。`git diff --check` 通过。

## 尚未证明的事

`EVIDENCE_MATCHED` 只表示**给定私有输入与匹配合同一致**，不是已认证 route proof，不能直接用于产品 `route_verified=True` 或解除 gate：

- 尚无真实 controller 采集器；run ID、时间和 source port 的来源必须由后续可信采集代码绑定到同一个已核验 engine 与原始请求，不能取自用户 JSON。
- 尚未实现 TLS 证书验证、禁止重定向、原始 HTTPS 流式响应持有、请求与 controller 同时采样、独立客户端、局部 CA fixture 与出口 body 验证。
- `previous_ids` 必须由采集器传入请求前 baseline 和本轮已消费 IDs；调用方遗漏不能被纯函数自行发现。
- 当前 UTC 时间关联还需未来采集器的 monotonic 总 deadline/时钟跳变防护配合；不能仅依赖墙钟宣称端到端保证。
- 匹配结果尚未连接状态判定器。将来必须把 `EVIDENCE_ROUTE_MISMATCH` 等硬错误正确映射为 FAIL，不能降格为“只是另一个来源缺失”的 PARTIAL。
- 固定 binary/支持的 Python 真实会话测试、Linux 合成协议握手及 Windows W1/W2 均未因此通过。

下一步是构建受控本地 HTTPS 请求与采集器的关联测试，取得本地 source port 并在持有同一请求响应期间采样；获取不到任何一条证据则保持未证实。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；F3 未完成，没有 P0 CLOSED。
