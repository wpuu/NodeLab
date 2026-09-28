# NL-REVIEW-014｜F3 出口正文解析与私有双源候选判定

日期：2026-09-28。承接 NL-REVIEW-013；不是生产 verdict authority。

## 本轮实现

### 两个固定格式的纯解析器

新增 `exit_response.parse_exit_response`：

- EXIT_A 只接受 ipify 风格的单字段 `{"ip": "..."}` JSON；重复键、额外字段、NaN/Infinity、错误类型和尾随垃圾均拒绝。
- EXIT_B 解析 Cloudflare trace 的 key=value 行，允许其它 trace 字段与 LF/CRLF；拒绝重复键、缺失 ip、无效 key、孤立 CR、控制字符及歧义空行。
- 原始 body 必须为 bytes，严格 UTF-8、最多 64 KiB；IP 只接受 ASCII 字符串并经 ipaddress 转换，拒绝 scope ID、IPv4-mapped IPv6、前后空白、端口、布尔/数字等隐式转换。
- 默认只接受 global unicast 地址，并排除 multicast/reserved/unspecified/loopback/link-local。
- 显式 fixture 开关仅额外允许三个 IPv4 文档段与 `2001:db8::/32`，不把任意私网地址变成合法测试出口。
- 返回私有 ExitAddress，固定 repr 和错误码；错误不含 body/IP 原文。

### 私有 fixture 判定

新增 `fixture_verdict.assess_fixture_pair`，只供本地 fixture 使用，要求在 session 清理完成后调用：

- `cleanup_ok`、运行时校验或 hard failure 不成立时先返回 FAIL。
- 逐源核对来源代号；双源 run、mixed port、目标、顺序窗口及不同连接 ID 必须符合合同。
- 从原始 snapshot **重新计算**连接证据，不信任缓存的 EvidenceMatch。
- FixtureCapture 现在私有保留本次 baseline/已消费 ID 集合，重算时继续拒绝重放，不能因重新判定丢失历史。
- DIRECT/错误链、跨运行实例、重放、歧义、非法证据等按硬失败处理，不因另一源正常或当前 body 无效而降为 PARTIAL。
- 只有缺失 capture/连接证据或无效 body 才可在另一源可用时形成 PARTIAL。此处对畸形/歧义等采用保守硬失败，未放宽 PASS 条件。
- 两源有效但同族不同 IP 为 CONFLICT；族不同为 PARTIAL；同族同 IP 才得到私有 PASS 候选。只有该分支有 `candidate_ip`，没有 `confirmed_exit_ip` 字段。

`FixtureVerdict` 不是公开输出对象；公共 serializer 仍拒绝该对象，且会把手工构造的 PASS/PARTIAL/CONFLICT 公共映射降为 FAIL。未改 `PROBE_GATE_OPEN`。

### 判定优先级回归修复

- 旧 `decide_probe_status` 先处理 unsupported，可能盖过 cleanup/hard failure；现在这些失败优先。UNSUPPORTED 只允许 source_a/source_b 都未产生观察的预网络阶段。对应旧测试更新为严格合同，并补负测。
- 旧 `match_pair` 在任意一源无匹配时提前返回，可能没有拒绝跨 run/mixed/window 的组合；现在先验证双源上下文，即使一源无连接证据也不能伪装合法 PARTIAL。
- 旧纯判定额外拒绝带 scope 的 IP、multicast 及不合法布尔控制参数。

## 验证

本轮新增 **99 项**测试（含参数化用例），覆盖解析格式/重复字段/大小/地址类型、文档地址显式允许、错误脱敏、缺失源、同意/冲突/地址族分歧、硬失败优先级、重放历史保留、缓存证据不可信及公共 gate 不放行。

本机真实 CONNECT/TLS fixture 的双源测试进一步读取 JSON 与 trace 两个原始响应格式，在代理/连接关闭后评估同 IP、不同 IP、IPv4/IPv6 三种候选状态。**网络与 TLS 是本地真实行为，runtime 标志与路由快照仍是测试构造的，不是 Mihomo 的生产证据。**

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
495 passed, 29 skipped
```

Linux / Python 3.11.2；`git diff --check` 通过。29 项跳过仍为 26 项真实 binary/session 与 3 项 Windows。

## 尚未完成

- 私有 dataclass/运行时布尔值不是密码学认证。产品不得接受外部构造的 FixtureCapture/FixtureVerdict 当作可信请求事实。
- EXIT_A/EXIT_B 在本轮关联的是固定解析格式；生产 URL 白名单、真实目标证书/连接采集和来源绑定尚未接入。不得把任意返回类似 JSON 的站点当作 ipify。
- 还未取得真实 Mihomo + 本地 VLESS/Trojan + 原始 HTTPS 双源 + controller 链证据的完整正负控。
- Python ≥3.12、Windows W1/W2、严格可取消总 deadline、公网短请求捕获可靠性与恢复一致性仍未验收。
- 本轮没有持久化出口结果、没有调用真实出口站点、没有 CLI 探测开闸。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；F3 未完成，没有 P0 CLOSED。
