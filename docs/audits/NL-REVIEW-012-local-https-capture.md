# NL-REVIEW-012｜F3 本地 HTTPS 流式采集候选

日期：2026-09-28。承接 NL-REVIEW-011，真实引擎 gate 仍未通过。

## 本轮实现

新增 `fixture_capture.collect_fixture_request`，严格限于本地 fixture：HTTPS host 只能是 localhost 或 127.0.0.1，显式 HTTP proxy 只能是 127.0.0.1 的给定端口。拒绝用户信息、fragment、无效端口、非本机目标与未启用证书/主机名验证的 SSLContext。

每次调用新建独立 HTTPX client，`trust_env=False`、不跟随重定向、不开 HTTP/2、不复用 keepalive。流程为：

1. 使用注入 reader 取得请求前 baseline 连接 ID；格式错误则请求不发出。
2. 记录本地 UTC/monotonic 锚点并发出原始 GET，通过代理 CONNECT 建立 TLS。
3. 仅接受 HTTP 200 和 identity 编码，读取网络流的实际 client_addr、server_addr 与 ssl_object；缺少这些信息不得猜 source port。
4. 在响应 stream 仍持有、正文尚未读取时取得第二次 snapshot，记录本地采集时间窗。
5. 有界读取同一响应正文（最多 64 KiB），关闭 stream/client，构造私有 RequestWindow 并调用匹配器，带上 baseline 与本轮已消费 IDs。

工作步骤共享绝对 monotonic deadline，晚结果拒绝；wall clock 倒退或相对 monotonic 偏移超过 100ms 即拒绝。它仍不承诺所有同步 I/O 可被硬性中断。

返回值是私有 `FixtureCapture`，repr 固定，只携带候选记录和原始 fixture body。**没有出口 IP 解析、没有 PASS、没有产品 route_verified 写入**。

另修复 `match_pair`：同 run ID 的双源还必须使用同一个 mixed port；不同代理端口的证据不能伪装同一 runtime 的双源。

## 实际完成的测试

新增 21 项采集测试与 1 项 mixed-port 回归。测试临时生成 OpenSSL 自签证书/私钥（局部信任、测试结束删除），只监听 loopback。测试代理在 CONNECT 后直接提供 TLS fixture 响应：这验证真实 TCP/CONNECT/TLS/HTTPX 流式行为，**并未实现或模拟 VLESS/Trojan 协议握手**。

为了验证采集顺序，服务端先发响应头、暂停正文，收到 snapshot reader 的采集通知后才释放正文。合成快照的源端口来自服务端实际看到的连接，客户端独立从 network_stream 读到源端口并进行匹配。两源用同一个 fixture proxy、不同本地目标名、新建两条连接，并做独立 ID 匹配。

测试覆盖环境代理不干扰、非 200/302 不继续、证书不受信、禁止关闭 TLS 验证、缺失/错误源端口/DIRECT 证据、正文限额、缺少客户端 socket 信息、快照异常/超时/取消、ID 重放、baseline 错误与时钟倒退。测试中的 snapshot reader/链是构造的，**不是 Mihomo controller 的真实路由事实**。

本轮运行：

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
350 passed, 29 skipped
```

Linux / Python 3.11.2，HTTPX 0.28.1。OpenSSL 可用，本地 TLS 测试均实际执行。`git diff --check` 通过。

## 未完成与安全门

- reader 尚未绑定认证 controller、精确 engine PID 或持续存活检查；run ID 由调用方给定，只是关联标签，不是身份认证。
- localhost-only 限制只用于本地实验，不能把它放宽成任意生产目标并当作受支持功能。当前 callback 也不是防恶意代码的沙箱。
- 尚未把 fixture_capture 与 private_engine_session 的真实 Mihomo/本地协议节点串起来。真实路由证据必须等可信采集器与本地协议 fixture 的正负控。
- 尚未完成响应来源/出口 IP 严格解析、双源判定器映射、缺证据重试、生产目标白名单与持久化。
- 本地 response 能够保持活跃由 fixture 控制，不证明公网短请求能稳定被 /connections 捕获。
- HTTPX timeout 是 I/O timeout，callback 和底层同步调用仍有 NL-REVIEW-008 所述不可硬中断边界。
- 29 项跳过仍为 26 项真实 binary/session 与 3 项 Windows。Python ≥3.12、Windows W1/W2、真实引擎与真实协议验收均未完成。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；F3 未完成，没有 P0 CLOSED。
