# NL-REVIEW-017 — 本机 VLESS v0 / TLS / TCP fixture

## 结论

本轮补充实际 loopback TLS/socket 上的 VLESS 协议 fixture 与独立 Python 客户端测试，不是 Mihomo 互操作验收。真实引擎用例已准备但全部跳过。`PROBE_GATE_OPEN=False`，`REAL_NODE_TEST_ALLOWED_NOW=NO`；没有生产集成、外部节点探测或 Windows 验收。

## 源码依据与限定范围

通过 GitHub API 阅读 MetaCubeX/mihomo 固定标签 `v1.19.31`：

- `transport/vless/vless.go`：版本 0；TCP=1、UDP=2、Mux=3；IPv4=1、domain=2、IPv6=3，不能复用 SOCKS5 地址枚举。
- `transport/vless/conn.go`：请求顺序为版本、16 字节 UUID、addons 长度及内容、命令、两字节大端端口、地址类型及地址；初始应用数据可与请求头合并发送。响应含版本和 addons 长度。
- `transport/vless/addons.go` 与 `adapter/outbound/vless.go`：空 flow 的基本请求没有 addons；Vision 有独立处理路径。

仅支持 canonical UUID、版本 0、零 addons、TLS/TCP。明确拒绝 addons/flow、UDP、mux、未知版本与地址类型；不覆盖 Vision、WS、gRPC、Reality 或其他扩展。源码阅读不等于执行真实引擎。

## 实现与测试

- `tests/fixtures/tls_forwarder.py`：提取 Trojan/VLESS 共享的 socket 所有权、TLS、loopback 目标白名单、有限 relay 和清理逻辑。输入域名不进行任意 DNS 解析；仅连接明确允许的本机端口。
- `tests/fixtures/trojan_tcp.py`：保留独立 Trojan 编解码，复用公共传输层。
- `tests/fixtures/vless_tcp.py`：常量时间 UUID 认证；独立 VLESS 编解码；只有在认证、目标检查、上游连接均成功后才发送一次 `00 00`。
- `tests/test_vless_tcp_fixture.py`：28 个 VLESS 用例覆盖分片/合并请求、三种地址类型、8192 字节负载及后续写入、认证/帧/目标/协议串用负控、TLS 信任与名称错误、上游拒绝时不 ACK、构造参数约束。另加 2 个参数化共享清理用例，验证 Trojan/VLESS 不完整请求头期间关闭并重复关闭 fixture。
- 实际本机协议测试共 **50 passed**（Trojan 20、VLESS 28、共享关闭 2）。客户端编码独立于服务端 codec；这些测试不制造或验证 Mihomo controller chains。

## 真实引擎验收准备

提取 `tests/fixtures/real_protocol_case.py`，由 `tests/test_real_trojan_tcp.py` 和 `tests/test_real_vless_tcp.py` 共用。各协议 4 个 opt-in 用例：成功、错误凭据、错误 SNI、不可信 CA。VLESS 凭据负控使用错误 UUID。

计划中的正向实验要求：固定版本 Mihomo、实际本机协议端点、两个本机 HTTPS 来源、原始且已认证的 controller 观测、NODE→PROBE chains、私有一致性判断以及清理。负向实验要求 fixture 拒绝、不转发、不产生候选结果。测试 CA 仅通过子进程环境传入。实际 CA 加载及 controller 行为仍未经 Mihomo 执行验证。

来源正文在观测后才释放；即使未来实验通过，也不能推出普通短请求的采样可靠性。

`scripts/f2_session_gate.py` 新增 `--suite vless-tcp`，要求精确 4 个通过且无跳过；协议成功范围仅 `LOCAL_FIXTURE_ONLY`，不授权真实节点测试。运行方式：

```sh
python3.12 scripts/f2_session_gate.py --suite vless-tcp --exe /absolute/path/to/pinned/mihomo
```

本轮实际执行 `.venv/bin/python scripts/f2_session_gate.py --suite vless-tcp --exe /home/user/NodeLab/tools/mihomo/mihomo`，结果：

```json
{"gate":"F3_LINUX_VLESS_TCP","status":"BLOCKED","code":"PYTHON_VERSION_UNSUPPORTED","passed":0,"skipped":0,"real_node_used":false,"real_node_test_allowed":false,"windows_acceptance":"NOT_RUN","route_proof":"NOT_RUN"}
```

当前 Python 为 3.11.2，且没有可用的固定版 Mihomo。本轮未再次尝试下载运行时；下载问题记录见审计 016。这个 gate 输出不代表其他前置条件已经通过。

## 回归结果

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
603 passed, 37 skipped in 29.90s

git diff --check
无输出（通过）
```

37 个跳过由既有真实二进制/会话 26 个、Trojan 4 个、VLESS 4 个和 Windows 3 个组成。本轮相较审计 016 增加 35 个通过、4 个跳过（28 个 VLESS、2 个共享关闭、5 个 gate 单测）。

## 未完成与下一步

优先补齐受支持 Python 和可验证的固定版 Mihomo，在本机执行默认 session、Trojan TCP、VLESS TCP 三套 gate，检查真实握手、TLS 信任、未经改写的 controller 观测及失败清理；不能以 Python fixture 测试代替它们。审计 016 及此前记录的运行时、deadline、身份绑定和 Windows 限制没有因此消除。没有真实路由证明、P0 CLOSED 或更广传输支持结论。
