# NL-REVIEW-016｜实际 Trojan/TCP 本地 fixture 与 IP 目标字段修复

日期：2026-09-28。承接 NL-REVIEW-015。

## 真实环境获取仍阻塞

本轮重新查询官方发布信息并尝试下载 Python 3.12.11 与固定 Mihomo v1.19.31。GitHub API 元数据可读，但 Python 官方下载域及 GitHub release-assets 域的 TLS 连接失败，未取得可执行文件。未关闭 TLS 校验、未使用未知镜像、未改写固定 binary 摘要。下载目录位于 Git 忽略的 tools/。

实际执行环境仍为 Linux / Python 3.11.2。真实引擎验收不能以本轮测试代替。

## 本地实际协议 fixture（不是 controller 替身）

新增 `tests/fixtures/trojan_tcp.py`，按固定 tag 实现最小 Trojan/TCP-over-TLS 服务端：

- SHA-224(password) 的 56 字节小写十六进制认证、CRLF、TCP command=1、SOCKS5 address+port、尾部 CRLF。
- IPv4/domain/IPv6 三种地址编码；目标只能是构造时显式允许的 loopback alias+port。实际 dial 固定 `127.0.0.1`，不解析输入域名、不连接输入外部 IP。
- 使用局部测试证书，不改主机信任库；常量时间比较认证值。
- 双向字节转发；拒绝 UDP、mux、错误帧、错误密码与非允许目标。不实现 WS/gRPC/VLESS，不做 HTTP fallback。
- 只持有本 fixture 的 socket；退出时关闭并等待处理线程，不扫描进程。
- 固定 repr/错误、不打印握手原文；密码每次动态生成。

新增 20 项实际本机协议测试，使用独立 Python 客户端编码 header，真实 TLS 握手、分片 header、8192 字节双向传输与负控。错误 CA/主机名在 TLS 层拒绝；错误 auth/frame/destination 不触及 echo upstream。

**这证明 fixture 与独立 Python 客户端的协议行为，不证明 Mihomo 兼容性。没有在这些测试中生成 controller 链作为“证据”。**

协议依据：[transport/trojan/trojan.go v1.19.31](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/transport/trojan/trojan.go) 的 Key/WriteHeader/CommandTCP；本轮通过 GitHub API 核实。

## 已修复：IP 字面量目标 metadata

准备实际引擎测试时核实：[adapter/inbound/util.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/inbound/util.go) 的 parseHTTPAddr 调用 [constant/metadata.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/constant/metadata.go) 的 SetRemoteAddress。对于 `127.0.0.1` 一类 IP 字面量，真实引擎设置 `host=""`、`destinationIP="127.0.0.1"`，而不是把 IP 文本填入 host。

原候选 matcher 和部分合成快照错误地要求 `host="127.0.0.1"`，会导致真实本地第二源无法匹配。本轮：

- matcher 对 IP 目标严格要求空 host + 精确 destinationIP；域名目标仍必须精确匹配 host。
- 空 host 不是通配符；错误 destinationIP、IPv4-mapped 表示或域名冒名均拒绝。
- 修正旧 TLS/controller 替身及编排单测的快照形状，新增 6 项回归，不用错误的 mock 数据自证。

## 真实 Mihomo 协议验收入口（尚未执行）

新增 `tests/test_real_trojan_tcp.py` 四个 opt-in 用例：正确配置、错误密码、错误 SNI、不可信 node CA。

预期真实链路：固定 Mihomo → 本机实际 Trojan/TLS 服务端 → 两个本机 HTTPS 来源。controller payload 不修改、不伪造；包装 reader 只在真实连接快照被读取后释放原始 HTTPS 响应正文。负控必须确认引擎确实到达并被 Trojan/TLS fixture 拒绝，不能仅凭“启动失败所以没有数据”让负控通过。

局部 Go CA 通过子进程环境 `SSL_CERT_FILE`、空 `SSL_CERT_DIR` 与固定 tag 的 `DISABLE_EMBED_CA`/`DISABLE_SYSTEM_CA` 设置控制；测试后恢复环境，未加入 skip-cert-verify。依据为 [component/ca/config.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/component/ca/config.go) 的 SystemCertPool 初始化。实际引擎是否按预期加载仍须运行验证。

现有确定性 gate 增加选项，默认 F2 session 行为不变：

```sh
python3.12 scripts/f2_session_gate.py --suite trojan-tcp --exe /absolute/path/to/mihomo
```

该模式只运行固定四项，必须全过且零 skip，才报告 `F3_LINUX_TROJAN_TCP / LOCAL_TROJAN_TCP_OK`；route_proof 仅标为 LOCAL_FIXTURE_ONLY，真实节点仍不获许可。新增 5 项 gate 测试验证少测、多测、空报告、skip 不得 PASS。

本环境实际 gate 输出：`BLOCKED / PYTHON_VERSION_UNSUPPORTED`，未声称协议验收通过。

## 验证统计

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
568 passed, 33 skipped
```

本轮新增 31 项实际执行并通过的用例，以及 4 项待真实 binary 的跳过用例。33 skip = 26 项旧真实 binary/session + 4 项新 Trojan/TCP + 3 项 Windows。`git diff --check` 通过。

## 仍未关闭

- 新真实 Mihomo 测试尚未运行，局部 CA 与非空 /connections 的互操作仍可能需要实测修正。
- 本轮只实现 Trojan TLS/TCP 服务端 fixture；VLESS、WS、gRPC、Reality 都没有新增握手支持声明。
- 不改变公开协议支持/探测授权矩阵，不宣称 Windows ACL/PID/共存、严格总 deadline 或崩溃一致性已验收。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`，F3/P0 未 CLOSED。
