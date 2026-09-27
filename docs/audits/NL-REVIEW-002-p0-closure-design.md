# NL-REVIEW-002｜NodeLab P0 修复合同与验收矩阵

**性质：仅设计工程合同；未修产品代码；未测试真实节点。**

**设计基线 / `AUDITED_HEAD`：** `e88b10ac9d949bd815d4df7a59ed8e3c5e0f3a8c`（执行开始时读取的远端 `main`）。

**输入：** [`NL-ASTRA-001-red-team-audit.md`](NL-ASTRA-001-red-team-audit.md) 已确认的 P0-01～P0-07；本文件不重新审计、不重新计严重度。
**合同判定：** 7 项均 **READY FOR IMPLEMENTATION，尚非 CLOSED**；`NL-003` 继续暂停；**现在不得用真实节点**。本文件的 `REPORT_COMMIT` 由提交后的最终交付信息提供，不能把提交哈希写进它自己的提交内容。

> 工程执行者只实现本文显式允许的 VLESS/Trojan 单节点可信闭环；碰到无法无损映射的方言，返回 `UNSUPPORTED`，不得“尽量连接”或悄悄改成 TCP/DIRECT。任何单项 `pytest passed` 或 `mihomo -t = 0` 都不构成 P0 CLOSED。

## 0. 统一术语、冻结边界及交付包

- **`NODE`**：本次唯一目标 Mihomo 出站代理，名称固定，永远不包含用户备注/URI；**`PROBE`**：仅含 `NODE` 的 selector，二者不得同名。每个探测独立 Mihomo 子进程、独立受保护工作目录、随机 controller `secret`、独立端口。**DIRECT 禁令只针对 IP 出口探测请求的 Mihomo 路由**；连接代理入口所需的系统 DNS/控制面可能直连，不能虚称“整机没有直连网络”。Mihomo 内置 `DIRECT` 对象即使出现在 API 中，也不等于它被本次请求使用。[3](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go#L402-L458) [8](https://wiki.metacubex.one/en/api/)
- **`OFFLINE_CLOSED`**：用虚构凭据、固定版本二进制、本机合成协议服务/回环目标与故障注入完成本合同 A～G，并在 Owner 的 Windows 上复核（不接触真实第三方节点/真实凭据；R-N1 允许对两个公开 IP 查询源作极小的宿主机直连负控）。它只是**首次真实验收的入场券**。**`CLOSED`**：相应离线证据齐全，且对确实要声称“真实可用”的 VLESS/Trojan 方言，Owner 随后在本机用其已有授权节点完成真实链路验收；未验收的方言仍 `UNSUPPORTED/UNCONFIRMED`。P0-02/04/05/06 的安全事实可在离线 Windows 阶段关闭；P0-01/03/07 的生产可用性声明不能靠合成服务器冒充真实节点验收。
- **允许文件范围：** 实施任务仅可改 `src/nodelab/{cli,mihomo_config,mihomo_process,parser,probe,redaction,types}.py`、必要的 `scripts/bootstrap_mihomo.ps1` 和相应 `tests/`；如需安装声明的直接依赖，只能就 `pyproject.toml` 提出最小变更并单独说明。**禁止**在本轮实施中引入 SQLite/FastAPI/worker/新协议/Agnes/Grok/Xboard、自动抓订阅或实节点样本。实施者每一原子任务提交前验证仅触及该任务列出的文件，测试值均虚构，日志/截图/CI/Git 不含任何可重放凭据。
- **最终交付包**（只有工程实施完成后才生成）：每任务的 diff 与测试清单、官方二进制 ZIP/EXE SHA、合成测试环境信息、配置**无 secret 的结构摘要**、`-t` 结果、Controller `/configs`/`/proxies`/`/rules` 的**允许字段断言**、`/connections` 对每个出口请求的 route-proof 断言、DIRECT 负控、Windows PID/ACL/残留检查、状态判定样例和未验证方言清单。原始 YAML、原始 controller 响应、URI 和捕获包一律不作为公开证据上传。

## 1. 实施策略：`SPLIT_TASKS`，4 个顺序原子任务

**选择 B（拆分），不做一次整体修改。** 依赖图为 `T1 → T2 → T3 → T4 → Owner Windows 离线验收 → 首次真实节点验收`；各任务在独立提交中通过自己列出的测试，不允许并行编辑同一模块。前序通过只是候选关闭，不许在 T4 端到端证据完成前宣称所有 P0 CLOSED。

| 顺序 | 唯一交付焦点 / 对应 P0 | 本任务触及范围与可独立验收的结果 | 明确禁止及进入下一任务的门槛 |
| --- | --- | --- | --- |
| **T1 安全输入与生命周期** | P0-05、P0-06；为后续提供私有 `RunContext` | `cli.py`、`types.py`、`redaction.py`、`mihomo_config.py` 的临时文件接口、`mihomo_process.py` 的 own-PID 清理、`probe.py` 的 `finally` 及仅相关 tests。先移除 URI argv；固定 public JSON/error allowlist；Windows 私有 temp ACL；虚构秘密故障注入后无残留。通过 E 节 adversarial matrix 中可由假进程/假控制器覆盖的输出与清理分支。 | 不修 Mihomo 业务配置、不运行真实节点；若配置仍错误，只测构造/校验失败的清理，真实启动/取消路径在 T4 再验。T1 后只给后续**虚构离线输入**开放此接口；真实输入须另过 H 节门禁。 |
| **T2 Mihomo 基座** | P0-02、P0-01、P0-04 | `mihomo_process.py`、`mihomo_config.py`、`probe.py` 的启动接口、必要时 `scripts/bootstrap_mihomo.ps1`，及相应 tests。固定可信 EXE + digest；单节点 TCP 基础骨架、唯一 `NODE`/`PROBE`、`secret`、回环 mixed、严格配置键白名单；`-t` 加 controller/监听/组/规则运行时断言；空/错 token 负测。 | 不增加 WS/gRPC/Reality 支持，不做出口 PASS；旧解析器只用于虚构 TCP 基本样例。未通过 controller 鉴权/端口归属不得进入 T3。 |
| **T3 严格解析和协议映射** | P0-03，补齐 P0-06 的新增字段泄漏测试 | `parser.py`、`types.py`、`mihomo_config.py` 与相应 tests；严格 per-line parser、B 节七行目标方言的静态映射和**凡声明 SUPPORTED 的**本机合成握手验证；Reality fixture 失败则按 B 节保持 `UNSUPPORTED_REALITY`，HTTPUpgrade 保持 `UNSUPPORTED_HTTPUPGRADE`。 | 不扩协议列表、不猜测参数、不得拿真实 URI 补测试；仅通过 `-t` 而缺本机握手/负控的模式不得标为 SUPPORTED。 |
| **T4 逐请求路由证明与状态机** | P0-07；集成复验 P0-01～06 | `probe.py`、必要的 `mihomo_process.py`/`mihomo_config.py` 接口和相应 tests。D 节连接级证据、双源真值/状态优先级、无效 NODE + 可联网宿主机负控、端口/超时/清理复测；提交 Owner Windows **离线**验收包。 | 不做 SQL、真实节点、批量 worker 或后台服务。缺任何 per-request route proof 时不得 PASS；Owner 未确认 OFFLINE_CLOSED 前禁止使用 `E:\NodeLab.secrets` 中的真实节点。 |

每任务验收为**可重跑的断言和负控**，不是“代码已写/20 tests passed”；每次提交交出 `task_id → tests → expected/actual (无 secret) → remaining gaps`。工程 executor 遇到范围外方言按 B/C 返回 `UNSUPPORTED`，不自行扩大任务。

## A. Mihomo **v1.19.31** 最小正确配置合同

以下是**结构模板**，仅有 RFC/本机虚构示例 UUID，`<...>` 值须由私有运行上下文注入；不是含真实节点的可直接复制配置：

```yaml
mode: rule
allow-lan: false
bind-address: 127.0.0.1
mixed-port: <UNIQUE_LOOPBACK_TCP_PORT>
log-level: warning
external-controller: 127.0.0.1:<UNIQUE_CONTROLLER_TCP_PORT>
secret: "<RANDOM_PER_RUN_CONTROLLER_SECRET>"
dns:
  enable: false
proxies:
  - name: NODE
    type: vless
    server: 127.0.0.1             # 合成服务器示例；真实值只由本机受保护输入注入
    port: <SYNTHETIC_SERVER_PORT>
    uuid: 00000000-0000-4000-8000-000000000001
    tls: true
    servername: node.test
    network: tcp
    skip-cert-verify: false
proxy-groups:
  - name: PROBE
    type: select
    proxies: [NODE]
rules:
  - MATCH,PROBE
```

**冻结执行规则：**

1. P0 单实例选择**顶层 `mixed-port`**，不同时生成 `listeners`，也不生成 `port`/`socks-port`/`tun`/`redir-port`。未来若改用 `listeners`，只能二选一，需新的运行时验收；其 `name` 而非 sing-box 的 `tag`，且不得设会绕过规则的 `listener.proxy`。`allow-lan: false`、`bind-address: 127.0.0.1`， controller 也只绑定回环。启动后检查该端口**真正**由本次子进程监听，HTTP CONNECT 经它成功或明确失败；不能把 localhost 上别的 Mihomo 当本次进程。[4](https://wiki.metacubex.one/en/config/inbound/) [26](https://wiki.metacubex.one/en/config/inbound/port/) [27](https://wiki.metacubex.one/en/config/inbound/listeners/)
2. `proxies` **恰好一个 `NODE`**，`proxy-groups` **恰好一个** `{name: PROBE, type: select, proxies: [NODE]}`，不使用 `url-test/fallback/load-balance`；`rules` **恰好** `["MATCH,PROBE"]`，`mode: rule`。不得显式配置 `DIRECT`/`REJECT` 作为任何 group 成员或 IP 出口探测目标，不得有 `proxy-providers`、`rule-providers`、`sub-rules`、`script`、`listener.proxy` 等隐藏改路机制。Mihomo 内置 DIRECT 是否存在不是判据；**请求自身的 chains/rule** 才是判据。[5](https://wiki.metacubex.one/en/config/proxy-groups/) [6](https://wiki.metacubex.one/en/config/rules/)
3. 使用**顶层** `secret` 和 `log-level: warning`，不允许 `external-controller-secret`、`log: {level:...}`。controller 密钥从 OS CSPRNG 生成**每次至少 256 位**，不进 argv/env/公开 JSON/截图；回环上的 `GET /configs` 无 token 或错 token 返回 401，正确 Bearer 返回 200，运行期间密钥不复用。controller 读请求使用独立 `httpx.Client(trust_env=False)`；IP 来源请求用独立 `httpx.Client(proxy="http://127.0.0.1:<mixed>", trust_env=False, follow_redirects=False)`；二者不能共享直连 fallback transport。[7](https://wiki.metacubex.one/en/config/general/#external-control-api) [19](https://www.python-httpx.org/advanced/proxies/) [25](https://www.python-httpx.org/environment_variables/)
4. **V0 P0 关闭阶段 `dns: {enable: false}`，不创建 `dns.listen`**，没有 1053 监听，不写 `nameserver-fallback`；节点入口域名由系统解析，必须把这一事实作为 DNS 边界记录，**不宣称无本地 DNS 泄露**。将来确需 Mihomo 内部 DNS/DoH 时另立任务，字段应是官方的 `fallback` 等，按 10 并发重新验证，无隐式更改。[10](https://wiki.metacubex.one/en/config/dns/)
5. Python 构造 config dict 时对**顶层和协议各层做封闭字段白名单**（顶层即上方十余键、内部只准相应协议 B 节字段），检查唯一名称、TCP 端口不同、规则仅 MATCH/PROBE、DNS 无 listen、证书验证默认开启；`yaml.safe_dump → safe_load` 结构往返相等。测试**主动注入** `inbounds`、`outbounds`、`ws`、`grpc`、`external-controller-secret`、`nameserver-fallback`、未知代理键：**NodeLab 自己必须拒绝** `CONFIG_SCHEMA_UNKNOWN_KEY`；不可指望 Mihomo `-t` 拒绝未知键。之后才运行**同一受保护 `-d` 和 `-f` 路径**的 `mihomo -t`，其成功也只算第一层。[3](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go#L402-L458)
6. **运行时第二层**：经鉴权读取 `/version`、`/configs`、`/proxies/NODE`、`/proxies/PROBE`、`/rules`。断言版本 1.19.31、`mixed-port` 与生成值一致、`mode=rule`、`PROBE.type=Selector`、`PROBE.all=[NODE]`、`PROBE.now=NODE`、`NODE` 类型与输入一致、`rules` **唯一一条** `type=MATCH, proxy=PROBE`（仅对 type/mode 做 Mihomo 已知大小写规范化，不宽松接受其它类型）；API 只显示有限代理元数据，**不能**用 `/proxies` 存在证明 WS/Reality 内部字段生效。controller 在测试全过程受鉴权，不允许配置被外部 PATCH/重载；缺任何字段/多个规则/端口未监听均 `FAIL(CONFIG_RUNTIME_MISMATCH)`。[8](https://wiki.metacubex.one/en/api/)

## B. VLESS / Trojan URI → ParsedNode → Mihomo → 运行时证据矩阵

**模型合同：** `ParsedNode` 私有字段按类别存储：`protocol ∈ {vless,trojan}`；`secret`（UUID 或完整 Trojan 密码）；`entry_host`（标准化 IP 或 IDNA A-label）、`entry_port`；`transport ∈ {tcp,ws,grpc,httpupgrade}`；`tls_mode ∈ {tls,reality}`（Trojan 仅 tls）；`sni`；`ws_host`、`ws_path`；`grpc_service_name`；`alpn: tuple[str,...]`；`client_fingerprint`；`flow`；`reality_public_key`、`reality_short_id`；`allow_insecure_requested`；原 URI/备注只在输入解析阶段短时驻留，解析完成后**不放进持久 ParsedNode/public 对象**（公开对象**没有** `extra_query`、原始 path/Host/SNI、原始/“脱敏”URI 或私密 `__repr__`）。外部不得拿旧 `tls: bool` 代替 `tls_mode`。所有值一次解码并单独验语义；任何声明了但未映射的关键参数立即 `UNSUPPORTED`，绝不删掉继续拨号。

| 模式与冻结输入方言（只用虚构 userinfo） | Typed ParsedNode 必要字段 | **Mihomo `proxies[0]` 必要字段** | 离线运行时应观察到的证据 / 状态 |
| --- | --- | --- | --- |
| **V1 VLESS TCP+TLS**：`security=tls&type=tcp`（`type` 缺省明确等于 tcp）、可选 `sni/peer`、`alpn`、`fp`、`flow=xtls-rprx-vision` | `protocol=vless, transport=tcp, tls_mode=tls, secret=合法 UUID, sni, flow` | `type:vless, uuid:<私值>, tls:true, servername:<SNI>, network:tcp, skip-cert-verify:false`；只有显式 Vision 才写 `flow`；显式 `fp`→`client-fingerprint`、`alpn`→列表 | `-t` + 本地 VLESS TLS 合成服务器完成握手并返回受控出口响应；错 UUID/SNI/证书/flow 必须失败；捕获的 CONNECT 链 `NODE`。 |
| **V2 VLESS WS+TLS**：`security=tls&type=ws&host=...&path=%2F...`，`host` 非空、path 一次解码为 `/...` | `transport=ws, tls_mode=tls, ws_host, ws_path, sni`；不得有 `flow`/`serviceName` | V1 基础 + `network:ws`、`ws-opts:{path:<decoded>,headers:{Host:<ws_host>}}`；**不出现** `ws` 顶层/代理子键 | 本地 WS/TLS fixture 核验 Host、path 与 SNI **彼此独立**，改错其中任何一项握手/路由失败；实际 `NODE` 连接链。 |
| **V3 VLESS gRPC+TLS**：`security=tls&type=grpc&serviceName=...` 必须非空 | `transport=grpc, grpc_service_name, sni, alpn`，不得有 WS Host/path/flow | V1 基础 + `network:grpc, grpc-opts:{grpc-service-name:<decoded>}`；如显式 ALPN 不含 `h2` 则 `UNSUPPORTED`；缺 ALPN 时按 gRPC 的 `h2` 要求**明确写** `alpn:[h2]` 并记为协议约定，不是 silent TCP fallback | 本地 gRPC fixture 仅接受指定 serviceName/HTTP2，错 serviceName/ALPN 必须失败；路由链 NODE。 |
| **V4 VLESS Reality（TCP）**：`security=reality&type=tcp&pbk=...&sid=...&sni=...&fp=...`；`sid=` 显式空值可表示空 short-id；可选合法 Vision flow | `tls_mode=reality, reality_public_key, reality_short_id, sni, client_fingerprint, flow`；`pbk` 经 base64url 验证可解出 32 字节公钥，非空 `sid` 为偶数位十六进制且不超过 16 位；关键值缺失即 `UNSUPPORTED` | `type:vless, tls:true, network:tcp, servername:sni, reality-opts:{public-key:pbk,short-id:sid}, client-fingerprint:fp`，Vision flow 仅合法时写 | **必须先**使用生成的虚构 Reality keypair 与本地 listener/本地 decoy 完成握手，故意错 pbk/sid/sni/fp 失败且链 NODE。若此离线 fixture 做不到，工程代码对 Reality **默认 `UNSUPPORTED_REALITY`，不输出可能误连的 YAML**；不可拿真实节点充当首个 fixture。[16](https://wiki.metacubex.one/en/config/proxies/tls/) [28](https://wiki.metacubex.one/en/config/inbound/listeners/vless/) |
| **V5 VLESS HTTPUpgrade**：`type=httpupgrade&security=tls&host=...&path=...` | 理论为 `transport=httpupgrade, ws_host, ws_path` | v1.19.31 存在 `network:ws` + `ws-opts.v2ray-http-upgrade:true`；它**不是** `network:httpupgrade` 或 `httpupgrade:{...}`。但本次 P0 范围**不启用此 URI 方言**，返回 `UNSUPPORTED_HTTPUPGRADE`（不启动 Mihomo）。 | 官方有配置开关但不能仅靠它证明某种 URI 方言与服务端握手兼容；留给独立带严格本地 HTTPUpgrade fixture 的兼容任务，未来重新开放。[15](https://wiki.metacubex.one/en/config/proxies/transport/) |
| **T1 Trojan TCP/TLS**：`type=tcp` 或缺省，`security=tls` 或缺省（Trojan 协议本身 TLS）；可选 `sni/peer,alpn,fp` | `protocol=trojan, transport=tcp, tls_mode=tls, secret=完整非空密码, sni` | `type:trojan, password:<私值>, sni:<SNI>, network:tcp, skip-cert-verify:false`；显式 `fp`→`client-fingerprint`，显式 `alpn`→列表。**不要**发出不被该版本 Trojan 选项承认的 `servername`/`tls` 字段 | 本地 Trojan TLS fixture 收到完整密码并校验证书/SNI，冒号密码不能被截短；错密码/SNI/证书必失败；链 NODE。[13](https://wiki.metacubex.one/en/config/proxies/trojan/) |
| **T2 Trojan WS/TLS**：`type=ws&host=...&path=...`，其余遵循 Trojan TLS 方言 | `transport=ws, ws_host, ws_path, sni` | T1 基础 + `network:ws, ws-opts:{path,headers:{Host}}` | 本地 Trojan-WS fixture 验 Host/path/SNI 与密码；错一处失败，链 NODE。 |
| **T3 Trojan gRPC/TLS**：`type=grpc&serviceName=...` 非空，其余遵循 Trojan TLS 方言 | `transport=grpc, grpc_service_name, sni, alpn` | T1 基础 + `network:grpc, grpc-opts:{grpc-service-name:<decoded>}`，显式 ALPN 必含 h2；缺省明确设 `alpn:[h2]` | 本地 Trojan gRPC fixture 验指定 serviceName、HTTP2/SNI/密码；错 serviceName 失败，链 NODE。 |

**统一字段决策，不留给 executor 自选：**

- `sni` 优先；只有 `sni` 缺失才允许 `peer` 别名，**两者同时出现即使相同也拒绝重复语义**；DNS 名用 A-label，小写化仅 DNS/枚举，不改 path/secret。VLESS/Trojan 的普通 TLS 若 `sni/peer` 均缺而入口为合法 DNS，**显式**设 `sni=entry_host`（与 Mihomo 自身 DNS 主机默认同义）；入口是 IP 且缺显式 SNI 时返回 `UNSUPPORTED_SNI_REQUIRED`，Reality 即使入口为 DNS 也必须有显式 `sni`。VLESS 写 `servername`，Trojan 写 `sni`。`host` 仅用于 WS 的 HTTP Host，**不等于** SNI；WS Host 值仅接受可验证的 DNS/IP 加可选端口，不允许空白/控制字符/换行或多行注入；gRPC/纯 TCP 上若出现 Host/path/serviceName 等互斥项，拒绝而非丢弃。
- `path` 只针对 WS/HTTPUpgrade，一次解码，必须非空且以 `/` 开头，不把缺失悄悄补成 `/`；拒绝 CR/LF/NUL 等控制字符。`serviceName` 只针对 gRPC，一次解码、非空，只接受可验证的 ASCII 服务名 `[A-Za-z0-9._/-]+` 且无控制字符（其它方言 UNSUPPORTED）；`flow` 只可为空或 `xtls-rprx-vision`，且只限 VLESS TCP+TLS/Reality，WS/gRPC 上带 `flow` 返回 `UNSUPPORTED_FLOW_COMBINATION`。[11](https://wiki.metacubex.one/en/config/proxies/vless/) [15](https://wiki.metacubex.one/en/config/proxies/transport/)
- `alpn` 一次解码后按逗号分隔成有序非空 token，空/重复或 gRPC 列表无 `h2` 拒绝；V0 允许 `h2`、`http/1.1`，其它 token（包括 QUIC `h3`）`UNSUPPORTED_ALPN`。`fp` 对应 uTLS `client-fingerprint`，**不是**服务器证书钉扎用的 `fingerprint`；对非空值只允许固定枚举 `chrome/firefox/safari/edge/android/ios/360/qq`（输入无关大小写，输出按 Mihomo 规范大小写；**勘误 2026-09-27**：本处原抄 wiki 写作 `iOS`，但 Mihomo v1.19.31 `component/tls/utls.go` 的 map 键为全小写 `ios` 且查找区分大小写，`iOS` 会在 `transport/vmess/tls.go` 静默退回普通 Go TLS，见 [`NL-REVIEW-003`](NL-REVIEW-003-f1-f2a-candidate-review.md) B1），`random` 因不能复现而拒绝；未给 fp 时 TLS 可不写，但 Reality 要求显式 fp。`allowInsecure` 缺省/`0`/`false` → `skip-cert-verify:false`；`1`/`true` 在**本次 P0 合同一律** `UNSUPPORTED_INSECURE_NOT_APPROVED`，不启动 Mihomo；将来诊断模式必须另行设计/授权，不能把 URI 自带值当用户批准。[16](https://wiki.metacubex.one/en/config/proxies/tls/)
- `encryption=none` 是传统 VLESS URI 的允许值，不启用 v1.19.31 新的非空 `encryption` 特性；其它 `encryption` 返回 `UNSUPPORTED_ENCRYPTION`。Trojan `security=none/reality`、VLESS `security=none/real`、未知 `type` 或额外会改变协议的参数均 `UNSUPPORTED`。未提及的 VMess/SS/HY2/TUIC/AnyTLS 不在 P0 关闭范围。
- **本机合成 fixture：** 只使用虚构 UUID/password、本机服务端和自签测试 CA。HTTPS 目标端由测试专属 `SSLContext` 验证，Mihomo 上游 TLS 必须由临时信任的测试 CA 验证（Windows 如需导入 CurrentUser trust store，测试完立即移除并校验；不可用 `skip-cert-verify:true` 替代）。真实节点通过后才扩大现实兼容性声明。Mihomo 的 VLESS/Trojan 官方入站支持本机 WS/gRPC/Reality 配置，fixture 服务端可为单独测试进程；**服务端为访问本机 echo 所做的 DIRECT 不属于待测客户端的 DIRECT 回退**，两端的日志/配置须分别标记且不得公开临时凭据。[28](https://wiki.metacubex.one/en/config/inbound/listeners/vless/) [29](https://wiki.metacubex.one/en/config/inbound/listeners/trojan/)

## C. Strict Parser Contract（所有错误逐行、无猜测）

1. **输入与行协议：** `parse_uri()` 只接受单行文本，不自行 `.strip()` 可能属于密码/URI 分量的字符；批量读取按原始字节换行分割，每个非空物理行按严格 UTF-8 单独解码，记录 1-based `line_number`，每行大小上限 8192 bytes，超过报静态 `LINE_TOO_LONG`；空白行记录 skipped_count。整批中一行无效不抛至顶层，不吞掉后续行。解析前的 CLI argv 检查不能回显传入的 URI（E 节）。
2. **结构与单次 percent decode：** `urlsplit`（或等价 RFC-aware 拆分）确认 scheme、authority、query、fragment 分界；除 query/form 编码规则，**每个组件仅一次** strict percent decode；先校验每个 `%` 后恰有两个 hex 位，UTF-8 非法拒绝；禁止二次 `unquote`。userinfo 含**恰好一个未经转义的 `@` 分隔符**，字面 `@` 密码须 `%40`；Trojan 整个 userinfo（**包括字面冒号**）就是 password，不作 `user:pass` 截断，空/全空白 password 拒绝；VLESS userinfo 应为规范化 UUID，冒号拒绝。Query 使用**明确记录的 `application/x-www-form-urlencoded` 方言**（`+` 表空格，真 `+` 写 `%2B`），因此不能把原始 `%252F` 再解码为 `/`。[18](https://docs.python.org/3/library/urllib.parse.html)
3. **主机与端口：** IPv6 字面量必须 `[2001:db8::1]:port`，`entry_host` 存不带括号的压缩 IP；非括号 IPv6、zone-id/链路本地、缺失/非十进制/0/>65535 端口 → 固定 `INVALID_HOST/INVALID_PORT`，捕获 `urlsplit`/`.port` 原生 `ValueError` 并转换，**绝不回显 URI**。IPv4 合法性由 `ipaddress` 检验。DNS U-label 经严格 IDNA2008（如明确声明直接依赖 `idna` 并使用 `uts46=False, std3_rules=True`）转为 A-label、逐标签/总长度及 round-trip 检验；不接受模糊映射；非法/无法规范化 IDN 返回 `INVALID_HOST`。此处支持解析 IPv6/IDN，不代表探测请求可绕开 D 节出口 IP family 约束。
4. **query 参数：** 只接收固定白名单 `type,security,sni,peer,host,path,serviceName,alpn,fp,flow,pbk,sid,allowInsecure,encryption`（大小写不敏感地匹配**键**，内部规范为上述名），任何大小写变体相撞/重复键（即便值一致）→ `DUPLICATE_PARAM`；未知 key → `UNSUPPORTED_QUERY_PARAM`；`uuid`/`password` 放 query 不替代 userinfo，按不支持拒绝。枚举值 `type/security/fp` 允许 ASCII 不区分大小写归一化，密码/path/SNI 原值不得意外大小写折叠；别名冲突（如 `sni` + `peer`）拒绝。空值仅 `sid=` 在 Reality 下按 B 节准许；`allowInsecure` 只接受 `0/1/false/true`，其它 → `INVALID_FLAG`。
5. **协议组合：** VLESS TCP/WS/gRPC 的 `security=tls` 必须明确；Reality 只限 `security=reality&type=tcp` 并校验 pbk/sid/sni/fp；Trojan 缺 `security` 明确表示 TLS，显式只可 `tls`；VLESS `type` 缺省才有记录过的 tcp 默认，Trojan 同理。`security/type` 未知 → `UNSUPPORTED_SECURITY/UNSUPPORTED_TRANSPORT`，不能退成无 TLS/TCP。WS 要 Host/path，gRPC 要 serviceName，输入了与当前 transport 不相容的关键字段时拒绝，不默默忽略。HTTPUpgrade 按 B 节**明确禁用**。
6. **fragment/metadata/错误：** fragment 一次解码可作为内存私值，**不进入 public JSON、错误、repr 或公开日志**，更不当成鉴权、判断住宅/CDN/多跳；`proxyip=` 字符串至多 private hint。逐行结果固定形状例如 `{"line_number":7,"probe_status":"FAIL","stage":"PARSE","error_code":"INVALID_PORT"}`；well-formed 但不在本次支持集的 URI 为 `UNSUPPORTED`，非法语法为 `FAIL`。捕获 `UnicodeDecodeError/ValueError/OverflowError` 为静态代码；不抄异常的 `str(exc)`、不得只返回 `None` 或整批 traceback。先验证再启动进程，UNSUPPORTED 不落临时 YAML、不联网。

**必要 per-line 表驱动负控：** 冒号密码、`%40`、`%252F`、`%2B`、非法 `%`、无/多 `@`、空 password、IPv6 bracket/无 bracket/zone、Unicode IDN 与 punycode 等价、`Security`/`security` 重复、`TLS` 枚举大小写、坏 port、`security=real`/unknown、`type=h2`、缺/错 gRPC serviceName、pbk/sid 错、空 ALPN/不含 h2、`allowInsecure=maybe/true`、互斥 Host/path/flow；把坏行夹在两条合法虚构行中，验证第二条仍处理且输出无原文。

## D. Route Proof Contract（**P0-07 主门槛**）

**要证明的是：两个特定 HTTPS 出口查询请求各自确实在本次子进程上匹配 `MATCH → PROBE → NODE`，不是证明“本机能访问两个网站”。** `mihomo -t=0`、controller 组 `now=NODE`、delay API 成功、两源 IP 相等分别都只是必要/辅助条件，任一单项都不是逐请求证据。Mihomo controller 提供 `/configs`、`/proxies`、`/rules` 与活动连接 `/connections`（`id,metadata,chains,rule,rulePayload`）；`/connections` 为**活动快照/WS，不是持久历史日志**，抓不到就不得 PASS。[8](https://wiki.metacubex.one/en/api/)

**D1 启动后 runtime preflight（无 IP 查询）：**

1. 校验二进制及**子进程 PID**、私有目录/本次随机 token；用无环境代理的控制面 client 先测试无 token/错 token 的 `/configs` 401、正确 token 200，确认 `/version` 为 1.19.31、`/configs` 反映 `mode=rule`、本次 mixed-port；用 socket/PID 归属确认 mixed/controller 真在 `127.0.0.1` 监听。
2. `/proxies/NODE` 存在、类型等于输入；`/proxies/PROBE` 存在且 `type=Selector, all=[NODE], now=NODE`；`/rules` 唯一 `MATCH → PROBE`；未配置额外策略组/提供者/重载/例外。每个源请求前后再次检查 PID 仍活、组 `now=NODE`、mode/rule 不变。**内置 DIRECT 的存在不造成 preflight 失败；被本次链使用则立即 FAIL。**
3. 若 Controller API schema/version 不合预期、鉴权旁路、mixed 端口被其他进程占用、进程退出或两次检查间配置被修改，停止当前探测，固定 `FAIL(RUNTIME_MISMATCH)`，无任何 `confirmed_exit_ip`。配置结构断言由 A 节白名单完成；不能只信 Mihomo 忽略未知字段后仍启动。

**D2 每个出口请求自己的连接级 route proof：**

1. 生产请求 A＝`https://api.ipify.org?format=json`（IPv4），B＝`https://www.cloudflare.com/cdn-cgi/trace`，只用显式 mixed HTTP proxy、`trust_env=False`、证书校验开启、禁止重定向；**测试 harness 可依赖注入两条纯本地 HTTPS fixture URL/解析器和局部信任 CA，生产用户不可任意改目标以绕过双源。** 先经 Bearer 订阅本次独立 controller 的 `/connections?interval=100` WS（或 100ms 间隔的有界 GET），然后**顺序**发起各请求；每源新建独立 HTTP client（禁跨源 keepalive/连接复用），使用 streaming response **在仍持有响应连接时**拍连接快照/事件，记录起止时间/connection id/源端口（若可观察）/目的 Host+port 与本次进程的匹配，读取完**同一请求**的已验证 HTTPS 响应。不得拿之前的 delay、另一网站或别的进程的 route 当本次来源证明；若服务端关闭太快抓不到连接，`ROUTE_UNPROVEN`，**不能补造链**，只在总 deadline 内有界重试，仍无证明则保持非 PASS。
2. 在 controller 的该连接对象上验证**唯一关联**：本次独立 mixed 端口、唯一源目标 Host+port、顺序且未并发的请求时间窗、connection id；如果能够读取 HTTP client 的本地 ephemeral port，**必须**与 controller `metadata.sourcePort` 一致；如未能读取，此窗口内须只有**一条**符合 host+port 的连接，否则歧义即不成立。还须验证 `rule` 规范化后为 `MATCH`，`chains` **恰为 `["NODE","PROBE"]`**（该 tag 在实际出站 `NODE` 创建连接后由 selector 追加 `PROBE`，**不要把数组最后一项误认成物理出站**），与 `PROBE.now=NODE` 一致；任何 DIRECT/REJECT/其它跳都属硬失败。测试时据 tag 的 `base.go`/`selector.go` 固定此顺序；若 Windows 离线实测的 v1.19.31 与之不同，**阻断 CLOSED，先复核事实**，不能临时放宽为“数组内有 NODE”。留存**最小布尔与固定代号**，不输出完整 metadata/原始 URL/Authorization。若该版本 API 不能让两个**原始出口请求**均稳定关联，工程执行者不得宣布 P0-07 CLOSED：状态转 `PARTIAL/FAIL`，交 Owner 另立证据机制评审，而不是降低 PASS 标准。[32](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/base.go#L245-L283) [33](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outboundgroup/selector.go#L24-L38)
3. 对每个 HTTPS body 验证状态 200、来源字段（ipify JSON `ip` / CF trace `ip=`）、严格 `ipaddress` 转换、`is_global`（生产模式）、IP family、目标/时间；无重定向。两源必须**同 family**才能判定相等/冲突；若一个 IPv4 另一个 IPv6，视作 family 未对齐而非“动态出口”证据。上述来源响应成功但链无证据不产生 `confirmed_exit_ip`。IPinfo/ASN/延迟属于后续富化，**不能替换 route proof**。受保护的纯合成 fixture 可用 RFC 文档地址模拟来源并在测试断言中识别，**不能**将合成地址写成生产 PASS。[20](https://www.ipify.org/) [21](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/)

**D3 强制负控（工程 CI + Owner Windows 离线）：**

| ID | 设置（全为虚构/本机或公开的小请求） | 必须结果 |
| --- | --- | --- |
| `R-N1` | `NODE` 指向 RFC 文档网段或明确关闭的本机端口，宿主机对**相同两查询目标可直连**（先仅本机验证 direct baseline）；通过待测 mixed 发起 | 目标 NODE 不可达，两个代理请求不得成功并不得 PASS。若环境中宿主机无法直连，只能记录“此条未覆盖”，不许声称假阳性门槛已关闭。 |
| `R-N2` | 虚构两源模拟器同时返回同一合法格式 IP，但 controller 连接证据缺失/无法关联 | `FAIL(ROUTE_UNPROVEN)`（零条有效链）或仅另一条已证实时 `PARTIAL`，无 confirmed_exit_ip，绝不 PASS。 |
| `R-N3` | 在纯函数中注入 `chains=[DIRECT]`，或在独立恶意配置 fixture 上将 mode 改为 direct/组成员改成 DIRECT（正常白名单须拒绝）；不得通过正式产品配置制造 DIRECT | 预检或连接级 `FAIL(ROUTE_DIRECT/RUNTIME_MISMATCH)`，即使两源 IP 相同。 |
| `R-N4` | 仅一源返回合法 IP；另一源断流或不同 family | 有一条 NODE 链则 `PARTIAL`；family 不同**不是** CONFLICT，不出 confirmed_exit_ip。 |
| `R-N5` | 两源均 NODE 链、同 family 但 IP 不同 | `CONFLICT`，不以源 A 覆盖源 B。 |
| `R-N6` | `-t=0` 但 mixed 未绑定/组缺失/密钥错/未知字段被忽略 | preflight `FAIL`，严禁走 IP 查询。 |
| `R-P1` | 本机虚构 VLESS/Trojan 服务端能够连到本机双源模拟器，响应同 family 同 IP；从已鉴权 controller 看到**两个请求自己的** NODE 链 | 仅合成测试得到 **`OFFLINE_PASS` 断言**；合成服务器不得作为生产资产 `PASS` 入池。证书校验开启且缺链立刻非 PASS。 |

`OFFLINE_PASS` 只是 `R-P1` 的**测试断言名**，**不是第六个公开 probe_status，也不允许合成 IP 入池**。

**D4 单次最终状态的确定性优先级**（工程须有纯函数及判定表单元测试）：

| 对外 `probe_status` | 精确条件 | `confirmed_exit_ip` / 发布资格 |
| --- | --- | --- |
| `UNSUPPORTED` | 语法可识别，但方言/组合不在 B/C 的允许集合，或 insecure 未单独批准；**发生在进程/网络前**。 | `null`；禁止发布。 |
| `FAIL` | 语法错误、二进制/配置/鉴权/监听/组/规则不匹配、任一连接证实 DIRECT/非 NODE、进程/统一 deadline 失败、零条可归属 NODE 的有效 IP 观察、或进程/私有文件清理失败。两个网站恰返回一样也不能覆盖。 | `null`；禁止发布；仅输出固定 `error_code/stage`。 |
| `CONFLICT` | **两源**均有各自 NODE route proof、TLS/HTTP/IP 均有效、同 IP family，但两个有效 IP 不同；没有上面的 hard FAIL。 | `null`；隔离/禁止发布。 |
| `PASS` | 支持的方言；运行时和鉴权、配置 schema 检查全通过；**两源各自** HTTPS+NODE chain+`MATCH/PROBE`，同 family 的两个**公有** IP 相等；默认 TLS 校验有效；进程及明文清理确认成功；无 hard FAIL。 | 唯一 `confirmed_exit_ip` 可写仅限 Owner 本地受保护结果；**不是**自动商业发布资格，真实样本另须 Owner 验收。 |
| `PARTIAL` | 运行时合同成立且**至少一个** route-backed 有效 IP，但另一源超时/无效/family 不同，或同 IP 的第二条请求无法证明路由；不存在 DIRECT/hard FAIL 和可证实同 family 不一致。 | `null`（可保留分源候选 IP 为私有观察），禁止发布。 |

判定顺序为 `UNSUPPORTED（预网络）→ 硬失败 FAIL（包括 cleanup）→ 双源有效但冲突 CONFLICT → 两源严格同意 PASS → 仅有一条可用 NODE 证据 PARTIAL → FAIL`。`proxy_http_ok` 只有在**至少一条有链的 HTTPS 200 + 有效 IP**时才 true；它本身不是 PASS。`handshake_ok` 若无法由本机协议 fixture / engine 明确证实，应为 null 而非推断 true；P0 不实现 `allowInsecure` 诊断后门。

## E. Secret Safety Contract

### E1 输入、模型、输出与异常

- **禁止任何 URI 作为 CLI argv**（现有 `parse <uri>`、`probe <uri>` 必须拒绝/废弃，拒绝信息不能让 argparse 回显原参数）。首选命令是 `probe-file --file <本机受保护绝对路径> --limit 1`；`parse/probe --stdin` 作为备用，**只能**从本地受保护文件通过管道输入，不在 PowerShell 历史中键入 URI 或使用含明文的 `echo`。路径可以出现在 argv，但文件内容、UUID/password 不行。Owner 的真实 URI 唯一输入存放在 **`E:\NodeLab.secrets`**（非仓库、非云同步、非 Git/CI），由 Owner 本机创建；测试只有虚构 fixture。不自动抓 HTTP(S) 订阅、不把 URI 发送给模型。
- `ParsedNode` 及 `RunContext` 一律是**私有对象**，包含 `secret/raw_uri/fragment/Host/path/SNI/extra_query/Reality key/sid` 的对象 `__repr__/__str__` **不得自动渲染这些值**，不允许 `dataclasses.asdict(node) - secret` 作为 public JSON。`display_name`、域名、路径和附加 query 都可含密码，**不是天然安全 metadata**。CLI/stdout、stderr、结果文件、测试报告、异常对象采用**同一固定 allowlist serializer**；默认 public schema 仅准 `schema_version,line_number,protocol,transport,tls_mode,probe_status,stage,error_code,config_ok,controller_ready,listener_ready,route_verified,source_count,sources_agree,latency_ms`（布尔/有限枚举/数值；缺值用 null），**不含** URI、UUID/password、entry_host/IP、SNI、Host/path、备注、额外 query、controller token、YAML、原始 HTTP body 或原始 error。经验证的 `exit_ip` 只写 Owner 本地 ACL 保护的**详细结果**，默认公开 JSON 不输出；详细结果也只能由经过 `ipaddress` 类型检查的结构化字段拼装。
- 异常仅输出 `stage ∈ {INPUT,PARSE,CONFIG,BINARY,STARTUP,CONTROLLER,ROUTE,EXIT_A,EXIT_B,CLEANUP}` 和**固定枚举 `error_code`**，加行号；禁止把 `str(exc)`、subprocess raw stdout/stderr、HTTP error body、路径或异常 chained cause 写到 public 输出。内部诊断可在 Owner 私有目录以受限 ACL/保留期保存**字段化计数**，不保存原始核心日志；没有“用正则清洗原始 YAML/stderr 即安全”的后门。解析器不把 raw URI 包装进异常。
- API/token 隔离：GitHub 凭据与 `IPINFO_TOKEN` 等环境变量不得传入 Mihomo 子进程；P0 closure 阶段 IPinfo 富化默认不运行。HTTPX `trust_env=False` 使代理/证书环境不会重定向控制面或出口请求；如果需要专用 CA，显式设置为仅隔离 fixture 的信任根，不全局关闭 TLS 验证。[19](https://www.python-httpx.org/advanced/proxies/) [25](https://www.python-httpx.org/environment_variables/)

### E2 私有 YAML、Windows ACL、清理状态机

- NodeLab 持有一个私有 per-run 上下文；生成的真实 `probe.yaml` 必然有必要的 credential，**从不展示/提交/打印它**。Windows 在受保护的 `E:\NodeLab.secrets\_runtime\<random_run_id>`（或 Owner 明示等价 NTFS 受保护本地根目录）创建，必须验证 NTFS、无 junction/symlink/reparse point、停止继承过宽 ACL、仅当前用户与 SYSTEM 有必要访问；对父目录及新建文件逐一读回 DACL，若有 Everyone/Users/Authenticated Users 广泛读取或 ACL 操作失败则**在写明文前** `FAIL(PRIVATE_DIR_UNSAFE)`。管理员可通过提权绕过 ACL，不能宣称可抵抗被攻陷的 Owner 会话或管理员。[30](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- 用安全独占创建（已有同名目录/文件失败），绝不走 `%TEMP%` 默认 ACL 的盲目假设；`write_probe_config` 抛错也必须回收。单个拥有者的 `try/finally` 覆盖写配置、**每轮端口尝试一次** `-t`、进程启动/就绪、控制器检查、出口查询、取消/KeyboardInterrupt/timeout/异常；先终止**该 Popen PID**、等待有上限，必要时只 kill 同一 PID，再删除本次 run dir，验证目录不存在/端口释放。`cleanup_stale_mihomo` 按名字/WMIC/`taskkill /IM`/全机扫描禁用或删除。没有确认 cleanup 的结果统一 `FAIL(SECRET_CLEANUP_FAILED)`，不因之前出口响应成功改回 PASS。
- Crash recovery：私有根内保留不含 secret 的 run_id+PID+创建时间+EXE 路径指纹/目录规范路径小型 marker；下次启动只处理**该私有根中已验证归属**的旧目录，先核验 PID 是否仍是本应用同一进程，再按精确 PID 清理并验证消失；不能证实归属时**不杀、不遍历其他 Mihomo**，标记 `RECOVERY_REVIEW_REQUIRED` 并禁止真实探测，由 Owner 本地处理。删除时防路径遍历/reparse point，不将 marker/敏感路径上报 Git。断电/OS crash 不能保证“当场删除”，靠重启后可核验恢复门槛，不能假称 `finally` 能处理断电。

### E3 adversarial secret test matrix（全部虚构随机 sentinel）

每次随机生成不符合 UUID 正则的 `FAKE_ONLY_<run>` 风格密码，并跨每个载体复制，覆盖 raw 与一次/两次 percent-encoded 形态；断言**所有公共输出**（stdout、stderr、repr、exception、JSON、unit failure、Git diff、日志）不存在任何原值或编码变体；详细结果不能包含 token/URI，活动 YAML 是唯一受保护的短时明文例外且须清理。显式用扫描器搜原始 sentinel，不以既有 UUID regex 测试代替。

| 编号 | 攻击载体 / 测试方法 | 必须验收的结果 |
| --- | --- | --- |
| `S1` | password/userinfo 本体为非常规非 UUID 随机密码，含 `:`、`@` 的 percent 编码 | 内存解析保真；public/repr/异常零泄漏，argv 无 URI，结束无 YAML。 |
| `S2` | fragment 重复完整密码、另含 Unicode/多段 percent 编码 | private only；public JSON 没有 `display_name` 或片段原文。 |
| `S3` | WS path 为带 token 的字符串，Host 与 SNI 含 sentinel（可放测试上合法域名片段） | 值如不合法则 fail closed；合法也只进私有 YAML，public 不输出 path/Host/SNI。 |
| `S4` | query 有 `auth/token/Password/password/UUID`、大小写混杂及未知键 | 严格 parser `UNSUPPORTED` 或固定语法错误，不把 raw query/键名值送进任何输出。 |
| `S5` | `%0A`/多行 Trojan password；直接构造恶意 `ParsedNode.secret` | 解析层拒绝控制字符；即使内部异常对象混入多行也不能在 `scrub_yaml_for_display` 正则后显示续行（**删除该展示方式**）。 |
| `S6` | 嵌套 `{"outer":{"secret":sentinel}}`、嵌套 list/tuple、dict key 包含 sentinel | 只从允许字段重新构造 public 对象，未知 key/value 一律不序列化。 |
| `S7` | `mihomo -t` 人工替身在 stdout/stderr/异常里写 sentinel；httpx 报错含 URI | public 仅固定码，不引用第三方原始错误；异常链不会意外打印 secret。 |
| `S8` | 配置失败、Popen 抛错、晚启动、控制器 401、双源超时、Ctrl-C/取消、强杀 NodeLab 重启 | 每次只处理 own PID，运行中 YAML ACL 满足要求；退出/恢复后无明文残留，无全机误杀。 |
| `S9` | `parse/probe <URI>`、PowerShell 命令历史、批量混合坏行、输出到 `data/probe-results/latest.json` | argv 显式拒绝且不回显 URI；批次逐行错误；默认结果不再用未加密文件保存潜在 secret metadata。 |

## F. Process / Port Contract

1. **唯一可信二进制**：安装目标只能是仓库源码布局 `repo_root/tools/mihomo/mihomo.exe`（源码路径可由 `src/nodelab/mihomo_process.py` 的 `parents[2]` 到仓库根，打包安装时必须用显式**本机受保护的绝对路径**，不能由 `cwd` 猜）；不查 `PATH`，不下载“最新版”，不运行用户提供的未知 exe。官方 Windows `mihomo-windows-amd64-compatible-v1.19.31.zip` 的 release SHA256 为 `93d14e9a13b49b2f2d256202d02cc8d14a7c4695edf084cae0f941986bc9c218`；本次从该**已校验 ZIP**独立计算的唯一 EXE SHA256 为 `1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b`。运行前检查规范路径、非 symlink、EXE 摘要相等，`-v` 能读到 `Mihomo Meta v1.19.31`；ZIP/EXE hash 或版本有一项不符 → `FAIL(BINARY_MISMATCH)`，不退到 PATH。Windows 原机 `-v` 成功仍须做摘要校验。[2](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.31)
2. **生命周期与 readiness**：记录 Popen 精确 PID、创建时间、exe/run dir；每轮端口尝试仅执行一次 `mihomo -t -d <private_run_dir> -f <private_run_dir>/probe.yaml`。`-t` 成功后启动同路径；使用 monotonic deadline 每 100–200ms 检查 PID、controller（**授权** `/configs`）、mixed TCP 监听/PID、`NODE`/`PROBE`/`MATCH`；所有条件齐全**立即 ready**，不能固定 sleep 8 秒，也不能以 `proc.poll() is None` 当服务就绪。启动后意外退出/端口只由别的 PID 占用/Controller 403 或 group 错 = FAIL，保留**脱敏 code**，不转储原始 stderr。若后续源请求期间子进程崩溃同样硬失败。Windows 用 `Get-NetTCPConnection -LocalPort <port> -State Listen` 的 `OwningProcess` 交叉验证，权限不足导致无法归属时不得把结果当通过。[31](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2025-ps)
3. **时限**：继承 V0 Spec 的**单节点工作 deadline 20 秒**，采用一把 monotonic 总时钟，不把分段超时相加。单次 `-t` 子预算 ≤4 秒、启动+runtime preflight ≤4 秒、controller 每次 ≤1 秒、每个出口源 ≤8 秒且一律 `min(子预算, 总剩余)`；可选 delay/ASN **不在 P0 PASS 必需路径**。总时间耗尽 → `FAIL(PROBE_DEADLINE)`；之后 own-PID 终止+目录删除另有最多 5 秒清理窗，清理失败仍 `FAIL(SECRET_CLEANUP_FAILED)` 并阻止新的真实探测。此 20s 可使慢但可用的节点成为 PARTIAL/FAIL，是 V0 可解释的时间策略，不能偷偷等待 2×30s 然后说 20s 合格。[`docs/NODELAB_V0_SPEC.md:317-325`](../NODELAB_V0_SPEC.md)
4. **端口竞态**：mixed/controller 两个独立 IPv4 回环 TCP 端口，分配时校验 `!=`；端口 0 的 bind/close 只是**候选**，不能宣称消除 TOCTOU。启动前被抢占或 readiness 看见别的 PID，在**同一个 20s deadline 内**按尝试 **最多 3 次**：关闭/确认本轮 own PID、清除本轮私有目录、重新分配**两个**端口及 controller secret、重写仅本轮 YAML 后再 `-t`/启动；超过次数 `FAIL(PORT_COLLISION)`。不切换端口来连接已存在的客户端，不在不清理旧配置时重试。DNS 本阶段禁用监听，所以两并发实例不碰 1053；进入有界并发前须测 ≥10 个合成并发、注入 mixed/controller 抢占、验证所有 PID/端口/组/密钥互不串线。
5. **进程权限/外部依赖**：Mihomo 子进程用最小必要工作目录和环境；Windows `terminate()/kill()` **只**针对 NodeLab 自己的 Popen，进程终止后 PID wait，不能按进程名清扫。对于子进程是否有自建孙进程、跨用户 ACL、OS 无法清理的强制断电场景，Windows 本机记录为额外未验项，不能用 Linux 测试代替。

## G. P0 Closure Matrix——逐项九栏合同

**状态约定：** 本节「CLOSED 客观证据」描述将来实现后的判据，**不是本轮已完成**。每项 Windows 列只用虚构 fixture，只有 H 节门槛打开后才动真实节点。测试 ID 引自 A～F；缺一个证据对应项保持 `NOT_CLOSED`，不允许由其他 P0 的测试代替。

### P0-01｜正确 Mihomo 配置

1. **根因：** `mihomo_config.py:74-115` 输出 sing-box 式 `inbounds/outbounds`、对象规则、错名 proxy/group，`-t` 即使因局部修正通过仍会忽略未知键。
2. **必须修改：** `src/nodelab/mihomo_config.py`、其调用 `src/nodelab/probe.py` 与 `tests/test_mihomo_config.py`/新增配置合同集。
3. **禁止扩展：** 不改 sing-box 兼容引擎、不加其它协议/通用配置编辑器、不能靠隐藏的 DIRECT 或新增 providers 使配置“可用”。
4. **最小实现：** A 节唯一 mixed、`NODE`/`PROBE`、`MATCH,PROBE`、DNS disabled、键白名单和结构 roundtrip；`-t` 后运行时核验。
5. **自动化测试：** 代表性 VLESS/Trojan 虚构模型的 YAML whitelist、`-t`、`/configs`、`/proxies`、`/rules`、mixed/PID 断言。
6. **负控测试：** 注入未知顶层键、未知协议字段、同名组/自环、规则对象、错端口：NodeLab **自行拒绝**或 runtime FAIL，R-N6。
7. **Windows 本机验收：** 合成 TCP 节点与独立 Mihomo 客户端，两处回环端口归属于本次 PID、组 now/规则正确，关进程后端口释放。
8. **CLOSED 客观证据：** 白名单检查+`-t`+运行时五项断言+负控+Windows 同向通过；真实要声称可用的协议在 H 后另有 Owner 验收记录。
9. **仍未验证：** 未由合成配置证明真实服务端兼容、Windows 特定 TLS/系统 DNS 行为；标为待 Owner 实测，不假称现已关闭。

### P0-02｜可信 Mihomo binary

1. **根因：** `mihomo_process.py:17-26` 寻址层级错、未知 PATH fallback。
2. **必须修改：** `src/nodelab/mihomo_process.py`，必要时 `scripts/bootstrap_mihomo.ps1` 仅补 EXE 摘要/manifest 校验，相应查找/版本 tests。
3. **禁止扩展：** 不自动下载 latest、不信 PATH 中其它客户端、不因 `-v` 显示同版本就省略 digest。
4. **最小实现：** F1 的唯一规范绝对路径、ZIP/EXE SHA+`-v`、不符即固定 BINARY_MISMATCH。
5. **自动化测试：** 虚构仓库布局与 installed explicit path、摘要不同但 version 相同/反之的替身；POSIX 与 Windows 路径接口测试。
6. **负控测试：** PATH 放置冒名 `mihomo.exe`，项目路径缺失或摘要错误时仍 FAIL，不能选 PATH。
7. **Windows 本机验收：** bootstrap 官方 ZIP，**不改 PATH** 找对 repo/tools EXE；报告路径可规范化、两个摘要及 `-v` 均满足，伪造替身被拒绝。
8. **CLOSED 客观证据：** 官方发布摘要对照、运行时 EXE SHA、路径/平台/版本及负控全记录，且只有此 EXE 被 Popen。
9. **仍未验证：** Windows Defender/杀毒软件拦截或用户系统权限可能导致失败，必须报告为 FAIL 而非换二进制；真实链路不由此项单独证明。

### P0-03｜无损 VLESS/Trojan 协议映射

1. **根因：** `parser.py:99-110` 关键字段未类型化，`mihomo_config.py:28-71` 未写 network/opts，Trojan SNI 名称错误；未知方言可能静默退成 TCP。
2. **必须修改：** `src/nodelab/{parser,types,mihomo_config}.py` 与 B/C 矩阵相关 tests；T1 的 public serializer 对新增字段保持不外泄。
3. **禁止扩展：** 不写真实用户样本、不自动启用 HTTPUpgrade、VMess/SS/HY2/TUIC 等、不因 `-t=0` 声称握手成功。
4. **最小实现：** B 节 TypedNode + 固定 URI 白名单 → 各字段一一映射；无法合成验收的 Reality 显式 UNSUPPORTED，HTTPUpgrade 始终 UNSUPPORTED。
5. **自动化测试：** B 节 V1–V4/T1–T3 静态映射、TLS/SNI/Host/path/serviceName/ALPN/flow/fp/pbk/sid 不丢失，支持项本机合成服务端确实验握手。
6. **负控测试：** 随意改错每个关键参数使合成服务端拒绝；不受支持 transport/encryption/insecure/pbk/sid 不落 YAML，严禁 TCP fallback。
7. **Windows 本机验收：** Owner 先仅用虚构本机 VLESS/Trojan TCP/WS/gRPC fixture（Reality fixture 若启用），证书/SNI 校验启用，无真实服务端。
8. **CLOSED 客观证据：** 每个宣告 SUPPORTED 的行都有 parser→dict→`-t`→受控握手→NODE route 的正负证据；其余具有 `UNSUPPORTED` 的无副作用测试。真实兼容的结论必须等 H 节。
9. **仍未验证：** 真实第三方的非标准 URI 方言、Reality 服务端的其它兼容设置、HTTPUpgrade；显式保留 UNSUPPORTED，不悄悄改行为。

### P0-04｜controller 鉴权

1. **根因：** `mihomo_config.py:113-114` 写 `external-controller-secret` 而 v1.19.31 读顶层 `secret`。
2. **必须修改：** `src/nodelab/mihomo_config.py`、`probe.py`/`mihomo_process.py` 的 controller client 与鉴权测试。
3. **禁止扩展：** 不绑 `0.0.0.0`、不把 secret 放 argv/公开 JSON、不以“本地回环”代替身份认证。
4. **最小实现：** A3/F2 随机 per-run secret，绑定回环；仅经 Bearer 在 `trust_env=False` client 访问受保护 endpoint。
5. **自动化测试：** 无/错 Bearer 对 `/configs` 均 401，正确 200；密钥不复用，进程清理后端口关闭。
6. **负控测试：** 错键名、空密钥、错误 controller 端口、错误 origin/client 环境代理都 FAIL；不能盲信 `/version`。
7. **Windows 本机验收：** 本次 PID/controller 端口、401/401/200 三联证据；截图仅截状态码，不含 token。
8. **CLOSED 客观证据：** 静态 YAML 白名单+官方版本 runtime 三联鉴权+Windows 回环/PID/清理证据。
9. **仍未验证：** 被攻陷的同一 Windows 用户会话可读取本用户资源，不声称 controller token 能挡同用户恶意程序。

### P0-05｜明文临时配置和生命周期

1. **根因：** `write_probe_config` 返回前后出错、`probe_node` 早退、`MihomoProcess.start` 未返回时 `proc=None`，明文 YAML 遗留。
2. **必须修改：** `src/nodelab/{mihomo_config,mihomo_process,probe}.py` 和故障注入/恢复 tests。
3. **禁止扩展：** 不删除整个 `%TEMP%`、不 `taskkill /IM`/按名清扫、不给全机同名 PID 授权、不得把 YAML 打印出来做日志诊断。
4. **最小实现：** E2/F2 的私有 run dir/ACL、单拥有者 `try/finally`、own-PID 终止后清理与恢复 marker，cleanup 失败禁止 PASS。
5. **自动化测试：** S5/S7/S8，对 `-t` 失败/Popen 失败/超时/取消/异常与正常成功后的文件、PID、端口逐一断言。
6. **负控测试：** 外部 Mihomo 与同名进程并存、欺骗旧 PID/reparse point/权限拒绝，绝不误杀或删除别人的目录。
7. **Windows 本机验收：** `E:\NodeLab.secrets` NTFS ACL/DACL、运行中目录权限、正常/故障后目录不存在及外部客户端 PID 未变，断电后重启仅按本应用 marker 恢复。
8. **CLOSED 客观证据：** 上述路径的自动+Windows ACL/PID/残留负测通过；清理失败产生固定失败码而非 PASS。
9. **仍未验证：** 真正的突然断电无法预先模拟所有 OS 状态；机器被同用户恶意代码/管理员控制不在 ACL 威胁保证内。

### P0-06｜public 输出不泄密

1. **根因：** `types.py:43-60`/`redaction.py:17-41` 按字段删 UUID 的黑名单方式遗漏任意 password、fragment/path/Host/query、多行 YAML、CLI argv。
2. **必须修改：** `src/nodelab/{types,redaction,parser,cli,probe,mihomo_config}.py` 与 E3 的 adversarial tests。
3. **禁止扩展：** 不在公网/Git 测真实凭据、不依赖只覆盖 UUID 的正则、不用 `str(exc)`/原始 YAML 经替换后再打印。
4. **最小实现：** E1 公共输出白名单、静态 error_code、禁 URI argv、私有详细结果、移除基于正则的 YAML 展示；新 TypedNode 字段一律默认不外露。
5. **自动化测试：** S1–S9 逐通道 sentinel 扫描，`redacted_result_dict(list)` 等列表/嵌套情况不出 traceback/secret。
6. **负控测试：** 备注与原始 Host/path 和 Password 混合大小写、冒号/换行、第三方 stderr/HTTP body 都不出现在 stdout/stderr/repr/JSON。
7. **Windows 本机验收：** PowerShell 历史/任务管理器命令行只有文件路径而非 URI；输出/错误/结果文件/失败日志扫描虚构 sentinel 无泄漏。
8. **CLOSED 客观证据：** E3 全部正负测在 CI + Windows 通过、Git 只含虚构 fixture、公开 JSON schema 无动态 key 或未经净化的字符串。
9. **仍未验证：** 真实第三方备注可能携带未知秘密；因此仍须禁止原始 metadata 进入 public，而非把 sentinel 测试当绝对安全证明。

### P0-07｜可归属的每请求 NODE 路由与 fail-closed 结果

1. **根因：** `probe.py:118-173` 两 IP 相同就 PASS，未验证两个原始请求各自走 `NODE`；此前配置未运行，故此为修复前序后激活的系统性假阳性风险。
2. **必须修改：** `src/nodelab/probe.py`，仅必要时 `mihomo_process.py/mihomo_config.py` 的连接跟踪接口，与判定纯函数/集成 tests。
3. **禁止扩展：** 不以 delay/`-t`/一条 route proof/宿主机直连基线代替两条证明；不选择 src1 当冲突时 confirmed，不把成功合成 fixture 当真实节点 PASS。
4. **最小实现：** D1 启动检查、D2 各源 active-connection 归属证据、D4 有限状态机，IPinfo/吞吐留到后续。
5. **自动化测试：** R-N1～N6/R-P1、两个来源分别出示 NODE 链才可 `OFFLINE_PASS`，各状态/优先级表驱动测试。
6. **负控测试：** 宿主机直连两个网站通而虚构 NODE 不可达仍 FAIL；两源相等但无链/ DIRECT 链 FAIL/非 PASS；配置中途被修改/关闭 controller FAIL。
7. **Windows 本机验收：** 正负合成服务 + 可联网宿主机对照；经鉴权 `/connections` 在每个原始出口请求上捕捉 MATCH/PROBE/NODE，检查窗口/PID/端口，清理后无占用。
8. **CLOSED 客观证据：** 两源请求 id/host/端口/时间及链的无 secret 断言、负控均通过，Owner 在 H 节首次真实节点探测后逐源复核并记录仅固定证据代号；否则只允许标 `OFFLINE_CLOSED`。
9. **仍未验证：** 短请求可能在 `/connections` 采样前结束，不能补造证明；此时结果只可 PARTIAL/FAIL、P0-07 NOT_CLOSED，需后续更可靠的引擎证据方案，经 Owner 批准后才改标准。

## H. Owner Windows 离线验收 → 首次真实节点的**唯一**开闸流程

**现在的门禁为 `REAL_NODE_TEST_ALLOWED_NOW: NO`。** 以下步骤只能由 Owner 本机执行；不需要、也不应把真实 URI/UUID/password 发给任何模型或 GitHub。

1. **代码/依赖/路径：** 逐一审 T1–T4 的提交仅在 0 节白名单范围；`main` 工作树 clean，Windows/Python 3.12 环境；bootstrap 官方 v1.19.31 ZIP/EXE SHA 及 `-v` 同时通过，禁 PATH 回退。**先用虚构文件**建立 `E:\NodeLab.secrets`（本机 NTFS、不在仓库/云同步）；检查所有父/子目录和运行时 YAML 的 DACL，无广泛读取、无 reparse point，失败便不放真实 URI。
2. **纯离线安全关：** S1–S9 与 C 节 strict parser 逐行矩阵；正常、配置拒绝、timeout、取消/重启 crash-recovery 中只留允许 JSON/固定 error_code，own PID 停止、temp YAML 删除，旁边一个用户已有 Mihomo 客户端未受影响。Owner 不粘贴 URI 到 CLI argv、聊天或 issue。
3. **纯离线协议与路由关：** 用虚构证书/密钥、本机 VLESS/Trojan 合成服务端和本机双源模拟器，依次执行 B 节 V1–V3、T1–T3 以及若要启用则 V4 Reality；HTTPUpgrade 必须 UNSUPPORTED。对每个支持的模式做至少一正一错参数负控；跑 R-N1～N6/R-P1，**R-N1 必须确认宿主机本身可以直连两真实查询源且虚构 NODE 不可达仍 FAIL**（只做小的直接查询，不运行真实第三方代理）。PID/端口/控制器鉴权/配置和双请求链路证据由 Owner 看**允许字段**的本地诊断；不拍原始 YAML。
4. **OFFLINE_CLOSED 签字：** P0-01～07 各自 G 节八号证据中的离线/Windows 部分全部有可重跑输出；不能捕获**两条原始请求**的 route proof、HOST/SNI/证书校验未过、secret ACL/清理失败、R-N1 未覆盖，均**不签**、仍 `NO`。此时 Owner 才能把 `REAL_NODE_TEST_ALLOWED_NOW` 从 NO 改为 **YES（仅 Owner 本机单节点、仅已离线支持的模式）**。本报告或工程 executor 不自行改这个开关。
5. **第一次使用真实节点：** Owner **自己**将已有授权的 VLESS、Trojan 分别保存为仅本机 `E:\NodeLab.secrets\vless.txt` / `trojan.txt` 等 NTFS 私有文件；运行仅接收文件路径的 `probe-file --file <本机受保护绝对路径> --limit 1`（或从受保护文件通过 `--stdin` 输入），优先各选一条 **TCP+TLS、`allowInsecure=false`**、无不受支持扩展；不使用第三方大量节点，不要把凭据放 shell history、repo、CI、issue、聊天或模型。首次不启 IPinfo token、测速或批量。
6. **Owner 真实闭环判定：** 同一次探测中有真实 TCP/协议握手、HTTP 两源各自严格 NODE route proof、TLS 有效、同 family 两个有效出口一致、进程/temp 正常清理；故意错误本地虚构负控继续 FAIL；全过程只保留本地私有 `PASS/PARTIAL/FAIL/CONFLICT/UNSUPPORTED`、stage/code/route 证据及经许可的出口 IP，绝不提供真实 URI/凭据。真实节点未过则该模式仍 `UNCONFIRMED`，全项目不得进入 NL-003；通过后才请 Owner 逐 P0 签 CLOSED，并另行处理上一轮已冻结的相关 P1 门槛。

## 依据与版本注记

依据均为官方原文/固定 tag，核验日期 2026-09-26；非固定网页后续可能漂移，因此任何升级须重验本合同。Mihomo v1.19.31 官方 release 与 `config.RawConfig`：[2](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.31) [3](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go#L402-L458)；官方入站/端口/规则/分组/API：[4](https://wiki.metacubex.one/en/config/inbound/) [26](https://wiki.metacubex.one/en/config/inbound/port/) [27](https://wiki.metacubex.one/en/config/inbound/listeners/) [5](https://wiki.metacubex.one/en/config/proxy-groups/) [6](https://wiki.metacubex.one/en/config/rules/) [7](https://wiki.metacubex.one/en/config/general/#external-control-api) [8](https://wiki.metacubex.one/en/api/)；DNS/协议：[10](https://wiki.metacubex.one/en/config/dns/) [11](https://wiki.metacubex.one/en/config/proxies/vless/) [12](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/vless.go#L58-L91) [13](https://wiki.metacubex.one/en/config/proxies/trojan/) [14](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/trojan.go#L45-L69) [15](https://wiki.metacubex.one/en/config/proxies/transport/) [16](https://wiki.metacubex.one/en/config/proxies/tls/) [28](https://wiki.metacubex.one/en/config/inbound/listeners/vless/) [29](https://wiki.metacubex.one/en/config/inbound/listeners/trojan/)；Python/HTTPX/Windows：[18](https://docs.python.org/3/library/urllib.parse.html) [19](https://www.python-httpx.org/advanced/proxies/) [25](https://www.python-httpx.org/environment_variables/) [30](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) [31](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2025-ps)；固定 tag 的连接链追加顺序：[32](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/base.go#L245-L283) [33](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outboundgroup/selector.go#L24-L38)。