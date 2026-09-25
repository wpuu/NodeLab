# NL-ASTRA-001｜NodeLab V0 代码与架构红队终审

```text
NL-ASTRA-001_DECISION

AUDITED_HEAD: 536c9056bbea0722309fd5aeb06246e2394824dd
OVERALL:
- PASS_AFTER_P0_FIX

P0_COUNT: 7
P1_COUNT: 11
P2_COUNT: 1

REAL_PROBE_REQUIRED_BEFORE_NL003: YES
```

审计日期：2026-09-26（Asia/Shanghai）。审计对象是上述 `main` HEAD，而不是任务书所列旧基线。`PASS_AFTER_P0_FIX` **不是**当前可以进入 NL-003：须先关闭全部 P0、在进入数据库/批量前关闭相关 P1，并在用户自己的受控环境完成经授权的真实 VLESS/Trojan 探测验收；本审计没有、也不要求获取真实 URI、UUID 或密码。底层架构可修复，不需要从零重做商业项目。

## 1. Executive Summary 与证据边界

**阻断性结论。** 当前实现尚不能构成可信的单节点闭环。Mihomo YAML 混用了 sing-box 风格键和 Mihomo 键：原样生成的 VLESS/Trojan 配置在 **Mihomo v1.19.31** 的 `-t` 下均失败；只删除导致类型错误的 `rules` 后，`-t` 虽通过，但进程没有 mixed 监听、没有名为 `PROBE` 的代理/策略组。Windows bootstrap 输出位置与 Python 查找位置相差一级。即使修正外层结构，WS/gRPC/HTTPUpgrade、Trojan SNI、Reality 等协议字段仍会缺失或被忽略。控制器的所谓密钥字段未被 Mihomo 识别。当前脱敏与临时配置清理也不能证明 secret 不泄漏。两出口源一致只是两个观测一致，不是“连接确实走目标节点”的证明。[2](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.31) [3](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go#L402-L458) [4](https://wiki.metacubex.one/en/config/inbound/) [5](https://wiki.metacubex.one/en/config/proxy-groups/) [6](https://wiki.metacubex.one/en/config/rules/)

**独立复核的范围及结果：**

- 读取了 `docs/NODELAB_V0_SPEC.md`、`pyproject.toml`、全部 `src/nodelab/*.py`、全部 `tests/*.py`、`scripts/bootstrap_mihomo.ps1`、任务书及仓库状态。运行环境为 Linux/Python 3.13.14；执行 `PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider`：**20 passed**，运行后 Git 工作树干净。此结果不等于 Windows/Python 3.12.10 或真实节点验收。
- 核对官方 2026-09-14 发布的 v1.19.31：Windows ZIP 的 GitHub release `sha256` 为 `93d14e9a13b49b2f2d256202d02cc8d14a7c4695edf084cae0f941986bc9c218`，与 bootstrap 脚本第 13 行一致；另下载并核对官方 Linux compatible 发布包 `sha256:04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc`，运行 `-v` 得到 `Mihomo Meta v1.19.31`。Linux 包只用于**离线虚构节点/本机端口**验证；没有运行真实第三方节点，没有探测用户网络中的真实凭据。版本专属结论还与官方 `v1.19.31` 源码交叉核对。[2](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.31) [3](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go#L402-L458)
- 原样生成的虚构 VLESS-WS 与 Trojan-TCP YAML：`mihomo -t` 均退出 **1**，报 `cannot unmarshal !!map into string`（`rules` 是对象列表，Mihomo 要求字符串列表）。**仅为隔离故障而在仓库外的测试副本删除 `rules`**：`-t` 退出 **0**，但运行时 `/configs` 返回 `mixed-port: 0`，`/proxies` 为空，`/proxies/PROBE` 返回 **404**，计划的 mixed 端口没有监听。这直接证明“通过 `-t`”仍可能只代表不识别的键被忽略；不是当前原样配置能通过 `-t`。
- 在同一仓库外虚构配置上，`external-controller-secret` 存在时无 Authorization 的 `GET /configs` 返回 **200**；换成 Mihomo 正确的 `secret` 后返回 **401**，携带正确 Bearer 才返回 **200**。把代理和组都命名 `PROBE` 并让组指向自己时，`-t` 明确报告 `loop is detected in ProxyGroup`。[7](https://wiki.metacubex.one/en/config/general/#external-control-api) [8](https://wiki.metacubex.one/en/api/)
- 两个虚构配置各起一个 Mihomo 实例，均保持进程存活，第二个却报告 TCP/UDP `127.0.0.1:1053: bind: address already in use`。纯单元级虚构凭据复核另证实：配置校验失败返回后临时 YAML 仍在且含明文；包含自定义鉴权参数或包含密码的备注可穿透公开结果；多行密码可穿透展示 YAML 的正则；`redacted_result_dict([])` 抛 `TypeError`。用毕清理了该复核涉及的临时目录。
- 未核验用户 Windows 的真实 DPAPI ACL/备份环境，也未对真实 VLESS/Trojan/出口 IP 作网络验收。以下涉及“修复后可能发生”的假阳性均明确是**条件性风险**，不假称当前原样配置已产生 PASS。

### 严重度与判定规则

P0＝继续开发前必须修复的阻断/凭据或错误发布风险；P1＝进入数据库/批量（或相应 API 阶段）前要关闭的设计及实现缺口；P2＝不阻断 V0 闭环。一个问题即使在当前的更早失败挡住了触发路径，也必须在解除前序阻断时一并修掉。分类以**当前代码事实**为准；不把未实现模块伪装成已测试通过。

## 2. 十二个领域逐项审计

### 2.1 Mihomo 配置正确性【P0-01、P0-03、P0-04；P1-04】

`src/nodelab/mihomo_config.py:28-115` 逐项对照 **v1.19.31** 的 `RawConfig`：

| 生成的字段/行为 | v1.19.31 的有效结构/结论 |
| --- | --- |
| `inbounds: [{type: mixed, tag, listen, port}]` | 顶层使用 `mixed-port` 或 `listeners: [{name, type: mixed, listen, port}]`；`inbounds` 未在 Mihomo RawConfig 中，原始 mixed 端口不存在。监听器 `name` 与 sing-box 式 `tag` 不可混用。[3](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go#L402-L458) [4](https://wiki.metacubex.one/en/config/inbound/) |
| `outbounds: [select, direct, block, proxy]` | Mihomo 使用顶层 `proxies` 和 `proxy-groups`；`outbounds` 被忽略。代理与组目前都叫 `PROBE`，机械改键后形成同名/自引用；组成员须使用独立代理名如 `NODE`。[5](https://wiki.metacubex.one/en/config/proxy-groups/) |
| `rules: [{type: ip-is-private,...},{type: final,...}]` | Mihomo `rules` 是规则字符串数组，如 `MATCH,PROBE`；对象无法反序列化，所以原样 `-t` 失败。当前 DIRECT 私网例外没有通过语义验收，不应作为探测出口的默认绕行。[3](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go#L450-L458) [6](https://wiki.metacubex.one/en/config/rules/) |
| `log: {level: warning, disable-access-log: true}` | Mihomo 对应 `log-level: warning`；当前日志子树不是其日志级别配置，不应宣称已静音。[9](https://wiki.metacubex.one/en/config/general/#log-level) |
| `external-controller: 127.0.0.1:port`、`external-controller-secret` | 监听地址有效且限定回环是正确方向；密钥字段是顶层 `secret`，不是 `external-controller-secret`。已离线复现无授权访问。[7](https://wiki.metacubex.one/en/config/general/#external-control-api) |
| `dns.enable`、`dns.listen: 127.0.0.1:1053`、`nameserver` | 前两项是 Mihomo 字段，但固定 1053 导致并发冲突；`nameserver-fallback` 并非官方回退字段，正确名称 `fallback`。须明确节点域名解析、上游 DoH、出口探测各自的 DNS 路径；不应声称“所有 DNS 均经代理”。[10](https://wiki.metacubex.one/en/config/dns/) |
| VLESS `uuid/flow/tls/servername/client-fingerprint/skip-cert-verify` | 这些字段在 **正确的** `proxies` VLESS 对象内存在；现位于忽略的 `outbounds`。`flow` 只支持适用值且应与实际 TLS/Reality 联动；不能只写字段即认为发生握手。[11](https://wiki.metacubex.one/en/config/proxies/vless/) [12](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/vless.go#L58-L91) |
| Trojan `password/tls/servername/skip-cert-verify` | Trojan 要求密码且实际使用 TLS；它的 SNI 配置字段是 `sni`，不是生成器的 `servername`。该版本 Trojan 的选项对象也没有 VLESS 式的 `tls` 开关；当前布尔值不构成 TLS 保证。[13](https://wiki.metacubex.one/en/config/proxies/trojan/) [14](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/trojan.go#L45-L69) |
| `ws:{path,headers}`、`grpc:{...}`、`httpupgrade:{path}` | Mihomo 用 `network: ws` + `ws-opts`、`network: grpc` + `grpc-opts.grpc-service-name`；HTTPUpgrade 应在支持的 WS 选项中设置 `ws-opts.v2ray-http-upgrade`。当前生成器既没有 `network`，也没有传送真实 `serviceName`；在正确顶层仅保留其旧嵌套字段，`-t` 仍可成功但丢失传输语义。Trojan 官方传输列为 `ws/grpc`。[15](https://wiki.metacubex.one/en/config/proxies/transport/) [13](https://wiki.metacubex.one/en/config/proxies/trojan/) |
| Reality / TLS / SNI / Host / path / ALPN / fingerprint / allow insecure | `security=reality` 当前解析为 `tls=False`；`pbk`/`sid` 没有映射到 `reality-opts.public-key/short-id`；`alpn` 未映射；Trojan 的 `fp` 未传到 `client-fingerprint`。VLESS `servername` 有对应字段，Trojan 要用 `sni`。WS Host/path 只有在 `network: ws` 且 `ws-opts` 正确时才有效；`skip-cert-verify` 对应输入 `allowInsecure`，但未知来源的 `true` 应受策略审批。[16](https://wiki.metacubex.one/en/config/proxies/tls/) [15](https://wiki.metacubex.one/en/config/proxies/transport/) |

不应简单把这份 YAML 改名当 sing-box 配置：sing-box 的官方格式是 **JSON**，虽有 `inbounds/outbounds`，其路由仍是 `route` 对象，不是这里的 Mihomo 式 `rules`，且代理选项也不能逐字段照搬。[17](https://sing-box.sagernet.org/configuration/)

### 2.2 URI 解析正确性【P0-03、P0-06；P1-01、P1-02】

`parser.py:45-151`：基本 VLESS 连字符 UUID 形状检查、百分号解码的普通 password、Unicode fragment、**带方括号的基础 IPv6** 和 Unicode 主机能解析，不能把这些已工作路径说成全部不支持。相反：RFC userinfo 可以出现冒号，而 `userinfo.split(':',1)[0]` 静默截断；空 Trojan password 被接受；`urlparse`/`.port` 对坏 IPv6/端口可直接抛原生 `ValueError`，`parse_uris` 只捕获 `NodeURIParseError`，坏行中断整批。`parse_qsl` 已解码 query，`path` 再 `unquote` 导致 `%252F` 双重解码；重复 `type/security/...` 静默取第一项；query 键和 `security` 值大小写不一致时退化成默认；`security=reality` 未识别；`serviceName`/ALPN/Reality/flow 等值没有严格校验及类型化映射。`allowInsecure=1` 来自未知链接即可关闭上游证书验证，没有显式信任门槛。基础 IDN 能读出 Unicode，却未定义 IDNA 规范化、等价比较及奇异 Unicode/非法百分号的拒绝策略。[18](https://docs.python.org/3/library/urllib.parse.html)

建议先固定受支持的 **URI 方言和参数白名单**，严格区分用户输入的原始字符串、经过一次解码的 URI 分量、鉴权 secret、仅供展示的提示；重复关键参数或不支持的 `security/type` 明确报错，按行提供结构化错误，不猜错的节点不能变成可用资产。传输参数用有类型的协议/transport/TLS 子配置而不是无限扩张的 `extra_query`，为未来 VMess/SS/HY2/TUIC/AnyTLS 使用单独适配器。规范化不可合并不同 SNI/Host/path/flow/Reality 公钥组合。

### 2.3 Secret / 隐私边界【P0-04、P0-05、P0-06；P1-09、P1-10】

原始 URI 与密码当前驻留 `ParsedNode.secret`，写入真实需要的 YAML **明文**，这一点在运行时不可完全回避，但不能因此把展示数据当安全：`types.py:43-60` 的 `public_dict()` 仍包含未经 allowlist 审核的备注、host/path、`extra_query`、`raw_uri_public`；`redaction.py:17-41` 只认识典型 UUID 和 `uuid=/password=` 字符串，不认识任意 Trojan 密码、未知 token 键或嵌套 `secret` 值。虚构密码放入 fragment 或 `auth` 参数可在“脱敏”JSON 中出现；`redact_uri` 对嵌在异常文本中的 URI 和大小写变化的 `Password=` 不充分；`scrub_yaml_for_display` 逐行正则不能遮盖换行的 YAML 密码。`parser.py:130-151`、`mihomo_process.py:43-59` 的注释“永不泄漏”没有得到证实。`cli.py:53-61` 将完整 URI 当命令行参数，可出现在 shell 历史/同用户进程参数中；`probe.py:196-201` 写未加密 `latest.json`，即使目录被 `.gitignore` 排除也不是文件保密控制。

`mihomo_config.py:118-127` 创建临时明文文件；若 `probe.py:104-107` 配置校验失败或 `MihomoProcess.start` 未返回，`proc is None`，`finally` **不会删除文件夹**，已用虚构密码复现。正常 `close` 则会删除自己的目录，是有限的正面点。Windows `%TEMP%` 实际 ACL 未在本 Linux 环境验证，不能断言它可供所有人读取；但同用户进程、备份/崩溃转储、测试失败及异常路径留下明文的事实不可接受。标准化错误码、输出字段 allowlist/敏感字段分级、所有退出路径的 `finally` 清理、受保护的私有临时目录/ACL、进程环境最小化、保留期与恢复/清理机制必须成套验收。不要把未经审查的 metadata 原样传给 Agnes；数据库中也要把 `display_name`、Host、Path、redacted URI 视为可能包含秘密的输入。当前检查没有发现仓库提交了真实 GitHub token；没有声称可排除未来日志或 Windows 崩溃转储泄漏。

### 2.4 Mihomo 进程生命周期【P0-02、P0-05；P1-03、P1-05】

`mihomo_process.py:17` 的 `parents[3]` 对源码布局指向**仓库的父目录**，而 `bootstrap_mihomo.ps1:15-18,50-70` 写到仓库内 `tools/mihomo`；已打印并比较两条路径。PATH 上若刚好存在别的 `mihomo.exe` 可侥幸运行未验证版本，不能代替正确查找/版本锁定。`probe.py:104` 和 `MihomoProcess.start:73` 重复 `-t`；`start:85-90` 在进程存活的情况下**总是等待完整 8 秒**，并不检查 controller、代理名或 mixed 监听；stdout/stderr 全部丢进 DEVNULL。启动失败、测试超时、取消/异常的路径不保证清理临时文件；已返回 `MihomoProcess` 的 `close()` 只杀其自身 Popen PID，这是合理的。Windows `terminate()`/`kill()` 可作用于这个 PID，但当前没有经过用户 Windows 环境的僵尸进程/子进程/权限故障验证。`cleanup_stale_mihomo():109-138` 虽**没有生产调用点**，一旦被接入 worker 将扫描并强杀机器上所有同名 `mihomo.exe`，包括用户自己的客户端；必须删除或限制到本应用记录的 PID + 创建时间 + 可执行路径，不得调用全局进程清扫。总时限既有两次最多 30 秒 `-t`、8 秒启动、最多 30 秒 delay、两次最多 30 秒出口请求、20 秒 IPinfo，明显不满足 Spec 的单次总超时 20 秒（`docs/NODELAB_V0_SPEC.md:319-325`）。

### 2.5 本地端口竞争【P1-04】

`find_free_port` 绑定 TCP 端口 0 后马上关闭，直到 Mihomo 启动有 TOCTOU；mixed 与 controller 两次分配也可能互撞，且只考察 IPv4 TCP。固定 DNS `127.0.0.1:1053` 会在两个实例竞争；已离线证明其中一个记录 UDP/TCP 绑定错误，**两个进程却均存活**，所以 PID 存活不等于所有监听器 ready。进入批量前要明确 DNS 服务是否真的需要暴露端口；若需要，采用受控分配/启动后检查/冲突重试的独立端口或共享 DNS 服务，并将所有端口绑定检查、worker 生命周期与有界并发纳入一致的作业状态机。不能只靠 `-t` 或固定 sleep。

### 2.6 出口 IP 真值【P0-07；P1-06】

`httpx.Client(proxy=...)` 通过本地 mixed HTTP proxy 发 HTTPS，**HTTPX 的显式 proxy 参数本身不是“失败后自动直连”的证据**；正常 TLS CONNECT 方式有官方说明。[19](https://www.python-httpx.org/advanced/proxies/) 风险在于 Mihomo 组/路由/配置未经核验：`probe.py:167-172` 仅因 ipify 和 Cloudflare trace 报同一个字符串就给 PASS；没有检查目标代理/组被加载及选择、该请求的实际路由链、是否发生 DIRECT，也没有负控证明无效代理绝不能 PASS。**现状原样配置本身校验失败，不是已经观察到 DIRECT 假阳性**；但修配置时若使测试 URL 直连，两源同为本机出口便可被该判定逻辑误判。建议所有探测 URL fail-closed 地路由唯一目标代理，启动时查询 `/proxies`、group `now` 与 `/rules`，以连接/路由证据关联请求，使用不通的虚构代理进行负控；对比宿主机直连基线只作为辅助证据，相同出口也可能是真代理同 NAT，不得单独认定无效。[8](https://wiki.metacubex.one/en/api/)

`api.ipify.org` 官方为 IPv4 端点，而 Cloudflare trace 可能返回另一 IP family，直接字符串比较不等于同一 family 的独立交叉验证。[20](https://www.ipify.org/) [21](https://developers.cloudflare.com/privacy-proxy/get-started/) 两源不一致时 `probe.py:133-144` 仍将源 1 当 `confirmed`、`proxy_http_ok=True`，甚至据此填充入口/出口关系；应标为 `CONFLICT/UNCONFIRMED` 并记录每个源的 IP family、时间、目标和可信等级。`resolve_entry()` 是**本机** `getaddrinfo`，不一定等于 Mihomo 最终连接的入口 IP；其 DNS 可能泄露入口查询但不证明 HTTPS 目标域名都本机解析。对返回值做 `ipaddress` 解析、公共地址/保留段与双栈约束、必要时对同 family 查询；绝不把未证实的 src1 作为可发布的 exit_ip。`ipinfo.io/{ip}`（`probe.py:21,149`）不是当前 IPinfo **Lite** 文档的 `https://api.ipinfo.io/lite/{ip}`；Lite 的 `asn` 和 `as_name` 是独立字段，且支持 Bearer。现有 `org or as_name` 不能保证 Lite 语义，不应将错误/空值当网络归属结论。IPinfo 查询应在出口 IP 获得后由独立控制面 HTTP client 完成，避免不必要地经未知测试节点访问带凭据的接口。[22](https://ipinfo.io/developers/lite-api)

### 2.7 延迟与质量【P1-03、P1-07；NO-ISSUE：默认不测速】

`/proxies/PROBE/delay?url=...&timeout=5000` 是对指定 URL 的一次核心测量，不是单纯 TCP RTT，也不是 TLS/WS/Reality/QUIC 的统一纯协议握手时间。现有 `PROBE` 未注册，无法量到它；修好后也需要记录 engine/version、入口/出口 IP family、目标 URL、状态码、DNS/TCP/TLS/应用阶段、采样窗口、成功/失败分母，分协议同工作负载比较。VLESS-WS、gRPC、Reality 与将来 HY2/TUIC 的 raw delay 不可不加上下文地排序。`probe.py:42-58,110-116` 一次成功且 `/generate_204` 有响应不足以推算 p50/p95、抖动或成功率；可按观察窗口保存至少多次样本及失败计数，给出 p50/p95、p95-p50、持续成功率和缺失数据原因。小流量吞吐测试只对自有/明确授权的节点显式开启，设置每节点字节上限、同入口节流和冷却；Spec 默认不做大文件测速是合理的（`docs/NODELAB_V0_SPEC.md:317-333`）。[8](https://wiki.metacubex.one/en/api/)

### 2.8 链路分类科学性【P1-08】

`docs/NODELAB_V0_SPEC.md:251-289,358-375` 的“入口 IP != 出口 IP 只证明分离”提醒是正确的；但同节 `RELAY_CONFIRMED` 定义为“IP 不同且无足够 CDN 证据”属于以**无证据**推出“确认中转”，须降为 `ENTRY_EXIT_SEPARATED`/`RELAY_SUSPECTED`。一台普通服务器的入口和 SNAT 出口、云 NAT/共享出口、CDN、链路中转都可能表现为 IP 不同；入口 DNS 多 A/AAAA 与观察 vantage 不一致也会污染结论。

| 层级 | 允许的记录/推断；不可推出的结论 |
| --- | --- |
| 可观测事实 | 一次 probe 的实际入口解析/拨号地址、目标请求的路由证据、两个经过验证的 exit_ip、时间、IP family、ASN 来源/版本；多个时间点不同 IP 是“观察到出口变化”。 |
| 高置信推断 | 同配置、同观测点、同 family、多时间/多目标的出口稳定性；入口 IP 落在被核验的 CDN 边缘网段且有多重证据时，标为 `CDN_FRONTED_LIKELY`；用户持有的 GCP 项目/实例与出口地址绑定的受控登记可支持“自有”。 |
| 低置信推断 | 备注、`proxyip=`/path 字符串、单个 ASN/机房标签只能作线索；入口/出口不同可说“分离”，不能证明具体跳数、CDN 或 relay。 |
| 不能由当前证据推出 | 永久固定出口、住宅已确认、独享/自有 GCP、精确物理链路或可商业担保的质量。IPinfo Lite 国家/ASN **不**提供住宅类型或资产所有权证明。[22](https://ipinfo.io/developers/lite-api) |

`FIXED` 的“至少 3 次且跨预设窗口”可以定义为**暂时观测稳定**的最低门槛，但建议至少跨 24 小时/不同时间段和两个目标、保持配置版本和观测条件相同；对“长期固定/可发布”还需更长窗口（如跨周）及持续复测，不能将 3 次当永久证明。`DYNAMIC` 需排除 IPv4/IPv6、源站差异、负载均衡/多出口正常路由和配置变化。住宅判定从严：没有可靠、独立、可回溯证据就 `UNKNOWN`/`SUSPECTED`；`GOOGLE_CLOUD`/`CLOUDFLARE` 等 ASN 只支持网络归属，不等于独享、自有、住宅。`deterministic_confidence` 应与规则版本、证据集合、样本覆盖/时效、反证和校准方法关联；不能由 LLM 自报 0.92 代替统计置信度。

### 2.9 SQLite / FastAPI 下一阶段架构【P1-09、P1-11】

Spec 的五个表是有用的起点，但**不是可直接冻结的数据库 schema**。`node_asset` 需稳定 ID、独立加密的 credential material、不可变 `asset_version`/生效时间和多来源/备注关系；`fingerprint` 对规范化**可连接配置**去重，直接拼接/哈希低熵密码的普通摘要可受离线猜测，建议带受保护密钥的 HMAC 与版本化归一化规则。**同一 URI 不同备注**是同一配置资产的两个来源/别名；**同入口不同 path/SNI/Host/flow/凭据**可能是不同可拨号配置，不能被 endpoint 合并；**换 UUID**是新的凭据/配置版本，能否关联“同一线路”靠单独、可审计的 lineage，不可默认合并 secret 或覆盖旧观察。[`docs/NODELAB_V0_SPEC.md:164-248`](../NODELAB_V0_SPEC.md)

`probe_run` 应不可变且引用 asset_version、engine/version、vantage、DNS/拨号与路由证明、阶段结果、重试与完整 deadline；`exit_observation` 最好按 source/family/time 记录证据而非只留最终 IP；`node_classification` 需 append-only 的规则/人工/AI 决策事件、证据及撤销记录；`pool` 需独立 membership/审批/隔离状态，不能把 `recommended_pool` 当实际发布。SQLite 使用唯一约束、事务性幂等导入/作业键、版本号 CAS 或单写队列、WAL/busy_timeout；网络请求期间不持有写事务。规定原始凭据生命周期与删除、敏感观测保留期和汇总历史的差异化 TTL、重探测时的 lineage，不让 `latest.json` 覆盖成为唯一历史。FastAPI 如在 NL-003 进入，即使只绑定回环也需本地鉴权、严格 Origin/CORS、CSRF 防护及权限分离；未知 URI/路径/订阅以后要防 SSRF，API 响应沿用脱敏 allowlist，而非自动序列化所有 metadata。

### 2.10 Windows DPAPI【P1-10；NO-ISSUE：V0 可先用 CurrentUser】

目前仓库无 DPAPI 代码，因此不能说已安全实现。单用户本机 V0 选择 **CurrentUser** 保护独立 secret_blob 是可行的简化；微软明确通常由同一用户/同一机器解密，漫游配置文件有例外。**LocalMachine** 使同机其他用户也可能解密，不适合作为默认“更可迁移”方案。数据库被盗与整机/用户会话被控的威胁不同：DPAPI 保护前者中的 blob，不能拦住能以用户身份运行的恶意代码，也不能保证未经加密的元数据或低熵去重哈希安全。测试原机恢复、换机失败/受控恢复、密码重置/凭据恢复、备份可用性与不可恢复提示；若确需跨机，采用单独显式加密导出/导入及受保护的密钥封装（envelope encryption），**不是**为 V0 自动引入跨设备常驻密钥管理系统。[23](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) [24](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dataprotectionscope?view=netframework-4.8.1)

### 2.11 Agnes 3.0 Flash 边界【P1-11；NO-ISSUE：目前未调用】

永远由本地事实/规则确定：parse/config/握手是否成功、实际选中路由、exit_ip 与冲突、ASN 来源、固定/动态观察、入口/出口关系、GCP 所有权、住宅是否被证实、隔离和自动发布资格。Agnes 可在将来仅接收**逐字段 allowlist** 的脱敏聚合 JSON，生成中文摘要、解释性 usage/risk 标签、有限枚举的推荐池及 reason_codes；不发送原始 URI、UUID/password、原始 path/备注/host 的未审查自由文本、API token。严格 JSON Schema 校验、明确 `UNKNOWN`、规则和模型版本/输入快照、审计和人工覆盖；LLM 推荐不能回写/覆盖 deterministic facts，也不能成为自动入池的唯一决定。若规则已足够，**V0 可以暂时不保留在线 AI 分类层**；Agnes 不是进入 NL-003 的前置条件。现有示例 `recommended_pool` 是推荐，不是批准；`confidence` 必须被视为未校准的模型建议。[`docs/NODELAB_V0_SPEC.md:354-392`](../NODELAB_V0_SPEC.md)

### 2.12 后续路线【见第 5 节】

不要在缺少可信单节点闭环时启动数据库、FastAPI 或批量 worker；P0 先离线修好并通过负控，再由 Owner 在自己的 Windows 环境用其已有、经授权的节点验收；不必也不应向审计者发送真实 URI/密码。考虑先完成可审计的存储/作业状态与有界 worker 后，再把同一服务暴露为 FastAPI。Agnes/Grok/Xboard 均继续后移。

## 3. P0 / P1 / P2 问题台账（位置、修法、验收）

以下每个 ID **只计数一次**；位置均指本报告顶部的 `AUDITED_HEAD`，引用 Spec 的条目不是已落地代码。

| ID | 级别 | 位置及确认的问题 | 推荐修法（不在本任务改代码） | 修复后验收 |
| --- | --- | --- | --- | --- |
| P0-01 | P0 | `src/nodelab/mihomo_config.py:74-115`, `tests/test_mihomo_config.py:14-50`：原样 YAML 规则类型失败；`inbounds/outbounds` 被忽略；`PROBE` 同名会形成自环。 | 按 v1.19.31 使用回环 `listeners`/`mixed-port`、独立 `proxies` 与 `proxy-groups` 名、`rules: [MATCH,PROBE]`、`log-level`、正确 DNS 字段，探测流量不加 DIRECT 回退。 | 对虚构 VLESS/Trojan `-t=0`，启动后检查 mixed 真监听、`/proxies/NODE` 和 `/proxies/PROBE`、组 `now`、`/rules`；错误键/同名自环负测必须失败。 |
| P0-02 | P0 | `src/nodelab/mihomo_process.py:17-26`, `scripts/bootstrap_mihomo.ps1:15-18,50-70`：`parents[3]` 查错目录；PATH 回退可选到未校验版本。 | 以仓库根（源码布局为 `parents[2]`）/显式配置找二进制，启动时锁定预期版本/来源；不要静默退到 PATH 不明程序。 | Windows bootstrap 后**不修改 PATH** 能找到并运行指定版本；错版本/伪二进制 fail closed。 |
| P0-03 | P0 | `src/nodelab/parser.py:99-110`, `src/nodelab/mihomo_config.py:28-71`：WS/gRPC/HTTPUpgrade/Reality/ALPN/Trojan SNI 等信息丢失或错名，部分可在 `-t=0` 时静默退化成 TCP。 | 类型化映射 `network`, `ws-opts`, `grpc-opts`, `reality-opts`, `sni`/`servername`, `alpn`, `client-fingerprint`, 受控 `flow` 和 TLS 检验，拒绝无法保真的 URI 方言。 | 同一批虚构矩阵覆盖 VLESS/Trojan TCP/WS/gRPC/Upgrade/Reality/IPv6/SNI/Host/path/ALPN；检查实际加载字段，不仅看 `-t`；支持的真实节点在 Owner 环境验收。 |
| P0-04 | P0 | `src/nodelab/mihomo_config.py:113-114`, `src/nodelab/probe.py:42-51`：错用 `external-controller-secret`，离线确认本地 API 无授权 200。 | 改用顶层 `secret`，坚持回环绑定、随机短生命周期密钥；client/controller 不信任代理环境变量。 | 无 Authorization `/configs` 必须 401、错误 token 401、正确 token 200；检查 CORS/本地访问边界；仅针对自有测试进程。 |
| P0-05 | P0 | `src/nodelab/mihomo_config.py:118-127`, `src/nodelab/probe.py:100-110,178-185`, `src/nodelab/mihomo_process.py:72-106`：测试失败/启动前异常留下明文 YAML。 | 以包围“写配置→校验→启动→探测”的唯一 `try/finally` 清理；私有目录/Windows ACL、限制环境、进程/崩溃后按本应用标记清理，不扫描或杀其他 Mihomo。 | 虚构密码对配置无效、启动失败、超时、取消和正常完成注入故障；均检查进程退出/明文目录不存在，Windows 权限实测。 |
| P0-06 | P0 | `src/nodelab/types.py:43-60`, `src/nodelab/parser.py:130-151`, `src/nodelab/redaction.py:10-41`, `src/nodelab/mihomo_config.py:130-134`, `src/nodelab/cli.py:53-61`, `src/nodelab/probe.py:196-201`：公开 dict、异常/展示 YAML、CLI 参数、结果 JSON 可泄漏任意 password/token。 | 数据最小化/固定输出 allowlist；按**已知本节点 secret 值及分量**脱敏而非只匹配 UUID；安全解析 YAML 而非行正则；拒绝可疑备注/附加 query，提供 stdin/受保护文件入口及结果文件权限。 | 虚构任意 Trojan 密码（大小写、换行、备注/path、未知 query、嵌套 `secret`）贯穿 stdout/stderr/repr/JSON/YAML/异常/落盘的负测；不出现明文；Git 和 shell 参数亦检查。 |
| P0-07 | P0 | `src/nodelab/probe.py:118-173`, `src/nodelab/mihomo_config.py:80-114`：两 IP 相等即 PASS，无目标代理及路由证据；**现状不可运行，属修配置后会激活的条件性假阳性风险**。 | 全部探测目的地明确只走唯一目标代理，校验 controller 代理/组/规则/连接链；无效代理负控必须失败；两源冲突不选任一为 confirmed。 | 虚构不可达代理 + 可用本机直连必须 FAIL；选错组/直连规则也 FAIL；两源一致但无链路证据不得 PASS；再由 Owner 在真实节点上核验。 |
| P1-01 | P1 | `src/nodelab/parser.py:59-110,116-127`, `src/nodelab/types.py:18-41`：冒号 userinfo 被截断、空 password、双重 decode、重复/大小写与未识别 security、坏端口可中断整批、自动 insecure。 | 固定 URI 方言，严格结构/范围/单次解码和分量编码校验；大小写策略、关键键去重、空密码拒绝、IPv6/IDN 规范化和 per-line 错误；未经审批不允许 `allowInsecure`。 | 表驱动属性/畸形输入测试；任何拒绝都不回显 secret、不覆盖其他合法行、不产生“成功”节点。 |
| P1-02 | P1 | `src/nodelab/cli.py:37-45`, `src/nodelab/redaction.py:17-41`, `src/nodelab/probe.py:188-201`：`redacted_result_dict(list)` 对 list 执行 `pop('secret',None)` 抛 `TypeError`；坏行还被静默过滤。 | 区分结果列表与单结果的输出 serializer；批量返回每行索引/原因、处理/跳过数，不默默丢资产；历史不只覆盖 `latest.json`。 | 空文件、全坏、混合行的 `probe-file` 返回可解释 JSON 和退出码，无 traceback、无 secret 泄漏。 |
| P1-03 | P1 | `src/nodelab/mihomo_process.py:43-106`, `src/nodelab/probe.py:42-58,100-185`, `docs/NODELAB_V0_SPEC.md:317-325`：固定等 8 秒但无 readiness、重复 `-t`、丢日志、无总时限。 | 一次配置测试；轮询 controller/指定代理/混合端口（必要时 DNS），进程退出立即失败；统一单节点 deadline、故障分阶段固定码，日志受限脱敏，确保 own-process 清理。 | 启动慢/端口占用/子进程立即崩/控制器不就绪等注入测试；不超配置总时限且无孤儿进程和临时明文。 |
| P1-04 | P1 | `src/nodelab/mihomo_config.py:19-25,82-93`：临时端口 TOCTOU、混合/控制器端口碰撞、DNS 1053 两进程冲突仍存活。 | 受控分配+绑定后验证+重试；如非必要取消公开 DNS listen，或按作业分配/共享；先在 10 并发模拟下实测再定默认并发。 | 10 个虚构实例无互相占端口/错误连到另一实例；强制抢占端口时作业显式 FAIL/重试，不能静默成功。 |
| P1-05 | P1 | `src/nodelab/mihomo_process.py:109-138`：`cleanup_stale_mihomo` 未被调用，但一旦调用会结束全机同名客户端。 | 删除该 API 或只按 NodeLab 维护的 PID+创建时间+路径终止本应用子进程；不用 WMIC 的全机“同名清扫”。 | 与独立 Mihomo 客户端共存：触发应用自身崩溃恢复，外部 PID 与其监听端口不变。 |
| P1-06 | P1 | `src/nodelab/probe.py:21-38,120-163`：IP 未验格式与 family，冲突仍默认 src1 为 confirmed；IPinfo Lite URL/字段不符官方。 | 同 family、强类型 IP/可信源交叉检查；冲突入隔离；按 `api.ipinfo.io/lite/{ip}` 与 `as_name` schema 获取，IPinfo token 用独立直连控制面客户端。 | 模拟 IPv4/IPv6、私有 IP、源冲突、错误 schema/401；不生成被“确认”的 exit 或错误的 ASN/住宅标签。 |
| P1-07 | P1 | `src/nodelab/probe.py:42-58,110-116`, `docs/NODELAB_V0_SPEC.md:317-333`：单次 group delay 当质量，缺 stage/样本数/分位数和失败率。 | 明确 delay 为指定 URL 端到端测试；保留成功与失败样本及协议/目标/时间，按窗口 p50/p95/抖动/成功率计算，吞吐 opt-in 且限字节。 | 虚构慢/丢包/不同协议数据能复算指标与分母；默认不下载测速文件或滥用第三方服务。 |
| P1-08 | P1 | `docs/NODELAB_V0_SPEC.md:251-289,358-375`：`RELAY_CONFIRMED` 无法由 IP 不同且“没有 CDN 证据”推出；FIXED/住宅/置信度口径不足。 | 事实/推断/未知分层；CDN/自有 GCP 要独立证据；按配置版本、vantage、时间窗判定“观察到稳定/变化”，不担保永久固定；置信度有可追溯证据与反证。 | 单 IP 差异只标分离；3 次同 IP 不出永久固定；备注声称住宅/GCP 不被自动确认为真；能回溯每个标签的证据。 |
| P1-09 | P1 | `docs/NODELAB_V0_SPEC.md:133-248`, `src/nodelab/probe.py:196-201`：资产指纹普通 secret 哈希、无版本/决策事件/池成员历史/幂等与留存方案。 | 现有五表扩展为凭据独立加密、可连接配置版本、source alias、append-only probe/observation/classification & pool membership 事件；去重用密钥 HMAC；唯一约束/单写队列和 TTL。 | 同 URI 不同备注、同入口不同 path/SNI、换 UUID、并发重试/重复导入/删除与备份恢复的迁移测试；历史不被 `latest` 覆盖。 |
| P1-10 | P1 | `docs/NODELAB_V0_SPEC.md:133-160`，**当前无 DPAPI 代码**：迁移/备份/密钥生命周期未定。 | Windows 单用户 `CurrentUser`、独立 secret_blob；有恢复需求才加口令保护的显式导出/密钥封装，不用 `LocalMachine` 作为默认；含失效/删除行为。 | Windows 本用户可解、其他用户不能解、换机缺密钥明确失败、显式恢复可用、数据库单独泄漏不出现可重放凭据。 |
| P1-11 | P1 | `docs/NODELAB_V0_SPEC.md:69-76,354-392`, `src/nodelab/types.py:56-60`：下阶段 FastAPI 鉴权/本地跨站边界未冻结；Agnes 推荐池与决定权未隔离。 | FastAPI 上线前设本地身份、Origin/CSRF/CORS、只读/修改权限；AI 输入固定 allowlist，输出只建议、不能覆盖事实/自动发布，V0 可先禁用。 | 无凭据/恶意 Origin 的写请求拒绝；模拟提示词注入、额外字段、冲突分类不会改变事实、隔离或实际池成员。 |
| P2-01 | P2 | `pyproject.toml:6-10`：Python 依赖仅设最低版本，运行组合未来可漂移；Mihomo bootstrap 反而正确锁定了 v1.19.31 + SHA。 | 后续发布/CI 记录已测试依赖组合与锁定文件；允许库开发时的版本范围与可复现交付配置分离。 | 全新受控 Windows 环境重建得到相同测试/核心版本；不影响本次单节点阻断修复。 |

**计数复核：P0 = 7，P1 = 11，P2 = 1。** NO-ISSUE/正面证据不计入上述数量：bootstrap Windows ZIP 校验值与官方 release 一致；已返回的进程通常只通过自身 Popen PID 关闭；controller 原有绑定地址是回环；基础 IPv6 方括号、普通 percent password 与中文备注解析能工作；测试中未使用/要求真实节点；默认不进行大流量测速。NO-ISSUE 不等于没有旁路风险。

## 4. 修复门槛与验收总方案

1. **离线格式合同**：测试针对官方 v1.19.31 固定 binary/源码；VLESS/Trojan 协议矩阵比较生成配置与 Mihomo API 所加载结构；除了 `-t`，检查监听、组 `now`、规则、正确 SNI/transport/Reality 字段。把错误字段被忽略视为失败；对缺参数要在解析阶段拒绝。禁止执行真实第三方节点来替代这一步。
2. **安全负控**：用 RFC 5737/3849 示例 IP、虚构凭据/本机回环目标，分别模拟错控制器密钥、坏 URI、无效密码/不可达上游、DIRECT/空组、端口竞争、DNS 1053 冲突、超时/崩溃；即使宿主机可直连两个 IP 查询源也绝不 PASS。检验所有 stdout/stderr/异常/JSON/临时 YAML 均不含虚构 secret，`finally` 清理无残留。
3. **Windows owner 验收**：由 Owner **自行**在已有授权的真实 VLESS 与 Trojan 节点上运行单节点探测，先检查 bootstrap 后 binary 可定位、Mihomo 版本、混合监听/组/控制器鉴权，再核验代理链路及双源同 family 出口；记录仅含脱敏的 stage/status、源 IP（如隐私政策允许）、证据来源和错误码，不需要向审计者发送 URI、UUID、密码。分别验收 TLS、WS、gRPC/Reality 等实际打算支持的方言；未覆盖者保持 `UNSUPPORTED/UNCONFIRMED`。至少各有成功样本和故意失败负控，且无 DIRECT 假阳性和明文残留。
4. **NL-003 入场条件**：本台账 P0 关闭；与持久化/批量关联的 P1（尤其 01–06、08–11）有实施方案并验收；真实探测闭环通过后，再批准资产 schema/worker/API。不能用 `20 passed` 或 `mihomo -t` 单独替代上述任一条。

## 5. 更合理的后续顺序与 Owner 唯一下一步

1. **立即冻结 NL-003 新功能；安排针对 P0-01 至 P0-07 的小范围修复任务，优先 P0-01（真实 Mihomo 配置合同），同时修 P0-02/04/05/06/07，而不是继续数据库或要用户交真实密钥。**
2. 完成上面的离线 v1.19.31 配置/API/负控/凭据测试、Windows 单实例与并发生命周期验收；修关联 P1 parser/端口/进程/IP 数据真实性问题。
3. Owner 在自己的环境完成经授权的 VLESS、Trojan 实际链路验收；未验收者不入池、不变 PASS。之后冻结资产身份/版本/事件/DPAPI/规则证据的数据合同。
4. 建 SQLite 的不可变 probe/observation/history + 秘密分离与幂等导入；实现受限 worker 和隔离/人工批准状态；再用受保护的本地 FastAPI 暴露已经验证的操作（可先提供只读 API）。
5. 形成有历史样本的分类规则与持续复测，按证据分层出推荐池；Agnes 只在规则不能充分解释时做可关闭的解释层；最后才是 Grok UI 和 Xboard 对接。两者均不在本次审计内。

**Owner 应该马上做的唯一下一步：** 下发一个“修复 NL-002 Mihomo 配置与可信探测闭环”的限定任务，要求工程负责人先用**虚构节点**交付 `-t + 运行时监听/代理/组/规则/鉴权 + 失败负控 + 临时凭据清理` 的自动化验收证据；审计报告不是修改产品代码的授权。待离线门槛达成，Owner 再在自己的 Windows 机器对已有授权节点做真实验收，不向任何模型提供真实 URI/密码。

## 6. 官方依据（核验日期 2026-09-26）

版本行为优先以 **Mihomo v1.19.31（2026-09-14 发布）tag 源码、官方发布包和离线实测** 为准；官方网页文档为 2026-09-26 查阅的现行页面，若将来随主线升级，需重新跑矩阵。其余来源均为官方原始文档：

- Mihomo：[2](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.31) 官方 release；[3](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go#L402-L458) 顶层 RawConfig；[12](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/vless.go#L58-L91) VLESS 选项；[14](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/trojan.go#L45-L69) Trojan 选项；[4](https://wiki.metacubex.one/en/config/inbound/) 入站；[5](https://wiki.metacubex.one/en/config/proxy-groups/) 代理组；[6](https://wiki.metacubex.one/en/config/rules/) 规则；[7](https://wiki.metacubex.one/en/config/general/#external-control-api) API secret；[8](https://wiki.metacubex.one/en/api/) 控制器 API；[10](https://wiki.metacubex.one/en/config/dns/) DNS；[11](https://wiki.metacubex.one/en/config/proxies/vless/) VLESS；[13](https://wiki.metacubex.one/en/config/proxies/trojan/) Trojan；[15](https://wiki.metacubex.one/en/config/proxies/transport/) WS/gRPC/HTTPUpgrade；[16](https://wiki.metacubex.one/en/config/proxies/tls/) TLS/Reality。
- 其它：[17](https://sing-box.sagernet.org/configuration/) sing-box 配置；[18](https://docs.python.org/3/library/urllib.parse.html) Python URI/`ValueError`；[19](https://www.python-httpx.org/advanced/proxies/) HTTPX 显式代理；[25](https://www.python-httpx.org/environment_variables/) HTTPX 默认读取环境（控制面建议 `trust_env=False`）；[20](https://www.ipify.org/) IPv4/IPv6 接口；[21](https://developers.cloudflare.com/privacy-proxy/get-started/) Cloudflare `cdn-cgi/trace`；[22](https://ipinfo.io/developers/lite-api) IPinfo Lite；[23](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)、[24](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dataprotectionscope?view=netframework-4.8.1) Windows DPAPI。
