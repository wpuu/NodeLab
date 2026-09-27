# NL-REVIEW-004｜`mihomo -t` 是弱判据：对 NL-REVIEW-002 P0-01 验收依据的勘误

- **性质：** 对固定引擎 **v1.19.31 实测**得出的判据强度测量，并据此调整 P0-01 的验收方式。**不改写** [`NL-REVIEW-002`](NL-REVIEW-002-p0-closure-design.md) A～H 的验收目标，只否定其中「一次 `-t` 通过」作为 P0-01 充分证据的部分。
- **日期：** 2026-09-27（Asia/Shanghai）
- **环境：** Linux 沙盒；官方发布二进制 `mihomo-linux-amd64-compatible-v1.19.31`，自报 `Mihomo Meta v1.19.31 linux amd64 with go1.26.8`，解包后 SHA-256 `b341a765412c192685264e038a6aad2ac1c67c12b8aceeb5c6f64955cf43f5ed`。
- **范围：** 全部输入为虚构凭据（UUID `1111...5555`、`FAKE_ONLY_*` 口令、TEST-NET-2 `198.51.100.7`、`*.example`）。**未接触任何真实节点、URI 或口令；`-t` 只做配置装载，不建立连接、不监听端口。** `REAL_NODE_TEST_ALLOWED_NOW` 仍为 **NO**，`PROBE_GATE_OPEN` 仍为 **False**。

## 1. 结论

`mihomo -t` **不能**用来证明配置正确。它验证的是「配置可装载」：引用完整性、必填字段、类型形状。它对**键名错误与未知键一律静默接受**。

P0-03 与 [`NL-REVIEW-003`](NL-REVIEW-003-f1-f2a-candidate-review.md) B1 关注的「字段被悄悄丢弃 / 错映射」这一整类缺陷，**全部能干净通过 `-t`**。因此 NL-REVIEW-002 中「一次 `-t` + 运行时预检」作为 P0-01 关闭依据的表述，在这一点上给出的是虚假信心。

## 2. 实测数据（同一枚固定二进制，逐条构造后 `-t`）

### 2.1 被静默接受的错误（判据失效区）

| 注入的缺陷 | `-t` 结果 | 为什么危险 |
| --- | --- | --- |
| Trojan 用 `servername` 取代 `sni` | **ACCEPTED** | `TrojanOption` 根本没有 `servername` 键（trojan.go:45-69），该值被丢弃，SNI 退化为 `server`（trojan.go:286-287） |
| Trojan 额外写一个 `tls: true` | **ACCEPTED** | 同样不存在于结构体，静默忽略 |
| `client-fingerprint: iOS` | **ACCEPTED** | **正是 B1**。查表区分大小写，未命中只 `log.Warnln`，随后退回普通 Go TLS |
| `client-fingerprint: netscape` | **ACCEPTED** | 同上，完全非法值也不报错 |
| 代理里加一个完全虚构的键 | **ACCEPTED** | 解码器忽略未知键 |
| `ws-opts.host`（sing-box 风格） | **ACCEPTED** | `WSOptions` 无 `host` 键（vmess.go:165-172），Host 丢失 |
| 顶层混入 sing-box 的 `outbounds` | **ACCEPTED** | 顶层未知键同样被忽略 |
| VLESS `uuid` 格式非法 | **ACCEPTED** | 装载期不校验 UUID 形状 |

### 2.2 能被抓到的错误（判据有效区）

| 注入的缺陷 | `-t` 结果 |
| --- | --- |
| `proxy-group` 指向不存在的代理 | REJECTED |
| `rules` 条目指向不存在的组 | REJECTED |
| VLESS 缺 `uuid`（必填缺失） | REJECTED |
| `rules` 写成 sing-box 的对象形式（类型错） | REJECTED |

**判据强度：8/12 的注入缺陷逃逸。** `-t` 的有效范围仅限引用完整性、必填缺失与顶层类型错误。

## 3. 据此采取的措施

1. **建立强判据替代它。** 从固定源码的 Go struct tag 反推合法键集合，断言生成器输出的**每一个键**都存在于 v1.19.31 的对应结构体中。该断言直接覆盖 2.1 的全部八项逃逸缺陷。键集合抄录在 `tests/test_engine_config.py` 内（连同来源文件与行号），与 `tests/test_strict_parser.py` 保留指纹 map 副本的做法一致。
2. **`-t` 降级为次级 smoke test。** 保留但标注「必要不充分」，且仅在环境变量 `NODELAB_MIHOMO_EXE` 指向固定二进制时运行，默认 skip，保证仓库测试套件自包含、不依赖下载。
3. **`type` 键的处置。** 强判据第一次运行即报 `type` 不在任何 Option struct 中。核对 `adapter/parser.go:13` 后确认它在解码前被单独消费用于分发，缺失会报 `missing type`，属合法必填键，因此带源码锚点加入白名单 —— 而不是反过来放宽断言。这次交互本身即证明该判据是活的。

## 4. 对验收合同的影响

- NL-REVIEW-002 A～H 的**验收目标不变**。改变的只是 P0-01 的**取证方式**：不得再以 `-t` 退出码 0 作为「Mihomo 配置正确」的证据。
- P0-01 的关闭证据应为：**(a)** 键集合 ⊆ 固定源码结构体；**(b)** 每个输出字段值附源码行号依据；**(c)** `-t` 装载通过；**(d)** F3 的逐请求 route proof。目前 (a)(b)(c) 已具备，**(d) 仍缺失**。
- 因此本轮**不宣布任何 P0 关闭**。P0-01/03 的配置生成侧已具备可信证据，但 P0-02（固定二进制与摘要校验）、P0-04（控制器鉴权的运行时验证）、P0-07b（route proof）均未实现。

## 5a. F2b 下半段：固定二进制与真实启动路径的实测

### 供应链：上游没有校验和

MetaCubeX 的 v1.19.31 release **不发布 checksum 文件，也没有签名**。因此摘要只能证明「与我们检查过的字节相同」，**不能证明「上游意图发布的字节」**。这一限制写进了 `engine_binary.py` 的模块文档，不得被描述成「已验证真实性」。

于 2026-09-27 从官方 release URL 下载并计算：

| 资产 | SHA-256 |
| --- | --- |
| `mihomo-linux-amd64-compatible-v1.19.31`（解包后） | `b341a765412c192685264e038a6aad2ac1c67c12b8aceeb5c6f64955cf43f5ed` |
| `mihomo-windows-amd64-compatible-v1.19.31.exe`（zip 内） | `1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b` |

Windows 那一条供 Owner 在 W2 安装后自行比对。二者均已进入 `KNOWN_DIGESTS`；Owner 若使用其他构建，用 `NODELAB_MIHOMO_SHA256` 提供自己的 pin。**任何情况下都不搜索 `PATH`、不按名匹配**，因此不可能误选 Owner 自己那份 Mihomo。

### 真实启动路径（非 `-t`）的实测结论

在虚构凭据（TEST-NET-2 `198.51.100.7`、`*.example`）下启动固定引擎实测：

| 断言 | 结果 |
| --- | --- |
| 控制面无 token | **401** |
| 控制面错 token | **401** |
| 控制面本次 run token | **200** |
| 运行目录内新增文件 | **无**（仍只有 `.owner.json` + `probe.yaml`） |
| mixed-port 监听 | 由我们 spawn 的那个 PID 持有，仅 `127.0.0.1` |
| `/proxies` 中的对象 | `NODE` 存在，`PROBE` 组 `now == NODE` |

**第一条重要结论：** NL-REVIEW-003 §4.2 担心的「Mihomo 以 `-d <run_dir>` 运行会自建 `cache.db` 之类文件，导致 `_Recovery` 的目录 allowlist 失配」—— 在 `profile.store-selected: false` + `store-fake-ip: false` 下**不成立**。allowlist `{.owner.json, probe.yaml}` 可以保持。该结论现已固化为回归测试。

### 一个被实测推翻的判定逻辑

监听归属检查最初写成「该端口上的**所有**监听都必须是回环」。这个规则是**错的**，并且立刻被环境证伪：本沙盒的基础设施会把每一个监听端口镜像到一个链路本地地址（`169.254.0.21`）上，于是一个严格只绑 `127.0.0.1` 的 socket 被判成 `LISTENER_NOT_LOOPBACK`。

正确语义是**只对我们自己 PID 持有的 socket 下断言**：端口被别的进程以别的地址镜像，不改变「我们的流量到 `127.0.0.1:port` 仍然进入我们的进程」这一事实。改正后四种情形均正确：自持回环 → `LAUNCH_OK`；自持 `0.0.0.0` → `LISTENER_NOT_LOOPBACK`；端口被他人独占 → `LISTENER_FOREIGN_OWNER`；无监听 → `LISTENER_MISSING`。

这一条同时是对 Owner 机器的提醒：**Windows 上如果装有端口转发/代理类软件，同样可能出现镜像监听**，按旧规则会误报。

### 顺带修掉的操作者陷阱

`NODELAB_MIHOMO_SHA256` 被 export 成空字符串时，原实现报 `BINARY_PIN_INVALID` 硬失败。空变量应等同于「未设置」。`NODELAB_MIHOMO_EXE` 同理。两者均已修正并加回归测试。

## 5b. 本轮之后 P0 的真实状态（仍无一项 CLOSED）

| P0 | 状态 | 说明 |
| --- | --- | --- |
| P0-01 正确 schema | 证据链 (a)(b)(c) 齐，缺 (d) | 键集合 ⊆ 源码结构体、字段附行号、`-t` 通过、运行时对象存在；仍缺 F3 route proof |
| P0-02 可信固定 binary | **实现完成，待 Windows 复验** | 无 PATH 回退、摘要 + 版本双校验、拒符号链接/全局可写；Windows 路径未在本环境执行 |
| P0-03 严格解析 | F2a 完成 + F2b 映射已校验 | |
| P0-04 每次随机 secret | **运行时已验证 401/401/200** | 仅 Linux；Windows 待 W2 |
| P0-05 私有生命周期 | F1 候选，待 W1 | 本轮额外验证了运行目录零残留 |
| P0-06 零泄漏 | F1 候选，待 W1 | |
| P0-07 route proof | **未开始** | `PROBE_GATE_OPEN` 仍为 False，CLI `probe-*` 仍返回 `PROBE_GATE_CLOSED` |

## 5. 附带观察

- 生成的配置在 `-t -d <run_dir>` 下运行后，**运行目录内没有多余文件**（`profile.store-selected: false` + `store-fake-ip: false` 生效）。这解决了 NL-REVIEW-003 §4.2 提出的「Mihomo 可能自建 `cache.db` 导致 `_Recovery` 的目录 allowlist 失配」的担忧——至少在 `-t` 路径上成立。**真正的启动路径（非 `-t`）尚未验证，F2b 的下一步必须复测。**
- Trojan 的默认 ALPN 由引擎按传输方式自行决定（tcp 用 `DefaultALPN`，ws 用 `DefaultWebsocketALPN`，trojan.go:106/153）。生成器仅在 URI 显式给出 `alpn` 时才写该键，避免覆盖引擎的传输相关默认值。
