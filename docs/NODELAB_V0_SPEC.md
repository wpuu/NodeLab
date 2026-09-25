# NodeLab V0 技术冻结规范

任务编号：NL-001  
状态：FROZEN / 可进入实现  
更新时间：2026-09-25

## 1. 项目目标

NodeLab 是代理/节点链接的本地资产鉴别、批量测试、分类与发布前审核工具。

第一阶段不负责：
- VPN 商城；
- Xboard 用户计费；
- 客户端；
- 支付；
- 推荐返佣。

第一阶段唯一目标：

> 将大量未知 `trojan://`、`vless://`、`vmess://`、`ss://`、`hysteria2://`、`tuic://`、`anytls://` 等链接批量导入后，自动完成确定性解析、真实连接测试、真实出口识别、链路分类、质量标签和节点池推荐，并保留人工确认入口。

---

## 2. 强制模型/工具分工

遵循 `control/PROJECT_RULES.md` 第 5 节。

### GPT-5.6 Sol High
默认负责：
- 架构；
- 数据模型；
- 规则设计；
- GitHub 修改；
- 代码审阅；
- 最终判断；
- Grok 前台提示词冻结。

### Claude Code + Agnes 3.0 Flash
只有在 Sol 当前工具无法完成下列工作时才使用：
- 用户 Windows 本机执行；
- 下载/启动 Mihomo；
- 本地真实代理拨号；
- 本地网络探测；
- 本地构建与测试；
- 必须在用户机器上操作的工作。

### Agnes 3.0 Flash API
只允许处理脱敏后的结构化探测结果，做：
- 固定 JSON 分类；
- 解释标签；
- 批量结构化补充。

禁止向 Agnes 发送：
- 完整代理 URI；
- UUID；
- Trojan 密码；
- Shadowsocks 密码；
- API Key；
- 其他可直接使用的凭据。

### Grok 4.6 High
仅在数据结构/API/页面信息架构冻结后，一次性生成前台。
按“免费生成、默认不能可靠二次修改”计算。

---

## 3. V0 技术架构

### 3.1 本地后台

- Python 3.12+
- FastAPI
- SQLite
- SQLAlchemy
- 后台任务队列：第一版使用进程内有界 worker，不引入 Redis
- Windows 为第一优先环境

### 3.2 代理实测内核

主内核：Mihomo

用途：
- 将解析后的节点转换为 Mihomo 配置；
- 实际协议握手；
- 节点延迟测试；
- 通过指定节点发起出口 IP 请求。

第二兼容内核：sing-box

只在以下情况启用：
- Mihomo 不支持的协议/参数；
- Mihomo 与 sing-box 结果冲突，需要兼容性对照；
- 后续新增协议。

NodeLab 自己不重新实现 VLESS/Trojan/Hysteria2 等协议栈。

### 3.3 IP 情报

V0 使用：
- 实际代理出口请求获取 exit_ip；
- IPinfo Lite 获取 country / country_code / ASN / AS name 等基础情报；
- 允许配置第二 IP 查询源做交叉校验。

住宅/机房判断不得仅依赖 LLM。
必须基于 ASN/组织/已知云厂商/CDN 规则和实测证据，无法确认时标记 UNKNOWN。

---

## 4. 输入范围

### 4.1 第一版必须支持

- vless://
- trojan://
- vmess://
- ss://
- hysteria2://
- hy2://
- tuic://
- anytls://

### 4.2 第一版输入方式

1. 多行文本批量粘贴；
2. TXT 文件；
3. Base64 编码订阅文本导入；
4. 去重导入。

HTTP(S) 订阅 URL 暂不自动抓取，后续独立增加，避免把任意 URL 默认当作代理订阅执行。

---

## 5. 安全存储

每一条代理资产分为：

### secret 层
- 原始 URI；
- UUID；
- password；
- private authentication material。

### metadata 层
- 协议；
- 入口；
- 端口；
- transport；
- TLS；
- SNI；
- Host；
- Path 特征；
- 实测数据；
- 分类；
- 池。

Windows V0：
- secret 层使用 Windows DPAPI 加密后进入 SQLite；
- UI 默认只显示脱敏内容；
- 日志禁止打印 secret；
- 发给 Agnes 的 JSON 永远只来自 metadata 层。

---

## 6. 核心数据模型

### 6.1 node_asset

- id
- fingerprint
- protocol
- display_name
- source
- secret_blob
- redacted_uri
- entry_host
- entry_port
- resolved_entry_ips[]
- transport
- tls_mode
- sni
- host_header
- path_hint
- client_fingerprint
- flow
- alpn[]
- created_at
- updated_at
- enabled

`fingerprint` 用规范化后的“非备注配置 + secret 哈希”生成，用于去重；不得用显示备注作为唯一性依据。

### 6.2 probe_run

- id
- node_id
- started_at
- finished_at
- engine
- parse_ok
- config_ok
- tcp_reachable
- handshake_ok
- proxy_http_ok
- latency_ms
- error_stage
- error_code
- error_summary

### 6.3 exit_observation

- id
- probe_run_id
- exit_ip
- country_code
- country
- asn
- as_name
- network_org
- ip_source_1
- ip_source_2
- sources_agree
- observed_at

### 6.4 node_classification

- node_id
- entry_type
- exit_behavior
- network_type
- stability_class
- quality_class
- recommended_pool
- deterministic_confidence
- ai_label
- ai_confidence
- risk_flags[]
- updated_at

### 6.5 pool

- id
- code
- name
- purpose
- auto_accept_rule
- requires_manual_review
- enabled

---

## 7. 确定性链路分类

分类不能由 Agnes 直接决定事实。

### entry_type

- DIRECT_ENDPOINT_CANDIDATE：入口 IP 与多次实测出口 IP 相同或高度一致
- CDN_FRONTED：入口解析到已知 CDN/边缘网络，出口为另一网络
- RELAY_CONFIRMED：入口与出口明确不同，且没有足够证据认定为 CDN 前置
- MULTI_HOP_SUSPECTED：存在明显 proxyip/relay 参数、多个出口或其他多跳证据，但不能完全确定拓扑
- UNKNOWN

注意：
入口 IP != 出口 IP 只能证明“入口与最终出口分离”，不能单凭这一点宣称具体经过几层中转。

### exit_behavior

- FIXED：跨至少 3 次探测、并跨预设时间窗口保持同一出口
- DYNAMIC：多次探测观察到多个出口 IP
- UNCONFIRMED：样本不足

### network_type

- GOOGLE_CLOUD
- AWS
- AZURE
- ORACLE
- HETZNER
- DIGITALOCEAN
- CLOUDFLARE
- OTHER_DATACENTER
- RESIDENTIAL_CONFIRMED
- RESIDENTIAL_SUSPECTED
- UNKNOWN

“住宅”默认从严：
- 不能因为节点备注写“住宅”就认定；
- 不能因为某个免费网站单次显示“住宅”就直接认定；
- 缺少可靠证据时必须降级为 SUSPECTED 或 UNKNOWN。

---

## 8. 探测流程

单节点探测：

1. 解析 URI；
2. schema 校验；
3. DNS 解析入口；
4. 生成 Mihomo 临时配置；
5. Mihomo 配置校验；
6. TCP/UDP 基础可达性；
7. 真实协议连接；
8. 通过该节点访问出口 IP 检测源 A；
9. 访问出口 IP 检测源 B；
10. 两源交叉验证；
11. IPinfo Lite 补充国家/ASN；
12. 记录延迟；
13. 根据历史 probe 判断固定/动态出口；
14. 运行确定性分类规则；
15. 必要时把脱敏 JSON 交给 Agnes 生成解释性标签；
16. 推荐目标池；
17. 人工确认或自动入池。

---

## 9. 批量探测规则

默认：
- 最大并发：10；
- 每节点连接超时：8 秒；
- 单次探测总超时：20 秒；
- 失败节点最多重试：2 次；
- 指数退避；
- 同一目标入口限制并发，防止误伤或被视为扫描。

V0 默认不做大文件测速。

测速属于显式可选操作：
- 默认关闭；
- 使用小样本文件；
- 设置每节点最大测试流量；
- 防止免费节点/第三方节点被批量消耗带宽。

---

## 10. 第一版节点池

- REVIEW：待人工审核
- SHARED_US_FIXED：美国固定出口共享池
- SHARED_US_DYNAMIC：美国动态出口共享池
- SHARED_EU：欧洲共享池
- CDN_RELAY：CDN/边缘前置池
- HIGH_LATENCY：高延迟池
- UNSTABLE：不稳定池
- DEAD：死亡池
- GCP_DEDICATED：自有 GCP 独享池
- QUARANTINE：异常/信息冲突隔离池

池名只是内部资产分类，不直接等于客户营销名称。

---

## 11. Agnes 输入输出冻结

只有确定性数据完成后才调用 Agnes。

输入示例：

```json
{
  "protocol": "vless",
  "transport": "ws",
  "tls": true,
  "entry_asn": "ASxxxx",
  "entry_network": "example",
  "exit_asn": "ASyyyy",
  "exit_network": "example2",
  "entry_exit_same": false,
  "exit_unique_count": 3,
  "probe_success_rate": 0.9,
  "latency_p50_ms": 210,
  "path_features": ["contains_proxyip_list"],
  "deterministic_class": "MULTI_HOP_SUSPECTED"
}
```

输出必须固定 JSON Schema：

```json
{
  "summary_cn": "美国多出口中转候选节点",
  "usage_tags": ["共享", "动态出口"],
  "risk_flags": ["third_party_upstream", "dynamic_exit"],
  "recommended_pool": "SHARED_US_DYNAMIC",
  "confidence": 0.92,
  "reason_codes": ["ENTRY_EXIT_DIFFER", "MULTIPLE_EXIT_IPS"]
}
```

Agnes 不得覆盖确定性字段，只能提供解释、标签和推荐。
出现冲突时以本地实测数据为准。

---

## 12. Grok 前台页面冻结条件

在下列内容完成前禁止调用 Grok 4.6 High：

- 数据表字段冻结；
- API 路由冻结；
- 状态枚举冻结；
- 页面信息架构冻结；
- 真实样例数据准备完成。

预计一次生成 5 个页面：

1. Dashboard 总览；
2. 批量导入；
3. 节点资产表；
4. 节点详情/探测历史；
5. 节点池管理。

生成后由 Sol 直接修改 GitHub 中必要的小范围前端问题，不默认要求 Grok 二改。

---

## 13. NL-001 验收标准

NL-001 只冻结设计，不要求本机执行。

PASS 条件：

- 协议范围明确；
- 数据模型冻结；
- secret 与 metadata 分离；
- Mihomo 主内核 / sing-box 兼容内核确定；
- 实测优先于 AI 推断；
- 批量探测边界明确；
- Agnes JSON 输入输出冻结；
- Grok 调用时机冻结。

下一任务：NL-002

NL-002 目标：
在用户 Windows 本机实现最小解析器 + Mihomo 单节点真实探测闭环，并用用户已经提供的 VLESS/Trojan 示例做脱敏验收。
