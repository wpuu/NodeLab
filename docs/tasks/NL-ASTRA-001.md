# NL-ASTRA-001｜NodeLab V0 架构与实现红队终审

状态：READY  
执行模型：GPT-6 Astra Max（使用可用的最高思考等级）  
任务性质：高难度只读技术终审 + 审计结果持久化  
代码修改：禁止  
Owner：GPT-5.6 Sol High

## 一、仓库与权威基线

仓库：

`wpuu/NodeLab`

目标分支：

`main`

开始执行时必须先读取并记录实际 HEAD，不得假设 HEAD 未变化。

当前已知基线（仅作定位，执行时仍需重新读取）：

`3fe8b08dd8535dc0c3b8824725637c910af11d40`

之后 Owner 已可能添加文档提交，所以必须以执行时 main 最新 HEAD 为准。

必须首先读取：

- `docs/NODELAB_V0_SPEC.md`
- `pyproject.toml`
- `src/nodelab/parser.py`
- `src/nodelab/types.py`
- `src/nodelab/redaction.py`
- `src/nodelab/mihomo_config.py`
- `src/nodelab/mihomo_process.py`
- `src/nodelab/probe.py`
- `src/nodelab/cli.py`
- `tests/`
- `scripts/bootstrap_mihomo.ps1`

## 二、背景

NodeLab 目标不是普通代理客户端。

目标是：

> 批量导入大量未知代理 URI，经过确定性解析、真实协议连接、出口 IP 实测、ASN/网络归属、链路行为、稳定性和质量检测，形成可持续复测、可分类、可人工审核、以后可发布到商业节点池的资产数据库。

第一阶段协议至少包括：

- VLESS
- Trojan
- VMess
- Shadowsocks
- Hysteria2
- TUIC
- AnyTLS

当前 NL-002 只实现了 VLESS + Trojan 的最小解析和探测框架。

用户拥有大量第三方节点，也有自有 GCP 节点。NodeLab 后续需要区分：
- 直连候选；
- CDN 前置；
- 中转；
- 动态出口；
- 固定出口；
- 数据中心；
- 住宅疑似/已确认；
- 自有 GCP 独享；
- 不稳定/死亡；
- 隔离观察。

Agnes 3.0 Flash 后续只允许处理脱敏后的固定 JSON，用于解释和推荐标签，不能替代确定性网络实测。

Grok 4.6 High 以后只用于一次性前台生成，不参与本任务。

## 三、为什么现在必须审计

NL-002 已报告：

- Python 3.12.10
- Mihomo v1.19.31
- Mihomo ZIP SHA256 校验 PASS
- pytest 20 passed
- VLESS parse PASS
- Trojan parse PASS
- secret scan PASS
- process cleanup PASS
- Git status clean

但**真实 VLESS/Trojan 节点尚未完成实测验收**。

Owner 初步人工审阅还发现：

`src/nodelab/mihomo_config.py`

当前使用了：

- `inbounds`
- `outbounds`

风格的配置结构。

而 Mihomo 当前公开文档主要描述：
- 顶层代理端口 / `listeners` 作为入站；
- `proxies` 作为代理节点；
- `proxy-groups` 作为策略组；
- `rules` 负责路由。

这可能是：
1. 当前 Mihomo 新版本确实兼容的合法结构；
2. 测试没有覆盖到真实配置语义；
3. 代码误用了 sing-box 风格结构；
4. 某些字段被 Mihomo 静默忽略。

本任务必须基于最新官方资料和代码事实独立判断，不能接受 Owner 的预判。

## 四、本任务唯一目标

在继续 NL-003（SQLite + FastAPI + 批量资产库）之前，回答：

> 当前 NodeLab V0 的技术基础是否足够正确、可靠和可扩展，还是存在必须先修的 P0/P1 设计或实现问题？

不要直接修改产品代码。

## 五、必须审的 12 个领域

### 1. Mihomo 配置正确性

逐字段审：

- mixed/listener 定义；
- proxy 节点定义；
- proxy group；
- rule；
- DNS；
- external controller；
- VLESS；
- Trojan；
- WS；
- gRPC；
- HTTPUpgrade；
- TLS；
- Reality；
- fingerprint；
- flow；
- SNI；
- Host；
- path；
- allow insecure。

必须判断当前生成 YAML 是否真正符合 Mihomo v1.19.31。

不得仅以 `mihomo -t` 是否退出 0 作为充分证据。

### 2. URI 解析正确性

审计：
- RFC/URI userinfo 处理；
- percent decode；
- IPv6；
- IDN；
- 重复 query key；
- 大小写；
- 空 password；
- malformed URI；
- VLESS UUID；
- Trojan password；
- fragment；
- WS path；
- gRPC serviceName；
- Reality 参数；
- XTLS flow；
- ALPN；
- fingerprint；
- allowInsecure；
- 未来协议扩展方式。

### 3. Secret / 隐私边界

检查：
- 原始 URI；
- UUID/password；
- temp YAML；
- exceptions；
- subprocess stderr/stdout；
- test failure；
- crash dump；
- data JSON；
- Git；
-日志；
-环境变量；
- Windows 临时目录。

确认目前所谓“secret 不泄漏”是否真的完整。

### 4. Mihomo 进程生命周期

审：
- startup readiness；
- 只 sleep 8 秒是否可靠；
- controller readiness；
- child process crash；
- cleanup；
- Windows terminate/kill；
- 临时目录；
- 多并发时是否误杀别的 Mihomo；
- `cleanup_stale_mihomo` 是否存在误杀用户其他 Mihomo 客户端的风险。

### 5. 本地端口竞争

审：
- find_free_port 的 TOCTOU；
- mixed port；
- controller port；
- DNS 1053 是否固定导致并发冲突；
- 多节点批量 probe 时是否能安全并发。

### 6. 出口 IP 真值

审：
- ipify；
- Cloudflare trace；
- 两源不一致；
- IPv4/IPv6；
- DNS 泄漏；
- direct fallback；
- 请求是否百分百经测试节点；
- Mihomo selector 是否真的选中了目标 proxy；
- 如何防止“代理失败后 DIRECT 导致误判出口”为 PASS。

### 7. 延迟与质量

审：
- delay API；
- latency 实际含义；
- 对 WS/TLS/Reality/Hysteria2/TUIC 是否可比；
- timeout；
- p50/p95；
- 抖动；
- 成功率；
- 何时需要小流量吞吐测试；
- 如何避免滥用第三方资源。

### 8. 链路分类科学性

重点审：

- entry IP != exit IP 到底能证明什么；
- CDN 与 relay 如何区分；
- dynamic exit 如何判定；
- 固定出口至少需要多少样本与时间跨度；
- proxyip/path 字符串只能作为何种证据；
- “住宅”如何避免误判；
- ASN/云厂商规则；
- classification confidence 如何定义。

要求明确区分：
- 可观测事实；
- 高置信推断；
- 低置信推断；
- 不能从现有证据推出的结论。

### 9. SQLite/FastAPI 下一阶段架构

在不写代码的前提下审查 V0 Spec 数据模型：

- node_asset
- probe_run
- exit_observation
- node_classification
- pool

判断：
- 是否缺 history/event；
- node secret 与 metadata 分离是否合理；
- fingerprint 去重策略是否会错误合并；
- 同一线路换 UUID 是否应该视作同一资产；
- 同一 URI 不同备注；
- 同一入口不同 path/SNI；
- 节点版本/配置变化；
- 并发更新；
- 幂等；
- 数据保留周期。

### 10. Windows DPAPI 方案

审：
- 单用户 DPAPI；
- LocalMachine vs CurrentUser；
- 数据备份/迁移；
- 换电脑；
- 数据库泄漏；
- 是否需要 envelope encryption；
- V0 是否应该先简化。

### 11. Agnes 3.0 Flash 边界

只审架构，不调用 Agnes。

回答：
- 哪些字段一定不能由 LLM 判断；
- 哪些可以交给 Agnes 生成固定 JSON；
- 如何防止 Agnes 推荐覆盖 deterministic facts；
- 是否值得保留 AI 分类层，还是规则已足够。

### 12. 后续路线

判断正确顺序是否应该仍是：

- NL-002 real probe
- 修复 P0/P1
- SQLite
- FastAPI
- 批量 probe worker
- 分类规则
- Agnes
- Grok UI
- Xboard integration

如果不正确，请给出更合理顺序。

## 六、强制联网核验

本任务涉及快速变化的软件。

必须联网核验，优先使用：

1. Mihomo 官方 GitHub / MetaCubeX 官方文档；
2. sing-box 官方文档；
3. Python/httpx 官方文档（若涉及）；
4. Microsoft DPAPI 官方文档；
5. IPinfo 官方文档。

不要依赖转载教程替代官方资料。

报告中对“当前版本行为”的关键结论必须附来源和日期/版本。

## 七、严重度定义

必须逐项标：

### P0
继续开发前必须修，可能造成：
- 真实节点无法工作；
- 出口检测产生系统性假阳性；
- secret 泄漏；
- 错误杀进程；
- 数据模型需要推倒重来；
- 真实商业使用产生严重安全问题。

### P1
应在进入批量/数据库前修。

### P2
可以在 V0 后补。

### NO-ISSUE
当前设计合理，无需修改。

不得为了显得严格而虚构问题。

## 八、必须输出的最终决策

报告开头必须给：

```text
NL-ASTRA-001_DECISION

AUDITED_HEAD:
OVERALL:
- PASS_TO_NL003
或
- PASS_AFTER_P0_FIX
或
- REDESIGN_REQUIRED

P0_COUNT:
P1_COUNT:
P2_COUNT:

REAL_PROBE_REQUIRED_BEFORE_NL003: YES/NO
```

然后给：

1. Executive Summary；
2. 逐领域审计；
3. P0/P1/P2 表；
4. 每个问题的代码位置；
5. 推荐修法，但不要修改代码；
6. 修复后的验收方法；
7. 下一阶段顺序；
8. “Owner 应该马上做的唯一下一步”。

## 九、禁止事项

- 不修改产品代码；
- 不重构；
- 不执行真实第三方节点；
- 不需要真实 URI；
- 不要求用户提供 UUID/password；
- 不引入新框架；
- 不从头重新设计整个商业项目；
- 不审 Xboard 商城；
- 不生成前台。

## 十、结果持久化

如果 GitHub 写权限可用：

只允许新增：

`docs/audits/NL-ASTRA-001-red-team-audit.md`

不得修改任何其他文件。

提交信息：

`docs: add NL-ASTRA-001 NodeLab red-team audit`

如果不能写 GitHub，完整输出报告即可，由 Owner 后续保存。

