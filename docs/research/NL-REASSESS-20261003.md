# NodeLab 商业复审与实施建议

核验日期时间：2026-10-03 22:14:18，Asia/Shanghai（UTC+08:00）。
用户界面选择：Astra / Ultra（用户提供）。本环境未取得可独立验证的精确运行模型 ID 和实际思考档位；不以提示词或角色描述证明配置。
执行方式：主负责人综合判断，四个并行研究任务分别复核市场、成本条款、Codex 能力与仓库代码。各自记录合并后再核验关键证据。
状态：研究完成；本文件是推荐和后续授权边界，不是产品主线变更、开闸许可或商业上线证明。

**推荐：保留 NodeLab，缩成有投入上限的自用资源调查工具；暂缓未知节点转售、套餐商城和返佣。先证明拥有值得管理的资源，再证明有人愿意为结果付款。**
目前没有证据支持把 NodeLab 列为主要赚钱项目，但也没有必要把已完成的解析、安全和本地协议实验全部丢弃。相邻的客户自备合法代理诊断服务，只值得小额验证，尚不值得直接开发为完整订阅软件。

## 1. 最新仓库事实

| 项目 | 2026-10-03 读取结果 |
| --- | --- |
| 仓库 | wpuu/NodeLab，公开；API 返回 push=true、admin=true |
| main | 55ce1b248e1bb5b2368ae34b4fcfbb34f9057a3f；2026-09-27 15:37:46，北京时间 |
| 已合并 PR #1 | F1/F2a 修复链，2026-09-27 合并 |
| 草稿 PR #2 | arena/01a0e60c-nodelab；bec881493564b1616a66cb7b640c788cc0a400fb；相对 main ahead=51、behind=0 |
| 另外两个远端分支 | arena/01a0e0e6-nodelab=a0056f571a1db1af3fb12903e11627cc2e037e4f；candidate/w1-gate=a0968debda292650b9f19fa4e82f8cee606a2216 |
| Issue 集合 | 此次返回仅 PR #1、#2；没有另一个独立 Issue 任务单 |
| 最新取得的真实验收 | Actions run 36467835941，head=2b108df70433b153761834c2f6a6fb04c3111f00，completed/success |
| 该验收与候选差异 | bec8814 仅在 2b108df 后增加一个文档提交；对比仅三个 docs 文件变化，无产品代码变化 |
| 用户 Windows | E:\NodeLab 的实际提交、未提交修改、运行结果未取得；当前 Windows 项目镜像不是那个目录 |

读取了远端分支清单、main 最近12个提交、全部返回的两个PR、Issue集合、main和候选的完整非截断文件树及两次commit comparison（提交对比）。核对 Actions 作业步骤，并实际读取日志中的固定结果字段，不只复述 PR 文案。

| 已取得的 Linux 关卡 | 实际结果 | 能证明的范围 |
| --- | --- | --- |
| 全量回归 | 1032 passed / 3 skipped | 跳过的三项是 Windows；不能代替实机 |
| 引擎会话 | 11 passed / 0 skipped | 合成环境中的真实固定引擎会话 |
| Trojan TLS TCP | 4 passed / 0 skipped | 本地协议夹具与 LOCAL_FIXTURE_ONLY 路由证据 |
| VLESS TLS TCP | 4 passed / 0 skipped | 同上 |

上述计数互有覆盖，不相加。日志明确 real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。原始 run 在 UTC 2026-09-28 18:48:50 启动，即北京时间 2026-09-29 02:48:50。

**已经发生真实 Linux 运行，不等于已经测过真实上游节点，更不等于可商用。**

## 2. 历史问题与现在的能力

| 历史 P0 | 实质变化 | 未完成的证明 |
| --- | --- | --- |
| 01 配置混用 | main已有正确Mihomo结构；候选有本地协议/路由实测 | 产品入口、外部线路与Windows |
| 02 二进制选错 | 固定版本/摘要/绝对路径，禁PATH回退；会话复核 | Windows；摘要也不等于上游签名 |
| 03 解析丢字段 | 严格类型化、单次解码、重复和未知参数拒绝 | 全部方言；Reality/HTTPUpgrade明确不支持 |
| 04 控制器鉴权 | 正确secret及401/401/200检查，Linux运行证据 | Windows |
| 05 残留与乱杀进程 | 私有目录、准确子进程归属、锁及恢复；Linux目录身份加固 | Windows、所有崩溃/敌对路径的完全防御 |
| 06 公共输出泄密 | 取消URI命令参数、固定白名单和错误码、私有对象，虚构秘密负测 | Windows完整路径；不能宣称抵抗所有同用户恶意程序 |
| 07 两源相等误报 | 判定要求各请求路由证据；候选有本地关联/捕获 | 生产入口和外部真实出口 |

因此不能沿用“7项全没修”。但正式历史关闭合同也没有全部满足；本轮不追认 CLOSED（全面关闭）。

main 的 probe 入口仍关闭，结果存储仍禁用；候选也未开放生产探测。代码主要是解析、安全生命周期和离线引擎实验。没有完成资产数据库、持久复测、ASN分类、前台、套餐、收款或返佣。SPEC里的八协议、DPAPI加密数据库、FastAPI等是旧设计，不是已实现能力。

解析候选范围主要为 Trojan/VLESS 的 TLS TCP/WS/gRPC；能解析某方言不代表已完成对应握手验收。Windows运行根仍绑定历史E盘位置，不具备通用安装体验。

团队有选择地读取 main 的 parser/types/probe/cli/redaction、engine_config/binary/launch、mihomo_config/process、SPEC/README/pyproject、安全与Windows测试、审计001/003/004和决策005；候选的 engine_session/offline_fixture/route_evidence/probe、044及workflow。connection_reader/fixture_capture/fixture_verdict只读首段与接口。未全面读全部44份审计、全部测试、旧tasks和每个历史分支；002未作全文重新审计。未取得历史rescue分支；远端分支清单没有它，不代表历史本地提交不存在。check annotations专用读取被工具端拒绝，本轮依作业步骤和实际日志核实结果。

## 3. 商业目标应先于技术路线

用户描述“很多链接”说明有调查素材，不说明已有供应。商业资产至少需要可核实来源、允许用途、转售许可、可重置凭据、配额、失效替换和长期控制。

- 链接数量不等于独立线路数量；同出口、相同上游账号、重复配置要分开统计。
- 格式错误、不支持方言、无法连接、暂时失败是不同状态；尤其不能把Reality不支持计为死亡节点。
- 入口和出口不同只能记录分离，不能直接证明多跳结构或具体中转层数。
- ASN（自治系统网络编号）和机房标签不能证明家庭设备、住宅授权或独享。
- 一次成功、甚至三次IP相同，仅说明观察结果；不能保证以后固定或稳定。
- 两个检测源看到不同IP可能来自轮换、IPv4/IPv6或测量差异；应记录“观测不一致”并调查，不能自动等同节点死亡。
- 美国云端成功不能代表天津或全国客户成功。质量必须带测量地点、时间、目标和失败分母。

自有GCP的控制权是真优势，住宅身份、全国稳定和低价商用带宽尚不是。免费AI可以减少文本处理成本，但不会产生线路控制权、获客、售后和收款资格。

普通上游分享凭据无法通过商城直接变成独立用户：必须掌握服务端，或另做自己的入口网关来认证、计数、禁用。入口网关又带来流量成本、滥用处置和单点故障；仍不能控制上游共享账号被他人耗尽或撤销。因此不能先建面板再期待供应问题自动解决。

## 4. 替代品与值得验证的差异

| 现成方案 | 已核实能力 | 判断 |
| --- | --- | --- |
| Sub-Store | 转换、聚合、筛选和订阅整理；AGPL-3.0 | 通用管理不值得重新开发；凭据应保留在自控环境 |
| sing-box URLTest | 周期性连通测试与出站选择 | 基础健康检查无需AI |
| FullTclash | 批量延迟、速度、拓扑和目标可达性检测 | 能力参照；原仓库2025-05-14归档，不直接作为新生产依赖 |
| Marzban | 用户、流量、到期、订阅及API；AGPL-3.0 | 有合法自控上游后可复用；不能接管未知分享链接 |
| Webshare | 正规付费代理/API/替换等；与Trojan/VLESS规格不同 | 普通云IP本身差异弱；购买也不自动获得转售权 |

Mihomo的2026-07-24 Issue #3022记录大量订阅测速并发导致路由器卡顿。旧Issue #1298记录健康检查和测量流量痛点；不能据此断言当前发行版仍复现。它们支持“有需求问题”，不支持“有人会购买NodeLab”。

推荐差异：保留凭据、控制测量流量、可重复的历史、失败归因及可信报告。它首先支持自用，商业上最多验证客户自备合法代理的固定范围诊断。客户是假设中的已付费采购代理、但业务经常失败的小型采集或自动化开发团队。普通免费节点使用者付费理由薄弱；大代理厂商也不是一人首单的理想切口。

NodeLab应卖“减少排查时间和错误采购”，而不是卖免费工具已有的延迟列表；目前尚无付费证据。

## 5. 第一批验证与停止条件

推荐先给工程探索最多两个可审查开发周期。这是投入控制建议，不是进度保证。第一周期用虚构数据生成离线资产盘点和样本报告；证明能输出输入总数、重复候选、协议分布、格式错误、不支持、来源及授权未知。随后才准备用户自持资源的本机离线盘点，由用户明确允许在对应目录处理；不需要上传URI给模型。

若资源具备测量许可，再单独批准受限实测：先一个协议、少量节点、串行、小响应、请求与字节上限，之后在预定7天窗口复测。记录失效、出口变化和成本，7天观察不能升级为长期服务保证。样本数量和预算由来源及权限决定，不机械全测。测试进行前需要凭据安全和路由负控通过。

并行的商业试验先准备中英文样本诊断报告、固定范围交付和推广草稿。本轮不发布。r/webscraping已有月度推广机制，已检索到2026年10月帖；全文读取被拒。发表前必须查看当月帖子与最新规则，只在允许入口推广，不自动私信，不在技术Issue做广告。买家可以看到具体失败归因样本，并主动询问。这个渠道可访问，不等于已验证转化。

假设试验价US$29–49，限定合法自备代理、单个任务/测量位置和请求上限；客户自跑或使用可撤销授权测试凭据。按报告和诊断收费，不保证目标平台永远可用。最多两轮公开验证、两周窗口，争取至少两个实际付费诊断；达不到就暂停商业扩展。这个阈值是管理选择，无成功率或收入预测。收款资格未确认前不启用结账。

以“真实付款+可重复交付+维护后仍有毛利”作为继续条件，不以免费测试、浏览量或GitHub星数代替。利润应扣上游、出站、IP、检测数据、支付退款、售后工时和税。若诊断需要大量人工、复购不足，保留自用功能，停止订阅软件投入。

若以后取得允许转售、可分配独立用户、能替换失效资源的供应合同，且相关位置实测和收款条件通过，可重新评估服务运营后台。推荐返佣不是现有获客优势；没有受众时不单独立项。

## 6. GCP成本核验及重要冲突

未读取用户云账户、具体SKU（计费项目）、账单、实例网络层级和抵扣。本节为官方规则和假设，绝非用户实际费用。

Compute Engine免费层在us-west1/us-central1/us-east1合计一个月等效一台e2-micro时数及30GB-month标准磁盘；同账单账号的三个项目不自动获得三份。其北美出站免费说明与Standard层的免费量不同。

官方VPC计价页写Standard首200GiB每账号跨全部区域；Network Service Tiers overview却写每区域每SKU 200GB。两页口径冲突，不能认定三台必有600GB，或已证明只有200GB。未看实际抵扣前，采用计价页保守预算；GB/GiB也不能混用。

假设30天、三公网IPv4、同一账号，以下仅网络与IP，排除计算/磁盘/税和维护：

| 合计出站假设 | 月成本估算 |
| --- | ---: |
| Standard 200GiB | 约US$10.80 |
| Standard 600GiB，按合计200免费 | 约US$44.80 |
| Premium全部600GiB，Iowa到中国大陆 | 约US$148.80 |

普通VM在用IPv4按US$0.005/小时，Standard超额首档US$0.085/GiB，示例Premium中国大陆US$0.23/GiB。三台同账号还可能有超额计算及磁盘费。真实独立合格账单账号另核，不能建议为规避限制组合账号。

单代理计费不要机械乘二：下载100GiB+上传10GiB，大约110GiB出站加开销；互联网入站一般免费。多云中继再逐段计费。AI促销credits不能默认抵扣VM或IP。普通预算告警不是硬限；新spend cap预览支持指定服务，不能据此对Compute Engine承诺自动封顶。

后续只读核账入口：Google Cloud Console > Billing > 选择各账单账号 > Reports，逐项查看Compute Engine、网络和IPv4 SKU、实际用量、免费抵扣、促销抵扣及净费用；Compute Engine > VM instances核对实例类型、区域、磁盘和网卡IP的网络层级。本轮未操作。改变网络层级可能更换公网IP、影响现有VPN，必须另批；不为了省钱自动调整。

## 7. 授权、许可证、经营与收款

Google条款允许有独立实质价值的客户应用，同时限制直接转售云服务、违法使用及为避费/绕限组合账号。不能把托管自己软件与倒卖云账号混为一谈；VPN没有被简单点名，不等于获得商用批准。

中国电信经营许可和工信部对未经许可跨境电信经营的解释，对向国内客户出售跨境节点流量构成重大前置条件。软件研究、自用测量和跨境电信销售不是同一业务；不能因此宣称全球VPN都违法。海外客户方向仍须确定经营主体、客户所在地、服务性质、目标网站授权和数据要求。本次不提供“换海外前台即可合法”的结论。

供应商授权是独立条件：Webshare官方明确再分发/转售需书面许可。未知节点的许可完全未取得，不能由免费来源推定。

Mihomo固定v1.19.31 LICENSE原始文件为GNU GPL v3；Sub-Store/Marzban为AGPL-3.0。GPL/AGPL不等于禁止商业用途，分发/修改和网络使用义务依具体组合评估；调用外部二进制也不能直接作为闭源合规结论。NodeLab树无LICENSE，公开可读不等于已授予开源再分发许可；后续发行前确认依赖和自身许可。此时只需内部研究，不先造复杂许可架构。

Stripe商户支持列表含香港，不含中国大陆；美国IP和GCP实例不能替代合法实体及开户材料。官方限制不是VPN一律禁止，也不是必然受理。先核实用户真实收款主体和允许的服务类别，才启用收费；不为这轮注册海外公司或开通付费账户。现金返佣、可提现余额、多层分销增加结算、退款套利和税务工作，首版取消。以后如确有需求，可验证一级服务折扣再决定现金机制，不冻结分成比例。

## 8. 实现建议

保留Python严格解析、脱敏边界、准确子进程生命周期、固定引擎校验及本地正负握手夹具；保存PR #2历史，合并需针对最终产品合同审核，不因测试数多自动合并。

最小产品从“可解释的资产清单”开始：命令行或简单本地界面，私有输入，匿名资产ID，格式/方言/重复/来源许可状态、后续测量时间与失败原因；只导出安全统计和报告。先不建八协议、第二引擎、10并发、队列、商城和AI分类。持久历史确实有价值时才加入SQLite；加密与权限按实际部署环境实现。

初期保留Mihomo，原因是已有固定版本和本地线路证据，替换立即产生重复验证。若实际资源主要是Reality或别的方言，再与现成工具做同样本/同预算比较；比较结果能推翻保留建议。复用协议实现，不自己写栈，也不直接合并旧安全流程作为最终威胁模型。

可靠性必需：秘密不进公开仓库/日志/模型；不能悄悄DIRECT回退；错误不冒充成功；只停止自有进程；超时/字节限额；持久状态标清测量位置与未知。隔离、单出站、无DIRECT和受控负测可以形成更简单的可靠边界，但必须证明实际行为，不以新架构名替代证据。不是所有新Linux路径永远要经过历史Windows门槛；若改为Linux产品，要重新批准边界并按Linux验收。若仍交付Windows，NTFS、ACL、进程和现有客户端共存必须实机证明。

Agnes/Grok本阶段均非依赖。以后Agnes只处理脱敏结构数据或明确执行；接口接入前实际验证，不猜名称。Grok首版免费只减少页面起稿成本，不解决迭代和维护。

## 9. GitHub和Codex安排

| 概念 | 推荐 |
| --- | --- |
| GitHub仓库 | 继续wpuu/NodeLab；本轮资料分支，保留旧记录。现阶段不迁仓库或拆子项目 |
| GitHub Projects看板 | 暂不需要；一个状态记录+少量Issue足够，看板不是执行器 |
| Codex云环境 | 推荐一个专用、仅关联NodeLab的已发布环境；已有合适环境就复用，不自动重建 |
| Codex任务 | 先一个主执行任务，各Agent只读研究/审查或分离文件；环境不等于正在工作 |
| 自动化 | 首先验证云任务和跨设备接续；之后只做状态检查，真实闭环证实后再扩展 |

当前官方新版Cloud入口、费用及自动化与旧版不同，不能沿用旧界面猜测。Pro包含Cloud资格但受账户推出和工作区设置限制。运行中的云任务可在电脑休眠后继续；本地任务及本地自动化依赖电脑。标准Cloud环境目前无单独VM费，模型消耗Codex相关用量；API/官方codex-action调用单独计费，不包含于Pro“全免费”。

网页/手机Scheduled支持合资格GitHub PR事件，网页同聊天调度支持分钟间隔；并不因此证明它能启动/续接新版Cloud开发任务。未核实该用户的实际Cloud环境、模型选择、用量或事件权限。首次环境与分支/PR验证步骤在同目录TXT交接文件；本轮未创建环境、定时器或云任务。

推荐由一个主Codex任务按目标和验收缺口决定下一项；分支、PR和Issue记录结果。任务结束前写检查点：真实HEAD、已完成、失败证据、下一项、权限边界。新任务先读记录；不依赖聊天记忆或未提交VM状态。负责人独立验收后再提合并。多Agent不得同时写同一文件；同分支只有一个写入者，跨分支重叠由主执行者整合。

模型推荐：日常GPT-6.1 Sol可用时从默认/Medium开始；可靠性和验收High，复杂隔离才Extra High；不可选则GPT-6 Sol。Astra用于商业和重大取舍；Luna/Agnes做明确可核验的重复处理。不默认所有任务Ultra，不伪造本账户菜单。

失败立即保存具体原因；可修依赖/测试失败由当前执行者修并复验，同一权限或网络阻塞不反复重开。用量不足保留进度，查Usage，等待或由用户用券；不自动买额度。缺权限只指明Cloud访问/仓库授权/push或PR权限，通过官方设置补齐，不让用户在聊天粘PAT。

允许自主：已批准阶段内的隔离开发、适当测试、研究和可审查资料。另需批准：真实资源/节点处理、产品主线重构或合并、正式部署、新增付费、改变GCP网络/实例、迁仓库、扩大凭据或生产权限。Windows只用于本机真实权限/客户端共存及当地线路证据；不要求每次研究或代码编写开机。

## 10. 最合理的下一步

本轮已完成重新判断及可执行交接，保持生产探测关闭、PR #2未合并。下一次“继续推进”建议完成第一轮离线资产盘点原型和示例报告：隔离分支、全虚构输入、无网络副作用，证明输出能帮助判断是否值得继续。先不用真实链接、GCP和API。自然检查点是原型+报告+证据+真实远端PR，不是再次增加几十份审计。

你现在无需公开Key、发送真实节点或启动E盘程序。愿意利用关机后的云开发时，只需按交接文件完成一次官方账号环境授权；可用性先实测。当前研究保存不增加部署或付费。未来的节点测量、服务运行、IP、检测数据库/API、支付和自动化可能产生费用，必须先说明预算和影响。

推翻本推荐的关键证据：有清楚可转售、可独立分配和替换的上游；相关地点持续测量通过；真实买家已付款且交付可重复；账单及服务工时之后仍有正毛利；合法经营/支付路径可落地。否则保留轻量自用，停止商业扩展。

## 来源与可回溯证据

以下均于2026-10-03检索或读取；网页显示日期不是统一的发布日期。价格、权限和页面内容以后须再核验。

仓库：
- [main](https://github.com/wpuu/NodeLab/tree/55ce1b248e1bb5b2368ae34b4fcfbb34f9057a3f)
- [PR #1](https://github.com/wpuu/NodeLab/pull/1)；[PR #2](https://github.com/wpuu/NodeLab/pull/2)
- [生产入口](https://github.com/wpuu/NodeLab/blob/55ce1b248e1bb5b2368ae34b4fcfbb34f9057a3f/src/nodelab/probe.py)
- [Actions验收](https://github.com/wpuu/NodeLab/actions/runs/36467835941)
- [候选044](https://github.com/wpuu/NodeLab/blob/bec881493564b1616a66cb7b640c788cc0a400fb/docs/audits/NL-REVIEW-044-linux-owned-directory-binding.md)

产品与需求：
- [Sub-Store](https://github.com/sub-store-org/Sub-Store)
- [sing-box URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/)
- [FullTclash](https://github.com/AirportR/fulltclash)
- [Marzban](https://github.com/Gozargah/Marzban)
- [Webshare价格](https://www.webshare.io/pricing)；[转售限制](https://help.webshare.io/en/articles/9987853-restricted-activities-with-webshare-proxies)
- [Mihomo需求3022](https://github.com/MetaCubeX/mihomo/issues/3022)；[历史1298](https://github.com/MetaCubeX/mihomo/issues/1298)
- [10月推广帖](https://www.reddit.com/r/webscraping/comments/1wuogjf/monthly_selfpromotion_october_2026/)：仅取得检索摘要，正文未取得，不能当最终发布许可
- [Mihomo固定版本LICENSE](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/LICENSE)：通过GitHub原始文件核实；普通仓库网页曾返回同名无关内容，未采用

成本与经营：
- [GCP免费层](https://docs.cloud.google.com/free/docs/free-cloud-features)
- [VPC价格](https://cloud.google.com/vpc/network-pricing)；[网络层级概览](https://docs.cloud.google.com/network-tiers/docs/overview)：免费量口径冲突
- [Google条款](https://cloud.google.com/terms)；[AUP](https://cloud.google.com/terms/aup)
- [支出上限预览](https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps)
- [电信条例](https://www.samr.gov.cn/zw/zfxxgk/fdzdgknr/bgt/art/2023/art_cb96d9e9147740f79f4c111bb637ce29.html)
- [工信部2017解释](https://www.cac.gov.cn/2017-01/26/c_1120381529.htm)：发布日期2017-01-26，结合现行许可原则使用
- [Stripe地区](https://stripe.com/global)；[限制业务](https://stripe.com/legal/restricted-businesses)

Codex：
- [账号和用量](https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan)
- [新版Cloud](https://learn.chatgpt.com/docs/cloud)；[环境设置](https://learn.chatgpt.com/docs/environments/cloud-environments)
- [Scheduled](https://learn.chatgpt.com/docs/automations)；[长任务](https://learn.chatgpt.com/docs/long-running-work)
- [模型](https://learn.chatgpt.com/docs/models)；[费用](https://learn.chatgpt.com/docs/pricing)
- [GitHub Action/API](https://learn.chatgpt.com/docs/github-action)
