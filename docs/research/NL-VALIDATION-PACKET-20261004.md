# NodeLab：交付样本、能力修正与下一阶段方案

记录时间：2026-10-04T23:38:36.068+08:00，Asia/Shanghai。
执行者：Codex。精确运行模型 ID 与实际思考档位无法独立核验。
研究方式：主负责人刷新仓库并复核原始来源；两个只读并行审查分别检查需求与交付边界。子审查没有写仓库、发布或使用真实节点。
性质：内部可审查资料，未发布推广，未提供结账，也不是已运行的网络诊断报告。

## 本轮判断

继续保留轻量自用盘点。暂停把现有代码包装成收费代理故障诊断服务。此前“客户自跑诊断”是待验证方向，本轮发现客户输入与现有能力错位，不能直接接单。

现有程序解析 Trojan/VLESS；所查 Webshare 代理买家的输入更接近 HTTP/SOCKS5。现有引擎能提供本地 HTTP/SOCKS 接口，并不等于已经支持这些上游或已完成目标网站诊断。
离线配置清点可以帮助决定下一步查什么，但免费排障资料、供应商客服及简单脚本降低了单卖盘点的差异；本轮仍没有预算、愿付费意向或付款证据。
不再为了试验价而扩建 HTTP/SOCKS 检测器。先验证用户现有资源分布，或取得具体主动买方的任务与预算。

## 仓库和验收基线

| 对象 | 实际读到的状态 |
| --- | --- |
| main | 55ce1b248e1bb5b2368ae34b4fcfbb34f9057a3f |
| 离线原型分支 | feat/offline-inventory-20261004 |
| 离线分支 HEAD | 5502e902cb29dc6801ee9f32a75cf8da7a0673a0 |
| 离线原型草稿 PR | #4，未合并 |
| 被实际测试的代码 | 960974b9894e5176387012757e4040b70c032137 |
| 既有真实云运行 | run 37208629541，Linux/Windows 标准运行器；证据已在上一检查点逐项读取 |
| 本轮执行 | 读取远端、原始网页、静态能力复核和样本数字一致性检查；没有新增产品代码或重新运行 pytest |

最新文档提交不冒充被测试代码。PR #2 与 #3 仍为草稿。Windows 云运行器不替代用户历史 E:\NodeLab 的实机验收。

## 现在能交付什么

| 能力 | 当前结果 | 交付解释 |
| --- | --- | --- |
| 一份逐行文本盘点 | 已有原型与虚构验收 | 最多512KiB；超限拒绝，不悄悄截断 |
| Trojan/VLESS 的 TLS TCP、WebSocket、gRPC 格式 | 可解析 | 格式被识别，不等于网络握手或可用 |
| 同次配置去重 | 可用 | 完整私有配置参与比较，公开顺序组编号；不同密码不误合并 |
| Reality、HTTPUpgrade、VMess等 | 当前不支持 | 不判成坏节点 |
| HTTP/HTTPS/SOCKS 上游 | 当前不支持 | 声明协议可以分类，无法完成该代理的诊断 |
| 来源、转售授权、独立线路数 | 未核实 | 配置组不等于独立线路或上游账号 |
| 延迟、出口、寿命、住宅属性、错误根因 | 未测 | 不能填入销售报告 |
| 非开发者安装与本机安全 | 未验收 | 当前仍需Python环境，尚不开放客户安装 |

## 中英文离线交付样本

此样本摘要使用实际执行生成的固定虚构数据，不涉及用户节点。完整匿名JSON与中文行级报告保存在离线原型分支 docs/examples/NL-OFFLINE-INVENTORY-SAMPLE.json、.md。

### 中文版本

**文件配置清点报告——全虚构示例**

这份输入共14物理行，其中2空白行、12非空记录。7条通过当前格式解析，3条属于当前不支持，2条有格式或字段错误。通过解析的7条归为5个配置组，另外2条是同批重复记录。

这只能说明文件里哪些配置可以继续调查。没有测试连通性、延迟、出口或长期稳定性；5个组不能被称为5条独立线路。来源与转售许可仍未知。公开报告不含完整链接、密码、节点地址、备注或秘密指纹。

下一步优先级：先检查错误记录；保留不支持记录并确认资源实际方言；再核对来源、使用许可与测量范围。未取得许可及限额前不对节点发请求。

### English version / 英文版本

**Configuration inventory — entirely fictional example**

The input contains 14 physical lines: 2 blank lines and 12 records. The current parser accepts 7 records, reports 3 as unsupported, and reports 2 as malformed. The 7 accepted records form 5 configuration groups, with 2 duplicate records within this input.

Parsing confirms only that a configuration matches the supported syntax. No connectivity, latency, exit address, or stability was measured. Five configuration groups do not establish five independent connections. Source and resale permission remain unknown. The public report contains no raw links, credentials, node addresses, remarks, or secret fingerprints.

Next steps: inspect malformed records, retain unsupported records for compatibility review, and establish source, permission, and a bounded measurement scope before sending any requests.

## 当前固定交付范围草稿

定位：离线配置盘点与格式兼容说明，先自用；没有证据支持独立收费。
输入：一份不超过512KiB的逐行URI（节点链接）文本，UTF-8编码，允许文件开头BOM；原始文件由拥有者保留。
输出：总数、声明/解析协议、格式错误、当前不支持、同次重复关系、来源/授权未知与未测提示。
公开交流只用固定匿名结果。不同批次的顺序编号不作持久身份。不要求客户向聊天、GitHub或服务方提交原始凭据。
订阅URL、整段Base64订阅、YAML面板导出不是已支持的输入；不自动抓取或转换。出现这些形态先报告范围不匹配。
服务方可解释报告中的兼容边界与检查顺序，但不据此证明资源资产价值、转售权或未来可用。
当前不报价、不接付费单，不承诺24小时修好问题；之前US$29–49仅为假设试验价，本轮不采用为现有产品价格。

English scope / 英文范围：
One bounded offline inventory of a line-based configuration file. Raw credentials stay with the owner. Deliverables are counts, supported-format classifications, unsupported and malformed records, within-input duplicate relationships, and explicit unknowns. This is not a connectivity test, an independent-exit count, or a paid repair offer. Network diagnosis is not currently available.

## 未来诊断服务草稿：尚未开放

只有主动买方给出明确问题和预算，且本机虚构验证证明对应协议及采集流程可用，才进入报价准备。不是先收费后补基础能力。

拟限定为：一个应用问题、一个测量位置、一个客户有权访问的目标、最多5个客户自有/可撤销代理端点；一次有上限的检查、一个异步报告、一次书面补充。无需英文实时会议。
拟测量预算由下一技术阶段验证并记录；可参考最多30次应用请求、串行、单次15秒、总执行10分钟、每响应最多64KiB。它们是设计假设，当前代码没有实现这些网络限制；不能把响应上限当成所有线路总计费上限，也不能把控制计时冒充硬实时终止。
返回证据只包括实际测得的失败阶段、试验分母、位置时间及未知；结论可以是“目标兼容性待确认”，不承诺总能修好或永久解锁。
真正可能付费的价值是供应商支持后仍未解决的跨客户端/跨供应商证据与节省排障时间，而不是复述帮助中心。
如果只能机械盘点或转述免费材料，就拒绝将其升级成付费诊断。暂不开发第二引擎、监控服务、支付、返佣或GCP网关。

## 不索要秘密的需求资格表

中英文均仅用于草稿；没有向任何人发送。

| 中文问题 | English question |
| --- | --- |
| 哪个应用发生什么问题？给固定错误类型即可，不发日志全文。 | Which application fails, and what is the error category? Do not send full logs. |
| 使用HTTP、SOCKS5、Trojan还是VLESS？不要发端点和密码。 | Which proxy protocol do you use? Do not share endpoints or credentials. |
| 供应商免费检查与客服处理到哪一步？还有什么不知道？ | What did the provider's free checks or support establish, and what remains unknown? |
| 你有权使用该代理和访问目标吗？是否必须在你的本机运行？ | Are you authorized to use the proxy and target, and must checks run locally? |
| 你想得到哪项具体决策：配置修正、供应商问题证据，还是停止换代理？ | What decision would a report help you make: configuration changes, provider evidence, or stopping unnecessary replacements? |
| 这个问题是否值得付费解决？预算、时间要求和验收结果是什么？ | Is resolving this worth paying for? What are the budget, timing, and acceptance criteria? |

只有回答包括具体决策、当前未解决、愿意按明确范围付费，才记为合格意向；帖子、赞数、免费测试者不是付费证据。实际收款之前还须完成经营与收款核验。

## 已核实的需求和替代品

1. 原始多供应商管理求助：用户使用2–3供应商及自建资源，任务断了才发现代理故障；评论提出简单脚本和开源工具。页面显示约7个月前，已归档，不是当前可回应买方。无预算。
   https://www.reddit.com/r/proxies/comments/1r5z44p/proxy_management_across_multiple_providers/

2. Webshare静态住宅代理用户：特定目标返回403，其他网站可以工作；已经换IP并问过供应商，仍无法确定原因。页面显示约2个月前，没有读到归档标记；是否仍未解决未知，无诊断预算。用户明确是合法手动测试，不是采集订单。原帖未明确协议，结合供应商资料推断HTTP/SOCKS5场景；推断不冒充原帖事实。
   https://www.reddit.com/r/proxies/comments/1uy02t5/getting_reddit_403s_with_webshare_static/

3. Webshare官方免费排障文档，标注2026-04-22：覆盖账户、鉴权、供应商、客户端、网络、目标问题，给出独立工具交叉检查与支持入口。降低通用报告差异，不证明用户会自行完成。
   https://help.webshare.io/en/articles/8370531-proxies-are-not-working-troubleshooting-common-issues

4. 官方Endpoint Generator，标注2026-09-03：提供测试命令和HTTP/SOCKS5输出。供应商具备自助验证，不等于NodeLab已支持同类输入。
   https://help.webshare.io/en/articles/16310718-endpoint-generator-rotating-residential

本轮没有取得当前有效、有诊断预算、愿提供匿名资料且可在中国个人条件下履约的主动买方。不能把上述需求改写成首单线索。

## 获客入口和未发布草稿

主负责人本轮已经读到 r/webscraping 的 October 2026 月度推广帖正文；AutoModerator 明确欢迎工具和测试者、推广集中此帖。这更新了前轮“只取得标题”的状态。独立rules页面返回Internal Error，不能称所有规则已核验；发布时还需当下帖子状态、账号资格和规则。
https://www.reddit.com/r/webscraping/comments/1wuogjf/monthly_selfpromotion_october_2026/

推荐先不发布针对采集团队的产品招募，因为现有工具协议不匹配。若以后明确批准需求验证，下面仅用于询问具体问题，不承诺可交付网络诊断：

English draft / 英文草稿：
I am exploring a provider-independent, local-first proxy troubleshooting report. I do not have a live diagnostic service or paid offer yet. My current prototype only inventories Trojan/VLESS configurations offline; it does not test HTTP/SOCKS proxies or target-site access. If provider support has left a specific issue unresolved, what decision would a useful report help you make, and would that decision justify a paid, fixed-scope review? Please share only the protocol and error category, never raw credentials or full logs.

中文对照：
我正在验证供应商独立、本机运行的代理排障报告是否有需求。目前没有可用的在线诊断或收费服务；原型只离线盘点Trojan/VLESS，不测试HTTP/SOCKS或目标访问。如果供应商支持后仍有具体问题，一份报告需要帮助你做什么决策，才值得按固定范围付费？只提供协议与错误类别，不发原始凭据或日志全文。

发布不会由“继续”自动触发。没有陌生私信、批量推广、岗位投标或代币消耗。

## 下一阶段：用户自有资源的本机离线盘点方案

目的：真正回答资源约是什么，避免继续猜测客户和协议。
这是具体待授权方案，不是本轮已执行动作。

范围：用户明确指定的一份节点文本，只读；不递归扫描E盘、浏览器、密码库或其他目录；初次最多512KiB，超过就报告超限，之后再商定分批方案。当前原型需要逐行URI；若仅有订阅地址，报告输入形态问题，不访问该地址。
环境：隔离目录与固定原型提交，不覆盖 E:\NodeLab 或改变现有代理客户端。准备代码/依赖可能联网，必须在接触真实输入之前完成；读取真实文件阶段不发送网络请求、不启动代理引擎。
保护：原始文件不进git、不上传聊天或云环境，不添加调试/原始日志；输出仅固定匿名报告。当前没有证明抵抗同用户恶意程序或从内存彻底抹除秘密，不用“私有”作过度安全承诺。
交付：一份匿名JSON、中文报告和执行元信息；用户愿意时仅分享匿名报告，来源与许可信息另用无凭据的手工说明。输出写入新目录，不覆盖输入、不删除文件。
检查：先完成虚构同样路径的准备验收，再对已授权真实文件运行。发生异常停止，仅固定错误码；不自动扩大文件范围或开启探测。
需要用户提供的是完整本机路径与此阶段授权，不是链接内容或API Key。电脑不可访问时保留准备结果，不能声称在关机电脑上处理文件。
成本：离线盘点运行没有节点探测流量；没有GCP、付费API或支付操作。准备阶段的正常依赖下载与Codex用量另记，不假设所有资源无限免费。
验收结果：真实记录计数、协议/方言分布、错误、不支持与重复比例；未知项保留未知。之后再判断是否值得批准少量受限测量。

## 本轮终点

中英文样本和固定范围已准备；样本统计已逐项对照远端实际JSON。资料提交不改变代码或部署，也不代表主线批准。
下一项优先是真实资源盘点，而不是新一轮软件扩建。进入真实文件阶段需要单独明确授权与路径，这是用户原始边界；本轮没有处理。
