# NL-DEC-005｜CURRENT STATE → NEXT EXECUTION DECISION

- **状态：** 技术负责人执行决策；不是 P0 完成证明。
- **核验日期：** 2026-09-26（Asia/Shanghai）
- **决策时远端基线：** `origin/main = cfac1e1daf6c21d1e24b26827a9f07a515fba20c`
- **范围：** 决定 P0 实施顺序、职责及 Git 保护方式；本决策不修改产品代码、不启用真实节点。
- **替代任务：** [`NL-P0-006`](../tasks/NL-P0-006.md)；旧 [`NL-P0-004`](../tasks/NL-P0-004.md) 保留为历史，不再下发执行。

## 1. 我核实的当前状态，而非从测试通过推断的状态

- 最新远端 `main` 的 `src/nodelab/`、`tests/`、`scripts/bootstrap_mihomo.ps1` 相对于 [`NL-REVIEW-002`](../audits/NL-REVIEW-002-p0-closure-design.md) 的基线未有产品代码修复；之后的远端提交只添加了设计报告和 `NL-P0-003/004` 任务。`NL-ASTRA-001` 的 **P0=7、P1=11、P2=1** 是既有审计台账，本决策不重复审计或重计严重度。
- 在最新远端代码的仓库外只读副本上，本次 Linux `python -m pytest -q -p no:cacheprovider` 得到 **20 passed**；测试临时文件放在独立目录并已删除。它们主要覆盖旧实现，不能证明正确 Mihomo 配置、Windows ACL 或逐请求 NODE 路由，更不能当作 P0 CLOSED。
- 七个 P0 均 **NOT_CLOSED**：P0-01 配置混入 sing-box 键且原样 `-t` 失败；P0-02 binary 根目录层级错且 PATH 可回退；P0-03 协议参数会丢失/错映射；P0-04 使用无效 controller secret 键；P0-05 早退可留下明文 YAML、还有危险的按名全机清理 API；P0-06 URI argv/公共对象/正则展示可泄漏秘密；P0-07 两源 IP 相等即 PASS、没有这两个请求各自的 NODE 路由证明。P0-07 是**前序修好后会激活的假阳性风险**，不能误写成当前错误配置已经观察到真实 DIRECT PASS。
- 当前环境是 Linux，不等于 Owner 的 Windows `E:\NodeLab`；**Windows NTFS/DACL、端口 OwningProcess、真实 Mihomo .exe 与用户既有客户端共存均未在本轮验收**。无真实节点、URI 或密码进入本轮测试。
- Mihomo 固定为官方 **v1.19.31**；正确的顶层 `mixed-port`、`proxies`、`proxy-groups`、字符串 `rules` 与顶层 `secret` 应以该 tag 源码和运行时为准；官方控制器 `/connections` 给出的是**活动连接快照/WS**，不是持久 route 日志，抓不到某条原始请求就不能补造证据。Windows DACL 可用系统接口和 `icacls` 验证，Linux 模拟不替代 NTFS 本机负测。[Mihomo 固定 tag](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/config.go#L402-L458) · [官方 API](https://wiki.metacubex.one/en/api/) · [Windows icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)

**工程结论：** 当前只能继续做**虚构凭据/本机合成环境下的 P0 修复**；`REAL_NODE_TEST_ALLOWED_NOW = NO`，`NL-003 = PAUSED`。`OFFLINE_CLOSED` 与真实生产可用性 `CLOSED` 严格区别，见 `NL-REVIEW-002` 的定义；所有协议是否可称 `SUPPORTED` 仍受其中 B/H 节约束。

## 2. 七项 P0 的真实依赖：前置门、可并行设计和后置证据

```text
P0-06（argv/public/异常零泄漏） ──┐
P0-07a（先把无证据 PASS 禁掉；纯判定函数）─┼─► 安全的虚构输入/无正向 PASS 的开发壳
P0-05（私有目录、ACL、唯一进程所有者/清理）┘        │
                                                 ├─► Windows 安全闸：真实 NTFS/ACL/PID，虚构 sentinel
P0-03（严格类型化解析、拒绝未支持方言）─────────────┤
P0-02（可信固定 binary、无 PATH 回退）───────────┤
P0-01（正确 schema、-t、监听/组/规则） ◄─ P0-03 ┤
P0-04（每次随机顶层 secret、鉴权/隔离控制面）◄── P0-05/01
                                                 └─► P0-07b（每条原始出口请求的连接级 NODE 证据）
                                                       └─► Windows 全量离线验收 ─► Owner 首次真实验收
```

上述箭头表示**宣称关闭/允许用真输入的门槛**，不要求纯函数、配置结构和测试在日历上完全串行。P0-07 的「无证据不得 PASS」必须最先启用；其**正面 route proof** 要等 01/02/03/04/05/06 形成可信运行实例才可能证明。P0-03 的支持矩阵要先于或同步于 P0-01 的协议配置；不能先用旧宽松解析器跑通 TCP，再把 TLS/WS/gRPC/Reality 字段的悄悄丢弃当作正常功能。P0-05 的 Windows 验收是运行私密 YAML 的硬门槛，不因 Linux 单测通过而消失。

## 3. 对原 T1→T4 的判断：`MODIFY`，保留验收合同，重排工程执行

`NL-REVIEW-002` 的 A～H 节（固定版本、方言矩阵、secret 矩阵、连接级证据和 Windows/真实验收）仍是**验收依据**；不改写历史报告。原 T1→T4 **不应照原样作为强制执行序列**：

1. T1 把可由本环境编写/用虚构数据验证的安全代码和必须在 Windows 验证的 DACL 混成一个「只能在 Windows 编码」任务，造成无必要的人工依赖；但没做 Windows 实测仍不得给 P0-05/06 签字。
2. T2 使用旧宽松解析器建立所谓可运行 TCP 基座，T3 才补无损解析，容易使关键 TLS/transport 字段被旧对象静默丢弃。工程上先定有类型的协议输入和 `UNSUPPORTED` 边界，再构造引擎配置。
3. T4 才实现 P0-07 时，T2/T3 若意外打开现有 IP 相等即 PASS，便制造暂时但真实的误报窗口；判定的**默认拒绝**要在任何运行时修复前落地，正面逐请求证明可以后置。`-t=0`、组 `now=NODE` 和 IP 相等均非 route proof。
4. T1 阶段无法在仍错误的 Mihomo 配置上独立证明**真实成功路径**清理；因此按「单阶段 candidate + 后续集成回归」管理，不称 T1 全面关闭。

**替代执行关卡（小提交；同一模块不平行改写）：**

| 关卡 | 本 Technical Owner 在当前环境直接完成 | 保持关闭的门与退出标准 |
| --- | --- | --- |
| **F0 Git 安全基线** | 保护独有提交，从最新 `origin/main` 单独建任务分支；只提交本决策与替代任务。 | 本地 `main` 不 reset/rebase/merge/force push；当前轮次不改产品代码。 |
| **F1 fail-closed 安全壳** | 用运行时生成的**虚构** sentinel，移除 URI argv 与动态 metadata 公共序列化；固定字段/错误码；建立私有单-owner RunContext/own-PID 清理及 Windows ACL 可注入平台实现；给判定纯函数加「两条 route proof 缺一不可」断言；Linux 故障注入、出入参扫描。 | 没有 Windows 真实 ACL/PID 证据，P0-05/06 仅候选；在 P0-07b 前产品不得返回 `PASS`/写 `confirmed_exit_ip`，不使用真实节点。原有鼓励不安全行为的测试必须改造，不能靠旧 20 tests 过关。 |
| **W1（最早必需的人工动作）** | 我给出固定候选 SHA 和可复跑测试入口后，用户 Windows 本机 Claude Code + Agnes 只执行 [`NL-P0-006`](../tasks/NL-P0-006.md) 的确定性 ACL、外部进程不受影响、clean-up 与 secret 输出负测；不让它设计/修改代码。 | Windows 环境、NTFS、真实 DACL/own PID 事实任一不明则 BLOCKED；失败退回本 Owner 修复，不得用 Linux 模拟或口头承诺放行。尚未做 Mihomo 功能验收。 |
| **F2 协议与引擎垂直切片** | 严格逐行 parser/TypedNode/白名单/单次解码先行；协议不支持即无副作用 `UNSUPPORTED`。再修固定 EXE/摘要、正确 Mihomo `NODE`/`PROBE` 配置、controller token、一次 `-t` + 运行时监听/PID/组/规则/401-401-200 预检；虚构本机协议 fixture 正负测。 | 对无本地握手证明的 Reality 保持 `UNSUPPORTED_REALITY`；HTTPUpgrade 保持 `UNSUPPORTED_HTTPUPGRADE`；TLS 不随 URI 的 `allowInsecure=true` 静默降级；F1 的「不得 PASS」门继续开启。 |
| **F3 逐请求 route proof** | 在受控单进程、两源各自的活动连接时间窗内关联 `MATCH → PROBE → NODE`，严格按该版本证据核对；实现 PASS/PARTIAL/CONFLICT/FAIL/UNSUPPORTED 状态优先级、无效 NODE + 宿主可直连负控、清理失败硬 FAIL、单次总 deadline；Linux 合成测试。 | 测试夹具的 `OFFLINE_PASS` 不等于真实探测 `PASS`；捕获不到任一请求连接、仅靠 IP 相等、DIRECT 或来源冲突都不能 PASS。合成证据不自动让任一 P0 CLOSED。 |
| **W2 + Owner 开闸** | 只有 F1～F3 完成后再提供固定 SHA/自包含测试入口；Windows 本机验官方 EXE、NTFS ACL/端口 PID、VLESS/Trojan 本地 fixture、S/R 负控及两条 route proof。最后由 Owner **自己**按 `NL-REVIEW-002` H 节决定是否开始已授权真实单节点验收。 | W2 未过：`REAL_NODE_TEST_ALLOWED_NOW=NO`；W2 过只可能是 `OFFLINE_CLOSED`。未实测的模式不得声称真实 `CLOSED`/进入 NL-003。 |

**工作分配裁定：** F0/F1/F2/F3 的设计、代码、单元测试、Linux 本机合成协议实验、文档和分支提交均由当前 Technical Owner 完成；不把 Linux 能可靠完成的工作机械转交 Windows 代理。Windows 的 NTFS DACL、真实 EXE/port `OwningProcess`、`E:\NodeLab` 及 Owner 已有其他 Mihomo 的行为，以及经授权首次真实节点测试，必须留在用户机器；Claude Code + Agnes 仅为**确定性本机执行器**，不能索取/上传真实 URI、UUID、password 或 API Key。W1 之后若失败，由本 Owner 接回代码修改，Windows 代理不顺手扩大范围。

## 4. `NL-P0-004: REPLACE`，而非简单取消安全要求

旧任务由 `NL-P0-003` 的 `ff-only` 分叉阻塞和 Linux/Windows 环境限制触发，要求 Windows 代理**重写整个 T1**。Git 分叉处置与 Windows ACL 实测的要求是对的，但「必须在 Windows 才能写任何 T1 代码」和「所有可模拟测试都交本地执行器」不符合当前 Owner 分工；还禁止实现 P0-07 的必要先手 fail-closed 门。**因此保留旧文档以供追溯、停止下发它，使用 F1 + [`NL-P0-006`](../tasks/NL-P0-006.md) 替代**：本 Owner 做代码和非 Windows 验证，Windows 任务在候选提交就绪后只做不能从 Linux 证明的确定性 W1 验收。旧 `NL-P0-003` 也不重试。W2 的完整 Windows 离线验收在代码就绪时按 A～H 合同给出当时可复跑的任务，不预先让 Windows 代理猜测试命令。

## 5. `b48a500` 的无损处理，以及边界

在**本沙盒仓库**确认 `main=b48a50033f865003c67bc9f35370fb25348d69fe`、`origin/main=cfac1e1daf6c21d1e24b26827a9f07a515fba20c`、共同祖先 `e88b10a...`，工作树干净。`b48a500` 和远端 `e18c4ca` 各自只添加了同名 `NL-REVIEW-002` 报告；文件正文仅**最后一处行尾换行**有差异。远端已具备报告内容，故**不 cherry-pick 产生重复报告，也不凭「内容近似」丢弃本地提交**。

在本沙盒创建了只指向 `b48a500` 的 `rescue/pre-owner-b48a500`；**沙盒本地 `main` 指针仍是 `b48a500`**，决策/后续实施分支从实际 `origin/main` 创建。没有 reset/rebase/merge/pull/force push，不移动本地 main、不改历史。今后若要使本地 `main` 与远端同线，先由 Owner 单独确认目标历史和保留分支，**本轮不处理**。

**重要边界：** `/home/user/wpuu/NodeLab` 的 rescue ref **不是**用户 Windows `E:\NodeLab` 的备份；后者实际 SHA、dirty 状态未在本环境核实。W1 前 Windows 执行器必须在 `E:\NodeLab` 自行检查 clean/main SHA 并建立准确指向其当时本地 main 的独立 rescue ref，再从指定候选 SHA 建验证分支；不能用本沙盒结果代替。

## 6. 下一动作与人工时间

**唯一下一工程动作：** 当前 Owner 在独立 `origin/main` 基线分支开始 **F1 fail-closed 安全壳**，首先阻断 URI argv/不受控公共输出和「无两条 route proof 仍可 PASS」，再完成私有运行生命周期的代码及虚构故障测试。**不运行 `NL-P0-004`，不请求真实节点，不启动 NL-003。**

**用户现在无需动作。** 最早必需用户参与是在 F1 候选提交、可复跑的 Windows W1 测试入口与固定 SHA 由本 Owner 准备好之后：请用户在自己的 Windows `E:\NodeLab` 环境让 Claude Code + Agnes 按 `NL-P0-006` 用**动态生成的虚构 sentinel**执行 NTFS/DACL、own-PID、旁路进程和残留验收，并只回报固定状态。再次人工介入是在 F2/F3 的完整 Windows 离线闭环，最后的真实授权节点验收只能由 Owner 自行决定。若仓库治理需合并审批，那是额外的 Git 权限门槛，不能预设已获批准。

**不得放宽的范围：** 无真实 VLESS/Trojan URI/UUID/password/API Key 入模型、日志、CI 或 Git；不做 SQLite、FastAPI、大规模 worker、Agnes 在线分类、Grok 前台、Xboard；不因「有可联网的宿主机」就触发真实节点探测。此前为 Git 访问提供的临时令牌须轮换，任何本地临时副本用毕删除，不记录令牌本身。
