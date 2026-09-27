# NL-REVIEW-003｜F1 + F2a 候选分支代码复核与修补

- **性质：** 对 [`NL-DEC-005`](../decisions/NL-DEC-005-current-state-next-execution.md) 之后的候选代码做独立复核，并在同一分支上修补其中可离线验证的缺陷。**不改变** [`NL-REVIEW-002`](NL-REVIEW-002-p0-closure-design.md) A～H 的验收合同，不重新审计 [`NL-ASTRA-001`](NL-ASTRA-001-red-team-audit.md) 的 P0 台账，不接触真实节点/凭据。
- **复核对象：** `fix/nl-p0-f2a-strict-parser` @ `731a94e`（= `decision/nl-dec-005-tech-owner` 4dbaf87 → F1 `11a0a79` → F2a `731a94e`，均自 `main` `cfac1e1` 分叉，均未合并、无 PR）。`main` 本身仍是 NL-ASTRA-001 审计时的旧代码，7 个 P0 全部 `NOT_CLOSED`。
- **复核方法：** 通读全部 `src/nodelab/*.py`、`tests/*.py`、决策/任务文档；在 Linux 隔离 venv 上运行候选测试（59 passed / 3 win32-only skipped）；对解析器做约 95 条对抗性 URI 输入；对 `RunContext` 做并发、重复写、子进程不可终止、崩溃残留等行为探针；对照 **Mihomo v1.19.31 源码**（非 wiki）核对 `client-fingerprint`、VLESS/Trojan option 键名。
- **结论：** 方案方向正确（先 fail-closed 门，再类型化解析，再引擎/路由证明），F1/F2a 实现可信；但有 1 个会造成静默 TLS 降级的实质缺陷、3 个 Owner 首次 Windows 实测就会踩到的问题、2 个必须在 F3/批量之前解决的设计缺陷。可离线验证的项已在本分支修补（见 §3）。`REAL_NODE_TEST_ALLOWED_NOW` 仍为 **NO**。

## 1. 已确认缺陷（按严重度；"证据"均为实际执行结果或源码行）

| 编号 | 级别 | 缺陷 | 证据 | 状态 |
|---|---|---|---|---|
| **B1** | P1 | `fp=ios` 输出 `client_fingerprint="iOS"`；Mihomo 只认小写 `ios`，未知值**静默**退回普通 Go TLS，正是 P0-03 要杜绝的降级。根因是 NL-REVIEW-002 抄了 wiki 的 `iOS`。 | `component/tls/utls.go` `GetFingerprint` 对全小写 map 做区分大小写查找，未命中仅 `log.Warnln`；`transport/vmess/tls.go` 在 `ok==false` 时直接 `tls.Client`（仅 Reality 报错）。 | **已修**：输出 `ios`；测试断言全部输出值 ⊆ 源码 map 键集合；NL-REVIEW-002 加勘误。 |
| **B2** | P1 | `RunContext._ensure_root` 以"根目录非空"判定崩溃残留 → 并发上限为 1；任何一次崩溃残留会永久阻塞后续运行；没有恢复命令。与 V0 Spec §9 的并发 10、合同 F.4 的 ≥10 合成并发直接冲突。 | 第二个活跃 `RunContext.__enter__` → `RECOVERY_REVIEW_REQUIRED`（实测）。 | **未修（设计级）**：F3/NL-003 之前必须改为按 `.owner.json` 的 `owner_pid` 存活性判定每个 run 目录，并提供显式 `recover` 命令；`.owner.json` 需补子进程创建时间以抗 PID 复用。 |
| **B3** | P1 | `close()` 中 stop 失败即抛出，`rmtree` 永不执行 → 明文 `probe.yaml` 留在磁盘。 | 注入不可终止子进程后 `SECRET_CLEANUP_FAILED`，`probe.yaml` 仍存在（实测）。 | **已修**：stop 与删除各自独立执行、最后以单一固定码汇报；新增测试证明 stop 失败时 YAML 与 run 目录仍被删除，且重试 `close()` 可完成。 |
| **B4** | P1 | 输入文件带 UTF-8 BOM 时第一行报 `UNSUPPORTED_PROTOCOL`。Windows 记事本默认写 BOM，合同 H 节让 Owner 手工建文件后 `--limit 1`，首次验收必然误失败。 | 实测。 | **已修**：仅剥除文件开头一次 BOM；文件中部 BOM 仍为错误。 |
| **B5** | P2 | 备注（fragment）含裸 `%`（如 `#剩余50%`）→ 整行 `INVALID_PERCENT_ENCODING`，而 fragment 根本不被使用。 | 实测。 | **已修**：fragment 宽松解码，仍拒绝控制字符（`%0A`/`%00`），其余位置的 percent 严格性不变。 |
| **B6** | P2 | 行尾/行首多余 ASCII 空白 → `INVALID_URI`。 | 实测。 | **已修**：`parse_uris` 按行剥除 ASCII 空白（凭据不在行边缘，无损）；`parse_uri()` 单条 API 保持严格。 |
| **B7** | P2 | `0x7f.0.0.1`、`0x7f000001`、`2130706433`、`example.123` 被当 DNS 名接受，违反合同"非法数字点分不得变 DNS 名"。 | 实测。 | **已修**：末标签全数字或任一 `0x` 十六进制标签 → `INVALID_HOST`。 |
| **B8** | P2 | IPv4-mapped IPv6 的 `entry_host` 在 Python 3.11/3.12 为 `::ffff:cb00:7105`，3.13 为 `::ffff:203.0.113.5`，跨版本不稳定。 | 实测（3.11）。 | **已修**：固定为 `::ffff:a.b.c.d` 拼写。 |
| **B9** | P2 | 解析**成功**的行被标为 `probe_status: UNSUPPORTED`，与 D4 中 `UNSUPPORTED`＝"方言不支持"冲突，用户无法区分好候选与不支持方言。 | 代码 `parser.py parse_uris`。 | **已修**：parse-only 成功行 `probe_status: null` + `stage: PARSE` + `error_code: PROBE_GATE_CLOSED`（schema 明确允许缺值 null；仍不可能被读成正向结论）。 |
| **B10** | P2 | Windows ACL 校验两个必踩坑均未写进 NL-P0-006：提权会话新建对象所有者为 `BUILTIN\Administrators` → 误报 `PRIVATE_DIR_UNSAFE`；Owner 预先手建的 `E:\NodeLab.secrets` 带继承 ACE，代码只读校验、不修复、无提示。 | 代码 `_ACL_CHECK_SCRIPT`、`_ensure_root`。 | **已修（文档）**：NL-P0-006 新增 §1a 前置条件；代码保持"只收紧自己新建的对象"的安全原则。 |
| **B11** | P2 | 每次 run 约 8–9 次 PowerShell 子进程做 ACL 校验（SID、parent/root/run_dir、两文件各两次、close 时 root），对 20 s 单节点 deadline 是显著开销。 | 代码计数。 | **未修**：F3 时间预算前处理——SID/root 校验按进程缓存，去掉 `_restrict_new_windows` 后的重复 `_verify`，中期用 ctypes `GetNamedSecurityInfoW`。需 Windows 实测，不在 Linux 上盲改。 |
| **B12** | P2 | 小项：`write_yaml` 每 run 仅一次（合同 F.4 端口冲突重写需每次新建 RunContext）；`stop_owned_process` 最坏 7 s > 合同 5 s；"不得 PASS"闸门在序列化器而非 `probe.py`；`pydantic` 声明未用；`requires-python>=3.12` 而代码可在 3.11 运行。 | 代码/实测。 | **未修**：写入 F2b/F3 设计前提。 |

## 2. 给 F2b 的源码级约束（避免再抄 wiki）

- **Trojan**：`TrojanOption` 没有 `tls`/`servername` 键，SNI 用 `sni`；ws 模式下 `if SNI != "" { wsOpts.Host = SNI }`，因此 Host≠SNI 时必须显式写 `ws-opts.headers.Host`。默认 ALPN：tcp `[h2, http/1.1]`，ws `[http/1.1]`。
- **VLESS**：ws 的 TLS ServerName 取 `servername`，其次 Host 头，再次 `server`；`fingerprint` 是证书 SHA256 钉扎，不是 uTLS 指纹。
- **client-fingerprint** 合法值以 `component/tls/utls.go` 的 map 键为准（测试文件 `tests/test_strict_parser.py` 内保留了 v1.19.31 的键集合副本）。F2b 应为每个输出的 Mihomo 字段值附源码行号。
- 启用 uTLS 指纹时若 Mihomo 日志被 DEVNULL，`wrong clientFingerprint` 警告不可见——F2b 的 `-t`/启动检查应把 stderr 收进私有缓冲并对固定告警串做断言（不外泄）。

## 3. 本分支变更清单（`arena/01a0e0e6-nodelab`，基于 `731a94e` fast-forward）

- `src/nodelab/parser.py`：B1 `ios`；B4 BOM；B5 fragment 宽松解码；B6 行边缘空白；B7 数字样式主机；B8 IPv4-mapped 规范化；B9 `ParsedLine.probe_status: str | None`。
- `src/nodelab/mihomo_config.py`：B3 `close()` 拆为 `_stop_child()` / `_remove_private_tree()`，两步必执行、单一固定码汇报，`_private_tree_removed` 允许重试。
- `tests/test_strict_parser.py`：`iOS`→`ios`；新增 6 个回归测试（指纹 ⊆ 源码 map、BOM/空白、fragment `%`、数字主机、IPv4-mapped、null 状态语义）。
- `tests/test_p0_safety.py`：S9 解析输出断言改为 `probe_status null + PROBE_GATE_CLOSED + stage PARSE`；新增 stop 失败仍删明文的生命周期测试。
- `docs/audits/NL-REVIEW-002-p0-closure-design.md`：`iOS` 勘误（仅加注，不改其余合同）。
- `docs/tasks/NL-P0-006.md`：新增 §1a Windows 前置条件。
- 验证：Linux venv（Python 3.11）`pytest tests/` → **66 passed, 3 skipped（win32-only）**；CLI 对"BOM + CRLF + `fp=iOS` + 备注含 `%` + 行尾空格"的记事本样式文件端到端解析正确，公共输出不含任何 sentinel。**Windows 侧的 W1 证据仍需按 NL-P0-006 在 Owner 本机取得。**

## 4. 建议的后续顺序

1. Technical Owner 复核本分支，合并到候选链（或 cherry-pick 到 `fix/nl-p0-f2a-strict-parser`）后再下发 W1 固定 SHA；W1 前务必先按 NL-P0-006 §1a 准备环境。
2. F2b 开始前落实 §2 约束与 B12 的 `write_yaml` 单次语义（每次重试新建 RunContext）。
3. F3 开始前定稿 B2 并发/恢复模型与 B11 ACL 开销，并把"不得 PASS"闸门收敛到 `probe.py` 单一常量，序列化器只做 schema 过滤。
4. W1 的 own-PID 证据只覆盖合成子进程路径，F2b 改写启动路径后必须在 W2 复验；若 Owner 人工往返成本高，可把 W1 并入 W2（前提是 §1a 已就绪）。
