# NL-REVIEW-010｜真实引擎会话验收入口（当前 BLOCKED）

日期：2026-09-28。承接 NL-REVIEW-009。

## 本轮结果：未获得真实引擎通过证据

通过 GitHub API 成功查询固定 Mihomo v1.19.31 与 Python standalone 3.12.11 发布信息，但下载发布资产跳转后均返回 EOF。未降低 TLS 校验、未改用未知镜像、未替换固定引擎摘要、未把未下载的文件当作可执行文件。

下载目标均位于 Git 忽略的 tools/。本环境仍为 Python 3.11.2，无真实 Mihomo binary，故真实会话验收 **BLOCKED**，不能声称 NL-REVIEW-009 已由真实引擎复验。

## 新增验收测试

`tests/test_real_engine_session.py` 提供 11 个 opt-in Linux 用例：

- VLESS/Trojan × TCP/WS/gRPC 的六种完整 private_engine_session。
- 真实引擎下正文错误和取消后的进程/文件清理。
- 重复 close、真实错误配置的 -t 拒绝、独立外部进程不受影响。

fixture 要求 Python ≥3.12、已配置的绝对 binary 路径、内置已知摘要；删除 Owner 自定义摘要 pin，防止测试用临时白名单绕过目录中的固定 binary。只生成随机虚构 UUID/password，配置的 upstream 是本机 sentinel listener；不向 mixed port 发送数据平面请求，退出时断言 upstream 未收到连接。

这些用例仅验 schema、预检与生命周期，**不是 TLS/WS/gRPC 握手证明，也不是逐请求 route proof**。本轮这 11 个测试全部因缺少 binary 而跳过。

## 确定性执行入口

新增 `scripts/f2_session_gate.py`，只适用于 Linux，使用运行脚本的同一个 Python 解释器：

```sh
python3.12 scripts/f2_session_gate.py --exe /absolute/path/to/mihomo
```

前提：Python ≥3.12，pytest、PyYAML、httpx、idna 已安装，binary 已按项目固定版本准备。脚本不下载、安装或修复环境，不改 Git，不索取节点凭据。

- 只执行上述固定测试文件；隔离 pytest 环境追加选项和第三方自动加载插件。
- stdout/stderr 不透出 pytest 原始日志；临时 JUnit 报告仅在临时目录存在，用后删除。
- 仅固定 JSON 字段和计数可见；缺 Python/依赖/binary 条件为 BLOCKED。
- 非零退出或报告含 failure/error 为 FAIL。
- 任何 skipped、空报告或用例数不等于 11，均不能 PASS。
- PASS 的范围只能是 `SYNTHETIC_SESSION_OK`；结果始终包含 `real_node_test_allowed=false`、`windows_acceptance=NOT_RUN`、`route_proof=NOT_RUN`。
- 不用外层强制超时杀掉 pytest，以免打断进程清理；各 session 自有工作/清理预算。取消或硬崩溃仍须按现有恢复规则复核残留，并非完整 crash-safe 验收。

## 本轮可验证证据

新增 14 项 gate 单测，使用模拟 JUnit 报告验证 prerequisite 阻断、固定输出、skip/少测/多测/错误报告不误报通过、临时报告删除。

恢复虚拟环境后：

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
254 passed, 29 skipped
```

29 个 skip = 15 项原固定 binary 测试 + 11 项新真实会话测试 + 3 项 Windows 测试。`git diff --check` 通过。

首次使用临时 PYTHONPATH 依赖目录运行时，两个既有子进程测试因子进程环境看不到依赖而失败；建立独立 .venv、在该解释器安装依赖后两项通过，未修改或放宽测试断言。

实际运行 gate 得到 `BLOCKED / PYTHON_VERSION_UNSUPPORTED`，与当前 3.11 环境一致。mock gate 报告的通过不计作真实引擎证据。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`。后续仍需在支持环境取得真实会话结果，Windows W1/W2 独立验收；F3 逐请求证据未实现。
