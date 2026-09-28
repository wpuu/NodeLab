# NL-REVIEW-005｜F2b 控制面隔离补强

日期：2026-09-28。基线：`55ce1b248e1bb5b2368ae34b4fcfbb34f9057a3f`。

## 本轮范围

检查 F2b 时发现：controller 的 401/401/200 只能说明鉴权响应，不能说明端口属于本次 child；而 urllib 默认采用环境代理并跟随重定向，可能把 bearer token 发向其他服务。

本轮实现：

- 在第一次 controller HTTP 请求之前，验证 controller 监听端口属于本次 child PID 且绑定 loopback。端口缺失按已有 deadline 等待；外部 PID、非 loopback 或无法核验立即失败，并走已有 child 清理路径。
- controller HTTP 禁用环境代理，不依赖 NO_PROXY 配置；拒绝所有 HTTP 重定向。
- HTTP 错误响应显式关闭；不返回响应正文、token 或动态异常文本。
- 新增 10 个合成测试：五种重定向、环境代理、三种不可信监听、成功路径校验顺序。仅使用随机虚构 token、本机 HTTP fixture 和模拟 child。

## 验证与限制

命令：`PYTHONPATH=src .venv/bin/python -m pytest -ra`

Linux / Python 3.11.2：**141 passed, 18 skipped**。其中 15 项需要固定 Mihomo binary，3 项需要真实 Windows。

本环境预装 Python 3.11；尝试获取项目要求的 Python 3.12 时下载 TLS 失败。因此上述仅为兼容性回归证据，**不构成声明支持的 Python ≥3.12 环境验收**；未降低 pyproject 的版本要求。

未使用真实节点，未运行真实 Mihomo，未验证 Windows NTFS/DACL/PID，未修改 `PROBE_GATE_OPEN=False`。本轮不宣称任何 P0 CLOSED，也未完成 F3。

## 后续

1. 在 Python ≥3.12 与固定 v1.19.31 binary 上复跑运行时集成测试。
2. F2 仍需补齐运行时规则核验、单次总 deadline 与完整私有生命周期集成；监听预检不是连接级 route proof，也不能消除预检与后续连接之间的竞争窗口。
3. 之后推进 F3 两条原始请求各自的连接级证据，保持无证据不得 PASS；W1/W2 仍须 Windows 本机执行。
