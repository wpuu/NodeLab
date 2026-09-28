# NL-REVIEW-006｜F2b 运行时路由配置核验

日期：2026-09-28。承接 NL-REVIEW-005；本轮不打开真实探测开关。

## 修复范围

旧预检仅判断 `NODE` 名称存在且 `PROBE.now=NODE`，无法拒绝实际 direct/global 模式、带 DIRECT 备用成员的组或优先命中的旁路规则。

现在在鉴权与端口归属检查后，读取私有 `/configs`、`/proxies`、`/rules` 快照，执行默认拒绝的核验：

- `mode` 必须为 `rule`。
- `NODE.type` 必须为 `Vless` 或 `Trojan`，拒绝只有名字的空对象或 Direct 冒名对象。
- `PROBE.type=Selector`、`now=NODE`、`all=[NODE]`，不允许备用成员。
- `/rules.rules` 必须恰好一条：整数 `index=0`、`type=Match`、空 `payload`、`proxy=PROBE`。
- 若规则带 `extra`，必须是对象且 `disabled` 严格为布尔 false，不能以 0、缺字段或 null 代替。
- 返回启动句柄前再次确认子进程仍存活。

错误只用固定码 `RUNTIME_MODE_INVALID`、`RUNTIME_RULES_INVALID` 或既有对象/进程错误码，不返回控制器正文。失败进入已有 own-child 清理路径。允许存在引擎内建的 DIRECT 对象，但它不得成为 PROBE 成员或规则目标。

## 固定版本依据

通过 GitHub API 读取官方 **v1.19.31** 源码，核实 API 大小写与字段：

- [tunnel/mode.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/tunnel/mode.go)：模式 `rule` 的序列化。
- [constant/adapters.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/constant/adapters.go)：`Vless`、`Trojan`、`Selector`。
- [adapter/outboundgroup/selector.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outboundgroup/selector.go)：`type`、`now`、`all`。
- [hub/route/rules.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/hub/route/rules.go)：规则数组、index 与可选 wrapper 的 disabled 状态。
- [constant/rule.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/constant/rule.go) 与 [rules/common/final.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/rules/common/final.go)：API 类型为 `Match`，payload 为空。

## 验证

命令：`PYTHONPATH=src .venv/bin/python -m pytest -ra`

Linux / Python 3.11.2：**175 passed, 18 skipped**（新增 34 项）。`git diff --check` 通过。

新增测试通过模拟 child 和控制器快照覆盖：两种协议、有/无 wrapper、28 种不合法响应、额外 DIRECT 规则、取快照期间 child 退出。负向测试验证启动失败并调用本次 child 的清理，不是只测孤立判定函数。既有控制面隔离正向夹具同步更新为完整形状。

限制仍然有效：Python ≥3.12 尚未复验；15 项真实固定 binary 测试和 3 项 Windows 测试跳过。源码核实与模拟测试不能代替真实引擎实验。

## 尚未完成

- 这里不比对 NODE 的全部协议配置，也不能检测取快照之后的配置变更或竞争窗口。
- 不是 F3 逐请求 route proof，没有捕获或关联两条出口请求。
- 总 deadline 的严格执行、清理失败的硬失败处理和私有 RunContext 生命周期集成仍待完成。
- `PROBE_GATE_OPEN=False`，`REAL_NODE_TEST_ALLOWED_NOW=NO`；没有 P0 因本轮而宣称 CLOSED。W1/W2 仍须真实 Windows 验收。
