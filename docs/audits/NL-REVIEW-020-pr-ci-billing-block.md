# NL-REVIEW-020 — PR 显式启用验收与 GitHub runner 阻塞

日期：2026-09-28。草稿 PR：<https://github.com/wpuu/NodeLab/pull/2>。

## 发布与入口调整

累计审计 005–019 的实现已提交为 `bf38caf6794cb09a956ddd8f9d4925f5e04bc9e3` 并推送到会话分支 `arena/01a0e60c-nodelab`，PR #2 保持草稿，没有合并或修改 main。

为避免仅为注册 `workflow_dispatch` 而合并未验收实现，本轮提交 `5f7f80871273592a8f92b934f42bf68ad94be587`，增加显式 opt-in 的 PR 入口：

- `pull_request` 只响应 main 目标的 labeled/synchronize/reopened。
- job 要求同仓库 PR 且带有 `run-local-acceptance` 标签；保留原 `workflow_dispatch`。
- 不使用 `pull_request_target`，不增加权限、secrets、外部节点输入或摘要覆盖。
- 保留双摘要准备、Python 3.12、三个零 skip/精确数量 gate、固定 JSON artifact 白名单和失败传播。
- 标签意味着允许该 PR 后续提交继续运行本机验收；工作流条件不抵御能够修改 workflow 的恶意仓库写入者。

对应静态测试和 `docs/Linux-local-acceptance.md` 已更新。本轮使用 `gh api` 为 PR 添加标签（旧版 gh 的 `pr edit` 因 Projects classic GraphQL 废弃报错，REST 标签 API 成功；不是认证错误）。

## 实际远端结果

| run | head SHA | 结果 | 解释 |
| --- | --- | --- | --- |
| 36399968265 | 5f7f80871273592a8f92b934f42bf68ad94be587 | skipped | synchronize 时尚未添加 opt-in 标签，不是验收通过 |
| 36399985871 | 5f7f80871273592a8f92b934f42bf68ad94be587 | failure | 标签触发成功，但 runner 启动前被账户 billing 条件阻止 |

验收运行：<https://github.com/wpuu/NodeLab/actions/runs/36399985871>。

通过 `gh run view` 和 GitHub check annotations 核实：

- job `local-acceptance`，job/check ID `108855290778`。
- `steps=[]`；没有安装依赖、下载/执行 Mihomo 或运行 pytest。
- artifact API 返回 `total_count=0`。
- GitHub 原始 annotation：

> The job was not started because recent account payments have failed or your spending limit needs to be increased. Please check the 'Billing & plans' section in your settings

此消息不能区分付款失败和额度限制的具体原因；没有读取或修改账户账单。它是执行基础设施阻塞，不是 gate 用例失败，也不是源码/YAML 或真实协议验收通过。

已移除 PR 的 `run-local-acceptance` 标签，避免后续提交重复尝试启动被阻止的任务。没有反复 rerun 或放宽门禁。移除标签不取消已启动任务；本次任务已经结束。

## 本地验证

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
637 passed, 37 skipped in 29.40s

git diff --check
通过
```

本地环境仍为 Python 3.11.2，无可用固定版 Mihomo。远端基础设施错误没有新增任何真实 handshake/controller/cleanup 证据，也没有减少 37 个 skip。

## 下一步与授权边界

需要仓库所属账户维护者检查 GitHub Settings 的 Billing & plans / Actions 付款及支出额度。修复后，可以重新给同仓库 PR 添加 `run-local-acceptance` 标签，在更新后的 revision 运行；也可以明确选择重跑旧 run，但应注意其 head SHA 是上表版本。

保持 PR 草稿，不自动合并 main，不修改账单或支出上限。工作流入口已实际触发，但是否能下载资源、启动真实引擎及通过三套 gate 仍未知。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；无真实路由证明、Windows 验收或 P0 CLOSED 结论。
