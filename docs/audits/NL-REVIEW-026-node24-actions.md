# NL-REVIEW-026 — 官方 Actions 原生 Node.js 24 迁移

日期：2026-09-28。处理审计 021–025 中反复出现的 Node 20 目标被平台强制在 Node 24 上执行的弃用警告。范围仅工作流依赖维护，不修改产品代码、验收门槛、付费设置或 main。

## 固定来源与兼容性核对

通过 GitHub API 查询官方 actions 仓库发布版本，解析 tag 的 commit 对象；随后按完整 commit SHA 读取 `action.yml` 与 README（不是只读会漂移的 major tag）。三者 `runs.using` 均明确为 node24：

| action | 版本 | 固定 commit |
| --- | --- | --- |
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-python | v7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| actions/upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |

官方发布链接：

- <https://github.com/actions/checkout/releases/tag/v7.0.1>
- <https://github.com/actions/setup-python/releases/tag/v7.0.0>
- <https://github.com/actions/upload-artifact/releases/tag/v7.0.1>

核对现有使用的输入仍受支持：checkout 的 persist-credentials，setup-python 的 python-version，upload-artifact 的多文件 path/name、if-no-files-found、retention-days 等。

- checkout/setup-python 的 Node 24 文档要求 runner 至少 v2.327.1；checkout 的容器内认证 git 操作另有 v2.329.0 要求，本工作流不执行该场景。
- setup-python v7 移除的 pip-install 输入本项目未使用；仍以独立步骤安装依赖。
- upload-artifact v7 的 archive=false 只支持单文件。本项目明确 archive=true，保留五份固定 JSON 的命名 ZIP artifact；include-hidden-files=false 也显式固定。
- checkout 不启用 allow-unsafe-pr-checkout，继续 persist-credentials=false。

这是特定来源、声明与所用接口的核对，不是对所有上游源码/打包依赖的全面安全审计或可重复构建证明。

## 不变的安全与测试范围

仍是只读权限、同仓库带标签 PR 或手动启用，不引用仓库 secrets，不使用 pull_request_target、不自动取消进行中的验收。Mihomo URL/双摘要、Python 3.12、737 项 full gate、三个具名 Windows skip、三个独立零 skip gate 全部不变。没有通过不安全 Node 版本环境变量绕过弃用要求。

增强已有 workflow 静态测试，核对三个明确 SHA、凭据不持久化、不启用不安全 PR checkout、显式 ZIP/隐藏文件策略。不新增 testcase，因此 full 预期总数不变。

```text
workflow 静态测试：9 passed in 0.06s
本地 Python 3.11.2 全量：700 passed, 37 skipped in 32.79s
```

代码/CI head：`1589b4a9123763ab440019a9ca20bfc9ca55e9af`。提交差异检查通过。

## 远端复验

- run：[36411287183](https://github.com/wpuu/NodeLab/actions/runs/36411287183)
- 已验收 head：`1589b4a9123763ab440019a9ca20bfc9ca55e9af`
- job/check ID：`108891838127`，job success，2 分 20 秒
- Ubuntu 24.04 / Python 3.12 / 官方双摘要固定 Mihomo v1.19.31
- event 为 pull_request；默认 checkout PR merge revision，上述 SHA 是事件 head。

通过 GitHub API 读回并程序化核对：

| gate | code | passed | skipped | route_proof |
| --- | --- | ---: | ---: | --- |
| LINUX_FULL_REGRESSION | FULL_REGRESSION_OK | 734 | 3 | NOT_RUN |
| F2_LINUX_SESSION | SYNTHETIC_SESSION_OK | 11 | 0 | NOT_RUN |
| F3_LINUX_TROJAN_TCP | LOCAL_TROJAN_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |
| F3_LINUX_VLESS_TCP | LOCAL_VLESS_TCP_OK | 4 | 0 | LOCAL_FIXTURE_ONLY |

全部 status=PASS，real_node_used=false、real_node_test_allowed=false、windows_acceptance=NOT_RUN。full 的三个 skip 严格限于具名 Windows 测试，独立 gate 仍零 skip。

Check annotations 共五条固定 JSON notice，零 warning/failure annotation；之前的 Node 20 弃用注释没有再出现。报告上传步骤成功；artifact API 确认一个未过期的 `local-gate-results-36411287183-1`，ID `10963879079`，大小 1360 字节。本轮报告正文取自 check annotations，未把 artifact 元数据当作 ZIP 内容校验。

核对后移除 opt-in 标签，避免文档提交重复触发；PR #2 保持草稿，未合并 main。文档提交不是上述已验收 head。

## 边界

本轮不解决 Windows NTFS E: / ACL / PID 验收、进程身份非原子竞态、崩溃恢复或生产探测授权。Linux 通过不能代替这些要求。`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；PR #2 保持草稿。
