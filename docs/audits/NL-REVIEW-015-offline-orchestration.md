# NL-REVIEW-015｜F3 单会话离线编排

日期：2026-09-28。承接 NL-REVIEW-014；真实引擎验收仍未完成。

## 本轮实现

新增内部入口 `offline_fixture.run_offline_fixture`，把已有组件连接为：

```text
本地范围/预算校验
  → private_engine_session（私有 YAML → -t → runtime）
  → BoundConnectionReader
  → EXIT_A 原始 HTTPS 流式采集
  → 传递 baseline/已见连接 ID
  → EXIT_B 独立 HTTPS 流式采集
  → runtime 最后复核
  → RunContext 停止 child、删除 YAML、释放锁
  → 复核 owner.closed 与 child 已退出
  → 私有双源判定
  → 再次检查 deadline → 返回私有候选结果
```

### 范围与失败优先级

- 节点 entry_host 仅允许 `127.0.0.1`；两源只允许 HTTPS localhost/127.0.0.1、不同主机名；禁止用户信息/fragment、不安全 TLS、无效预算。不合范围时不创建 session。
- 从入口创建一个绝对 monotonic deadline，透传到 session、两源 capture 和 reader；不为 B 重新创建预算。修改了内部 `_deadline` 透传接口，独立调用原默认行为保留。
- 源级 HTTP/正文错误或源级 timeout，在总预算仍足够且 runtime 重新核验成功时允许继续另一源，最终最多 PARTIAL。
- 总 deadline、runtime/reader 失效、证据错误链、重放、畸形关联等为硬失败；A 硬失败时不启动 B。
- 清理成功之前不调用 assess_fixture_pair；清理失败优先覆盖先前的同意/冲突/路由错误。正文、快照、IP 均不写结果文件。
- KeyboardInterrupt 在 session 清理之后继续传播；未知内部异常转换固定 `FIXTURE_EXECUTION_FAILED`，不回显异常原文。
- session 已进入后不能用 UNSUPPORTED 掩盖错误；晚返回的判定也不能在 deadline 到期后报告同意。
- 产品 CLI 不调用此入口，公开 gate 未修改。

## 验证：两个不同层次，不能混称真实引擎证据

### 编排故障矩阵

`tests/test_offline_fixture.py` 使用真实 POSIX RunContext/私有文件与 Python 替身 child，但 mock 启动和请求结果。验证顺序、同一 deadline、连接 ID 传递、仅一套 runtime、缺源/冲突/族差异、软错误、硬错误停止 B、进程退出、总超时、清理优先级、取消、输入无副作用和秘密错误不回显。

另注入真实私有目录删除失败：child 已停止但 YAML 无法删除时必须 FAIL，不进入判定；恢复删除方法后确定性重试清理，测试不遗留虚构凭据。

### 完整本机 I/O 集成

新增测试专用 `tests/fixtures/f3_engine_substitute.py` 与 `tests/test_offline_fixture_integration.py`：

- 只替换 pinned binary 校验及 engine 可执行程序；真实 private_engine_session 仍执行一次 -t 和一次 runtime。
- runtime child 自己持有两个 loopback 监听；PID/创建时间/可执行路径指纹、401/401/200 控制面鉴权、配置/组/规则预检均走实际代码。
- 同一 child 处理 CONNECT/TLS 与受认证的合成 /connections；双源使用独立客户端 socket。controller 在快照读取前暂停正文，读取后释放，证据采样与原始响应保持关联。
- 正向同 IP 得到私有 PASS 候选；第二源链被替换为 DIRECT 时，即使返回同 IP 也得到 FAIL/EVIDENCE_ROUTE_MISMATCH。
- 返回结果前两个子进程均退出、私有根无本次目录/锁/YAML。临时 TLS 私钥和证书在测试结束删除。

**关键限制：这个替身直接终止本地 TLS，其 NODE/PROBE 链是测试构造的。它不是 Mihomo，不实现 VLESS/Trojan，不可作为真实协议握手或真实 route proof 验收。**

## 本轮结果

新增 **42 项**测试。

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
537 passed, 29 skipped
```

Linux / Python 3.11.2，OpenSSL 可用，本机 I/O 集成两项实际执行。`git diff --check` 通过。

29 个 skip 仍为 26 项真实 Mihomo binary/session 测试与 3 项 Windows 测试。Python ≥3.12 仍未复验。

## 仍未完成

- 尚无固定 v1.19.31 + 本地 VLESS/Trojan 服务端 + 原始双源 HTTPS 的真实 controller 链闭环。
- 该入口是 local-only fixture 编排，不能把输入放宽为外部节点/生产出口 URL 后称为已授权功能。
- 同步系统调用、HTTP 底层 I/O 的不可硬中断限制未消除；shared deadline 和晚结果拒绝不等于严格墙钟中断。
- 软源失败后没有自动重试；未实现生产目标白名单、生产报告持久化、真实短请求采样可靠性验收。
- Windows W1/W2、硬崩溃恢复一致性与真实环境共存未通过。

后续应优先取得支持的 Python/固定引擎环境，并用真实本地协议 fixture 代替合成引擎，不能仅增加 mock 用例就宣布 F3 完成。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；没有 P0 CLOSED。
