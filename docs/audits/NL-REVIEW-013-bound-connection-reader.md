# NL-REVIEW-013｜F3 实例绑定快照读取器

日期：2026-09-28。承接 NL-REVIEW-012。未打开产品探测 gate。

## 本轮实现

新增 `connection_reader.BoundConnectionReader`，只从内部 `LaunchedEngine` 句柄构造，不接受任意 controller URL、token、PID 或 run ID 参数。

- 启动器在创建 runtime 后、预检前采样 OS ProcessIdentity，留存在私有引擎句柄；每个句柄分配独立 UUID run 标签。缺完整身份的句柄不能构造读取器，不能在采集时临时认领当时恰好占用 PID 的进程。
- 读取器只接受规范的 `http://127.0.0.1:<port>` 控制端点、不同的有效 mixed port 和固定格式 token。
- 每次 HTTP 请求前后检查 Popen 存活、owner 未关闭且仍持有同一 child、PID/创建时间/可执行路径指纹完全一致、controller 与 mixed 两个监听均归属该 child 且 loopback。身份比较不采用恢复逻辑中允许缺失 fingerprint 的宽松匹配。
- 每次快照读取重新检查 `/connections` 无 token 和错误 token 均返回 401，再用句柄 token 获取 JSON。所有 HTTP 操作共享调用方 deadline，沿用禁环境代理、禁重定向及正文大小限制。
- `_controller_json` 增强为仅接受 HTTP 200，不能把 201/202/206 的合法 JSON 当作授权成功快照。
- 快照要求固定容器类型、受限连接数量、合法且不重复的 UUID 与 metadata 对象；只有通过后置进程/端口检查才能返回。
- 错误固定编码、repr 固定；无原始 controller、token 或路径输出。

新增 `collect_bound_fixture_request`：从 reader 派生 run ID 和 mixed port，调用方不能覆盖；请求发出前和完整响应读取后追加 runtime guard。原 callback fixture API 保留供合成测试，两者都保持 localhost-only，不是生产探测 API。

## 验证

新增 **46 项**测试，覆盖：绑定参数不合法、身份缺失/创建时间或指纹变化、错误端口归属、不同鉴权失败、进程在请求前/中/后退出、owner 关闭、快照畸形与重复 ID、共享 deadline、固定异常码、端口接管后丢弃结果、绑定适配器参数不可由调用方覆盖、HTTP 非 200 拒绝及 response 后 guard 否决成功。

其中一个测试创建真实 Linux Python 替身子进程：同一 child 拥有 loopback controller 和 mixed listener；父进程通过 stdin 管道传随机虚构 token，argv 不含 token。实际 `/proc` 身份/端口归属与 HTTP 401/401/200 检查通过；停止 child 后读取被拒绝。此替身仅返回空连接快照，**不提供协议握手或真实路由证据**。

真实引擎会话 opt-in 用例已追加实例绑定 reader 的断言，但用例数量仍为 11，gate 计数合同不变；它们尚未在真实 binary 上执行。

```text
PYTHONPATH=src .venv/bin/python -m pytest -ra
396 passed, 29 skipped
```

Linux / Python 3.11.2。`git diff --check` 通过。29 个 skip 仍为 26 项真实 binary/session 与 3 项 Windows。

## 仍不得声称已解决的边界

- pre/post PID 与监听核验是离散观察，不是 socket-to-PID 原子绑定；核验与连接建立间仍有竞争窗口，不能声称恶意端口接管风险完全消失。
- executable fingerprint 是已存在的规范路径摘要，不是每次读取时重新核验文件字节。固定 binary 的来源/TOCTOU 限制仍存在。
- 内部 Python 对象可以由同进程代码构造，不是抵抗同进程恶意代码的密码学凭证。真实输入必须经可信 private_engine_session 创建句柄；不能把传入构造对象当作外部认证。
- 读取器重新核验鉴权、身份和监听，不重新读取每次请求的全量 `/configs`/`proxies`/`rules`。规则运行中变化和原始请求链仍须结合对应证据处理。
- 本轮没有将真实 Mihomo、本地 VLESS/Trojan fixture、TLS 原始请求与非空 `/connections` 快照串成完整正负控；不能据替身读取成功宣布 F3 完成。
- reader 与 capture 的 deadline 仍受同步 I/O 不能硬中断的已知限制。
- 还缺出口 body 严格解析、双源状态映射、真实短请求捕获可靠性与 Windows W1/W2 验收。

`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`；没有 P0 CLOSED。
