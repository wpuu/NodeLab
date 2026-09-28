# Linux 私有运行残留：只读检查

在受支持 Python 3.12+ 环境安装本项目后：

```sh
nodelab recover --inspect
# 或指定已有私有根目录：
nodelab recover --inspect --root /absolute/private/root
```

这不是清理命令。它不创建根目录或恢复锁、不探测 flock、不读取 YAML、不查询 owner/child 身份、不发送进程信号、不删除或改写运行文件。Windows 等非 Linux 平台会返回 `RECOVERY_INSPECTION_UNSUPPORTED`；没有回退到未经验证的实现。

`--inspect` 与 `--confirm` 互斥。既有 `recover --confirm` 仍可能停止已验证 child、删除私有文件，需要独立授权，不能把一次检查结果作为后续清理许可。

## 看懂报告

报告是独立的 `RECOVERY_INSPECTION` 白名单 JSON。`inspection_status=COMPLETE` 和退出码 0 只表示本次检查完成，**不表示恢复成功、没有活进程或目录可以删除**。

以下字段始终为 false：

- `cleanup_performed`
- `process_signals_sent`
- `process_identity_checked`
- `recovery_authorized`

每行只含 `line_number`、`reason`、`lock_state`，不输出目录名、路径、PID、可执行指纹、marker 内容或凭据。编号只是这一次扫描的顺序，不是永久标识或 PID；文件变化后顺序可能改变。

| reason | 含义及边界 |
| --- | --- |
| LAUNCH_PENDING | 存在启动待确认文件；不证明它的内容可信，也不猜测未知 PID |
| MARKER_STAGING_PRESENT | 存在 marker 暂存文件，发布状态不明确 |
| MARKER_MISSING | 缺恢复 marker，包括空目录 |
| MARKER_INVALID | 已有记录未通过既有有界读取/格式/boot/child 形状检查，或读取不安全 |
| RECOVERY_CHECK_REQUIRED | 仅静态 marker 检查通过；仍需原恢复程序核对 owner/child，可能是活跃运行 |
| UNEXPECTED_CONTENT | run 目录有非预期内容，未打开这些内容 |
| ENTRY_UNSAFE | run 入口不是安全的私有普通目录，例如软链接或权限异常 |
| UNRECOGNIZED_ENTRY | 根目录中有非预期名称；名称不会被输出 |
| LOCK_WITHOUT_DIRECTORY | 本次扫描看到了锁文件但没看到对应目录，不表示锁已失效 |
| RECOVERY_LOCK_PRESENT | 存在恢复锁文件，不判断是否正被占用 |

`lock_state=PRESENT_UNCHECKED` 只表示外观符合当前 UID、0600、单硬链接、零长度的普通锁文件要求；**不代表 live，也不代表 stale**。`ABSENT` 只表示检查时未发现，`UNSAFE` 表示类型/权限等不符或检查失败，`NOT_APPLICABLE` 用于无法关联 run 的入口。

## 遇到残留时

保留现场，不要自动补 marker 字段、删除启动意图或按名称批量终止进程。检查不会解决未知 PID，也不会解除新运行被残留阻塞的状态。操作者需要私下核对运行来源、owner 是否仍在及可用身份依据；缺少足够依据时应继续复核，而不是猜测或绕过门禁。

原恢复命令仍按当前代码重新验证；即便记录通过静态检查，也可能因为活 owner、身份不可读、boot 变化等拒绝恢复。检查不是锁、不是租约，也不是保证后续条件不变的快照。

Linux 的显式恢复另行打开并持有 `.recover.lock` 的排他 flock，取得锁后核对 fd 与当前路径为同一安全 inode；stale 锁不先删除再重建。竞争或替换要求复核，inspection 不执行这些操作。释放锁时若发现替换或删除失败也会报错，但此前恢复体可能已执行动作，不能将该错误理解成回滚。见审计 039；普通 run 锁及敌对路径替换仍有独立边界。

## 大小、错误与只读边界

每个扫描目录最多接受 256 个入口，使用有界 scandir；超限返回 `RECOVERY_INSPECTION_LIMIT`，不截断后伪装成完整报告。根目录不安全、I/O 错误或不支持的平台返回固定错误，原始异常文本不公开。marker 读取沿用 4096 字节上限和 Linux 描述符检查。

只读指本工具不显式写、删、改文件；普通读取可能触发内核的 atime 更新。敌对父目录替换、同身份恶意写入和并发变化不因此获得完整保护；结果仅是短暂观察，不是认证。

生产门禁仍关闭：`PROBE_GATE_OPEN=False`、`REAL_NODE_TEST_ALLOWED_NOW=NO`。该工具不是 Windows、断电恢复、外部节点或生产验收证明。

Linux 普通 run 锁的残留删除也必须打开现有锁、取得 flock 并核对 inode，不因一次 stale 探测直接 unlink，也不补建缺失锁。竞争或打开后路径变化要求复核。此规则只保护锁删除，尚未把整个 run 目录恢复变为持锁事务；见审计 040。
