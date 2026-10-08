# 离线合成资源容量模拟器

此工具只验证假设数据与算术，不发放节点、不探测、不联网、不收费。所有示例额度、费用、人数、日期、证据编号均为虚构，不代表任何云厂商产品、实际资源数量或盈利预测；不包含实际业务计划。

## 运行（Python 3.12+，仅标准库，无需安装依赖）

在仓库根目录运行：

```sh
PYTHONPATH=src python -m nodelab.capacity examples/capacity_synthetic.json --now 2030-01-01T00:00:00Z
PYTHONPATH=src python -m unittest discover -s tests -p test_capacity.py -v
```

Windows PowerShell 可先设置 `$env:PYTHONPATH="src"`，再运行相同的 python 命令。未做 Windows 实机验收。

## 台账约定

- `synthetic_only` 必须为 true；仅使用 R0001、G0001、E0001 这类匿名编号。额外字段被拒绝。不要提供真实账单、IP、节点 URI、账号、秘密或客户数据。
- `resources` 记录来源（owned、licensed、third_party_shared、unknown）、来源证据、使用/转供授权、授权证据、到期时间和核验状态。免费共享 VPN 也可记录，不限于云服务器。第三方共享不等于得到转供许可。
- `group` 为共享额度组编号；独立性未知时填 null，保留在台账但不算容量。不能为同一个账号/计费池的不同 VM 或节点各建独立额度。额度不明不可填写“无限”。
- `groups` 每个真实共享计费/额度池只出现一次；重复组 ID 直接拒绝。同组多个可用资源不会重复增加额度。工具无法检测被错误拆成不同 ID 的同一实际计费池，操作者必须保证组映射的假设正确。
- `quota`、`used` 可以为 null，任何一个未知则不计该组容量。`quota_evidence` 为空或 verified 为 unknown 亦不计容量。已用量大于额度视为矛盾输入并拒绝。
- 所有输入用量均属于明确的同一个 `window_start` 至 `window_end` 时间窗，不是速率。额度组必须与规划窗完全一致，不自动折算月/年、滚动额度或累计跨月额度。
- 授权必须 use_authorization 和 supply_authorization 都为 allowed 且存在证据；资源 verified 为 verified、来源有证据、到期覆盖整个窗口，才参与假设容量计算。结束时间按半开区间处理，到期恰好等于窗口终点可以覆盖该窗口。
- E 编号只代表示例中的证据断言，不是工具已经验证了授权文件。自述“能用、速度不错、很多人在用”不证明独立额度、转供许可、并发或长期可靠性。

## 计算与费用

1 GB = 1,000,000,000 字节；1 GiB = 1,073,741,824 字节。用十进制算术转换，再以整数字节求和。预留比例 0 至 1，扣除后向下取整。

需求 = 免费人数 × 免费人均用量 + 高级人数 × 高级人均用量。`capacity_sufficient` 只表示输入假设下的额度算术成立，不能承诺真实服务；`service_ready` 与 `reliability_assessed` 固定 false，`committable_capacity_bytes` 固定 0。并发、带宽、质量、故障率与合规经营均未验证。

`cost` 是该组在规划窗口的已知费用小计，可为 null；`cost_complete=false` 表示仍有费用缺项。零采购成本需要明确填 0，不等于总成本为零。金额按 CNY/USD/EUR 分列，不自行换汇。输出计算全台账费用，包含不可分配的组，避免隐去持续发生的成本。尚未归属于资源组的人工/支付/税费等成本不包含在小计内，不能从小计推导经营总成本。

共享组未知的资源另外列入 `ungrouped_resources_cost_and_hours_unknown`，不将其成本或工时算作零。

`service_hours` 为该组该窗口预计支持工时，未知填 null，已知值可汇总；未计算人力价格。即使采购为零，也保留工时未知。没有收入、定价或利润计算。

示例：100 GiB 的唯一共享池已用 10 GB，预留 20% 后为 77,899,345,920 字节；10 人 × 2 GB 加 2 人 × 10 GiB 需求为 41,474,836,480 字节。假设额度够用，但只知道 25 CNY 费用小计，费用仍不完整、服务工时未知；另一个第三方共享资源的组/授权/有效期/核验均未知，排除。上述数字全是假设，不能代表盈利或服务可交付。

## 边界

纯函数 `simulate(document, now=aware_datetime)` 可独立复用，返回新报告，不修改台账；CLI 只读取一个受限普通文件并输出 JSON，不产生配置或分配动作。单文件 512 KiB，最多各 1000 组/资源；非法数字、负值、NaN/Infinity、重复 JSON 键及额外字段被拒绝。所有读取错误只输出固定错误码，不回显路径/输入。

不修改盘点器或 PROBE_GATE_OPEN=False。Windows 路径保护逻辑尚待实机测试；Linux 网络挂载不能单凭路径判断，请只使用本地合成文件。严格无文件系统 IO 可直接调用纯函数。没有探测、服务端、支付或订阅管理。
