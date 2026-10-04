# 离线盘点原型验收与接续

实际记录时间：2026-10-04T22:27:38.098+08:00，Asia/Shanghai。
执行者：Codex；精确运行模型 ID 和实际思考档位无法独立核验。
本轮读到既有功能分支和草稿 PR #4，因此复用现有代码，没有重复覆盖其他执行者的实现。

## 已核实
main = 55ce1b248e1bb5b2368ae34b4fcfbb34f9057a3f。
被验收代码 = 960974b9894e5176387012757e4040b70c032137。
分支 = feat/offline-inventory-20261004。
草稿 PR = https://github.com/wpuu/NodeLab/pull/4。
真实运行 = https://github.com/wpuu/NodeLab/actions/runs/37208629541。
运行完成时间：2026-10-04 22:16:39，Asia/Shanghai。

实际读取 run、两个 job 的步骤与解码日志，不只依据 PR 文案：
- Ubuntu 24.04：虚构盘点/CLI/严格解析/Trojan/VLESS/脱敏测试步骤 success；main 回归步骤 success。回归输出包含三个 skip，不冒充零跳过全覆盖。
- Windows 2022：同组虚构盘点/CLI/解析/脱敏测试步骤 success；Linux main 回归步骤按工作流条件 skipped。
- 两边示例生成步骤 success；从各自日志取回 base64 编码的 JSON、Markdown，解码并逐字比较，内容一致。
- pytest 输出使用安静选项，未取得清晰汇总计数，不编造通过项数量。整体 success 不等于用户本机安全验收。
- 本轮本地终端不可连接，未本地运行 Python；上述执行证据来自 GitHub 云运行器。

## 实际示例
14 物理行，2 空白，12 非空记录；7 解析、3 不支持、2 错误；5 规范化配置组、2 重复记录。
保存到 docs/examples/NL-OFFLINE-INVENTORY-SAMPLE.json 和同名 .md，内容直接来自云端执行日志，非手写预期值。
来源、转售授权、质量、出口、寿命、住宅属性与独立线路数量依然未知。
公开结果没有 URI、节点地址、凭据、备注、秘密指纹或私有路径。此次样本全虚构。

## 当前状态和限制
原型已存在且本次离线云验收通过；草稿 PR 尚未合并。生产探测仍关闭。
没有取得 E:\NodeLab 状态，没有处理真实私有文件、真实节点、GCP、API Key；未部署或收费。
Linux 和 Windows 标准运行器证明虚构离线流程，不证明用户本机 ACL、代理客户端共存、真实线路或商业供应。
本记录为文档提交，实际验收绑定上面的代码 SHA；不能把后续文档 SHA冒充被运行代码。

## 下一步
先复核样本报告是否足以支持用户盘点决策，再准备客户自跑诊断的中英文交付样本与固定范围草稿。
继续阶段可以自主做文档、虚构输入和隔离改动；不自动发布推广、不收款、不接真实资源、不合并 main。
如要进入本机真实输入盘点，先准备无需上传 URI 的具体操作和凭据保护方案，再请求该阶段批准。
用户当前无需操作。不创建无真实执行机制的后台接力。

## 复现
按 pyproject 安装项目及 pytest。
使用 .github/workflows/offline-inventory.yml 的实际测试命令。
运行 scripts/inventory_demo.py --check 验证已提交样本与固定虚构输入一致。
本次取回样本与运行输出已比对；--check 对新增文档提交本轮未重新执行。
