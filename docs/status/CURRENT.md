# NodeLab 当前状态

更新：2026-10-05（Asia/Shanghai）。

已完成 Windows 本机离线文件入口、最小 ZIP 和虚构输入云验收，最终测试代码提交 `45cbb67fab99bed79fbf9980fbbe3788db1b9640`，运行 37216977500 成功。

Windows 114 项通过；Linux 相关验收 99 项通过、15 项跳过，全部主回归 193 项通过、33 项跳过。包内 21 文件校验通过。

- [验收记录](NL-OFFLINE-ENTRY-ACCEPTANCE-20261005.md)
- [运行包](../../dist/NodeLab_Offline_V1.zip)
- [使用说明](../NodeLab_Offline_Readme.txt)
- 分支：`feat/offline-inventory-entry-20261005`；草稿 PR #5 基于 PR #4，main 未合并。

包仍需 Python 3.12+ 和 Tk。用户电脑与真实节点均未验收，没有扫描历史 E:\\NodeLab。下一步为用户本机选择已下载文本并复制匿名摘要回来，原文不上传。

商业收费尚未验证，当前保持自用盘点定位。现有严格解析器不具备目标 HTTP/SOCKS 客户所需的完整诊断能力。

模型：Codex；精确底层型号与思考档位不可验证。
