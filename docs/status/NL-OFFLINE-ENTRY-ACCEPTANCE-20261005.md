# NodeLab 本机离线入口验收 — 2026-10-05

结论：个人自用的 Windows 文件入口和最小运行包已通过云端虚构输入验收。用户电脑、真实资源和商业收费仍未验收。

## 可交付物

- [NodeLab_Offline_V1.zip](../../dist/NodeLab_Offline_V1.zip)：85660 字节，21 个文件，不含真实输入。
- [使用说明](../NodeLab_Offline_Readme.txt)；完整解压后双击 NodeLab_Offline.cmd。
- 需要本机已有 Python 3.12+ 和 Tk。包中不带 Python，不是独立 exe。
- 包内固定 idna 3.20，附 BSD-3-Clause 许可证和逐文件 SHA256 清单。
- ZIP SHA256：`5b86d342dd2c379460074da002da7bde9dea378c6012d3f9e0d36d11082493d7`。
- MANIFEST.code_commit：`45cbb67fab99bed79fbf9980fbbe3788db1b9640`，等于最终代码验收提交。
- 压缩包在 Git 分支中持久保存；Actions 临时产物的过期不影响该副本。

## 云验收证据

- [GitHub Actions 运行 37216977500](https://github.com/wpuu/NodeLab/actions/runs/37216977500)，结论 success。
- 测试提交：`45cbb67fab99bed79fbf9980fbbe3788db1b9640`。
- Windows 2022 / Python 3.12：114 passed，0 failed，0 skipped。
- Ubuntu 24.04 相关验收：99 passed，15 skipped；跳过的是 Windows 特有分支。
- Ubuntu 24.04 全部主回归：193 passed，33 skipped，0 failed；原有条件性跳过仍在。
- 实际 Windows Tk 控件验收：取消文件选择不生成目录；随后选择虚构文件，保存匿名报告并复制匿名摘要。
- 抽取运行包后用 Python -S 禁用 site-packages 完成自检；父目录伪造旧 src/nodelab 会抛错的哨兵未被加载，证明优先使用包内模块。
- 检查输入内容、大小、修改时间不变；包括 BOM、空文件、坏 UTF8、512KiB 边界和过大输入。
- 模拟读取、报告写入、临时完成标记写入与标记发布失败；错误只含固定代码，无 URI、秘密、主机、备注和源路径。
- DNS、socket 创建与连接、子进程和 shell 操作在隔离测试进程内均被 Python 审计钩子拦截；未导入引擎模块，探测门保持关闭。
- 最终 ZIP 在交付环境抽取，21 文件清单及每个 SHA256 均匹配；ZIP 内提交亦匹配最终测试提交。

## 边界与未完成项

本入口只读取用户通过文件选择器明确选定的一份已下载本地逐行文本，不修改客户端。匿名报告保存在 %LOCALAPPDATA%\\NodeLab\\Reports 下的随机唯一目录，最终完整完成标记发布后才显示成功；失败目录不能视为成功结果。

拒绝 UNC、设备命名空间、ADS、映射网络盘、符号链接、重解析点和离线占位标志。Python 钩子不能控制 OS 文件选择器、其他软件或后台同步，也不保证抵御恶意文件系统竞态。

没有具体真实文件路径，本轮未扫描用户盘符，未读取真实节点，未测试历史 E:\\NodeLab。云端 Windows 成功不能代表用户电脑的软件环境通过，更不代表节点可用。

支持现有 Trojan/VLESS 解析范围；订阅 URL、整体 Base64、YAML 输入没有抓取或转换。解析成功仅表示受支持格式，可用性、期限、来源和转售授权仍未知。

商业侧仍没有付款验证，HTTP/SOCKS 客户需求与当前能力存在差距；当前目标继续定位为自用离线盘点。

## 当前仓库状态与下一步

- 分支：`feat/offline-inventory-entry-20261005`。
- [草稿 PR #5](https://github.com/wpuu/NodeLab/pull/5)，基于 PR #4 的功能分支；均未自动合并。
- main 复核仍为 `55ce1b248e1bb5b2368ae34b4fcfbb34f9057a3f`。
- 最后一个代码修复是包内模块优先，避免解压到旧仓库旁边后误加载旧版本。
- 用户只需：下载、完整解压、双击，在本机选择文本，然后复制匿名摘要回来。无需上传原文。
- 下一步：根据该匿名摘要做真实资源的数量与格式基线；真实连通性探测仍需单独明确目标。
- 记录时间：2026-10-05（Asia/Shanghai）。模型：Codex；精确底层型号和思考档位当前不可验证。
