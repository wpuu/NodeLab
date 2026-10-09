# NodeLab 当前状态

更新：2026-10-09（北京时间）；执行助手：Codex，细分模型未独立核验。

Windows x64 独立桌面候选已实际构建，内含Python3.13.16/Tcl/Tk8.6.15，用户无需预装Python。冻结程序在删除源码暂存、清空PATH后实际通过自检、虚构URI/Base64处理、三次报告往返、匿名错误、文件不改写、网络/DNS/子进程阻断及隐藏Tk窗口。生成ZIP成功后逐项文件哈希读回通过；下载产物再次核对1002个文件、压缩包哈希与CRC。用户Windows电脑完整桌面验收仍未完成。

实际代码提交：79d1064b34eb9429fad070b2a72280bc454504bf。
候选分支：feat/offline-inventory-standalone-20261009。
草稿审查：https://github.com/wpuu/NodeLab/pull/6
成功CI：https://github.com/wpuu/NodeLab/actions/runs/37913566382
审查目标为既有离线入口分支；main未合并。

| 实际验收 | 通过 | 跳过 | 失败 |
| --- | ---: | ---: | ---: |
| Windows离线/桌面测试 | 618 | 0 | 0 |
| Linux离线验收 | 599 | 19 | 0 |
| Linux完整回归 | 693 | 37 | 0 |

计数范围重叠，不相加。Linux源码CI为3.12.15/Tcl8.6.14，源码acceptance严格拒绝不支持的Tcl profile，该拒绝路径按预期通过。独立Linux3.12.14/Tcl9.0.4冻结程序另有真实构建/解压/旧源码与PYTHONPATH干扰/系统调用网络拒绝证据，不能替代Windows。

报告核对保留严格schema、内容逐字节一致与类型/身份/重解析点检查。Windows跨stat API比较明确birthtime，各自前后仍核对完整ctime。返回前按原字节上限重新读回三报告，以内部摘要识别元数据不变的改写。内部摘要不输出或保存；该流程仍非原子快照、作者或原始输入认证。

此前/proc环境六项失败已在成功Linux完整回归的JUnit逐项确认通过。构建依赖固定8包及18个官方wheel哈希，独立venv无system-site-packages；程序只包含7个NodeLab离线模块，模块白名单已由实际Windows构建检查。

候选内运行时许可notice已随包复制，原生依赖许可完整核对仍PENDING；release_ready=false。清单指纹不是发布签名。未执行用户Windows本机或真实节点验收，生产探测关闭。下一步仅使用虚构文件完成Windows本机桌面验收，再处理候选发布条件。

- [独立桌面候选与本轮验收记录](NL-OFFLINE-STANDALONE-20261009.txt)
- [报告核对历史记录](NL-OFFLINE-REPORT-CHECK-20261009.txt)
- [输入格式历史记录](NL-OFFLINE-INPUT-METADATA-20261009.txt)
- [构建后Windows包说明](../NodeLab_Standalone_Readme.txt)

产物许可补正：实际PE版本识别libcrypto-3.dll为OpenSSL3.5.9、zlib1.dll为1.3.1。已按官方精确tag补充各自完整许可及OpenSSL实际版权归属说明，补正候选已由上述新提交/CI成功重新生成，下载后的1002文件哈希与三份新增notice逐项核对通过。此项补充不等于全部原生依赖分发条件已核验。
