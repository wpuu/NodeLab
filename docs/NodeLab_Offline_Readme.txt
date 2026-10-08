NodeLab 本机离线盘点 V1（个人自用准备版）

1. 解压整个压缩包，双击 NodeLab_Offline.cmd。
2. 需要本机已有 Python 3.12或以上，并包含Tk图形组件。缺失时只提示，不自动安装或下载。
3. 点“选择文件并盘点”，选择一份已下载的本地UTF-8逐行节点文本（可带BOM；LF或CRLF换行）。
   最多512KiB、1000条非空记录；空白行不占记录额度，但计入字节上限。
4. 窗口显示匿名统计。“解析成功”只表示格式受支持，不代表节点可用。
5. 点“复制匿名摘要”，可以仅分享摘要。原始链接和密码留在本机。
6. JSON、中文报告保存在 %LOCALAPPDATA%\NodeLab\Reports\report-随机编号。
   一个报告目录只有存在 COMPLETE.json 才表示完整写入；失败目录不作完成结果。
7. 关闭窗口即可。输入文件不修改，已有代理客户端不改动。

输入与错误提示：
- 超过1000条非空记录时显示 INPUT_TOO_MANY_RECORDS，整份拒绝，不截断、不生成报告。
- 1000条上限限制匿名逐条报告的大小和内存使用；512KiB字节上限仍同时生效。
- UTF-16、ANSI及仅CR换行不在支持范围。编码错误不代表节点失效。
- 如需转换编码，请仅在本机另存为UTF-8副本，保留原文件；不要上传原文或使用在线转换。

Python/Tk准备（由你手动完成，不需要节点文件）：
- 已有Python时，在命令提示符运行 py -3 --version，确认3.12或以上；
  再运行 py -3 -m tkinter，能打开测试窗口即可关闭。没有py时用python替代。
- 缺失时只从Python官方网站选择适合Windows的完整安装包：
  https://www.python.org/downloads/windows/
- 在完整安装器的自定义安装中保留 Tcl/Tk and IDLE；可选择当前用户安装。
  保留Python启动器，或选择添加Python到PATH，以便双击入口找到解释器。
  不要使用不含Tk的embeddable嵌入式包，也无需安装Mihomo或其他节点工具。
- 已安装但缺Tk时，可用原安装器的Modify补选Tcl/Tk；完成后重新做上述测试。
- 安装器选项说明：https://docs.python.org/3.12/using/windows.html#the-full-installer
  本轮云端基线为Python 3.12；用户电脑上的安装与实际窗口仍需本机验证。

当前解析：Trojan/VLESS 的TLS TCP、WebSocket、gRPC。
Reality、HTTPUpgrade及其他不支持项会单独统计；不会判成失效节点。
订阅网址、整段Base64订阅、YAML不是支持输入，不会自动抓取。

程序有运行期网络/DNS与外部进程审计拒绝；不启动代理引擎。
输入拒绝UNC、设备路径、网络盘、符号链接、Windows重解析点和云占位文件。
这不等于控制电脑上其他软件的同步、监控或恶意行为；请使用本地已下载文件。
报告仍含文件结构统计，由你决定是否分享。不要上传原始节点文本。
本包不含Python运行时，不是无依赖exe。未证明你历史E盘程序的安全性。

仅复用既有严格解析器和匿名盘点模块；idna依赖随包附许可证和版本清单。
仓库：wpuu/NodeLab。生产探测保持关闭。
