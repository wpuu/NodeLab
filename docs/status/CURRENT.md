# NodeLab 当前状态

更新：2026-10-09（Asia/Shanghai）；执行助手：Codex，细分模型未独立核验。

当前隔离候选包含显式Base64离线入口、输入格式记录、保存报告只读核对与原生桌面打包流程。固定入口基线 fe8c1399af7485aff70ead0015b5ab6dd6441455。本轮GitHub写入已恢复，候选分支 feat/offline-inventory-standalone-20261009 已创建；已保存代码提交44a68b5e17416496851270fa1cf7df9a484fd161及草稿PR #6：https://github.com/wpuu/NodeLab/pull/6。

本地离线验收578通过、18跳过。原生Linux冻结程序已实际构建，自带Python/Tcl，源码暂存删除、PATH清空后两种自检通过；重新解压、邻近旧源码和PYTHONPATH干扰下通过，网络系统调用拒绝条件下同二进制通过。明确这是Linux内部验证，未执行Windows桌面验收，Linux二进制不作为Windows交付。

新builder只使用最小离线模块白名单、固定依赖及官方wheel哈希、无system-site-packages的隔离venv。校验PYZ仅含7个NodeLab离线模块；冻结程序须通过虚构输入两格式、三报告往返、只读快照、匿名输出、不一致拒绝与网络/子进程阻断。构建成功且哈希写完后才发布完成ZIP。失败不残留完成ZIP/hash。

首轮CI 37909168353因Windows无3.12.14二进制安装包及Linux源码测试Tcl环境差异失败，未生成Windows程序。已按官方setup-python manifest调整Windows为Python3.13.16原生x64、Linux源码CI为3.12.15；本地Linux冻结验证保持3.12.14。运行时契约与故障注入测试同步修正，冻结包验收门槛不放宽。二轮CI 37910107868：Linux离线582通过18跳过、完整回归676通过36跳过；Windows97失败503通过，报告读取被文件元数据比较拒绝。CPython3.13.16源码与官方issue #157671确认Windows路径stat的ctime为创建时间、句柄fstat的ctime为ChangeTime。修正为跨API比较birthtime，dev/ino/size/mtime/attributes仍严格一致；同API前后仍比较完整ctime和birthtime。第三轮CI 37910878294：Windows614通过1失败，身份兼容修正有效；剩唯一测试夹具把Markdown写为CRLF，被正确拒绝。夹具改为固定LF，读取器逐字节校验保留；第四轮CI待回读。Windows流程须由实际Windows runner构建并通过冻结自检/隐藏Tk窗口，再产生Windows候选。当前目标是完整目录包，自带运行时且不要求用户预装Python；必须保留_internal目录。构建配方已准备，不等于Windows程序已生成或用户电脑实测通过。

- [本轮独立桌面候选记录](NL-OFFLINE-STANDALONE-20261009.txt)
- [报告核对记录](NL-OFFLINE-REPORT-CHECK-20261009.txt)
- [格式记录](NL-OFFLINE-INPUT-METADATA-20261009.txt)
- [源码包使用说明](../NodeLab_Offline_Readme.txt)
- [构建后Windows桌面包说明](../NodeLab_Standalone_Readme.txt)

包仍为开发候选。依赖原生库许可证完整清单、用户Windows桌面及真实节点验收均未完成。清单指纹不是签名。此前/proc环境六项失败在真实Linux全套回归范围已无失败；历史Windows114项不可用于新版本。生产探测关闭，未部署或合并main。
