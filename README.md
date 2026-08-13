# MobileE
> 老工具图形化重制版 · 一站式移动端逆向辅助工具箱
MobileE 是面向小团队内部测试的本地 Android / iOS 安全工作台。前端使用 Vue 3，桌面与后端使用 Tauri 2 + Rust；分析、设备命令和报告默认在本机完成。

## 当前能力

- Android / iOS 设备识别、架构、Root/越狱、SELinux、进程和 Frida 环境检查。
- ADB Root Shell、透明代理、证书安装、常用存储与组件检查。
- Frida 脚本运行、DEX Dump、SO Dump/ELF 修复、iOS Mach-O Dump。
- APK：AXML Manifest、权限、组件、导出入口、签名、JADX/Apktool 源码回退分析。
- IPA：Info.plist、ATS、Entitlements、Mach-O 架构/cryptid、Objective-C metadata、IMP/模块偏移和 JMCodeProtect 映射。
- DEX、SO、Mach-O、Flutter AOT、React Native/JS Bundle 的敏感信息、Endpoint、SDK 和代码入口扫描。
- 静态与运行时数据边界关联、MASVS 验证矩阵、运行时验证计划和 AI Evidence Context Pack。
- HTML 报告、项目快照（`.mskcase`）和版本基线对比。

> `cryptid=0` 只表示主程序没有 Apple FairPlay 加密或已经解密，不代表不存在 JMCodeProtect 等第三方代码保护。

## 开发环境

- Node.js 20+
- Rust stable
- macOS 为主要 iOS 测试与打包平台；Android 功能也支持 Windows/macOS 主机。
- 动态能力按需安装 ADB、Frida；APK 深度源码分析可选配置 JADX/Apktool。
- iOS 动态测试需要可访问的测试设备、对应的 usbmux 工具和兼容的 Frida 环境。

## 常用命令

```bash
npm ci
npm run dev
npm run check
npm run tauri dev
npm run tauri build
```

`npm run check` 会执行 Vue/TypeScript 类型检查、Rust 格式检查和 Rust 单元测试。

## 分析结果如何理解

- `static-candidate`：静态候选，只能作为测试入口。
- `runtime-observed`：运行时已经观察到相关行为，但仍需结合影响形成最终结论。
- `not-assessed`：当前没有证据，不代表已经通过。
- Scan Coverage 显示本轮索引、二进制深扫和结果裁剪范围；出现 `PARTIAL` 时应先阅读覆盖度警告。

项目快照会保存 App 分析结果、MASVS 人工结论和复核备注，可作为下一版本的基线。

## 目录

```text
src/                         Vue 前端、领域类型和 Tauri 调用边界
src-tauri/src/advanced/      AI、规则、数据边界、Frida、评估与快照模块
src-tauri/rules/             可热加载的敏感信息、框架和保护规则
frida-scripts/               内置/可选 Frida 观察与 Dump 脚本
docs/                        使用与分析说明
```

## 使用范围

本工具用于团队自有或已获授权的移动应用、设备和测试环境。静态特征、框架符号或保护文件名不能单独证明漏洞，最终结论应保留可复现步骤和运行时证据。

## 贡献

Android/IOS-Runtime获取参考hooker项目，感谢

## 免责声明

使用者需对自身行为合规性负责，作者不对任何滥用行为承担责任。
