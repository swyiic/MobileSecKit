# App Analyzer 使用说明

## 分析顺序

1. 把 APK/IPA 拖到 App Analyzer，或选择本机绝对路径。
2. 先看平台、包名/Bundle ID、版本、签名和架构；`frameworks` 会根据包内特征给出 Flutter、React Native、Unity、Cordova/WebView、Xamarin/.NET 或 Native 线索。
3. Android 的 `AndroidManifest.xml` 会优先尝试本机 AXMLPrinter/AXML decoder；即使没有外部工具，内置 Rust AXML 回退也会生成可读 XML，并从中提取权限和组件。
4. 查看 Sensitive information / location 表。它只显示类别和路径，不回显匹配到的值。

## 线索分类

- 网络：HTTP/HTTPS/WS URL、IPv4 地址、疑似接口路径。
- 凭据：API key、Access/Secret key、Client secret、Bearer、Password、AES key、Private key。
- 个人信息：手机号格式、身份证号格式。
- 文件与存储：SharedPreferences、数据库/SQLite/Realm、WebView/IndexedDB/Cookies、Keychain/Keystore、证书和 provisioning profile。

这些是静态线索，不代表已经确认泄漏；应回到源码、运行时日志和测试数据中复核。

## Frida 入门流程

Android 选择 `device` 后，先让主机 Frida CLI 与设备端 frida-server 版本一致，再按 ABI 推送并启动。刷新进程，选择 Attach（已运行）或 Spawn（冷启动），先执行内置只读脚本，观察 PID、架构、模块和网络表面。

iOS 选择 Frida 设备后不走 ADB。若进程枚举提示 Developer Disk Image，选择本机镜像目录并挂载，再刷新。若工具版本或设备通道仍不兼容，把外部脚本放到“外部脚本路径”中运行并保留日志。

## 参考项目的提炼

- Android-GetAPKInfo / AXMLPrinter：包名、版本、签名摘要和二进制 XML 解码。
- ApkAnalyser：资源、组件、权限和架构的静态索引思路。
- APKLeaks：URL、端点和自定义正则规则；本项目采用本地、只报类别/路径的规则扫描。
- frida-ios-dump-ng：iOS 运行时提取的设备、Frida、输出目录和元数据工作流；本项目保留外部脚本/终端入口，生成的 IPA 再交给 App Analyzer 做静态分析。
