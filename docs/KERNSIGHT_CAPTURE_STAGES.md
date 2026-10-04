# KernSight 分阶段采集

本次修改提供两种明确的阶段生命周期；默认继续保留启动重采。仅发布主机验证过的前端/后端逻辑，尚未进行本阶段的真机验收。

## 模式与默认值

| Me 选项 | 行为 | 实例与快照 |
| --- | --- | --- |
| `startup_replay`（默认） | L0 冷启动 → L1 冷启动 → 包快照 → Linker 冷启动 | 三个独立 session；快照属于 L1 实例，Linker 随后重启 |
| `unified`（显式选择） | 一次冷启动、一个 ksightd capture；L0 → L1 → Linker 顺序窗口；成功后快照 | L0 传感器全程保留；阶段切换不重启；要求同一 PID 与 kernel start_ticks |

默认窗口为 15/90/15 秒；每段 1–300 秒。统一模式允许总和最多 900 秒，旧单窗口仍限制为 1–300 秒。L1 固定 TLS+JNI+Binder userspace；Linker 只在独立窗口运行。统一模式不会重演后续能力各自的启动调用，也不会补回已经卸载的代码。

## 兼容与命令

新设备参数为 `--inspect-stages l0:15,l1:90,linker:15`，总时长必须等于阶段总和。新 IPC 为 `start_kernsight_staged_capture`，请求带可选 `inspectStages`。不带该字段的旧请求继续走 `start_kernsight_capture`，不自动迁移策略。

统一模式不能与旧 Inspect flags/named adapter、mirror/MITM 或单模式 ELF/offset/build-id/time 参数混用。CLI 还要求 package/PID、spool，拒绝 UID-only、whole-device 和非零 count。Me 保留包范围选择与原传感器/采样上限。

新后端在任何 cold-start wrapper 之前读取设备上 `ksightd capture --help`，确认存在阶段参数；旧 agent 会明确报错，不自动降级或扩大采集范围。桌面前端与 Rust 后端必须一起更新。Rust 依赖仍固定 KernSight v0.2.10；它不证明设备上的 agent 支持新增 CLI，也不会自动升级设备或部署探针。

## 完成与失败证据

agent 回传 `kernsight.capture-stage/v1`。Me 校验每阶段恰有开始与结束、同一 session、计划时长相符、全部为 window_elapsed，且 PID 与非零 process_start_ticks 字符串相同。退出失败、缺失/重复标记、not_started、实例变化均停止后续快照，并保留已返回的日志/阶段回执。

`coverage=not_attested`：命令成功与窗口结束都不代表业务全覆盖。界面运行进度是计划时间估计，真实阶段状态以返回记录为准。最终快照使用 requireLive，不能确认目标仍在运行就拒绝，不自动重启；这项检查仍不是完整的快照实例代际证明。

统一会话只有原会话结束辅助补采和最后显式包快照，启动重采有各独立会话的辅助补采。探针关闭时未读 perf 尾部不能宣称已经 drain。

## 主机验证与设备待验项

运行 `npm run test:kernsight-plan`、`npm run build`、`cargo test --manifest-path src-tauri/Cargo.toml --lib --locked` 与 Rust fmt。计划测试通过现有 TypeScript 编译器在内存中加载生产模块，可在 Node 20+ 执行，不要求 experimental strip-types，不新增依赖；CI 同样运行计划测试。

本阶段主机计划测试 13 项通过，Rust 报告 142 项通过，其中 1 项未配置设备时提前返回，不能计作设备验收；前端构建与格式检查通过。设备上的新版 agent、探针附加/释放、阶段边界耗时、取消、进程退出、预算结束和实际业务捕获均仍待受控验收。
