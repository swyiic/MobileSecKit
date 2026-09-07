import type {
  RuntimeEvidenceStepKey,
  RuntimeEvidenceStepStatus,
  TerminalEntry,
} from '@/types'

const DEFINITIONS: Record<'android' | 'ios', Array<Omit<RuntimeEvidenceStepStatus, 'status'>>> = {
  android: [
    { key: 'injection', label: '注入基线', description: '确认 frida-agent 与用户脚本能进入目标进程。' },
    { key: 'language-runtime', label: 'Java / ART', description: '采集 Java VM、ClassLoader 与已加载类运行时快照。' },
    { key: 'network-tls', label: 'Network / TLS', description: '观察网络请求、TLS 初始化与信任相关调用。' },
    { key: 'webview-bridge', label: 'WebView / JSBridge', description: '观察 URL 加载、脚本执行和 JavaScript Interface 注册。' },
    { key: 'storage-crypto', label: 'Storage / Crypto', description: '观察 SharedPreferences、KeyStore 与 Cipher API 使用。' },
    { key: 'root-environment', label: 'Root 环境', description: '记录 Root 路径和运行环境线索，不隐藏或修改结果。' },
    { key: 'dex-artifact', label: 'DEX 运行时产物', description: '回收、校验、修复并去重运行时 DEX。' },
    { key: 'so-artifact', label: 'SO 运行时产物', description: '回收 SO 内存分段、重建 ELF 并扫描敏感线索。' },
  ],
  ios: [
    { key: 'injection', label: '注入基线', description: '确认 frida-agent 与用户脚本能进入目标进程。' },
    { key: 'language-runtime', label: 'ObjC Runtime', description: '采集 App 自有类、Selector、IMP 与模块偏移。' },
    { key: 'network-tls', label: 'Network / TLS / Keychain', description: '观察 URLSession、TLS Challenge、Security 与 Keychain 调用。' },
    { key: 'webview-bridge', label: 'WebView / JSBridge', description: '观察 WKWebView、Handler、导航与 JavaScript 调用。' },
    { key: 'app-artifact', label: 'Mach-O / IPA 产物', description: '运行时解密主程序并生成可重新静态分析的 IPA。' },
    { key: 'protection', label: '保护 / 终止观察', description: '记录异常、终止调用栈及保护框架运行线索。' },
  ],
}

const OUTPUT_MARKERS: Record<RuntimeEvidenceStepKey, RegExp> = {
  injection: /ME_ANTI_INSTRUMENTATION_RESULT:|ME_IOS_INJECTION_OK/i,
  'language-runtime': /ME_ANDROID_JAVA_RUNTIME:|ME_CLASSLOADER_RESULT:|objc-runtime-(?:ready|summary|methods)/i,
  'network-tls': /ME_ANDROID_NETWORK_RUNTIME:|ios-runtime-network-ready|loaded-network-modules|urlsession-(?:request|resume)|tls-challenge|security-api-call|keychain-call/i,
  'webview-bridge': /ME_ANDROID_WEBVIEW_RUNTIME:|jsbridge-(?:observer-ready|existing-delegate-snapshot|handler-registered|message-received|navigation|javascript-evaluation|risk-candidate)/i,
  'storage-crypto': /ME_ANDROID_STORAGE_CRYPTO_RUNTIME:/i,
  'root-environment': /ME_ANDROID_ROOT_INDICATORS:/i,
  'dex-artifact': /ME_DEX_ARTIFACT_READY|Multidex 集合|Multidex 合集/i,
  'so-artifact': /ME_SO_ARTIFACT_READY|重建报告：.*reconstruction-report\.json/i,
  'app-artifact': /ME_IOS_ARTIFACT_READY|输出 IPA：/i,
  protection: /ME_IOS_TERMINATION_(?:CALL|TRACE_READY)|ME_IOS_FATAL_EXCEPTION|jmprotection|deniedfishhook/i,
}

const FAILURE_RE = /failed to|失败|被拒绝|blocked|refused|timeout|timed out|early end-of-stream|terminated during injection|unable to attach/i

export function runtimeOutputCompletesStep(key: RuntimeEvidenceStepKey, output: string) {
  return OUTPUT_MARKERS[key].test(output)
}

export function runtimeStepForScript(path?: string): RuntimeEvidenceStepKey | undefined {
  const name = path?.split(/[\\/]/).pop()?.toLowerCase() || ''
  if (/anti_instrumentation_probe|ios_injection_probe/.test(name)) return 'injection'
  if (/inspect_java_runtime|inspect_classloader|inspect_objc_runtime/.test(name)) return 'language-runtime'
  if (/observe_android_network_runtime|observe_ios_network_runtime|inspect_network_surface/.test(name)) return 'network-tls'
  if (/observe_android_webview_runtime|observe_ios_jsbridge/.test(name)) return 'webview-bridge'
  if (/observe_android_storage_crypto_runtime/.test(name)) return 'storage-crypto'
  if (/inspect_root_indicators/.test(name)) return 'root-environment'
  if (/ios_termination_trace|observe_jmprotection/.test(name)) return 'protection'
  return undefined
}

function inferredStep(entry: TerminalEntry): RuntimeEvidenceStepKey | undefined {
  if (entry.runtimeStep) return entry.runtimeStep
  const value = `${entry.command}\n${entry.output}`
  return (Object.entries(OUTPUT_MARKERS) as Array<[RuntimeEvidenceStepKey, RegExp]>)
    .find(([, marker]) => marker.test(value))?.[0]
}

export function runtimeEvidenceCoverage(
  history: TerminalEntry[],
  platform: 'android' | 'ios',
  appId?: string,
): RuntimeEvidenceStepStatus[] {
  const normalizedApp = appId?.trim().toLowerCase()
  const scoped = history
    .filter((entry) => !normalizedApp || entry.appId?.trim().toLowerCase() === normalizedApp)
    .filter((entry) => !entry.platform || entry.platform === 'unknown' || entry.platform === platform)
    .sort((left, right) => right.time - left.time)

  return DEFINITIONS[platform].map((definition) => {
    const latest = scoped.find((entry) => inferredStep(entry) === definition.key)
    if (!latest) return { ...definition, status: 'idle' }
    const markerPresent = runtimeOutputCompletesStep(definition.key, `${latest.command}\n${latest.output}`)
    const complete = latest.success && markerPresent
    return {
      ...definition,
      status: complete ? 'complete' : 'blocked',
      lastRunAt: latest.time,
      detail: complete
        ? '已获取可识别的运行时证据。'
        : latest.output.split(/\r?\n/).find((line) => FAILURE_RE.test(line))?.trim().slice(0, 240)
          || '步骤未产生约定的完成标记，已按被拦截或未完成处理。',
    }
  })
}
