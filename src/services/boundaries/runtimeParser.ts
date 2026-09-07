import type { DataBoundaryObservation, TerminalEntry } from '@/types'

const URL_RE = /\b(?:https?|wss?):\/\/[^\s"'<>\])}]+/gi
const MARKERS: Array<{ boundary: string; direction: string; title: string; needles: string[]; dataTypes: string[]; severity: string; platforms?: Array<'android' | 'ios'> }> = [
  { boundary: 'runtime-code', direction: 'internal', title: 'Android Java / ART 运行时结构', needles: ['me_android_java_runtime:'], dataTypes: ['class', 'class loader', 'runtime code'], severity: 'info', platforms: ['android'] },
  { boundary: 'network', direction: 'egress', title: 'Android 网络 / TLS 运行时观察', needles: ['me_android_network_runtime:'], dataTypes: ['request metadata', 'TLS configuration'], severity: 'review', platforms: ['android'] },
  { boundary: 'webview', direction: 'bidirectional', title: 'Android WebView / JSBridge 运行时观察', needles: ['me_android_webview_runtime:'], dataTypes: ['URL', 'JavaScript Interface'], severity: 'review', platforms: ['android'] },
  { boundary: 'storage', direction: 'internal', title: 'Android 存储 / 密码学运行时观察', needles: ['me_android_storage_crypto_runtime:'], dataTypes: ['storage key name', 'cryptography metadata'], severity: 'review', platforms: ['android'] },
  { boundary: 'runtime-integrity', direction: 'internal', title: 'Android Root 环境观察', needles: ['me_android_root_indicators:'], dataTypes: ['root environment indicator'], severity: 'review', platforms: ['android'] },
  { boundary: 'tls', direction: 'egress', title: '运行时 TLS / 信任决策', needles: ['sectrust', 'certificatepinner', 'pinning', 'trustmanager', 'hostnameverifier', 'ssl', 'tls'], dataTypes: ['certificate', 'request / response'], severity: 'review' },
  { boundary: 'webview', direction: 'bidirectional', title: '运行时 WebView / JS 桥接', needles: ['webview', 'wkwebview', 'javascriptinterface', 'methodchannel', 'rctbridge', 'cordova', 'capacitor'], dataTypes: ['JavaScript message'], severity: 'review' },
  { boundary: 'storage', direction: 'internal', title: '运行时本地存储', needles: ['keychain', 'sharedpreferences', 'userdefaults', 'sqlite', 'realm', 'core data', 'mmkv', 'datastore'], dataTypes: ['database record', 'credential'], severity: 'review' },
  { boundary: 'crypto', direction: 'internal', title: '运行时密码学处理', needles: ['commoncrypto', 'cccrypt', 'cipher', 'keystore', 'secure enclave', 'encrypt', 'decrypt', 'aes', 'rsa'], dataTypes: ['key', 'application data'], severity: 'review' },
  { boundary: 'identity', direction: 'internal', title: '运行时身份 / 会话材料', needles: ['authorization', 'bearer ', 'cookie:', 'set-cookie', 'access_token', 'refresh_token', 'sessionid', 'credential', 'login'], dataTypes: ['token', 'cookie', 'credential'], severity: 'review' },
  { boundary: 'dynamic-code', direction: 'internal', title: '运行时动态代码 / 模块加载', needles: ['dexclassloader', 'inmemorydexclassloader', 'me_classloader_result', 'dexelements', 'dlopen', 'loadlibrary', 'system.load', 'dynamic dex', 'plugin'], dataTypes: ['code / module'], severity: 'review' },
  { boundary: 'runtime-code', direction: 'internal', title: 'iOS Objective-C 运行时结构', needles: ['objc-runtime-summary', 'objc-runtime-methods'], dataTypes: ['class', 'selector', 'implementation address'], severity: 'info', platforms: ['ios'] },
  { boundary: 'dynamic-code', direction: 'internal', title: 'Android DEX 运行时回收', needles: ['me_dex_ready', 'me_dex_dump', 'me_dex_scan', 'collect dex', 'repaired-classes'], dataTypes: ['dex', 'runtime code'], severity: 'review', platforms: ['android'] },
  { boundary: 'runtime-code', direction: 'internal', title: 'Android SO 运行时回收', needles: ['me_so_ready', 'me_so_dump', 'me_so_range', 'collect so', 'repaired-lib'], dataTypes: ['ELF module', 'native code'], severity: 'review', platforms: ['android'] },
  { boundary: 'anti-instrumentation', direction: 'internal', title: '运行时 Anti-Instrumentation 确认', needles: ['me_anti_instrumentation_result:', 'me_ios_injection_ok', 'refused to load frida-agent', 'terminated during injection'], dataTypes: ['process instrumentation state', 'code / module'], severity: 'review' },
  { boundary: 'runtime-integrity', direction: 'internal', title: '运行时完整性 / 保护事件', needles: ['anti-debug', 'jailbreak', 'root detection', 'ptrace', 'sysctl', 'deniedfishhook', 'process terminated'], dataTypes: ['process state', 'code / module'], severity: 'review' },
  { boundary: 'network', direction: 'egress', title: '运行时网络出口', needles: ['http', 'request', 'response', 'urlsession', 'afnetworking', 'okhttp', 'retrofit', 'alamofire', 'cfnetwork', 'libcurl', 'endpoint', 'baseurl'], dataTypes: ['request / response'], severity: 'info' },
]

function stableId(value: string) {
  let hash = 2166136261
  for (const char of value) {
    hash ^= char.charCodeAt(0)
    hash = Math.imul(hash, 16777619)
  }
  return `runtime-boundary-${(hash >>> 0).toString(16)}`
}

function cleanUrl(value: string) {
  return value.replace(/[.,;:!?]+$/, '').slice(0, 320)
}

function isLowSignalUrl(value: string) {
  const lower = value.toLowerCase()
  return value.includes('%@') || value.includes('%s') || value.includes('%d')
    || lower.includes('/runner/work/') || lower.includes('/deriveddata/')
    || ['developer.apple.com', 'developer.android.com', 'stackoverflow.com', 'github.com', 'npmjs.com', 'opencv.org'].some((host) => lower.includes(host))
    || /\.(?:png|jpe?g|gif|svg|css|js)(?:[?#]|$)/i.test(value)
}

function endpointFrom(line: string) {
  const match = line.match(URL_RE)?.[0]
  if (!match) return undefined
  const endpoint = cleanUrl(match)
  return isLowSignalUrl(endpoint) ? undefined : endpoint
}

function frameworkFrom(line: string) {
  const lower = line.toLowerCase()
  const rules: Array<[string, string[]]> = [
    ['AFNetworking', ['afnetworking', 'afhttp', 'afurlsession']],
    ['Alamofire', ['alamofire']],
    ['OkHttp', ['okhttp']],
    ['Retrofit', ['retrofit']],
    ['URLSession / CFNetwork', ['urlsession', 'nsurlsession', 'cfnetwork']],
    ['Flutter', ['flutter', 'methodchannel']],
    ['React Native', ['react native', 'rctbridge']],
    ['WebKit', ['wkwebview', 'webkit']],
  ]
  return rules.find(([, needles]) => needles.some((needle) => lower.includes(needle)))?.[0]
}

function operationFrom(line: string) {
  const match = line.match(/(?:operation|selector|method|request|hook|target)\s*[:=]\s*([^,;]+)/i)
  return match?.[1]?.trim().slice(0, 240)
}

function sourceLocation(entry: TerminalEntry, lineNumber: number) {
  return `${entry.command} · output line ${lineNumber}`
}

function normalizedAppId(value?: string) {
  return value?.trim().toLowerCase() || ''
}

function belongsToScope(entry: TerminalEntry, expectedAppId?: string, expectedDeviceId?: string) {
  const appId = normalizedAppId(expectedAppId)
  const deviceId = expectedDeviceId?.trim().toLowerCase() || ''
  if (!entry.persisted && deviceId && entry.deviceId && entry.deviceId.toLowerCase() !== deviceId) return false
  if (!appId) return true
  if (entry.appId) return normalizedAppId(entry.appId) === appId
  // Backward compatibility for history entries captured before scoped metadata
  // was introduced. Only accept them when the exact package/bundle identifier
  // is visible in the command; generic logs are intentionally excluded.
  return entry.command.toLowerCase().includes(appId)
}

export function parseRuntimeBoundaries(
  history: TerminalEntry[],
  platform: 'android' | 'ios' | 'unknown' = 'unknown',
  expectedAppId?: string,
  expectedDeviceId?: string,
): DataBoundaryObservation[] {
  const observations: DataBoundaryObservation[] = []
  for (const entry of history.filter((item) => belongsToScope(item, expectedAppId, expectedDeviceId))) {
    if (platform !== 'unknown' && entry.platform && entry.platform !== 'unknown' && entry.platform !== platform) continue
    const lines = entry.output.split(/\r?\n/)
    lines.forEach((line, index) => {
      const trimmed = line.trim()
      if (!trimmed) return
      const lower = trimmed.toLowerCase()
      const marker = MARKERS.find((candidate) => (!candidate.platforms || platform === 'unknown' || candidate.platforms.includes(platform)) && candidate.needles.some((needle) => lower.includes(needle)))
      const endpoint = endpointFrom(trimmed)
      const networkLine = Boolean(endpoint) || /\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/i.test(trimmed)
      const selected = marker || (networkLine ? MARKERS[MARKERS.length - 1] : undefined)
      if (!selected) return
      const keyTarget = endpoint || operationFrom(trimmed) || frameworkFrom(trimmed) || selected.title
      const correlationKey = `${selected.boundary}|${keyTarget.toLowerCase().replace(/\s+/g, ' ').trim()}`
      observations.push({
        id: stableId(`${entry.time}|${entry.command}|${index}|${trimmed}`),
        boundary: selected.boundary,
        direction: selected.direction,
        title: selected.title,
        summary: '运行日志中捕获到数据边界相关事件；这是动态观察结果，不代表完整调用链。',
        sourceType: 'runtime',
        sourceLocation: sourceLocation(entry, index + 1),
        platform: entry.platform || (entry.command.toLowerCase().includes('adb') ? 'android' : platform),
        framework: frameworkFrom(trimmed),
        dataTypes: [...selected.dataTypes],
        producer: selected.boundary === 'network' || selected.boundary === 'tls' ? 'application' : undefined,
        consumer: selected.boundary === 'network' ? 'remote service' : undefined,
        operation: operationFrom(trimmed),
        endpoint,
        runtimeTarget: operationFrom(trimmed),
        severity: selected.severity,
        confidence: 'runtime-observed',
        evidence: [trimmed],
        correlationKey,
        observedAt: entry.time,
      })
    })
  }
  const merged = new Map<string, DataBoundaryObservation>()
  for (const item of observations) {
    const existing = merged.get(item.correlationKey || item.id)
    if (!existing) {
      merged.set(item.correlationKey || item.id, item)
      continue
    }
    existing.evidence = [...new Set([...existing.evidence, ...item.evidence])].slice(0, 20)
    existing.dataTypes = [...new Set([...existing.dataTypes, ...item.dataTypes])]
    existing.sourceLocation = `${existing.sourceLocation}; ${item.sourceLocation}`
  }
  return [...merged.values()].sort((a, b) => (b.observedAt || 0) - (a.observedAt || 0))
}
