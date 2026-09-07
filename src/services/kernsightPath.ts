export type PathPriority = 'focus' | 'watch' | 'background' | 'gap'

export interface AnalysisHop {
  key: string
  layer: 'L0' | 'L1' | 'L2' | 'GAP'
  title: string
  detail: string
  strength: 'confirmed' | 'correlated' | 'inferred' | 'absent'
  priority: PathPriority
  badge: string
  items: string[]
}

export type FlowVerb = '获取' | '推出' | '落地' | '缺口'

export interface AnalysisFlowStep {
  n: number
  verb: FlowVerb
  layer: 'L0' | 'L1' | 'L2' | 'GAP'
  title: string
  from: string
  got: string
  land: string[]
  next: string
  strength: AnalysisHop['strength']
  priority: PathPriority
}

const AOSP_BINDER = /^(android\.os\.|android\.app\.|android\.view\.|android\.gui\.|android\.hardware\.|IActivity|IApplication|IWindow|ISurface|IAllocator|IContentProvider|IPackageManager|IActivityManager|IActivityClient|IActivityTask)/i
const STUB_DEX = /(^|\/)(apk-dex\/|apk\/|classes\.dex$|RiskStub)/i
const BUSINESS_DEX = /(readable-dex\/|runtime\/mem-|blob-dex\/|heap-blob|memory-dex)/i
const RUNTIME_SO = /(runtime\/runtime-so\/|^runtime-so)/i
const INSTALL_SO = /(^lib\/|^oat\/)/i
const NOISY_PREF = /(umeng|firebase|crashlytics|google_app|webview|perfmark|device_id\.xml$)/i

export function classifyDex(path: string, source = '') {
  const haystack = `${source} ${path}`
  if (BUSINESS_DEX.test(haystack) || source === 'heap-blob' || source === 'memory-dex') return 'focus' as const
  if (STUB_DEX.test(path) || source.includes('apk')) return 'background' as const
  return 'watch' as const
}

export function classifySo(path: string, source = '') {
  if (RUNTIME_SO.test(path) || source === 'runtime-so') return 'focus' as const
  if (INSTALL_SO.test(path)) return 'background' as const
  if (/apk-assets|libexec|jiagu|secneo|bangcle/.test(path)) return 'watch' as const
  return 'watch' as const
}

export function classifyPrivate(path: string, contentClass = '') {
  if (contentClass === 'plaintext_candidate' || /runtime\/plaintext\//.test(path)) return 'focus' as const
  if (/\.db(?:-wal|-shm|-journal)?$/i.test(path)) return 'focus' as const
  if (/data-private\/.+\/(shared_prefs|files|no_backup)\//.test(path) && !NOISY_PREF.test(path)) return 'focus' as const
  if (/data-private\//.test(path)) return 'watch' as const
  return 'background' as const
}

export function priorityLabel(priority: PathPriority) {
  return ({
    focus: '重点关注',
    watch: '可复核',
    background: '背景',
    gap: '缺口',
  })[priority]
}

function unique(values: Array<string | null | undefined>) {
  return [...new Set(values.map(value => String(value || '').trim()).filter(Boolean))]
}

export function buildAnalysisPath(input: {
  processes: any[]
  networkBackbone: Array<{ name: string; endpoint: string; protocol: string; strength: string; detail: string }>
  handshake: any[]
  plaintext: any[]
  httpPlaintext: any[]
  httpCalls: any[]
  httpCodeRefs: any[]
  jniExports: any[]
  kernelTokens: string[]
  binderSemantic: any[]
  dump?: {
    package: string
    profile: string
    dex: number
    heapDex: number
    so: number
    privateFiles: number
    plaintextWindows: number
    artifacts: any[]
    frameworks: any[]
  } | null
  privateFiles: Array<{ path: string; contentClass?: string }>
  gaps: string[]
}): AnalysisHop[] {
  const hops: AnalysisHop[] = []
  const packageName = input.processes.find(row => row.package)?.package || input.dump?.package || 'unresolved'
  hops.push({
    key: 'identity',
    layer: 'L0',
    title: packageName,
    detail: `${input.processes.length} 个进程实例。身份键是 boot_id:pid:start_time_ns，不能只按 PID 合并。`,
    strength: input.processes.length ? 'confirmed' : 'absent',
    priority: input.processes.length ? 'watch' : 'gap',
    badge: input.processes.length ? '进程身份' : '无进程',
    items: input.processes.slice(0, 6).map(row => `${row.label || row.package || 'proc'} · PID ${(row.process_ids || []).join(', ')}`),
  })

  const sockets = input.networkBackbone.filter(row => row.strength !== 'inferred' || !String(row.endpoint).startsWith('/'))
  const named = sockets.filter(row => row.strength === 'confirmed' || row.strength === 'correlated')
  hops.push({
    key: 'network',
    layer: 'L0',
    title: named.length ? named.map(row => row.name).slice(0, 3).join(' · ') : (sockets.length ? '只有 socket，没有 SNI/DNS' : '没有网络主干'),
    detail: named.length
      ? named.map(row => `${row.name} → ${row.endpoint} (${row.protocol}${row.detail ? ` · ${row.detail}` : ''})`).join('；')
      : 'Handshake 只在 connect 后首写出现。复用连接或空 sockaddr 时可以为 0，不能写成没有 TLS。',
    strength: named.some(row => row.strength === 'confirmed') ? 'confirmed' : (named.length ? 'correlated' : (sockets.length ? 'inferred' : 'absent')),
    priority: named.length ? 'focus' : (sockets.length ? 'watch' : 'gap'),
    badge: named.length ? 'DNS / SNI → socket' : '网络缺口',
    items: named.slice(0, 8).map(row => `${row.name} → ${row.endpoint}`),
  })

  const jniExportsEarly = asArray(input.jniExports)
  const exportedJni = jniExportsEarly.filter(row => asArray(row.names).length)
  const jniPlain = input.plaintext.filter(row => String(row.adapter || '').startsWith('jni_'))
  const tlsPlain = input.plaintext.filter(row => !String(row.adapter || '').startsWith('jni_'))
  hops.push({
    key: 'tls',
    layer: 'L1',
    title: input.httpPlaintext.length ? `${input.httpPlaintext.length} 组 HTTP 类明文` : (tlsPlain.length ? '只有 tls_record，不是 HTTP 明文' : '没有 L1 TLS 明文'),
    detail: input.httpPlaintext.length
      ? 'Inspect SSL_read/write 或 JNIEnv UTF-8 preview。这是进程缓冲区明文，不是 MITM。'
      : (tlsPlain.length ? 'content_class=tls_record 是密文/告警，不能标成请求体。' : '需要单包 --inspect-tls 且 ELF64 导出符号；AArch32 ENOTSUP 不表示 App 没有明文。'),
    strength: input.httpPlaintext.length ? 'confirmed' : (tlsPlain.length ? 'inferred' : 'absent'),
    priority: input.httpPlaintext.length ? 'focus' : 'gap',
    badge: input.httpPlaintext.length ? 'TLS 明文' : '无 HTTP 明文',
    items: input.httpPlaintext.slice(0, 4).map(row => `${row.adapter || 'tls'} ${row.direction || ''} ${row.content_class || ''}`.trim()),
  })
  hops.push({
    key: 'jni',
    layer: 'L1',
    title: jniPlain.length ? `${jniPlain.length} 组 JNIEnv 明文` : (exportedJni.length ? '只有 dump Java_* 导出，没有 JNI Inspect 命中' : '没有 JNIEnv 明文'),
    detail: jniPlain.length
      ? 'GetStringUTFChars / NewStringUTF / byte[] 来自 libart JNINativeInterface（GetFunctionTable + jni.h 槽）。不是 ART 对象字段，也不是 Java 调用栈。'
      : '需要 --inspect-jni。加固包通常没有 Java_*；明文仍可能过 JNIEnv。',
    strength: jniPlain.length ? 'confirmed' : (exportedJni.length ? 'correlated' : 'absent'),
    priority: jniPlain.length ? 'focus' : 'gap',
    badge: jniPlain.length ? 'JNI 明文' : 'JNI 缺口',
    items: jniPlain.slice(0, 6).map(row => `${row.adapter || 'jni'} ${row.direction || ''} ${(row.preview || '').slice(0, 80)}`.trim()),
  })

  const apiCalls = asArray(input.httpCalls)
  const codeRefs = asArray(input.httpCodeRefs)
  const apiItems = apiCalls.slice(0, 8).map(row => {
    const host = row.host || '-'
    const path = row.path || (row.status ? `HTTP ${row.status}` : '')
    const origin = row.origin === 'heap' ? '堆' : 'Inspect'
    const ref = codeRefs.find(item => item.path === row.path || item.host === row.host)
    const where = ref ? ` ← ${(ref.matches || [])[0] || ref.relative_path || 'DEX'}` : ''
    return `${origin} ${row.method || ''} ${host}${path}${where}`.trim()
  })
  hops.push({
    key: 'http_api',
    layer: 'L1',
    title: apiCalls.length ? `${apiCalls.length} 条 HTTP API` : '没有解析出 HTTP 目录',
    detail: apiCalls.length
      ? `Inspect/堆 HTTP/1。${codeRefs.length} 条路径在 DEX 字符串或 class->method 里出现（correlated，不是 JNI 调用栈）。导出 Java_* ${exportedJni.length} 个 SO；空 names 表示 SO 被剥符号。JNI 明文走 --inspect-jni 的 JNIEnv 表，不是 Java_*。`
      : '需要 HTTP/1 或 JSON preview；堆窗口要对齐到 HTTP/1.1。HTTP/2 前言之后不解。',
    strength: apiCalls.some(row => row.origin !== 'heap') ? 'confirmed' : (apiCalls.length ? 'correlated' : 'absent'),
    priority: apiCalls.length ? 'focus' : 'gap',
    badge: codeRefs.length ? `HTTP 目录 · DEX ${codeRefs.length}` : (apiCalls.length ? 'HTTP 目录' : '无 API 目录'),
    items: apiItems,
  })

  const appTokens = input.kernelTokens.filter(name => !AOSP_BINDER.test(name))
  const tokens = appTokens.length ? appTokens : input.kernelTokens
  hops.push({
    key: 'binder',
    layer: 'L0',
    title: tokens.length ? tokens.slice(0, 4).join(' · ') : (input.binderSemantic.length ? '仅 L1 Parcel，内核 token 空' : '没有 Binder token'),
    detail: input.kernelTokens.length
      ? `内核 token ${input.kernelTokens.length} 个；AOSP 系统接口已降为背景。用户态 IComponent 不会回填到内核证据。`
      : (input.binderSemantic.length ? '不要用 L1 IComponent 名称冒充 L0 token。' : '本会话没有可展示的 Binder 接口。'),
    strength: input.kernelTokens.length ? 'confirmed' : (input.binderSemantic.length ? 'correlated' : 'absent'),
    priority: appTokens.length ? 'focus' : (input.kernelTokens.length ? 'background' : 'gap'),
    badge: appTokens.length ? '应用 Binder' : (input.kernelTokens.length ? '系统 Binder' : 'Binder 缺口'),
    items: tokens.slice(0, 8),
  })

  const dex = unique(asArray(input.dump?.artifacts).filter(item => item.kind === 'dex').map(item => String(item.relative_path || '')))
  const focusDex = dex.filter(path => classifyDex(path) === 'focus')
  const stubDex = dex.filter(path => classifyDex(path) === 'background')
  hops.push({
    key: 'dex',
    layer: 'L2',
    title: focusDex.length ? `${focusDex.length} 个可读/堆 DEX` : (stubDex.length ? '只有安装包 stub DEX' : (input.dump ? 'dump 里没有 DEX 清单' : '还没有接入 dump')),
    detail: focusDex.length
      ? `优先 JADX 这些副本。安装包 ${stubDex.length} 个 DEX 多半是壳 stub。DEX↔mmap 只是 correlated。`
      : '安装包 classes.dex 在壳场景通常不是业务码。',
    strength: focusDex.length ? 'inferred' : 'absent',
    priority: focusDex.length ? 'focus' : (input.dump ? 'watch' : 'gap'),
    badge: focusDex.length ? '业务 DEX' : 'DEX 缺口',
    items: (focusDex.length ? focusDex : stubDex).slice(0, 8),
  })

  const so = unique(asArray(input.dump?.artifacts).filter(item => item.kind === 'elf').map(item => String(item.relative_path || '')))
  const runtimeSo = so.filter(path => classifySo(path) === 'focus')
  hops.push({
    key: 'so',
    layer: 'L2',
    title: runtimeSo.length ? `${runtimeSo.length} 个已加载 runtime SO` : (so.length ? '只有安装态 SO' : '没有 SO 清单'),
    detail: runtimeSo.length
      ? `进程已映射的 SO，优先于 apk lib/。规则命中 ${asArray(input.dump?.frameworks).map((item: any) => item.name).join(' / ') || '无'} 只是候选。`
      : '安装目录 SO 不代表本次 session 执行了它。',
    strength: runtimeSo.length ? 'inferred' : 'absent',
    priority: runtimeSo.length ? 'focus' : 'watch',
    badge: runtimeSo.length ? 'runtime SO' : 'SO',
    items: (runtimeSo.length ? runtimeSo : so).slice(0, 8),
  })

  const privateFocus = input.privateFiles.filter(file => classifyPrivate(file.path, file.contentClass) === 'focus')
  hops.push({
    key: 'private',
    layer: 'L2',
    title: privateFocus.length ? `${privateFocus.length} 个 CE/DE 重点文件` : (input.dump?.privateFiles ? `${input.dump.privateFiles} 个有界私有文件` : '没有 CE/DE 清单'),
    detail: privateFocus.length
      ? 'at-rest 副本：库、prefs、明文候选。没有同会话 host/路径证据时，不连接到上面的 socket。'
      : 'dump 只拷 shared_prefs/databases/files/no_backup，不是完整 /data/data。',
    strength: 'inferred',
    priority: privateFocus.length || input.dump?.plaintextWindows ? 'focus' : (input.dump?.privateFiles ? 'watch' : 'gap'),
    badge: input.dump?.plaintextWindows ? `CE/DE · 堆明文 ${input.dump.plaintextWindows}` : 'CE/DE',
    items: privateFocus.slice(0, 10).map(file => file.path),
  })

  if (input.gaps.length) {
    hops.push({
      key: 'gaps',
      layer: 'GAP',
      title: `${input.gaps.length} 个本会话缺口`,
      detail: '缺口必须留在链上。不能用时间邻近或 AI 补成 confirmed。',
      strength: 'absent',
      priority: 'gap',
      badge: '诚实缺口',
      items: input.gaps.slice(0, 8),
    })
  }
  return hops
}

export function buildAnalysisFlow(input: Parameters<typeof buildAnalysisPath>[0]): AnalysisFlowStep[] {
  const hops = buildAnalysisPath(input)
  const byKey = Object.fromEntries(hops.map(hop => [hop.key, hop]))
  const identity = byKey.identity
  const network = byKey.network
  const tls = byKey.tls
  const binder = byKey.binder
  const dex = byKey.dex
  const so = byKey.so
  const priv = byKey.private
  const gaps = byKey.gaps
  const named = input.networkBackbone.filter(row => row.strength === 'confirmed' || row.strength === 'correlated')
  const dnsNames = unique(input.handshake.map(row => row.sni || row.http_host).concat(named.map(row => row.name)))
  const steps: Array<Omit<AnalysisFlowStep, 'n'>> = []

  steps.push({
    verb: identity?.priority === 'gap' ? '缺口' : '获取',
    layer: 'L0',
    title: '进程实例',
    from: 'session 里的 fork/exec/rename 与包名候选',
    got: identity?.items[0] || '没有聚合到进程',
    land: [],
    next: '用这个进程去对齐 DNS、connect、Binder 和 dump PID',
    strength: identity?.strength || 'absent',
    priority: identity?.priority || 'gap',
  })

  const hasDns = named.length > 0
  steps.push({
    verb: hasDns ? '推出' : '缺口',
    layer: 'L0',
    title: 'DNS 回答',
    from: identity?.items[0] || '进程身份',
    got: hasDns ? dnsNames.slice(0, 4).join(' · ') : '没有 QNAME / resolved_name',
    land: [],
    next: hasDns ? '用 A/AAAA 对齐后面的 connect 对端' : '没有名字就不能把 IP 说成某个业务域名',
    strength: network?.strength || 'absent',
    priority: hasDns ? 'focus' : 'gap',
  })

  steps.push({
    verb: named.some(row => row.strength === 'confirmed') ? '落地' : (hasDns ? '推出' : '缺口'),
    layer: 'L0',
    title: 'Handshake → socket',
    from: hasDns ? `DNS ${dnsNames[0] || ''}` : '只有 socket 生命周期',
    got: named.length
      ? named.slice(0, 4).map(row => `${row.name} → ${row.endpoint}${row.detail ? ` · ${row.detail}` : ''}`).join('；')
      : 'connect 后没有看到 ClientHello / HTTP Host 首写',
    land: [],
    next: named.length ? '若 ELF64 挂了 Inspect，下一跳看这个对端上的 TLS 明文' : '复用连接或空 sockaddr 时 Handshake 可以为 0，不能写成没有 TLS',
    strength: network?.strength || 'absent',
    priority: named.length ? 'focus' : 'gap',
  })

  steps.push({
    verb: tls?.priority === 'focus' ? '获取' : '缺口',
    layer: 'L1',
    title: 'TLS 明文',
    from: named[0] ? `${named[0].name} → ${named[0].endpoint}` : '上一跳的 socket',
    got: tls?.title || '没有 HTTP 类明文',
    land: [],
    next: tls?.priority === 'focus' ? '明文 preview 只证明进程缓冲区内容，不自动等于某条 CE/DE 文件外发' : '32 位 ENOTSUP 或未导出 SSL_write 时改看 dump 堆窗口，仍不能连到 socket',
    strength: tls?.strength || 'absent',
    priority: tls?.priority || 'gap',
  })

  const httpApi = byKey.http_api
  steps.push({
    verb: httpApi?.priority === 'focus' ? '推出' : '缺口',
    layer: 'L1',
    title: 'HTTP API 目录',
    from: 'Inspect TLS 明文或 dump runtime/plaintext 堆窗口',
    got: httpApi?.items.slice(0, 4).join(' · ') || httpApi?.title || '没有解析出 method/host/path',
    land: [],
    next: httpApi?.priority === 'focus' ? '带 ← class->method 的是 DEX 字符串重合（correlated），不是 ART/JNI 调用栈。导出 Java_* 为空时只能 JADX 这些 DEX。' : 'HTTP/2 或无 SSL_write 时目录为空，不能写成没有业务流量',
    strength: httpApi?.strength || 'absent',
    priority: httpApi?.priority || 'gap',
  })

  steps.push({
    verb: binder?.priority === 'gap' ? '缺口' : '获取',
    layer: 'L0',
    title: 'Binder token',
    from: identity?.items[0] || '同一进程实例',
    got: binder?.items.slice(0, 6).join(' · ') || binder?.title || '没有 token',
    land: [],
    next: '内核 token 与用户态 Parcel 分开展示；空 token 不回填 IComponent',
    strength: binder?.strength || 'absent',
    priority: binder?.priority || 'gap',
  })

  const dexFiles = (dex?.items || []).slice(0, 8)
  steps.push({
    verb: dexFiles.length ? '落地' : '缺口',
    layer: 'L2',
    title: '可读 / 堆 DEX',
    from: 'pull-package --launch 的进程内存与 readable-dex',
    got: dex?.title || '没有 DEX',
    land: dexFiles,
    next: dexFiles.length ? '优先 JADX 这些文件；安装包 classes.dex 多半是 stub' : '先导入或拉取该包 dump',
    strength: dex?.strength || 'absent',
    priority: dex?.priority || 'gap',
  })

  const soFiles = (so?.items || []).slice(0, 8)
  steps.push({
    verb: soFiles.length ? '落地' : '缺口',
    layer: 'L2',
    title: 'runtime SO',
    from: '同一 dump 里已映射的 .so',
    got: so?.title || '没有 SO',
    land: soFiles,
    next: soFiles.length ? '壳/加密规则只是文件名候选，不证明算法已执行' : '只有 apk lib/ 时不要当成这次 session 执行了它',
    strength: so?.strength || 'absent',
    priority: so?.priority || 'watch',
  })

  const privateFiles = (priv?.items || []).slice(0, 10)
  steps.push({
    verb: privateFiles.length ? '落地' : '缺口',
    layer: 'L2',
    title: 'CE / DE 私有文件',
    from: 'dump 时的 at-rest 四类目录',
    got: priv?.title || '没有 CE/DE',
    land: privateFiles,
    next: privateFiles.length ? '文件名可对照上面的 SNI/Host，但不能单独证明发到了那条 socket' : '没有私有文件清单时只能停在 session 层',
    strength: 'inferred',
    priority: priv?.priority || 'gap',
  })

  if (gaps) {
    steps.push({
      verb: '缺口',
      layer: 'GAP',
      title: '链上断开的地方',
      from: '上面各跳的空结果',
      got: gaps.items.slice(0, 6).join('；') || gaps.title,
      land: [],
      next: '不要用时间邻近或 AI 把这些补成 confirmed',
      strength: 'absent',
      priority: 'gap',
    })
  }

  return steps.map((step, index) => ({ ...step, n: index + 1 }))
}

function asArray(value: unknown): any[] {
  return Array.isArray(value) ? value : []
}
