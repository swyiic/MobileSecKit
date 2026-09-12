<template>
  <div class="toolbox-layout">
    <div v-if="!androidAvailable" class="notice"><span class="material-symbols-outlined">info</span>当前设备不是 Android，ADB Toolbox 不可用；请切换到 Frida Toolbox。</div>
    <section class="tool-workspace-header panel">
      <div class="tool-workspace-copy">
        <div class="eyebrow">DEVICE OPERATIONS</div>
        <h2>设备操作</h2>
        <p>先选择任务，再执行操作。采集、网络实验和普通 ADB 工具彼此分区，避免误把不同链路当成同一功能。</p>
      </div>
      <span class="device-chip">{{ device?.model || '未选择设备' }}</span>
      <nav class="tool-section-tabs" aria-label="设备操作分类">
        <button v-for="item in toolSections" :key="item.id" :class="{ active: toolSection === item.id }" @click="toolSection = item.id">
          <span class="material-symbols-outlined">{{ item.icon }}</span>
          <span><strong>{{ item.label }}</strong><small>{{ item.hint }}</small></span>
          <i v-if="item.id === 'traffic' && mirrorRunning"></i>
        </button>
      </nav>
      <button v-if="latestHistory && toolSection !== 'console'" class="tool-latest-result" @click="toolSection = 'console'">
        <span class="material-symbols-outlined" :class="latestHistory.success ? 'success' : 'failed'">{{ latestHistory.success ? 'check_circle' : 'error' }}</span>
        <span><small>最近操作</small><strong>{{ latestHistory.command }}</strong></span>
        <em>查看日志</em>
      </button>
    </section>

    <section v-if="toolSection === 'inspect'" class="quick-action-grid">
      <button v-for="item in quickActions" :key="item.action" type="button" :disabled="running || !device || !props.androidAvailable" @click.stop="runQuick(item.action, item.argument)">
        <span class="material-symbols-outlined">{{ item.icon }}</span>
        <span><strong>{{ item.label }}</strong><small>{{ item.hint }}</small></span>
      </button>
      <button type="button" :disabled="running || !device || !androidAvailable" @click.stop="shellCommand = 'getprop'; submitShell()">
        <span class="material-symbols-outlined">terminal</span>
        <span><strong>Shell</strong><small>自由命令行</small></span>
      </button>
    </section>

    <section v-if="toolSection === 'inspect'" class="control-panel panel">
      <div class="section-title compact">
        <div><div class="eyebrow">DEVICE FORENSICS</div><h2>ADB Toolbox</h2></div>
        <span class="device-chip">{{ device?.model || 'No device' }}</span>
      </div>
      <div class="form-grid">
        <label>
          <span>常用检查</span>
          <select v-model="selectedAction">
            <option v-for="option in presets" :key="option.value" :value="option.value">{{ option.label }}</option>
          </select>
        </label>
        <label v-if="needsPackage">
          <span>目标包名</span>
          <input v-model.trim="argument" placeholder="com.example.app" @keydown.enter.prevent.stop="submit" />
        </label>
        <button type="button" class="primary-button run-command" :disabled="running || !device || !androidAvailable || (needsPackage && !argument)" @click.stop="submit">
          <span class="material-symbols-outlined">{{ running ? 'progress_activity' : 'play_arrow' }}</span>
          {{ running ? 'Running…' : '执行检查' }}
        </button>
      </div>
      <p class="safety-note">只读检查使用普通 <code>adb shell</code>，SELinux 开关和透明代理等特权操作才使用 <code>su -c</code>；SELinux 修改通常只在本次开机有效。</p>
    </section>

    <section v-if="toolSection === 'files'" class="deploy-panel panel">
      <div class="section-title compact"><div><div class="eyebrow">APP DEPLOY</div><h2>安装 / 卸载应用</h2></div><span class="device-chip">写操作</span></div>
      <div class="certificate-row deploy-file-row">
        <input v-model.trim="apkPath" placeholder="本机 APK 路径，例如 /tmp/app.apk" />
        <button type="button" class="ghost-button" :disabled="running || !device || !androidAvailable" @click.stop="pickApk">选择 APK</button>
        <button type="button" class="primary-button" :disabled="!apkPath || !device || !androidAvailable || running" @click.stop="installApk">安装</button>
      </div>
      <div class="collect-row deploy-uninstall-row">
        <input v-model.trim="uninstallPackage" placeholder="卸载包名，例如 com.example.app" @keydown.enter.prevent.stop="uninstallApk" />
        <button type="button" class="ghost-button" :disabled="!uninstallPackage || !device || !androidAvailable || running" @click.stop="uninstallApk">卸载应用</button>
      </div>
    </section>

    <section v-if="toolSection === 'files'" class="transfer-panel panel">
      <div class="section-title compact"><div><div class="eyebrow">FILE TRANSFER</div><h2>脱壳产物与设备文件</h2><p>输入内容会自动保留，切换页面后不会恢复默认值。</p></div><span class="device-chip">ADB</span></div>
      <div class="transfer-workflows">
        <article>
          <header><span class="material-symbols-outlined">download</span><div><strong>从手机拉取产物</strong><small>adb pull · 目录或单个文件</small></div></header>
          <div class="form-grid">
            <label><span>设备远程路径</span><input v-model.trim="pullRemote" placeholder="/storage/emulated/0/Download/dexDump" /></label>
            <label><span>Mac 本地目录</span><input v-model.trim="pullLocal" placeholder="/Users/xxx/Desktop/MobileE-Dumps" /></label>
            <button class="primary-button" :disabled="!pullRemote || !pullLocal || !device || !androidAvailable || running" @click="pullDumps">开始拉取</button>
          </div>
        </article>
        <article>
          <header><span class="material-symbols-outlined">upload</span><div><strong>推送本地文件到手机</strong><small>固定保存到 /storage/emulated/0/Download/</small></div></header>
          <div class="certificate-row">
            <input v-model.trim="pushLocal" placeholder="选择要推送的本地文件" />
            <button class="ghost-button" :disabled="running" @click="pickPushFile">选择文件</button>
            <button class="primary-button" :disabled="!pushLocal || !device || !androidAvailable || running" @click="pushFile">推送到 Download</button>
          </div>
        </article>
      </div>
    </section>

    <section v-if="toolSection === 'traffic'" class="mirror-panel panel">
      <div class="section-title compact">
        <div>
          <div class="eyebrow">KERNSIGHT · eBPF</div>
          <h2>eBPF 采集</h2>
          <p>App 仍直连原站 TLS。ksightd 拷 SSL_write/SSL_read 明文，把 POST/URL/头/body 和响应送进 Burp 历史，不设 VPN、iptables、系统代理。Burp Intercept 请关掉；全局 upstream 规则需排除 127.0.0.1:18081。Flutter / QUIC 以后再补。</p>
        </div>
        <span class="device-chip" :class="{ active: mirrorRunning, warning: mirrorCleanupPending }">{{ mirrorBusy ? '处理中…' : !mirrorStatusKnown ? '正在确认状态…' : mirrorRunning ? 'RUNNING' : mirrorCleanupPending ? '待清理' : '就绪' }}</span>
      </div>
      <div class="mirror-grid">
        <label><span>目标包</span><input v-model.trim="mirrorPackage" :disabled="mirrorRunning" placeholder="com.icbc" /></label>
        <label><span>Burp IP</span><input v-model.trim="mirrorHost" :disabled="mirrorRunning" placeholder="192.168.3.9" /></label>
        <label><span>Burp 端口</span><input v-model.number="mirrorPort" :disabled="mirrorRunning" type="number" min="1" max="65535" /></label>
      </div>
      <div class="ks-sensor-switches mirror-flags">
        <label><input v-model="mirrorViaAdb" :disabled="mirrorRunning" type="checkbox" />ADB reverse（手机 127.0.0.1 → 本机 Burp，并 forward 18081 回放口）</label>
        <label><input v-model="mirrorLaunch" :disabled="mirrorRunning" type="checkbox" />重启目标应用后采集（会先结束当前进程）</label>
      </div>
      <div class="proxy-actions">
        <button class="primary-button" :disabled="!mirrorStatusKnown || mirrorBusy || mirrorRunning || mirrorCleanupPending || !device || !androidAvailable || !mirrorPackage || !mirrorHost || !mirrorPort" @click="startMirror">
          <span class="material-symbols-outlined" :class="{ 'mirror-spinner': mirrorBusy }">{{ mirrorBusy ? 'progress_activity' : mirrorRunning ? 'sensors' : 'play_arrow' }}</span>
          {{ mirrorBusy && !mirrorRunning ? '正在启动…' : mirrorRunning ? '采集中…' : '开始镜像' }}
        </button>
        <button class="ghost-button" :disabled="mirrorBusy || (!mirrorRunning && !mirrorCleanupPending)" @click="stopMirror">
          <span class="material-symbols-outlined">stop</span>
          {{ mirrorCleanupPending && !mirrorRunning ? '清理残留' : '停止镜像' }}
        </button>
      </div>
      <p class="safety-note">{{ mirrorRunning ? `运行中：${mirrorPackage} → ${mirrorHost}:${mirrorPort}，单次明文最多 64 KiB；响应通过 127.0.0.1:18081 回放。点停止才会结束。` : mirrorCleanupPending ? 'ksightd 已退出，但设备上仍有 KernSight pcap 子进程；请点击“清理残留”完成会话封存。' : `不限时长。LAN 填 ${mirrorHost}:${mirrorPort}；ADB reverse 则 Burp 听 0.0.0.0:${mirrorPort}。若 Burp 配置了全局 upstream，请为 127.0.0.1:18081 添加直连例外，否则历史中会只有请求、没有原始响应。` }}</p>
      <p v-if="mirrorStatusDetail" class="mirror-process-detail">{{ mirrorStatusDetail }}</p>
      <section v-if="mirrorRunning || mirrorCoverage.observedFragments" class="mirror-coverage" :data-state="mirrorCoverage.state">
        <header>
          <div><small>LIVE COVERAGE · 仅计数</small><strong>{{ mirrorCoverageLabel }}</strong></div>
          <b>{{ mirrorCoverage.delivered.toLocaleString() }} 条已进入 Burp</b>
        </header>
        <div class="mirror-coverage-grid">
          <span><small>网络连接 / 握手</small><strong>{{ mirrorCoverage.networkConnects }} / {{ mirrorCoverage.networkHandshakes }}</strong></span>
          <span><small>边界片段</small><strong>{{ mirrorCoverage.observedFragments.toLocaleString() }}</strong></span>
          <span><small>完成重组</small><strong>{{ mirrorCoverage.reconstructedMessages.toLocaleString() }}</strong></span>
          <span><small>请求 / 响应</small><strong>{{ mirrorCoverage.reconstructedRequests }} / {{ mirrorCoverage.reconstructedResponses }}</strong></span>
          <span><small>重组缓冲</small><strong>{{ formatMirrorBytes(mirrorCoverage.bufferedBytes) }}</strong></span>
          <span><small>投递失败 / 重试</small><strong>{{ mirrorCoverage.deliveryFailed }} / {{ mirrorCoverage.retryPending }}</strong></span>
        </div>
        <div class="mirror-adapter-line">标准 TLS {{ mirrorCoverage.standardTlsFragments }} · 厂商边界 {{ mirrorCoverage.vendorFragments }} · JNI {{ mirrorCoverage.jniFragments }} · 待识别方向 {{ mirrorCoverage.unknownDirections }}</div>
        <div v-if="mirrorCoverage.stackCandidates" class="mirror-stack-line">
          <span>已加载网络栈 <b>{{ mirrorCoverage.stackCandidates }}</b></span>
          <span>导出符号候选 <b>{{ mirrorCoverage.stackExportCandidates }}</b></span>
          <span>固定边界 <b>{{ mirrorCoverage.stackPinnedBoundaries }}</b></span>
          <span>待固定边界 <b>{{ mirrorCoverage.stackEmpiricalBoundaries }}</b></span>
          <span>Keylog 候选 <b>{{ mirrorCoverage.stackKeylogCandidates }}</b></span>
          <span>暂未覆盖 <b>{{ mirrorCoverage.stackUncovered }}</b></span>
        </div>
        <p>{{ mirrorCoverageHint }}</p>
      </section>
      <details class="mirror-live-log" open>
        <summary>实时诊断日志（{{ mirrorLogs.length }}）</summary>
        <pre>{{ mirrorLogs.length ? mirrorLogs.join('\n') : '等待设备端启动信息…' }}</pre>
      </details>
    </section>

    <section v-if="toolSection === 'traffic'" class="security-tools panel">
      <div class="section-title compact"><div><div class="eyebrow">BURP / MITM LAB</div><h2>代理与证书</h2></div><span class="device-chip">需要 root 的选项会失败而不会静默修改</span></div>
      <div class="proxy-grid">
        <label><span>Proxy IP / Host</span><input v-model.trim="proxyHost" placeholder="192.168.3.100" /></label>
        <label><span>Port</span><input v-model.number="proxyPort" type="number" min="1" max="65535" /></label>
        <div class="proxy-actions">
          <button class="primary-button" :disabled="!androidAvailable" @click="$emit('proxy', { action: 'set', host: proxyHost, port: proxyPort })">设置系统代理</button>
          <button class="ghost-button" :disabled="!androidAvailable" @click="$emit('proxy', { action: 'clear', host: proxyHost, port: proxyPort })">清理系统代理</button>
          <button class="primary-button" :disabled="!androidAvailable" @click="$emit('proxy', { action: 'transparent_set', host: proxyHost, port: proxyPort })">启用透明代理</button>
          <button class="ghost-button" :disabled="!androidAvailable" @click="$emit('proxy', { action: 'transparent_clear', host: proxyHost, port: proxyPort })">清理透明代理</button>
        </div>
      </div>
      <div class="certificate-row">
        <input v-model.trim="certificatePath" placeholder="本机证书路径，例如 /tmp/burp.crt" />
        <button class="ghost-button" :disabled="!certificatePath || props.certificateBusy" @click="inspectCertificate">计算证书 Hash</button>
        <button class="primary-button" :disabled="props.certificateBusy || !certificatePath || !androidAvailable" @click="$emit('install-certificate', certificatePath)">安装到系统信任目录</button>
      </div>
      <div v-if="props.certificateFeedback" role="status" aria-live="polite" :aria-busy="props.certificateBusy" class="certificate-feedback"><span v-if="props.certificateBusy" class="material-symbols-outlined mirror-spinner">progress_activity</span><pre>{{ props.certificateFeedback }}</pre></div>
      <div v-if="props.certificate" class="certificate-result">
        <span><b>subject_hash_old</b> {{ props.certificate.subjectHash }}</span>
        <span><b>SHA-256</b> {{ props.certificate.sha256 }}</span>
        <span><b>目标</b> {{ props.certificate.systemTarget }}</span>
        <small>{{ props.certificate.note }}</small>
      </div>
    </section>

    <section v-if="toolSection === 'console'" class="shell-panel panel">
      <div class="section-title compact"><div><div class="eyebrow">REMOTE SHELL</div><h2>命令行</h2></div></div>
      <div class="shell-row"><span class="shell-prefix">$ adb shell</span><input v-model="shellCommand" placeholder="settings get global http_proxy" @keyup.enter="submitShell" /><button class="primary-button" :disabled="!shellCommand || !device || !androidAvailable" @click="submitShell">执行</button></div>
    </section>

    <section v-if="toolSection === 'console'" class="terminal-panel">
      <header>
        <div class="traffic-lights"><i></i><i></i><i></i></div>
        <span><span class="material-symbols-outlined">terminal</span> adb-session</span>
        <button title="清空输出" @click="$emit('clear')"><span class="material-symbols-outlined">delete</span></button>
      </header>
      <div class="terminal-body">
        <div v-if="!history.length" class="terminal-empty"><p>Android Security Toolkit</p><span>选择检查、代理操作或输入 Shell 命令。</span></div>
        <article v-for="entry in history" :key="entry.time">
          <p class="terminal-command"><time :datetime="new Date(entry.time).toISOString()">{{ formatDateTime(entry.time) }}</time><span>$</span> {{ entry.command }}</p>
          <pre :class="{ failed: !entry.success }">{{ entry.output }}</pre>
        </article>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch, type Ref } from 'vue'
import { open } from '@tauri-apps/plugin-dialog'
import type { AdbAction, CertificateInfo, DeviceSummary, KernSightMirrorCoverage } from '@/types'
import { formatDateTime } from '@/utils/time'
import { monitoringBackend } from '@/services/backend'

const props = defineProps<{ active: boolean; device?: DeviceSummary; androidAvailable: boolean; history: { time: number; command: string; output: string; success: boolean }[]; running: boolean; certificate: CertificateInfo | null; certificateBusy?: boolean; certificateFeedback?: string }>()
const androidAvailable = computed(() => props.androidAvailable)
type ToolSection = 'inspect' | 'files' | 'traffic' | 'console'
const toolSections: { id: ToolSection; label: string; hint: string; icon: string }[] = [
  { id: 'inspect', label: '检查', hint: '状态与只读诊断', icon: 'fact_check' },
  { id: 'files', label: '应用与文件', hint: '安装、拉取和推送', icon: 'folder_copy' },
  { id: 'traffic', label: '流量实验', hint: 'eBPF 镜像、代理与证书', icon: 'lan' },
  { id: 'console', label: '终端与日志', hint: 'Shell 和操作记录', icon: 'terminal' },
]
const savedToolSection = localStorage.getItem('mobilee.adb.toolSection') as ToolSection | null
const toolSection = ref<ToolSection>(toolSections.some(item => item.id === savedToolSection) ? savedToolSection! : 'inspect')
watch(toolSection, value => localStorage.setItem('mobilee.adb.toolSection', value), { flush: 'sync' })
const latestHistory = computed(() => props.history[0])
const emit = defineEmits<{
  run: [payload: { action: AdbAction; argument?: string }]
  shell: [command: string]
  proxy: [request: { action: string; host: string; port: number }]
  'certificate-info': [path: string]
  'install-certificate': [path: string]
  pull: [request: { remote: string; local: string }]
  push: [localPath: string]
  log: [entry: { command: string; output: string; success: boolean }]
  clear: []
}>()

const presets: { value: AdbAction; label: string }[] = [
  { value: 'logcat', label: 'Logcat（最近 120 行）' },
  { value: 'processes', label: '全部进程' },
  { value: 'system_properties', label: '系统属性 / Build' },
  { value: 'storage', label: '外部存储文件清单' },
  { value: 'shared_preferences', label: 'SharedPreferences 文件' },
  { value: 'databases', label: '应用数据库文件' },
  { value: 'webview_storage', label: 'WebView 存储文件' },
  { value: 'permissions', label: '包权限检查' },
  { value: 'mounts', label: '挂载点 / SELinux 线索' },
  { value: 'proxy_status', label: '代理状态' },
  { value: 'selinux_status', label: 'SELinux 当前状态' },
  { value: 'selinux_permissive', label: 'SELinux → Permissive（临时）' },
  { value: 'selinux_enforcing', label: 'SELinux → Enforcing' },
]
const quickActions: { action: AdbAction; label: string; hint: string; icon: string; argument?: string }[] = [
  { action: 'logcat', label: 'Logcat', hint: '应用崩溃与错误', icon: 'bug_report' },
  { action: 'storage', label: 'Storage', hint: '外部文件清单', icon: 'folder_open' },
  { action: 'proxy_status', label: 'Proxy', hint: '当前代理', icon: 'lan' },
  { action: 'selinux_permissive', label: 'SELinux Off', hint: '临时 Permissive', icon: 'lock_open' },
  { action: 'selinux_enforcing', label: 'SELinux On', hint: '恢复 Enforcing', icon: 'lock' },
]
function persistentRef(key: string, fallback: string): Ref<string> {
  const value = ref(localStorage.getItem(key) || fallback)
  watch(value, current => localStorage.setItem(key, current), { flush: 'sync' })
  return value
}

const savedAction = localStorage.getItem('mobilee.adb.action') as AdbAction | null
const selectedAction = ref<AdbAction>(presets.some((item) => item.value === savedAction) ? savedAction! : 'logcat')
watch(selectedAction, value => localStorage.setItem('mobilee.adb.action', value), { flush: 'sync' })
const argument = ref('')
const shellCommand = ref('')
const proxyHost = ref('192.168.3.100')
const proxyPort = ref(8888)
const mirrorPackage = persistentRef('mobilee.adb.mirrorPackage', '')
const mirrorHost = persistentRef('mobilee.adb.mirrorHost', '192.168.3.9')
const mirrorPort = ref(Number(localStorage.getItem('mobilee.adb.mirrorPort') || '8080'))
watch(mirrorPort, value => localStorage.setItem('mobilee.adb.mirrorPort', String(value)), { flush: 'sync' })
const mirrorViaAdb = ref(localStorage.getItem('mobilee.adb.mirrorViaAdb') === '1')
watch(mirrorViaAdb, value => localStorage.setItem('mobilee.adb.mirrorViaAdb', value ? '1' : '0'), { flush: 'sync' })
const mirrorLaunch = ref(localStorage.getItem('mobilee.adb.mirrorLaunch') === '1')
watch(mirrorLaunch, value => localStorage.setItem('mobilee.adb.mirrorLaunch', value ? '1' : '0'), { flush: 'sync' })
const mirrorRunning = ref(false)
const mirrorCleanupPending = ref(false)
const mirrorStatusDetail = ref('')
const mirrorBusy = ref(false)
const mirrorStatusKnown = ref(false)
const mirrorLogs = ref<string[]>([])
const emptyMirrorCoverage = (): KernSightMirrorCoverage => ({ networkConnects: 0, networkHandshakes: 0, observedFragments: 0, observedBytes: 0, reconstructedMessages: 0, reconstructedRequests: 0, reconstructedResponses: 0, delivered: 0, deliveryFailed: 0, retryPending: 0, unknownDirections: 0, bufferedBytes: 0, attachedProbes: 0, activeProbes: 0, standardTlsFragments: 0, vendorFragments: 0, jniFragments: 0, stackCandidates: 0, stackExportCandidates: 0, stackPinnedBoundaries: 0, stackEmpiricalBoundaries: 0, stackKeylogCandidates: 0, stackUncovered: 0, state: 'idle' })
const mirrorCoverage = ref<KernSightMirrorCoverage>(emptyMirrorCoverage())
const mirrorCoverageLabel = computed(() => ({
  idle: '等待采集',
  waiting_for_network: '等待目标应用联网',
  waiting_for_boundary: '尚未命中数据边界',
  unrecognized_stream: '已命中，但协议尚未识别',
  delivery_failed: 'Burp 投递失败',
  waiting_for_pair: '已重组，等待请求/响应配对',
  delivering: '正在投递',
}[mirrorCoverage.value.state] || '正在诊断'))
const mirrorCoverageHint = computed(() => {
  const state = mirrorCoverage.value.state
  if (state === 'waiting_for_network') return '尚未观察到目标应用建立连接。请确认包名对应当前运行进程，并在 App 中触发一次联网操作。'
  if (state === 'waiting_for_boundary' && mirrorCoverage.value.stackEmpiricalBoundaries) return `已识别 ${mirrorCoverage.value.stackEmpiricalBoundaries} 个厂商边界，但 ABI 规则尚未固定，为避免再次造成 App 闪退，当前不会自动挂载。`
  if (state === 'waiting_for_boundary' && mirrorCoverage.value.stackUncovered) return `已发现 ${mirrorCoverage.value.stackUncovered} 个当前规则无法解码的网络栈；需要补充对应构建版本的固定规则。`
  if (state === 'waiting_for_boundary' && mirrorCoverage.value.stackExportCandidates) return '已找到可挂载的导出符号候选但尚无命中：可能当前请求走了另一套 SDK，或该库只是被加载但未实际承载连接。'
  if (state === 'waiting_for_boundary') return '目标进程存在，但当前挂载点没有命中。通常表示流量经过尚未覆盖的 Cronet、QUIC、Flutter 或自研边界。'
  if (state === 'unrecognized_stream') return '已经复制到数据片段，但尚未重组成 HTTP/1 或 HTTP/2；这不是 Burp 连接故障。'
  if (state === 'delivery_failed') return '已重组出消息，但无法送达 Burp。请检查监听地址、ADB reverse 和 upstream 直连例外。'
  if (state === 'waiting_for_pair') return '已识别协议，正在等待配对或后台投递；无需重复启动镜像。'
  if (state === 'delivering') return '采集、协议重组和 Burp 投递链路均已有实际命中。'
  return '启动镜像后，这里会区分“没有命中”“无法重组”和“无法投递”。'
})
function formatMirrorBytes(value: number) {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`
  return `${(value / 1024 / 1024).toFixed(1)} MiB`
}
let mirrorPolling: ReturnType<typeof setInterval> | undefined
let mirrorChecking = false
const certificatePath = ref('')
const apkPath = persistentRef('mobilee.adb.apkPath', '')
const uninstallPackage = persistentRef('mobilee.adb.uninstallPackage', '')
const pullRemote = persistentRef('mobilee.adb.pullRemote', '/storage/emulated/0/Download/dexDump')
const pullLocal = persistentRef('mobilee.adb.pullLocal', '/Users/swyiic/Desktop/MobileE-Dumps')
const pushLocal = persistentRef('mobilee.adb.pushLocal', '')
const needsPackage = computed(() => ['permissions', 'shared_preferences', 'databases', 'webview_storage'].includes(selectedAction.value))

function submit() { emit('run', { action: selectedAction.value, argument: argument.value }) }
function runQuick(action: AdbAction, quickArgument?: string) { selectedAction.value = action; emit('run', { action, argument: quickArgument }) }
function submitShell() { if (shellCommand.value) emit('shell', shellCommand.value) }
function inspectCertificate() { if (certificatePath.value) emit('certificate-info', certificatePath.value) }
async function pickApk() {
  const selected = await open({ multiple: false, filters: [{ name: 'Android packages', extensions: ['apk'] }] })
  if (typeof selected === 'string') apkPath.value = selected
}
async function pickPushFile() {
  const selected = await open({ multiple: false })
  if (typeof selected === 'string') pushLocal.value = selected
}
function installApk() { if (apkPath.value) emit('run', { action: 'install_apk', argument: apkPath.value }) }
function uninstallApk() { if (uninstallPackage.value) emit('run', { action: 'uninstall_apk', argument: uninstallPackage.value }) }
function pullDumps() { if (pullRemote.value && pullLocal.value) emit('pull', { remote: pullRemote.value, local: pullLocal.value }) }
function pushFile() { if (pushLocal.value) emit('push', pushLocal.value) }
async function refreshMirrorStatus() {
  if (mirrorChecking) return
  mirrorChecking = true
  try {
    const status = await monitoringBackend.kernSightMirrorStatus(props.device?.serial)
    mirrorRunning.value = !!status.running
    mirrorCleanupPending.value = !!status.cleanupPending
    mirrorStatusDetail.value = status.detail || ''
    mirrorLogs.value = status.logs || []
    mirrorCoverage.value = status.coverage || emptyMirrorCoverage()
    mirrorStatusKnown.value = true
    if (status.package) mirrorPackage.value = status.package
  } catch (cause) {
    mirrorStatusKnown.value = false
    mirrorStatusDetail.value = `状态检查失败：${String(cause)}`
  } finally {
    mirrorChecking = false
  }
}
onMounted(() => {
  if (props.active) void refreshMirrorStatus()
  mirrorPolling = setInterval(() => {
    // This view stays mounted to preserve a KernSight session. Do not let its
    // hidden/status polling contend with an install, uninstall or another ADB
    // command for the process-wide ADB gate.
    if (props.active && !props.running) void refreshMirrorStatus()
  }, 2000)
})
onUnmounted(() => { if (mirrorPolling) clearInterval(mirrorPolling) })
watch(() => props.active, active => {
  if (active && !props.running) void refreshMirrorStatus()
})

async function startMirror() {
  if (mirrorBusy.value || mirrorChecking || mirrorRunning.value || mirrorCleanupPending.value || !mirrorStatusKnown.value || !mirrorPackage.value || !mirrorHost.value || !mirrorPort.value || !props.device?.serial) return
  mirrorBusy.value = true
  const target = `${mirrorHost.value}:${mirrorPort.value}`
  try {
    const result = await monitoringBackend.startKernSightMirror({
      serial: props.device.serial,
      package: mirrorPackage.value,
      durationSeconds: 0,
      files: false,
      filesFd: false,
      network: true,
      networkIo: false,
      memory: false,
      memoryAll: false,
      binder: false,
      sched: false,
      includeThreads: false,
      inspectTls: true,
      inspectJni: false,
      inspectLinker: false,
      inspectAdapter: null,
      hideDebug: false,
      sampleOneIn: 1,
      inspectMaxBytes: 65_536,
      inspectMaxHits: 1_000_000,
      launchAfterAttach: mirrorLaunch.value,
      mirrorBurp: target,
      mirrorViaAdb: mirrorViaAdb.value,
    })
    mirrorRunning.value = true
    mirrorCleanupPending.value = false
    emit('log', {
      command: result.commandPreview || `ksightd --mirror-burp ${target}`,
      output: result.stdout || '镜像已启动',
      success: true,
    })
  } catch (cause) {
    emit('log', { command: 'start mirror', output: String(cause), success: false })
  } finally {
    mirrorBusy.value = false
    void refreshMirrorStatus()
  }
}

async function stopMirror() {
  if (mirrorBusy.value) return
  mirrorBusy.value = true
  try {
    const status = await monitoringBackend.stopKernSightMirror(props.device?.serial, mirrorViaAdb.value ? mirrorPort.value : undefined)
    mirrorRunning.value = false
    mirrorCleanupPending.value = !!status.cleanupPending
    mirrorStatusDetail.value = status.detail || ''
    mirrorCoverage.value = status.coverage || emptyMirrorCoverage()
    emit('log', { command: 'stop mirror', output: status.detail || '已停止镜像并清理设备端采集进程', success: true })
  } catch (cause) {
    mirrorStatusDetail.value = String(cause)
    emit('log', { command: 'stop mirror', output: String(cause), success: false })
  } finally {
    mirrorBusy.value = false
    await refreshMirrorStatus()
  }
}
</script>
