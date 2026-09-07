<template>
  <div class="toolbox-layout">
    <div v-if="!androidAvailable" class="notice"><span class="material-symbols-outlined">info</span>当前设备不是 Android，ADB Toolbox 不可用；请切换到 Frida Toolbox。</div>
    <section class="quick-action-grid">
      <button v-for="item in quickActions" :key="item.action" :disabled="running || !device || !props.androidAvailable" @click="runQuick(item.action, item.argument)">
        <span class="material-symbols-outlined">{{ item.icon }}</span>
        <span><strong>{{ item.label }}</strong><small>{{ item.hint }}</small></span>
      </button>
      <button :disabled="!device || !androidAvailable" @click="shellCommand = 'getprop'; submitShell()">
        <span class="material-symbols-outlined">terminal</span>
        <span><strong>Shell</strong><small>自由命令行</small></span>
      </button>
    </section>

    <section class="control-panel panel">
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
          <input v-model.trim="argument" placeholder="com.example.app" @keyup.enter="submit" />
        </label>
        <button class="primary-button run-command" :disabled="running || !device || !androidAvailable || (needsPackage && !argument)" @click="submit">
          <span class="material-symbols-outlined">{{ running ? 'progress_activity' : 'play_arrow' }}</span>
          {{ running ? 'Running…' : '执行检查' }}
        </button>
      </div>
      <p class="safety-note">只读检查使用普通 <code>adb shell</code>，SELinux 开关和透明代理等特权操作才使用 <code>su -c</code>；SELinux 修改通常只在本次开机有效。</p>
    </section>

    <section class="deploy-panel panel">
      <div class="section-title compact"><div><div class="eyebrow">APP DEPLOY</div><h2>安装 / 卸载应用</h2></div><span class="device-chip">写操作</span></div>
      <div class="certificate-row deploy-file-row">
        <input v-model.trim="apkPath" placeholder="本机 APK 路径，例如 /tmp/app.apk" />
        <button class="ghost-button" :disabled="!device || !androidAvailable" @click="pickApk">选择 APK</button>
        <button class="primary-button" :disabled="!apkPath || !device || !androidAvailable || running" @click="installApk">安装</button>
      </div>
      <div class="collect-row deploy-uninstall-row">
        <input v-model.trim="uninstallPackage" placeholder="卸载包名，例如 com.example.app" @keyup.enter="uninstallApk" />
        <button class="ghost-button" :disabled="!uninstallPackage || !device || !androidAvailable || running" @click="uninstallApk">卸载应用</button>
      </div>
    </section>

    <section class="transfer-panel panel">
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

    <section class="mirror-panel panel">
      <div class="section-title compact">
        <div>
          <div class="eyebrow">KERNSIGHT · eBPF</div>
          <h2>eBPF 采集</h2>
          <p>App 仍直连原站 TLS。ksightd 拷 SSL_write/SSL_read 明文，把 POST/URL/头/body 和响应送进 Burp 历史，不设 VPN、iptables、系统代理。Burp Intercept 请关掉；全局 upstream 规则需排除 127.0.0.1:18081。Flutter / QUIC 以后再补。</p>
        </div>
        <span class="device-chip" :class="{ active: mirrorRunning }">{{ mirrorBusy ? '处理中…' : !mirrorStatusKnown ? '正在确认状态…' : mirrorRunning ? 'RUNNING' : '就绪' }}</span>
      </div>
      <div class="mirror-grid">
        <label><span>目标包</span><input v-model.trim="mirrorPackage" :disabled="mirrorRunning" placeholder="com.icbc" /></label>
        <label><span>Burp IP</span><input v-model.trim="mirrorHost" :disabled="mirrorRunning" placeholder="192.168.3.9" /></label>
        <label><span>Burp 端口</span><input v-model.number="mirrorPort" :disabled="mirrorRunning" type="number" min="1" max="65535" /></label>
      </div>
      <div class="ks-sensor-switches mirror-flags">
        <label><input v-model="mirrorViaAdb" :disabled="mirrorRunning" type="checkbox" />ADB reverse（手机 127.0.0.1 → 本机 Burp，并 forward 18081 回放口）</label>
        <label><input v-model="mirrorLaunch" :disabled="mirrorRunning" type="checkbox" />启动时冷启动目标包</label>
      </div>
      <div class="proxy-actions">
        <button class="primary-button" :disabled="!mirrorStatusKnown || mirrorBusy || mirrorRunning || !device || !androidAvailable || !mirrorPackage || !mirrorHost || !mirrorPort" @click="startMirror">
          <span class="material-symbols-outlined" :class="{ 'mirror-spinner': mirrorBusy || mirrorRunning }">{{ mirrorBusy || mirrorRunning ? 'progress_activity' : 'play_arrow' }}</span>
          {{ mirrorBusy && !mirrorRunning ? '正在启动…' : mirrorRunning ? '采集中…' : '开始镜像' }}
        </button>
        <button class="ghost-button" :disabled="mirrorBusy || !mirrorRunning" @click="stopMirror">
          <span class="material-symbols-outlined">stop</span>
          停止镜像
        </button>
      </div>
      <p class="safety-note">{{ mirrorRunning ? `运行中：${mirrorPackage} → ${mirrorHost}:${mirrorPort}，单次明文最多 64 KiB；响应通过 127.0.0.1:18081 回放。点停止才会结束。` : `不限时长。LAN 填 ${mirrorHost}:${mirrorPort}；ADB reverse 则 Burp 听 0.0.0.0:${mirrorPort}。若 Burp 配置了全局 upstream，请为 127.0.0.1:18081 添加直连例外，否则历史中会只有请求、没有原始响应。` }}</p>
      <details v-if="mirrorLogs.length" class="mirror-live-log">
        <summary>实时诊断日志（{{ mirrorLogs.length }}）</summary>
        <pre>{{ mirrorLogs.join('\n') }}</pre>
      </details>
    </section>

    <section class="security-tools panel">
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

    <section class="shell-panel panel">
      <div class="section-title compact"><div><div class="eyebrow">REMOTE SHELL</div><h2>命令行</h2></div></div>
      <div class="shell-row"><span class="shell-prefix">$ adb shell</span><input v-model="shellCommand" placeholder="settings get global http_proxy" @keyup.enter="submitShell" /><button class="primary-button" :disabled="!shellCommand || !device || !androidAvailable" @click="submitShell">执行</button></div>
    </section>

    <section class="terminal-panel">
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
import type { AdbAction, CertificateInfo, DeviceSummary } from '@/types'
import { formatDateTime } from '@/utils/time'
import { monitoringBackend } from '@/services/backend'

const props = defineProps<{ device?: DeviceSummary; androidAvailable: boolean; history: { time: number; command: string; output: string; success: boolean }[]; running: boolean; certificate: CertificateInfo | null; certificateBusy?: boolean; certificateFeedback?: string }>()
const androidAvailable = computed(() => props.androidAvailable)
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
  { value: 'packages', label: '第三方应用包列表' },
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
  { action: 'packages', label: 'Packages', hint: '已安装应用', icon: 'apps' },
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

const selectedAction = ref<AdbAction>((localStorage.getItem('mobilee.adb.action') as AdbAction) || 'logcat')
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
const mirrorBusy = ref(false)
const mirrorStatusKnown = ref(false)
const mirrorLogs = ref<string[]>([])
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
  if (mirrorChecking || mirrorBusy.value) return
  mirrorChecking = true
  try {
    const status = await monitoringBackend.kernSightMirrorStatus()
    mirrorRunning.value = !!status.running
    mirrorLogs.value = status.logs || []
    mirrorStatusKnown.value = true
    if (status.package) mirrorPackage.value = status.package
  } catch {
    mirrorStatusKnown.value = false
  } finally {
    mirrorChecking = false
  }
}
onMounted(() => {
  void refreshMirrorStatus()
  mirrorPolling = setInterval(() => void refreshMirrorStatus(), 2000)
})
onUnmounted(() => { if (mirrorPolling) clearInterval(mirrorPolling) })

async function startMirror() {
  if (mirrorBusy.value || mirrorChecking || mirrorRunning.value || !mirrorStatusKnown.value || !mirrorPackage.value || !mirrorHost.value || !mirrorPort.value || !props.device?.serial) return
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
      inspectJni: true,
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
    await monitoringBackend.stopKernSightMirror()
    mirrorRunning.value = false
    emit('log', { command: 'stop mirror', output: '已停止镜像并清理 ksightd capture', success: true })
  } catch (cause) {
    emit('log', { command: 'stop mirror', output: String(cause), success: false })
  } finally {
    mirrorBusy.value = false
  }
}
</script>
