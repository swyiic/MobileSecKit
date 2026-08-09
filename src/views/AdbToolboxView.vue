<template>
  <div class="toolbox-layout">
    <div v-if="!androidAvailable" class="notice"><span class="material-symbols-outlined">info</span>当前设备不是 Android，ADB Toolbox 不可用；请切换到 Frida Toolbox。</div>
    <section class="quick-action-grid">
      <button v-for="item in quickActions" :key="item.action" :disabled="running || !device || !androidAvailable" @click="runQuick(item.action, item.argument)">
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
      <p class="safety-note">ADB Toolbox 的检查和 Shell 默认通过手机端 <code>su -c</code> 执行；SELinux 开关只修改本次开机状态，重启后通常恢复。内核不支持或 Magisk/KernelSU 未授权时会保留完整失败日志。</p>
    </section>

    <section class="security-tools panel">
      <div class="section-title compact"><div><div class="eyebrow">BURP / MITM LAB</div><h2>代理与证书</h2></div><span class="device-chip">需要 root 的选项会失败而不会静默修改</span></div>
      <div class="proxy-grid">
        <label><span>Proxy IP / Host</span><input v-model.trim="proxyHost" placeholder="192.168.3.100" /></label>
        <label><span>Port</span><input v-model.number="proxyPort" type="number" min="1" max="65535" /></label>
        <button class="primary-button" :disabled="!androidAvailable" @click="$emit('proxy', { action: 'set', host: proxyHost, port: proxyPort })">设置系统代理</button>
        <button class="ghost-button" :disabled="!androidAvailable" @click="$emit('proxy', { action: 'clear', host: proxyHost, port: proxyPort })">清理系统代理</button>
        <button class="primary-button" :disabled="!androidAvailable" @click="$emit('proxy', { action: 'transparent_set', host: proxyHost, port: proxyPort })">启用透明代理</button>
        <button class="ghost-button" :disabled="!androidAvailable" @click="$emit('proxy', { action: 'transparent_clear', host: proxyHost, port: proxyPort })">清理透明代理</button>
      </div>
      <div class="certificate-row">
        <input v-model.trim="certificatePath" placeholder="本机证书路径，例如 /tmp/burp.crt" />
        <button class="ghost-button" @click="inspectCertificate">计算证书 Hash</button>
        <button class="primary-button" :disabled="!certificatePath || !androidAvailable" @click="$emit('install-certificate', certificatePath)">安装到系统信任目录</button>
      </div>
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
        <div v-if="!history.length" class="terminal-empty"><p>Android Security Console</p><span>选择检查、代理操作或输入 Shell 命令。</span></div>
        <article v-for="entry in history" :key="entry.time">
          <p class="terminal-command"><span>$</span> {{ entry.command }}</p>
          <pre :class="{ failed: !entry.success }">{{ entry.output }}</pre>
        </article>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import type { AdbAction, CertificateInfo, DeviceSummary } from '@/types'

const props = defineProps<{ device?: DeviceSummary; androidAvailable: boolean; history: { time: number; command: string; output: string; success: boolean }[]; running: boolean; certificate: CertificateInfo | null }>()
const { androidAvailable } = props
const emit = defineEmits<{
  run: [payload: { action: AdbAction; argument?: string }]
  shell: [command: string]
  proxy: [request: { action: string; host: string; port: number }]
  'certificate-info': [path: string]
  'install-certificate': [path: string]
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
const selectedAction = ref<AdbAction>('logcat')
const argument = ref('')
const shellCommand = ref('')
const proxyHost = ref('192.168.3.100')
const proxyPort = ref(8888)
const certificatePath = ref('')
const needsPackage = computed(() => ['permissions', 'shared_preferences', 'databases', 'webview_storage'].includes(selectedAction.value))

function submit() { emit('run', { action: selectedAction.value, argument: argument.value }) }
function runQuick(action: AdbAction, quickArgument?: string) { selectedAction.value = action; emit('run', { action, argument: quickArgument }) }
function submitShell() { if (shellCommand.value) emit('shell', shellCommand.value) }
function inspectCertificate() { if (certificatePath.value) emit('certificate-info', certificatePath.value) }
</script>
