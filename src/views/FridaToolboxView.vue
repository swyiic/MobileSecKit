<template>
  <div class="frida-layout">
    <section class="panel frida-header-card">
      <div class="section-title">
        <div><div class="eyebrow">RUNTIME OBSERVATION</div><h2>Frida Toolbox · {{ device?.platform === 'ios' ? 'iOS' : 'Android' }}</h2><p>{{ device?.platform === 'ios' ? 'iOS 使用 Bundle ID + Spawn 执行脚本和 Mach-O 砸壳。' : 'Android 使用包名执行 DEX、SO 与诊断工作流。' }}</p></div>
        <button class="primary-button" :disabled="!device" @click="$emit('refresh')"><span class="material-symbols-outlined">refresh</span>刷新进程</button>
      </div>
      <div class="frida-notice"><span class="material-symbols-outlined">info</span><span v-if="device?.platform === 'ios'">iOS 已内置 Mach-O 砸壳和 IPA 回收，不要使用 Hooker 的 Android DEX/SO 脚本；Attach 出现 (os/kern) failure 时使用 Spawn。</span><span v-else>Android 提供内置 DEX/SO 自动工作流。</span></div>
      <details class="frida-guide"><summary>Frida 保姆级使用流程</summary><ol><li>Android：确认设备为 <code>device</code>，准备与主机 CLI 同版本、匹配 ABI 的 frida-server，点击“推送并启动”。</li><li>iOS：确认越狱设备的 Frida 通道可见；如果提示 Developer Disk Image，先选择目录并挂载，再刷新进程。</li><li>刷新进程后选择包名；Attach 适合已运行 App，Spawn 适合冷启动观察。先运行内置只读诊断脚本，再通过“外部脚本路径”加载你审查过的脚本。</li><li>导出/脱壳类工具建议在终端单独运行并把生成的 IPA/APK 回拖到 App Analyzer，工具只负责本地索引、架构识别和敏感线索分类。</li></ol></details>
    </section>

    <section class="panel environment-card">
      <div class="section-title compact"><div><div class="eyebrow">TOOLCHAIN</div><h2>电脑与设备环境</h2></div><span class="device-chip">{{ environment?.hostOs || '—' }} / {{ environment?.hostArch || '—' }}</span></div>
      <div class="tool-status-grid">
        <div v-for="tool in fridaTools" :key="tool.executable" class="tool-status" :class="tool.category">
          <span class="tool-status-dot" :class="{ missing: !tool.available }"></span>
          <div><strong>{{ tool.name }}</strong><small>{{ tool.available ? (tool.version || tool.path) : '未安装' }}</small></div>
        </div>
      </div>
      <p v-if="!fridaTools.length" class="empty-inline">未检测到 Frida 相关工具；App Analyzer 的静态分析工具不在这里展示。</p>
      <button v-if="!hostFridaAvailable || environment?.hostFridaToolsMatch === false" class="primary-button" @click="$emit('install-host')">{{ hostFridaAvailable ? '修复电脑端 Frida / frida-ps 版本' : '自动安装电脑端 Frida Tools' }}</button>
      <p class="safety-note">电脑端 frida / frida-ps：{{ environment?.hostFridaToolsMatch === true ? '版本一致' : environment?.hostFridaToolsMatch === false ? '版本冲突，请点击修复' : '待检测' }} · 设备 Frida：{{ environment?.deviceFridaReachable ? '连接可用' : '未连接' }}{{ environment?.deviceFridaRequiresDeveloperImage ? '（需要挂载 iOS Developer Disk Image）' : '' }} · 版本 {{ environment?.deviceFridaVersion || '路径未知' }} · ABI {{ environment?.deviceArchitecture || 'Apple ARM64' }} · 推荐 {{ environment?.recommendedFridaServer || 'iOS 使用 Frida 设备通道' }} · 主机/设备版本{{ environment?.fridaVersionMatch === true ? '一致' : environment?.fridaVersionMatch === false ? '不一致' : '待检测' }}</p>
      <div v-if="device?.platform === 'android'" class="frida-server-row"><input v-model.trim="serverPath" placeholder="本机 frida-server 二进制路径（按 ABI 选择 arm64/x86）" /><button class="primary-button" :disabled="!serverPath" @click="$emit('server', { action: 'start', path: serverPath })">推送并启动</button><button class="ghost-button" :disabled="!hostFridaAvailable || environment?.hostFridaToolsMatch === false" @click="$emit('download')">自动下载、Root 推送并启动</button><button class="ghost-button" @click="$emit('server', { action: 'log' })">查看服务日志</button><button class="ghost-button" @click="$emit('server', { action: 'stop' })">停止</button></div>
      <div class="host-config-row"><label><span>主机工具目录（可手动配置 adb/frida 所在目录）</span><input :value="toolDirectory" placeholder="例如 /opt/homebrew/bin 或 C:\\Android\\platform-tools" @change="$emit('environment-config', ($event.target as HTMLInputElement).value)" /></label><button class="ghost-button" @click="$emit('open-terminal')">打开系统终端检测</button></div>
      <div v-if="device?.platform === 'ios'" class="host-config-row"><label><span>iOS Developer Disk Image 目录（可选）</span><input v-model.trim="developerImagePath" placeholder="包含 DeveloperDiskImage.dmg 的目录" /></label><button class="primary-button" :disabled="!developerImagePath" @click="$emit('mount-image', developerImagePath)">挂载 Developer Image</button></div>
    </section>

    <section class="panel frida-control-card">
      <div class="section-title compact"><div><div class="eyebrow">PROCESS TARGET</div><h2>进程与脚本</h2></div><span class="device-chip">{{ device?.model || 'No Frida device' }}</span></div>
      <div class="host-config-row"><label><span>外部脚本目录（可选；内置 DEX/SO 不需要目录）</span><input :value="scriptDirectory" placeholder="可留空，或选择 /path/to/hooker/js" readonly /></label><button class="ghost-button" @click="chooseScriptDirectory">选择目录</button></div>
      <div class="frida-form-grid">
        <label><span>进程 / 应用</span><select v-model="selectedProcess"><option value="">请选择目标</option><option v-for="process in processes" :key="process.identifier + process.pid" :value="process.identifier">{{ process.pid ? `RUNNING ${process.pid}` : 'STOPPED' }} · {{ process.name }} · {{ process.identifier }}</option></select></label>
        <label><span>诊断脚本</span><select v-model="selectedScriptPath"><option value="">编辑器中的脚本</option><option v-for="item in visibleScripts" :key="item.id" :value="item.path">{{ item.name }}</option></select></label>
        <label><span>模式</span><select v-model="mode"><option value="attach">Attach（已运行）</option><option value="spawn">Spawn（冷启动）</option></select></label>
        <button class="primary-button" :disabled="!selectedProcess || attachUnavailable || (!script.trim() && !externalScriptPath && !selectedScriptPath)" @click="submit"><span class="material-symbols-outlined">play_arrow</span>运行脚本</button>
      </div>
      <p v-if="attachUnavailable" class="dependency-notice"><strong>当前 App 未运行，无法 Attach。</strong> 请切换为 Spawn（冷启动）；Frida 17 默认会在脚本载入后继续运行应用，不需要旧参数 <code>--no-pause</code>。</p>
      <label class="script-editor"><span>用户脚本（仅本次运行，默认脚本只读取进程模块信息）</span><textarea v-model="script" spellcheck="false"></textarea></label>
      <label class="external-script"><span>外部脚本路径（填写后优先于下拉框和编辑器）</span><div class="external-script-row"><input v-model.trim="externalScriptPath" placeholder="/absolute/path/to/script.js" /><button class="ghost-button" @click="chooseScript">选择脚本</button><button class="primary-button" :disabled="!selectedProcess || !externalScriptPath || attachUnavailable" @click="submit">运行此外部脚本</button><button v-if="externalScriptPath" class="ghost-button" @click="externalScriptPath = ''">清除</button></div></label>
      <p class="active-script-line"><strong>当前将执行：</strong>{{ activeScriptLabel }}</p>
      <div v-if="device?.platform === 'android'" class="dex-workflow">
        <div><strong>DEX Dump 自动工作流</strong><p>程序已内置 Frida 17 原生 dump_dex.js。运行期间每秒 Root 镜像产物，App 随后闪退也不会丢失已生成 DEX。</p><button class="ghost-button compact-button" @click="useBuiltIn('dex')">使用内置 DEX 脚本</button></div>
        <label><span>触发等待</span><input v-model.number="dexDuration" type="number" min="10" max="120" /></label>
        <label><span>Mac 输出目录（留空则桌面 Me-Dumps）</span><div class="external-script-row"><input v-model.trim="dexDestination" placeholder="~/Desktop/Me-Dumps" /><button class="ghost-button" @click="chooseDexDestination">选择</button></div></label>
        <button class="primary-button" :disabled="!dexDumpReady" @click="runDexDump">一键 Dump、修复并拉回 Mac</button>
        <small v-if="activeScriptPath && !isDexScript">当前脚本不是 DEX Dump 脚本，请从脚本列表选择 dump_dex。</small>
      </div>
      <div v-if="device?.platform === 'android'" class="dex-workflow so-workflow">
        <div><strong>SO Dump 动态库工作流</strong><p>内置 dump_so.js 会提取 App 私有的已加载/新加载 SO 内存映像，自动拉回电脑，并扫描 URL、IP、接口和硬编码凭据。</p><button class="ghost-button compact-button" @click="useBuiltIn('so')">使用内置 SO 脚本</button></div>
        <label><span>触发等待</span><input v-model.number="soDuration" type="number" min="10" max="120" /></label>
        <label><span>Mac 输出目录（留空则桌面 Me-Dumps）</span><div class="external-script-row"><input v-model.trim="soDestination" placeholder="~/Desktop/Me-Dumps" /><button class="ghost-button" @click="chooseSoDestination">选择</button></div></label>
        <button class="primary-button" :disabled="!soDumpReady" @click="runSoDump">一键 Dump SO、拉回并分析</button>
        <small v-if="activeScriptPath && !isSoScript">当前脚本不是 SO Dump 脚本；点击“使用内置 SO 脚本”。</small>
      </div>
      <div v-if="device?.platform === 'ios'" class="dex-workflow ios-dump-workflow">
        <div><strong>iOS Mach-O 砸壳与 IPA 回收</strong><p>自动按 Bundle ID Spawn，读取已解密 Mach-O segments、清零 cryptid、拉回 App Bundle、替换主程序并组装 IPA；无需 Hooker、SSH 或 Paramiko。</p></div>
        <label><span>Mac 输出目录（留空则桌面 Me-Dumps）</span><div class="external-script-row"><input v-model.trim="iosDestination" placeholder="~/Desktop/Me-Dumps" /><button class="ghost-button" @click="chooseIosDestination">选择</button></div></label>
        <button class="primary-button" :disabled="!iosDumpReady || running" @click="runIosDump">{{ running ? '砸壳并回收中…' : '一键砸壳并生成 IPA' }}</button>
        <small>会重新启动 App；完成后自动验证主程序 cryptid，并把 IPA 路径写入日志。</small>
      </div>
      <div v-if="running && device?.platform === 'ios'" class="analysis-progress"><div class="analysis-progress-bar"><i></i></div><strong>正在通过 Frida RPC 拉回 App Bundle 并构建 IPA…</strong><small>大型 App 可能需要数分钟，请保持 USB 与 frida-server 稳定。</small></div>
      <details class="frida-guide"><summary>SSL Pinning + Burp 保姆级使用</summary><ol><li>Burp → Proxy settings 新建监听，例如 <code>0.0.0.0:8888</code>；记下 Mac 局域网 IP。</li><li>ADB Toolbox 设置系统/透明代理为 <code>Mac-IP:8888</code>。HTTPS 仍报证书错误时，先用证书工具安装 Burp CA。</li><li>在这里选择目标 App、选择 <code>just_trust_me.js</code>，模式选 Spawn，再点击运行。日志出现 hooked/bypass 等字样后，在手机里操作登录、列表、详情等页面。</li><li>回到 Burp 的 HTTP history 查看请求。若浏览器能抓、App 不能抓，通常是 native/BoringSSL/HTTP3 或代理检测；结合脚本日志选择对应脚本，并可暂时关闭 QUIC 后复测。</li><li>普通“运行脚本”采集约 12 秒日志；需要持续观察可重复运行。DEX Dump 使用上方独立工作流和更长等待时间。</li></ol></details>
    </section>

    <section class="terminal-panel">
      <header><div class="traffic-lights"><i></i><i></i><i></i></div><span><span class="material-symbols-outlined">hub</span> frida-session</span></header>
      <div class="terminal-body">
        <div v-if="!history.length" class="terminal-empty"><p>Frida diagnostics</p><span>刷新进程后选择目标。</span></div>
        <article v-for="entry in history.slice(0, 10)" :key="entry.time"><p class="terminal-command"><span>$</span> {{ entry.command }}</p><pre :class="{ failed: !entry.success }">{{ entry.output }}</pre></article>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { open } from '@tauri-apps/plugin-dialog'
import type { DeviceSummary, EnvironmentReport, FridaProcess, FridaScriptEntry } from '@/types'

const props = defineProps<{
  device?: DeviceSummary
  processes: FridaProcess[]
  scripts: FridaScriptEntry[]
  environment: EnvironmentReport | null
  toolDirectory: string
  scriptDirectory: string
  history: { time: number; command: string; output: string; success: boolean }[]
  running: boolean
}>()
const emit = defineEmits<{ refresh: []; run: [request: { process: string; pid?: number; mode: string; script: string; scriptPath?: string }]; 'dex-dump': [request: { package: string; scriptPath: string; destinationDirectory?: string; durationSeconds?: number }]; 'so-dump': [request: { package: string; scriptPath: string; destinationDirectory?: string; durationSeconds?: number }]; 'ios-dump': [request: { bundleId: string; destinationDirectory?: string }]; 'script-directory': [directory: string]; server: [request: { action: 'start' | 'stop' | 'log'; path?: string }]; download: []; 'install-host': []; 'environment-config': [directory: string]; 'open-terminal': []; 'mount-image': [directory: string] }>()

const selectedProcess = ref('')
const mode = ref(props.device?.platform === 'ios' ? 'spawn' : 'attach')
const selectedScriptPath = ref('')
const externalScriptPath = ref(localStorage.getItem('security-console.fridaScriptPath') || '')
const serverPath = ref('')
const developerImagePath = ref('')
const dexDestination = ref(localStorage.getItem('security-console.dexDestination') || '')
const dexDuration = ref(30)
const soDestination = ref(localStorage.getItem('security-console.soDestination') || '')
const soDuration = ref(30)
const iosDestination = ref(localStorage.getItem('security-console.iosDumpDestination') || '')
const script = ref(`// Safe starter: inspect process identity and loaded modules only.
console.log(JSON.stringify({
  pid: Process.id,
  arch: Process.arch,
  modules: Process.enumerateModules().slice(0, 30).map(m => ({ name: m.name, base: m.base.toString(), size: m.size }))
}, null, 2));`)
const visibleScripts = computed(() => props.scripts.filter((item) => item.platform === 'both' || item.platform === props.device?.platform))
const fridaTools = computed(() => props.environment?.tools.filter((tool) => tool.group === 'frida') || [])
const hostFridaAvailable = computed(() => fridaTools.value.some((tool) => tool.executable === 'frida' && tool.available))
const selectedTarget = computed(() => props.processes.find((process) => process.identifier === selectedProcess.value))
const attachUnavailable = computed(() => mode.value === 'attach' && !!selectedProcess.value && !selectedTarget.value?.pid)
const activeScriptPath = computed(() => externalScriptPath.value || selectedScriptPath.value)
const isDexScript = computed(() => /dex/i.test(activeScriptPath.value.split(/[\\/]/).pop() || ''))
const dexDumpReady = computed(() => props.device?.platform === 'android' && !!selectedProcess.value && !!activeScriptPath.value && isDexScript.value)
const isSoScript = computed(() => /(?:dump[_-]?so|so[_-]?dump)/i.test(activeScriptPath.value.split(/[\\/]/).pop() || ''))
const soDumpReady = computed(() => props.device?.platform === 'android' && !!selectedProcess.value && !!activeScriptPath.value && isSoScript.value)
const iosDumpReady = computed(() => props.device?.platform === 'ios' && !!selectedProcess.value)
const activeScriptLabel = computed(() => externalScriptPath.value ? `外部脚本：${externalScriptPath.value}` : selectedScriptPath.value ? `脚本列表：${selectedScriptPath.value}` : '编辑器中的脚本')

watch(externalScriptPath, (value) => localStorage.setItem('security-console.fridaScriptPath', value))
watch(dexDestination, (value) => localStorage.setItem('security-console.dexDestination', value))
watch(soDestination, (value) => localStorage.setItem('security-console.soDestination', value))
watch(iosDestination, (value) => localStorage.setItem('security-console.iosDumpDestination', value))
watch(() => props.device?.platform, (platform) => { if (platform === 'ios') mode.value = 'spawn' })
watch(selectedScriptPath, (value) => { if (value) externalScriptPath.value = '' })

async function chooseScript() {
  const selected = await open({ multiple: false, filters: [{ name: 'Frida JavaScript', extensions: ['js'] }] })
  if (typeof selected === 'string') {
    selectedScriptPath.value = ''
    externalScriptPath.value = selected
  }
}

async function chooseScriptDirectory() {
  const selected = await open({ directory: true, multiple: false })
  if (typeof selected === 'string') emit('script-directory', selected)
}

async function chooseDexDestination() {
  const selected = await open({ directory: true, multiple: false })
  if (typeof selected === 'string') dexDestination.value = selected
}

async function chooseSoDestination() {
  const selected = await open({ directory: true, multiple: false })
  if (typeof selected === 'string') soDestination.value = selected
}

async function chooseIosDestination() {
  const selected = await open({ directory: true, multiple: false })
  if (typeof selected === 'string') iosDestination.value = selected
}

function useBuiltIn(kind: 'dex' | 'so') {
  const scriptEntry = visibleScripts.value.find((item) => kind === 'dex' ? item.category === 'dex-dump' : /dump[_ ]?so|so[_ ]?dump/i.test(item.name))
  if (!scriptEntry) return
  externalScriptPath.value = ''
  selectedScriptPath.value = scriptEntry.path
  mode.value = 'spawn'
}

function runDexDump() {
  if (!dexDumpReady.value) return
  emit('dex-dump', { package: selectedProcess.value, scriptPath: activeScriptPath.value, destinationDirectory: dexDestination.value || undefined, durationSeconds: dexDuration.value })
}

function runSoDump() {
  if (!soDumpReady.value) return
  emit('so-dump', { package: selectedProcess.value, scriptPath: activeScriptPath.value, destinationDirectory: soDestination.value || undefined, durationSeconds: soDuration.value })
}

function runIosDump() {
  if (iosDumpReady.value) emit('ios-dump', { bundleId: selectedProcess.value, destinationDirectory: iosDestination.value || undefined })
}

function submit() {
  emit('run', { process: selectedProcess.value, pid: selectedTarget.value?.pid, mode: mode.value, script: script.value, scriptPath: externalScriptPath.value || selectedScriptPath.value || undefined })
}
</script>
