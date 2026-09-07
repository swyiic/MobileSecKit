<template>
  <div class="frida-layout">
    <section class="panel frida-header-card">
      <div class="section-title">
        <div><div class="eyebrow">RUNTIME OBSERVATION</div><h2>Frida Toolbox · {{ device?.platform === 'ios' ? 'iOS' : device?.platform === 'android' ? 'Android' : '未选择设备' }}</h2><p>{{ device?.platform === 'ios' ? 'iOS 使用 Bundle ID + Attach/Spawn 执行运行时观察和 Mach-O 回收。' : device?.platform === 'android' ? 'Android 使用包名执行 DEX、SO 与诊断工作流。' : '连接并选择设备后，页面会只展示对应平台的运行时流程。' }}</p></div>
        <button class="primary-button" :disabled="!device" @click="$emit('refresh')"><span class="material-symbols-outlined">refresh</span>刷新进程</button>
      </div>
      <div class="frida-notice"><span class="material-symbols-outlined">info</span><span v-if="device?.platform === 'ios'">iOS 已内置 Mach-O 回收和运行时观察；JMCodeProtect 场景优先让 App 保持前台后使用 Attach，Attach 出现 (os/kern) failure 或进程未运行时再切换 Spawn。</span><span v-else-if="device?.platform === 'android'">Android 提供内置 DEX/SO 自动工作流。</span><span v-else>当前仅显示主机环境；选择设备后再加载平台脚本与操作。</span></div>
      <details class="frida-guide"><summary>Frida 保姆级使用流程</summary><ol><li>Android：确认设备为 <code>device</code>，准备与主机 CLI 同版本、匹配 ABI 的 frida-server，点击“推送并启动”。</li><li>iOS：确认越狱设备的 Frida 通道可见；如果提示 Developer Disk Image，先选择目录并挂载，再刷新进程。不要全局隐藏越狱环境，否则 Sileo/Frida 服务也可能被隔离，零 Hook 会在脚本执行前失败；目标 App 的兼容策略应单独配置。</li><li>刷新进程后选择包名；Attach 适合已运行 App，Spawn 适合冷启动观察。注入导致目标退出后，MobileE 会清除旧 PID，并把已安装应用保留为 <code>STOPPED</code> 供 Spawn 重试。</li><li>先运行内置只读诊断脚本，再通过“外部脚本路径”加载你审查过的脚本。若目标在 agent 注入前退出，用户脚本无法处理，应改用内部调试构建或目标级测试配置。</li><li>导出/脱壳类工具建议在终端单独运行并把生成的 IPA/APK 回拖到 App Analyzer，工具只负责本地索引、架构识别和敏感线索分类。</li></ol></details>
    </section>

    <section class="panel environment-card">
      <div class="section-title compact"><div><div class="eyebrow">FRIDA ENVIRONMENT</div><h2>Frida 环境与检测</h2><p>检测主机 Frida 工具、设备通道、版本匹配和运行条件。</p></div><span class="device-chip">{{ environment?.hostOs || '—' }} / {{ environment?.hostArch || '—' }}</span></div>
      <div class="tool-status-grid">
        <div v-for="tool in fridaTools" :key="tool.executable" class="tool-status" :class="tool.category">
          <span class="tool-status-dot" :class="{ missing: !tool.available }"></span>
          <div><strong>{{ tool.name }}</strong><small>{{ tool.available ? (tool.version || tool.path) : '未安装' }}</small></div>
        </div>
      </div>
      <p v-if="!fridaTools.length" class="empty-inline">未检测到 Frida 相关工具；App Analyzer 的静态分析工具不在这里展示。</p>
      <button v-if="!hostFridaAvailable || environment?.hostFridaToolsMatch === false" class="primary-button" @click="$emit('install-host')">{{ hostFridaAvailable ? '修复电脑端 Frida / frida-ps 版本' : '自动安装电脑端 Frida Tools' }}</button>
      <p class="safety-note">电脑端 frida / frida-ps：{{ environment?.hostFridaToolsMatch === true ? '版本一致' : environment?.hostFridaToolsMatch === false ? '版本冲突，请点击修复' : '待检测' }} · 设备 Frida：{{ environment?.deviceFridaReachable ? '连接可用' : '未连接' }}{{ environment?.deviceFridaRequiresDeveloperImage ? '（需要挂载 iOS Developer Disk Image）' : '' }} · 版本 {{ environment?.deviceFridaVersion || '路径未知' }} · ABI {{ environment?.deviceArchitecture || '待识别' }} · 推荐 {{ environment?.recommendedFridaServer || (device?.platform === 'ios' ? 'iOS 使用 Frida 设备通道' : device?.platform === 'android' ? '按 ABI 选择 Android frida-server' : '请先选择设备') }} · 主机/设备版本{{ environment?.fridaVersionMatch === true ? '一致' : environment?.fridaVersionMatch === false ? '不一致' : '待检测' }}</p>
      <div v-if="device?.platform === 'android'" class="frida-server-row"><div class="configured-path"><span>frida-server</span><code>{{ appConfig.fridaServerPath || '未配置，可使用自动下载' }}</code></div><button class="primary-button" :disabled="!appConfig.fridaServerPath" @click="$emit('server', { action: 'start', path: appConfig.fridaServerPath })">推送并启动</button><button class="primary-button" @click="$emit('server', { action: 'harden' })">Frida痕迹清理</button><button class="ghost-button" :disabled="!hostFridaAvailable || environment?.hostFridaToolsMatch === false" @click="$emit('download')">自动下载并启动</button><button class="ghost-button" @click="$emit('server', { action: 'log' })">服务日志</button><button class="ghost-button" @click="$emit('server', { action: 'stop' })">停止</button></div>
      <div class="environment-actions"><button class="ghost-button" @click="$emit('refresh-environment')"><span class="material-symbols-outlined">manage_search</span>重新检测 Frida 环境</button><button class="ghost-button" @click="$emit('open-terminal')"><span class="material-symbols-outlined">terminal</span>终端诊断</button><button class="ghost-button" @click="$emit('open-settings')"><span class="material-symbols-outlined">settings</span>修改全局路径</button></div>
      <div v-if="device?.platform === 'ios'" class="configured-action"><div class="configured-path"><span>Developer Disk Image</span><code>{{ appConfig.iosDeveloperImageDirectory || '未配置' }}</code></div><button class="primary-button" :disabled="!appConfig.iosDeveloperImageDirectory" @click="$emit('mount-image', appConfig.iosDeveloperImageDirectory)">挂载 Developer Image</button><button class="ghost-button" @click="copyIosCountermeasure">{{ copyFeedback || '复制 iOS 对抗命令' }}</button></div>
      <details v-if="device?.platform === 'ios'" class="frida-guide developer-image-help"><summary>Developer Disk Image.dmg 是什么，什么时候需要？</summary><p>它是 Apple/Xcode 随 iOS 版本提供的开发调试支持镜像，不是 IPA、系统固件或 Frida Server。只有环境检测明确显示“需要 Developer Disk Image”或调试服务不可用时才需要挂载；镜像及其签名文件应与手机 iOS 版本匹配。越狱设备通过 root 启动的 frida-server 通常不靠它完成注入，因此 Frida 已能列出进程时无需重复挂载。</p></details>
      <p v-if="device?.platform === 'ios'" class="safety-note"><strong>iOS 对抗分为两层：</strong>iOS 没有 ADB 通道，环境层的 frida-server 改名、随机端口和旧进程清理，需要在设备 NewTerm（root）执行复制的命令；agent 层的 ptrace/sysctl/越狱检测兼容已内置，运行脚本时会按 Compat / Aggressive 策略自动生效。查看环境层命令输出末尾的 <code>PORT=xxxxx</code>，再用 <code>frida -H &lt;设备IP&gt;:&lt;PORT&gt; -ps</code> 验证。</p>
    </section>

    <section class="panel frida-control-card">
      <div class="section-title compact"><div><div class="eyebrow">PROCESS TARGET</div><h2>进程与脚本</h2></div><span class="device-chip">{{ device?.model || 'No Frida device' }}</span></div>
      <div v-if="guidanceRequest" class="runtime-guidance">
        <span class="material-symbols-outlined">route</span>
        <div><strong>来自 App Analyzer 的运行确认任务</strong><p>目标 <code>{{ guidanceRequest.appId }}</code>；MobileE 会自动选择并运行真正的零 Hook 探针。确认输出会回填静态候选，随后可回到 App Analyzer 或 AI Context 做整体分析。</p></div>
      </div>
      <div class="configured-action script-library-summary"><div class="configured-path"><span>脚本来源</span><code>{{ embeddedScriptCount }} 个内置 · {{ externalScriptCount }} 个外部；统一在“诊断脚本”下拉框选择</code></div><button class="ghost-button" @click="$emit('open-settings')">外部脚本设置</button></div>
      <div class="frida-form-grid">
        <label><span>进程 / 应用</span><select v-model="selectedProcess"><option value="">请选择目标</option><option v-for="process in processes" :key="process.identifier + process.pid" :value="process.identifier">{{ process.pid ? `RUNNING ${process.pid}` : 'STOPPED' }} · {{ process.name }} · {{ process.identifier }}</option></select></label>
        <label><span>诊断脚本</span><select v-model="selectedScriptPath"><option value="">编辑器中的脚本</option><option v-for="item in visibleScripts" :key="item.id" :value="item.path">{{ item.name }}</option></select></label>
        <label><span>模式</span><select v-model="mode"><option value="attach">Attach（已运行）</option><option value="spawn">Spawn（冷启动）</option></select></label>
        <label v-if="device?.platform === 'ios'"><span>iOS 兼容策略</span><select v-model="iosCompatibilityProfile"><option value="minimal">Minimal（不额外添加兼容 Hook）</option><option value="compat">Compat（限定来源的 ptrace / 越狱路径）</option><option value="aggressive">Aggressive（高风险 task / dlsym / 信号）</option></select></label>
        <label><span>观察时长（秒）</span><input v-model.number="observationDuration" type="number" min="5" max="300" /></label>
        <button class="primary-button" :disabled="!selectedProcess || attachUnavailable || (!script.trim() && !externalScriptPath && !selectedScriptPath)" @click="submit"><span class="material-symbols-outlined">play_arrow</span>运行脚本</button>
      </div>
      <p v-if="analysisAppId" class="runtime-scope-note" :class="{ mismatch: !!selectedProcess && !targetMatchesAnalysis }">
        <span class="material-symbols-outlined">filter_alt</span>
        静态分析目标：<code>{{ analysisAppId }}</code> ·
        <template v-if="!selectedProcess">请选择同一 Bundle ID / 包名，运行结果才会进入该 App 的 AI Context。</template>
        <template v-else-if="targetMatchesAnalysis">当前目标一致，任务结束后原始输出会自动记录；其中可识别的运行事件会归入该 App。</template>
        <template v-else>当前选择的是 <code>{{ selectedProcess }}</code>，日志仍会保存，但不会混入 <code>{{ analysisAppId }}</code> 的 Data Boundaries / AI Context。</template>
      </p>
      <p v-if="attachUnavailable" class="dependency-notice"><strong>当前 App 未运行，无法 Attach。</strong> 请切换为 Spawn（冷启动）；Frida 17 默认会在脚本载入后继续运行应用，不需要旧参数 <code>--no-pause</code>。</p>
      <p v-if="device?.platform === 'ios'" class="safety-note">先用 Minimal + “iOS 注入通道探针（零 Hook）”。如果连 <code>ME_IOS_INJECTION_OK</code> 都没有出现，失败发生在用户脚本执行前，Compat/Aggressive 也无法从脚本内部修复。Aggressive 仅用于普通注入已经成功、但 App 随后主动检测并退出的场景。</p>
      <label class="script-editor"><span>用户脚本（仅本次运行，默认脚本只读取进程模块信息）</span><textarea v-model="script" spellcheck="false"></textarea></label>
      <div class="configured-action external-script"><div class="configured-path"><span>默认外部脚本</span><code>{{ externalScriptPath || '未配置' }}</code></div><button class="ghost-button" @click="$emit('open-settings')">设置脚本</button><button class="primary-button" :disabled="!selectedProcess || !externalScriptPath || attachUnavailable" @click="submit">运行外部脚本</button></div>
      <p class="active-script-line"><strong>当前将执行：</strong>{{ activeScriptLabel }}</p>
      <div v-if="device" class="ios-runtime-workflow runtime-evidence-workflow">
        <header>
          <div><strong>{{ device.platform === 'ios' ? 'iOS' : 'Android' }} 运行时证据流程</strong><small>与 App Analyzer 的运行时证据项一一对应；按包名自动关联。任一步骤被拦截时立即停止后续自动采集，保留已有证据，静态分析不受影响。</small></div>
          <button class="primary-button" :disabled="!runtimeWorkflowReady || running" @click="runFullRuntimeWorkflow">{{ running ? '运行时采集中…' : '执行平台运行时流程' }}</button>
        </header>
        <div class="runtime-step-grid">
          <button v-for="(step, index) in runtimeWorkflowSteps" :key="step.key" class="runtime-step-button" :class="`state-${runtimeStatus(step.key)}`" :disabled="!selectedProcess || running" @click="runRuntimeStep(step)">
            <b>{{ index + 1 }}</b><span><strong>{{ step.label }}</strong><small>{{ runtimeStatusLabel(step.key) }}</small></span>
          </button>
        </div>
        <small>{{ device.platform === 'ios' ? 'Network/TLS 与 WebView 需要在观察时长内操作 App；没有事件时仍会保留观察器已就绪的负向证据。' : 'Java、网络、WebView、存储/密码学和 Root 均为只读观察；不会修改请求、信任结果、存储值或 Root 状态。' }}</small>
        <details v-if="device.platform === 'ios'" class="frida-guide compact-runtime-tools"><summary>保护 / 终止专项（独立运行）</summary><div class="ios-runtime-actions"><button class="ghost-button" :disabled="!selectedProcess || running" @click="runBuiltinDiagnostic('ios_termination_trace.js')">追踪异常 / 终止调用栈</button><button class="ghost-button" :disabled="!selectedProcess || running" @click="runBuiltinDiagnostic('observe_jmprotection.js')">观察 JMProtection / FishHook</button></div><p>专项观察不属于默认流程，避免额外 Hook 干扰基础证据。只有出现终止调用或保护事件才形成实质证据。</p></details>
      </div>
      <div v-if="device?.platform === 'android'" class="dex-workflow">
        <div><strong>DEX 运行时产物 · {{ runtimeStatusLabel('dex-artifact') }}</strong><p>程序已内置 Frida 17 原生 dump_dex.js。先勘查 ClassLoader 委派链与 dexElements，可定位隐藏 DEX / 热修复补丁；随后 Dump 会同时覆盖现有元素、内存 DEX 与 DefineClass。</p><button class="ghost-button compact-button" :disabled="!selectedProcess || running" @click="runBuiltinDiagnostic('inspect_classloader.js')">先勘查类加载器</button><button class="ghost-button compact-button" @click="useBuiltIn('dex')">使用内置 DEX 脚本</button></div>
        <label><span>触发等待</span><input v-model.number="dexDuration" type="number" min="10" max="120" /></label>
        <div class="configured-path workflow-path"><span>DEX 输出目录</span><code>{{ dexDestination || '桌面 MobileE-Dumps' }}</code></div>
        <button class="primary-button" :disabled="!dexDumpReady" @click="runDexDump">按当前模式 Dump、修复并拉回电脑</button>
        <small v-if="activeScriptPath && !isDexScript">当前脚本不是 DEX Dump 脚本，请从脚本列表选择 dump_dex。</small>
      </div>
      <div v-if="device?.platform === 'android'" class="dex-workflow so-workflow">
        <div><strong>SO 运行时产物 · {{ runtimeStatusLabel('so-artifact') }}</strong><p>内置 dump_so.js 会提取 App 私有的已加载/新加载 SO 内存映像，自动拉回电脑，并扫描 URL、IP、接口和硬编码凭据。</p><button class="ghost-button compact-button" @click="useBuiltIn('so')">使用内置 SO 脚本</button></div>
        <label><span>触发等待</span><input v-model.number="soDuration" type="number" min="10" max="120" /></label>
        <div class="configured-path workflow-path"><span>SO 输出目录</span><code>{{ soDestination || '桌面 MobileE-Dumps' }}</code></div>
        <button class="primary-button" :disabled="!soDumpReady" @click="runSoDump">按当前模式 Dump SO、拉回并分析</button>
        <small v-if="activeScriptPath && !isSoScript">当前脚本不是 SO Dump 脚本；点击“使用内置 SO 脚本”。</small>
      </div>
      <div v-if="device?.platform === 'ios'" class="ios-dump-compact">
        <div><strong>Mach-O / IPA 运行时产物 · {{ runtimeStatusLabel('app-artifact') }}</strong><small>复用上方启动模式与兼容策略；输出目录使用全局设置，未配置时保存到桌面 MobileE-Dumps。</small></div>
        <button class="primary-button" :disabled="!iosDumpReady || running" @click="runIosDump">{{ running ? '砸壳并回收中…' : '一键砸壳并生成 IPA' }}</button>
      </div>
      <div v-if="running && device?.platform === 'ios'" class="analysis-progress"><div class="analysis-progress-bar"><i></i></div><strong>正在执行 iOS Frida 工作流…</strong><small>请保持 iPhone 解锁、屏幕常亮和 USB / frida-server 稳定；运行时观察期间请操作目标页面触发事件。</small></div>
      <details class="frida-guide"><summary>SSL Pinning + Burp 保姆级使用</summary><ol><li>Burp → Proxy settings 新建监听，例如 <code>0.0.0.0:8888</code>；记下 Mac 局域网 IP。</li><li>ADB Toolbox 设置系统/透明代理为 <code>Mac-IP:8888</code>。HTTPS 仍报证书错误时，先用证书工具安装 Burp CA。</li><li>在这里选择目标 App、选择 <code>just_trust_me.js</code>，模式选 Spawn，再点击运行。日志出现 hooked/bypass 等字样后，在手机里操作登录、列表、详情等页面。</li><li>回到 Burp 的 HTTP history 查看请求。若浏览器能抓、App 不能抓，通常是 native/BoringSSL/HTTP3 或代理检测；结合脚本日志选择对应脚本，并可暂时关闭 QUIC 后复测。</li><li>普通“运行脚本”采集约 12 秒日志；需要持续观察可重复运行。DEX Dump 使用上方独立工作流和更长等待时间。</li></ol></details>
    </section>

    <section class="terminal-panel">
      <header><div class="traffic-lights"><i></i><i></i><i></i></div><span><span class="material-symbols-outlined">hub</span> frida-session</span></header>
      <div class="terminal-body">
        <div v-if="!history.length" class="terminal-empty"><p>Frida diagnostics</p><span>刷新进程后选择目标。</span></div>
        <article v-for="entry in history.slice(0, 10)" :key="entry.time"><p class="terminal-command"><time :datetime="new Date(entry.time).toISOString()">{{ formatDateTime(entry.time) }}</time><span>$</span> {{ entry.command }}</p><pre :class="{ failed: !entry.success }">{{ entry.output }}</pre></article>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { appConfig, updateAppConfig } from '@/services/config'
import { runtimeEvidenceCoverage } from '@/services/runtimeCoverage'
import type { DeviceSummary, EnvironmentReport, FridaProcess, FridaScriptEntry, RuntimeEvidenceStepKey, RuntimeWorkflowStep, TerminalEntry } from '@/types'
import { formatDateTime } from '@/utils/time'

const props = defineProps<{
  device?: DeviceSummary
  processes: FridaProcess[]
  scripts: FridaScriptEntry[]
  environment: EnvironmentReport | null
  history: TerminalEntry[]
  running: boolean
  analysisAppId?: string
  guidanceRequest?: { id: number; appId: string; platform: 'android' | 'ios'; purpose: 'anti-instrumentation' }
}>()
const emit = defineEmits<{ refresh: []; run: [request: { process: string; pid?: number; mode: string; script: string; scriptPath?: string; durationSeconds?: number; compatibilityProfile?: 'minimal' | 'compat' | 'aggressive'; platform?: 'android' | 'ios' }]; 'runtime-workflow': [request: { process: string; pid?: number; mode: 'attach' | 'spawn'; durationSeconds?: number; compatibilityProfile?: 'minimal' | 'compat' | 'aggressive'; steps: RuntimeWorkflowStep[] }]; 'dex-dump': [request: { package: string; scriptPath: string; destinationDirectory?: string; durationSeconds?: number; mode?: 'attach' | 'spawn'; pid?: number }]; 'so-dump': [request: { package: string; scriptPath: string; destinationDirectory?: string; durationSeconds?: number; mode?: 'attach' | 'spawn'; pid?: number }]; 'ios-dump': [request: { bundleId: string; destinationDirectory?: string; mode?: 'spawn' | 'attach'; compatibilityProfile?: 'minimal' | 'compat' | 'aggressive' }]; server: [request: { action: 'start' | 'stop' | 'log' | 'harden'; path?: string }]; download: []; 'install-host': []; 'open-terminal': []; 'mount-image': [directory: string]; 'refresh-environment': []; 'open-settings': []; 'guidance-consumed': [] }>()

const selectedProcess = ref('')
const mode = ref(props.device?.platform === 'ios' ? 'spawn' : 'attach')
const selectedScriptPath = ref('')
const externalScriptPath = computed({ get: () => appConfig.fridaScriptPath, set: (value: string) => updateAppConfig({ fridaScriptPath: value }) })
const dexDestination = computed(() => appConfig.dexDestination)
const dexDuration = ref(30)
const soDestination = computed(() => appConfig.soDestination)
const soDuration = ref(30)
const iosDestination = computed(() => appConfig.iosDumpDestination)
const copyFeedback = ref('')
const IOS_COUNTERMEASURE_COMMAND = `pkill -9 -f frida-server 2>/dev/null || true
pkill -9 -f '/myfs' 2>/dev/null || true
sleep 1
if [ -f /var/jb/usr/bin/frida-server ]; then FS=/var/jb/usr/bin/frida-server; else FS=/usr/bin/frida-server; fi
if [ ! -f "$FS" ]; then echo "找不到 frida-server：$FS" >&2; exit 1; fi
TARGET=/var/jb/usr/bin/myfs
if [ ! -d /var/jb/usr/bin ]; then TARGET=/usr/bin/myfs; fi
cp "$FS" "$TARGET" || exit $?
chmod 755 "$TARGET"
SEED=\${RANDOM:-$(date +%s)}
PORT=$(( (SEED % 25000) + 20000 ))
nohup "$TARGET" -l 0.0.0.0:$PORT >/tmp/myfs.log 2>&1 &
pid=$!
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then echo "myfs 启动失败，随机端口 $PORT 可能已占用或 Frida 版本不匹配" >&2; tail -n 20 /tmp/myfs.log 2>/dev/null; exit 1; fi
echo "$PORT" >/tmp/mobilee-frida.port
echo "myfs PID=$pid"
echo "PORT=$PORT"
ps aux | grep myfs | grep -v grep`
const iosCompatibilityProfile = ref<'minimal' | 'compat' | 'aggressive'>(appConfig.iosCompatibilityProfile)
const observationDuration = ref(60)
const appliedGuidanceId = ref<number>()
const script = ref(`// Safe starter: inspect process identity and loaded modules only.
console.log(JSON.stringify({
  pid: Process.id,
  arch: Process.arch,
  modules: Process.enumerateModules().slice(0, 30).map(m => ({ name: m.name, base: m.base.toString(), size: m.size }))
}, null, 2));`)
const visibleScripts = computed(() => props.scripts.filter((item) => item.platform === 'both' || item.platform === props.device?.platform))
const embeddedScriptCount = computed(() => visibleScripts.value.filter((item) => item.path.startsWith('builtin://')).length)
const externalScriptCount = computed(() => visibleScripts.value.length - embeddedScriptCount.value)
const fridaTools = computed(() => props.environment?.tools.filter((tool) => tool.group === 'frida') || [])
const hostFridaAvailable = computed(() => fridaTools.value.some((tool) => tool.executable === 'frida' && tool.available))
const selectedTarget = computed(() => props.processes.find((process) => process.identifier === selectedProcess.value))
const targetMatchesAnalysis = computed(() => selectedProcess.value.trim().toLowerCase() === (props.analysisAppId || '').trim().toLowerCase())
const attachUnavailable = computed(() => mode.value === 'attach' && !!selectedProcess.value && !selectedTarget.value?.pid)
const activeScriptPath = computed(() => externalScriptPath.value || selectedScriptPath.value)
const isDexScript = computed(() => /dex/i.test(activeScriptPath.value.split(/[\\/]/).pop() || ''))
const dexDumpReady = computed(() => props.device?.platform === 'android' && !!selectedProcess.value && !!activeScriptPath.value && isDexScript.value)
const isSoScript = computed(() => /(?:dump[_-]?so|so[_-]?dump)/i.test(activeScriptPath.value.split(/[\\/]/).pop() || ''))
const soDumpReady = computed(() => props.device?.platform === 'android' && !!selectedProcess.value && !!activeScriptPath.value && isSoScript.value)
const iosDumpReady = computed(() => props.device?.platform === 'ios' && !!selectedProcess.value)
const activeScriptLabel = computed(() => externalScriptPath.value ? `外部脚本：${externalScriptPath.value}` : selectedScriptPath.value ? `脚本列表：${selectedScriptPath.value}` : '编辑器中的脚本')
const runtimeCoverage = computed(() => devicePlatform.value
  ? runtimeEvidenceCoverage(props.history, devicePlatform.value, selectedProcess.value || props.analysisAppId)
  : [])
const devicePlatform = computed<'android' | 'ios' | undefined>(() => props.device?.platform === 'android' || props.device?.platform === 'ios' ? props.device.platform : undefined)
const runtimeWorkflowDefinitions = computed(() => devicePlatform.value === 'ios'
  ? [
      ['injection', '注入基线', 'ios_injection_probe.js'],
      ['language-runtime', 'ObjC Runtime', 'inspect_objc_runtime.js'],
      ['network-tls', 'Network / TLS / Keychain', 'observe_ios_network_runtime.js'],
      ['webview-bridge', 'WebView / JSBridge', 'observe_ios_jsbridge.js'],
    ] as const
  : [
      ['injection', '注入基线', 'anti_instrumentation_probe.js'],
      ['language-runtime', 'Java / ART', 'inspect_java_runtime.js'],
      ['network-tls', 'Network / TLS', 'observe_android_network_runtime.js'],
      ['webview-bridge', 'WebView / JSBridge', 'observe_android_webview_runtime.js'],
      ['storage-crypto', 'Storage / Crypto', 'observe_android_storage_crypto_runtime.js'],
      ['root-environment', 'Root 环境', 'inspect_root_indicators.js'],
    ] as const)
const runtimeWorkflowSteps = computed(() => runtimeWorkflowDefinitions.value.flatMap(([key, label, fileName]) => {
  const scriptEntry = visibleScripts.value.find((item) => item.path.endsWith(fileName))
  return scriptEntry ? [{ key: key as RuntimeEvidenceStepKey, label, scriptPath: scriptEntry.path }] : []
}))
const runtimeWorkflowReady = computed(() => !!selectedProcess.value && runtimeWorkflowSteps.value.length === runtimeWorkflowDefinitions.value.length)

watch(() => appConfig.iosCompatibilityProfile, (value) => { iosCompatibilityProfile.value = value })
watch(() => props.device?.platform, (platform) => { mode.value = platform === 'ios' ? 'spawn' : 'attach' })
watch(selectedScriptPath, (value) => {
  if (!value) return
  externalScriptPath.value = ''
  script.value = ''
})
watch(externalScriptPath, (value) => { if (value) selectedScriptPath.value = '' })
watch(() => props.analysisAppId, (appId) => {
  if (!appId) return
  const match = props.processes.find((process) => process.identifier.toLowerCase() === appId.toLowerCase())
  selectedProcess.value = match?.identifier || ''
}, { immediate: true })
watch(() => props.processes.map((process) => process.identifier).join('\n'), () => {
  if (selectedProcess.value || !props.analysisAppId) return
  const match = props.processes.find((process) => process.identifier.toLowerCase() === props.analysisAppId?.toLowerCase())
  if (match) selectedProcess.value = match.identifier
})

function applyGuidanceRequest() {
  const request = props.guidanceRequest
  if (!request || request.purpose !== 'anti-instrumentation' || appliedGuidanceId.value === request.id) return
  const target = props.processes.find((process) => process.identifier.toLowerCase() === request.appId.toLowerCase())
  if (target) {
    selectedProcess.value = target.identifier
    mode.value = target.pid ? 'attach' : 'spawn'
  }
  const fileName = request.platform === 'ios' ? 'ios_injection_probe.js' : 'anti_instrumentation_probe.js'
  const probe = visibleScripts.value.find((item) => item.path.endsWith(fileName))
  if (probe) {
    externalScriptPath.value = ''
    selectedScriptPath.value = probe.path
  }
  if (request.platform === 'ios') iosCompatibilityProfile.value = 'minimal'
  if (target && probe) {
    appliedGuidanceId.value = request.id
    emit('guidance-consumed')
    queueMicrotask(() => { if (!props.running) submit() })
  }
}

watch(
  [
    () => props.guidanceRequest?.id,
    () => props.processes.map((process) => `${process.identifier}:${process.pid || 0}`).join('\n'),
    () => props.scripts.map((item) => item.path).join('\n'),
  ],
  applyGuidanceRequest,
  { immediate: true },
)

async function copyIosCountermeasure() {
  try {
    await navigator.clipboard.writeText(IOS_COUNTERMEASURE_COMMAND)
    copyFeedback.value = '已复制'
    window.setTimeout(() => { copyFeedback.value = '' }, 1800)
  } catch {
    copyFeedback.value = '复制失败，请检查权限'
    window.setTimeout(() => { copyFeedback.value = '' }, 2400)
  }
}

function runBuiltinDiagnostic(fileName: 'ios_injection_probe.js' | 'ios_termination_trace.js' | 'observe_jmprotection.js' | 'inspect_objc_runtime.js' | 'observe_ios_network_runtime.js' | 'observe_ios_jsbridge.js' | 'inspect_classloader.js') {
  const scriptEntry = visibleScripts.value.find((item) => item.path.endsWith(fileName))
  if (!scriptEntry || !selectedProcess.value || props.running) return
  externalScriptPath.value = ''
  selectedScriptPath.value = scriptEntry.path
  if (fileName === 'ios_injection_probe.js') iosCompatibilityProfile.value = 'minimal'
  if (mode.value === 'attach' && !selectedTarget.value?.pid) mode.value = 'spawn'
  submit()
}

function runtimeStatus(key: RuntimeEvidenceStepKey) {
  return runtimeCoverage.value.find((step) => step.key === key)?.status || 'idle'
}

function runtimeStatusLabel(key: RuntimeEvidenceStepKey) {
  return ({ idle: '未执行', complete: '已完成', blocked: '被拦截' } as const)[runtimeStatus(key)]
}

function emitRuntimeWorkflow(steps: RuntimeWorkflowStep[]) {
  if (!selectedProcess.value || props.running || !steps.length) return
  emit('runtime-workflow', {
    process: selectedProcess.value,
    pid: selectedTarget.value?.pid,
    mode: mode.value === 'attach' && selectedTarget.value?.pid ? 'attach' : 'spawn',
    durationSeconds: observationDuration.value,
    compatibilityProfile: devicePlatform.value === 'ios' ? iosCompatibilityProfile.value : undefined,
    steps,
  })
}

function runRuntimeStep(step: RuntimeWorkflowStep & { label: string }) {
  emitRuntimeWorkflow([{ key: step.key, scriptPath: step.scriptPath }])
}

function runFullRuntimeWorkflow() {
  emitRuntimeWorkflow(runtimeWorkflowSteps.value.map(({ key, scriptPath }) => ({ key, scriptPath })))
}

function useBuiltIn(kind: 'dex' | 'so') {
  const scriptEntry = visibleScripts.value.find((item) => kind === 'dex' ? item.category === 'dex-dump' : /dump[_ ]?so|so[_ ]?dump/i.test(item.name))
  if (!scriptEntry) return
  externalScriptPath.value = ''
  selectedScriptPath.value = scriptEntry.path
}

function runDexDump() {
  if (!dexDumpReady.value) return
  emit('dex-dump', { package: selectedProcess.value, scriptPath: activeScriptPath.value, destinationDirectory: dexDestination.value || undefined, durationSeconds: dexDuration.value, mode: mode.value as 'attach' | 'spawn', pid: selectedTarget.value?.pid })
}

function runSoDump() {
  if (!soDumpReady.value) return
  emit('so-dump', { package: selectedProcess.value, scriptPath: activeScriptPath.value, destinationDirectory: soDestination.value || undefined, durationSeconds: soDuration.value, mode: mode.value as 'attach' | 'spawn', pid: selectedTarget.value?.pid })
}

function runIosDump() {
  if (iosDumpReady.value) emit('ios-dump', { bundleId: selectedProcess.value, destinationDirectory: iosDestination.value || undefined, mode: mode.value as 'spawn' | 'attach', compatibilityProfile: iosCompatibilityProfile.value })
}

function submit() {
  emit('run', { process: selectedProcess.value, pid: selectedTarget.value?.pid, mode: mode.value, script: script.value, scriptPath: externalScriptPath.value || selectedScriptPath.value || undefined, durationSeconds: observationDuration.value, compatibilityProfile: props.device?.platform === 'ios' ? iosCompatibilityProfile.value : undefined, platform: devicePlatform.value })
}
</script>
