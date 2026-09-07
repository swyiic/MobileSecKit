<template>
  <div v-if="props.open" class="settings-backdrop" role="presentation" @click.self="emit('close')" @keydown.esc="emit('close')">
    <aside class="settings-drawer" role="dialog" aria-modal="true" aria-label="全局设置">
      <header class="settings-header">
        <div>
          <div class="eyebrow">APPLICATION SETTINGS</div>
          <h2>全局设置</h2>
          <p>工具路径、分析规则、Android Runtime 与 AI Provider 配置统一从这里管理。</p>
        </div>
        <button class="icon-button" title="关闭设置" @click="closeSettings"><span class="material-symbols-outlined">close</span></button>
      </header>

      <div class="settings-body">
        <section class="settings-section">
          <div class="settings-section-title"><span class="material-symbols-outlined">folder_managed</span><div><strong>工具与路径</strong><small>本机工具、脚本和 Dump 产物目录</small></div></div>
          <label class="settings-field"><span>主机工具目录</span><div class="settings-input-row"><input v-model.trim="appConfig.toolDirectory" placeholder="例如 /opt/homebrew/bin 或 C:\\Android\\platform-tools" /><button class="ghost-button" @click="chooseDirectory('toolDirectory')">选择</button></div></label>
          <label class="settings-field"><span>Frida 外部脚本目录</span><div class="settings-input-row"><input v-model.trim="appConfig.fridaScriptDirectory" placeholder="可留空，或选择 hooker/js 目录" /><button class="ghost-button" @click="chooseDirectory('fridaScriptDirectory')">选择</button></div></label>
          <label class="settings-field"><span>默认外部 Frida 脚本</span><div class="settings-input-row"><input v-model.trim="appConfig.fridaScriptPath" placeholder="/absolute/path/to/script.js" /><button class="ghost-button" @click="chooseScript">选择</button></div></label>
          <label class="settings-field"><span>Android frida-server</span><div class="settings-input-row"><input v-model.trim="appConfig.fridaServerPath" placeholder="按设备 ABI 选择 frida-server" /><button class="ghost-button" @click="chooseFile('fridaServerPath')">选择</button></div></label>
          <label class="settings-field"><span>iOS Developer Disk Image 目录</span><div class="settings-input-row"><input v-model.trim="appConfig.iosDeveloperImageDirectory" placeholder="包含 DeveloperDiskImage.dmg 的目录" /><button class="ghost-button" @click="chooseDirectory('iosDeveloperImageDirectory')">选择</button></div></label>
          <div class="settings-grid">
            <label class="settings-field"><span>DEX 输出目录</span><div class="settings-input-row"><input v-model.trim="appConfig.dexDestination" placeholder="默认桌面 MobileE-Dumps" /><button class="ghost-button" @click="chooseDirectory('dexDestination')">选择</button></div></label>
            <label class="settings-field"><span>SO 输出目录</span><div class="settings-input-row"><input v-model.trim="appConfig.soDestination" placeholder="默认桌面 MobileE-Dumps" /><button class="ghost-button" @click="chooseDirectory('soDestination')">选择</button></div></label>
            <label class="settings-field"><span>iOS Dump 输出目录</span><div class="settings-input-row"><input v-model.trim="appConfig.iosDumpDestination" placeholder="默认桌面 MobileE-Dumps" /><button class="ghost-button" @click="chooseDirectory('iosDumpDestination')">选择</button></div></label>
            <label class="settings-field"><span>iOS 默认兼容策略</span><select v-model="appConfig.iosCompatibilityProfile"><option value="minimal">Minimal</option><option value="compat">Compat</option><option value="aggressive">Aggressive</option></select></label>
            <label class="settings-field settings-toggle"><span><b>Android 启动后自动基础加固</b><small>默认关闭；开启后推送成功会改名并使用随机端口</small></span><input v-model="appConfig.hardenFridaByDefault" type="checkbox" /></label>
          </div>
        </section>

        <section class="settings-section">
          <div class="settings-section-title"><span class="material-symbols-outlined">filter_alt</span><div><strong>分析过滤</strong><small>减少 IPA / APK 报告中的 URL 噪音</small></div></div>
          <label class="settings-field"><span>排除的域名或 URL（每行一条）</span><textarea v-model="appConfig.excludedUrls" placeholder="example.com&#10;*.analytics.example.com&#10;https://cdn.example.com/static/*"></textarea></label>
          <p class="settings-help">裸域名会过滤其子域名；完整 URL 支持前缀匹配。修改后重新分析当前 APK / IPA 才会应用。</p>
          <div class="settings-grid">
            <label class="settings-field"><span>Apktool 路径</span><div class="settings-input-row"><input v-model.trim="appConfig.apktoolPath" placeholder="apktool 或 apktool.jar" /><button class="ghost-button" @click="chooseFile('apktoolPath')">选择</button></div></label>
            <label class="settings-field"><span>JADX 路径</span><div class="settings-input-row"><input v-model.trim="appConfig.jadxPath" placeholder="jadx 或 jadx.jar" /><button class="ghost-button" @click="chooseFile('jadxPath')">选择</button></div></label>
          </div>
        </section>

        <section class="settings-section">
          <div class="settings-section-title"><span class="material-symbols-outlined">monitor_heart</span><div><strong>KernSight 证据链</strong><small>为 L0 Observe / L1 Inspect / L2 Dump 准备部署、USB 通道与缓存策略</small></div></div>
          <div class="settings-grid">
            <label class="settings-field"><span>部署模式</span><select v-model="appConfig.androidMonitorDeploymentMode"><option value="auto">Auto Detect（推荐）</option><option value="development">Dev Root（ADB + su）</option><option value="system">System Image（init / bpfloader）</option></select></label>
            <label class="settings-field"><span>PC 本地转发端口</span><input v-model.number="appConfig.androidMonitorLocalPort" type="number" min="1" max="65535" /></label>
            <label class="settings-field"><span>事件批次大小</span><input v-model.number="appConfig.androidMonitorBatchSize" type="number" min="50" max="5000" step="50" /></label>
            <label class="settings-field"><span>设备断线缓存上限（MB）</span><input v-model.number="appConfig.androidMonitorSpoolLimitMb" type="number" min="64" max="16384" step="64" /></label>
            <label class="settings-field settings-toggle"><span><b>已授权设备自动重连</b><small>USB 恢复后重新建立 ADB 转发并续接已有会话</small></span><input v-model="appConfig.androidMonitorAutoReconnect" type="checkbox" /></label>
            <label class="settings-field settings-toggle"><span><b>自动更新 Dev Agent</b><small>仅对已经确认授权的开发设备生效；首次部署仍必须手动确认</small></span><input v-model="appConfig.androidMonitorAutoProvision" type="checkbox" /></label>
          </div>
          <div class="monitor-settings-note">
            <span class="material-symbols-outlined">usb</span>
            <p><strong>当前规划通道：USB / ADB forward</strong><small>ADB 只负责部署、控制与传输，不参与内核事件采集。TrustZone、TEE 与系统可信区不能在设备连接时通过 ADB 动态写入。</small></p>
          </div>
        </section>

        <section class="settings-section">
          <div class="settings-section-title"><span class="material-symbols-outlined">neurology</span><div><strong>AI Provider</strong><small>云端或本地模型连接参数</small></div></div>
          <div class="settings-grid">
            <label class="settings-field"><span>Provider 类型</span><select v-model="appConfig.aiProviderKind"><option value="ollama">Ollama（本地）</option><option value="openai-compatible">OpenAI-compatible（云端 / 本地）</option></select></label>
            <label class="settings-field"><span>模型标识</span><input v-model.trim="appConfig.aiProviderModel" placeholder="Provider 中的模型名称" /></label>
            <label class="settings-field settings-wide"><span>Base URL</span><input v-model.trim="appConfig.aiProviderBaseUrl" type="url" placeholder="http://127.0.0.1:11434" /></label>
            <label class="settings-field settings-wide"><span>API Key</span><div class="settings-input-row"><input v-model="appConfig.aiProviderApiKey" :type="showApiKey ? 'text' : 'password'" autocomplete="off" placeholder="本地保存，可留空" /><button class="icon-button settings-visibility-button" :title="showApiKey ? '隐藏 API Key' : '显示 API Key'" type="button" @click="showApiKey = !showApiKey"><span class="material-symbols-outlined">{{ showApiKey ? 'visibility_off' : 'visibility' }}</span></button></div></label>
            <label class="settings-field"><span>超时（秒）</span><input v-model.number="appConfig.aiProviderTimeout" type="number" min="10" max="600" /></label>
            <label class="settings-field"><span>最大输出 Tokens</span><input v-model.number="appConfig.aiProviderOutputTokens" type="number" min="400" max="32000" step="100" /></label>
          </div>
          <div class="settings-provider-actions"><button class="primary-button" :disabled="providerTesting" @click="testProvider"><span class="material-symbols-outlined" :class="{ spinning: providerTesting }">{{ providerTesting ? 'sync' : 'wifi_tethering' }}</span>{{ providerTesting ? '测试中…' : '保存并测试连接' }}</button><span v-if="providerMessage" :class="{ error: providerError }">{{ providerMessage }}</span></div>
          <p v-if="availableModels.length" class="settings-help">可用模型：{{ availableModels.slice(0, 8).join(' · ') }}</p>
        </section>
      </div>

      <footer class="settings-footer">
        <span><span class="material-symbols-outlined">check_circle</span>配置自动保存到本机 config.ini</span>
        <button class="primary-button" @click="closeSettings">完成</button>
      </footer>
    </aside>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { open as openDialog } from '@tauri-apps/plugin-dialog'
import { aiBackend } from '@/services/backend'
import { appConfig, saveAppConfigNow, updateAppConfig } from '@/services/config'
import type { AiProviderRequest } from '@/types'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ close: [] }>()
const showApiKey = ref(false)
const providerTesting = ref(false)
const providerMessage = ref('')
const providerError = ref(false)
const availableModels = ref<string[]>([])

watch(() => JSON.stringify(appConfig), () => updateAppConfig({}))

async function closeSettings() {
  try {
    await saveAppConfigNow()
  } catch {
    // Browser preview has no Tauri IPC. Native builds persist normally; the
    // drawer should still close in preview and during shutdown races.
  } finally {
    emit('close')
  }
}

function providerRequest(): AiProviderRequest {
  return {
    providerKind: appConfig.aiProviderKind,
    baseUrl: appConfig.aiProviderBaseUrl,
    apiKey: appConfig.aiProviderApiKey || undefined,
    model: appConfig.aiProviderModel,
    timeoutSeconds: appConfig.aiProviderTimeout,
    maxOutputTokens: appConfig.aiProviderOutputTokens,
  }
}

async function testProvider() {
  providerTesting.value = true
  providerMessage.value = ''
  providerError.value = false
  availableModels.value = []
  try {
    await saveAppConfigNow()
    const status = await aiBackend.testProvider(providerRequest())
    providerMessage.value = status.message
    providerError.value = !status.success
    availableModels.value = status.availableModels
  } catch (error) {
    providerMessage.value = `连接失败：${String(error)}`
    providerError.value = true
  } finally {
    providerTesting.value = false
  }
}

async function chooseDirectory(key: 'toolDirectory' | 'fridaScriptDirectory' | 'iosDeveloperImageDirectory' | 'dexDestination' | 'soDestination' | 'iosDumpDestination') {
  const selected = await openDialog({ directory: true, multiple: false })
  if (typeof selected === 'string') updateAppConfig({ [key]: selected })
}

async function chooseFile(key: 'fridaServerPath' | 'apktoolPath' | 'jadxPath') {
  const selected = await openDialog({ directory: false, multiple: false })
  if (typeof selected === 'string') updateAppConfig({ [key]: selected })
}

async function chooseScript() {
  const selected = await openDialog({ multiple: false, filters: [{ name: 'Frida JavaScript', extensions: ['js'] }] })
  if (typeof selected === 'string') updateAppConfig({ fridaScriptPath: selected })
}
</script>
