<template>
  <details class="static-surface analyzer-disclosure" open>
    <summary class="analyzer-disclosure-summary">
      <div>
        <div class="eyebrow">ATTACK SURFACE</div>
        <h3>权限、组件与配置 <small>{{ totalItems }} 项</small></h3>
        <p>红色优先复核，黄色需要结合系统版本、权限保护和业务用途判断。</p>
      </div>
      <span class="material-symbols-outlined disclosure-chevron">expand_more</span>
    </summary>
    <div class="analyzer-disclosure-body static-surface-grid">
      <section>
        <h3>Permissions <small>{{ analysis.permissions.length }}</small><button type="button" class="help-dot" :aria-expanded="help === 'permission'" @click.stop="help = help === 'permission' ? '' : 'permission'">?</button></h3>
        <p v-if="help === 'permission'" class="inline-help">红色为短信、联系人、录音、精确位置、安装包、悬浮窗、全盘存储等高风险权限；黄色需结合 Android 版本、厂商 ROM 和业务场景复核。</p>
        <div class="tag-list"><span v-for="permission in analysis.permissions" :key="permission" :class="`risk-tag-${permissionRisk(permission)}`" :title="permissionHint(permission)">{{ permission }}</span><em v-if="!analysis.permissions.length">未找到 / 工具不可用</em></div>
      </section>
      <section>
        <h3>Components <small>{{ analysis.components.length }}</small><button type="button" class="help-dot" :aria-expanded="help === 'component'" @click.stop="help = help === 'component' ? '' : 'component'">?</button></h3>
        <p v-if="help === 'component'" class="inline-help">重点手测 exported=true 且没有 permission 保护的组件；仅“存在组件”不等于漏洞。</p>
        <div class="tag-list"><span v-for="component in analysis.components" :key="component" :class="`risk-tag-${componentRisk(component)}`" :title="componentHint(component)">{{ component }}</span><em v-if="!analysis.components.length">未找到 / 工具不可用</em></div>
      </section>
      <section>
        <h3>{{ analysis.platform === 'ios' ? 'Info.plist / Entitlements' : 'Manifest security flags' }} <small>{{ analysis.manifestFlags.length }}</small><button type="button" class="help-dot" :aria-expanded="help === 'manifest'" @click.stop="help = help === 'manifest' ? '' : 'manifest'">?</button></h3>
        <p v-if="help === 'manifest'" class="inline-help">{{ analysis.platform === 'ios' ? '重点检查 ATS、get-task-allow、文件共享、后台模式及隐私用途声明。' : 'debuggable=true、allowBackup=true、usesCleartextTraffic=true 通常需要醒目标记；最终风险仍取决于 targetSdk、网络安全配置和业务数据。' }}</p>
        <div class="tag-list"><span v-for="flag in analysis.manifestFlags" :key="flag" :class="`risk-tag-${manifestRisk(flag)}`" :title="manifestHint(flag)">{{ flag }}</span><em v-if="!analysis.manifestFlags.length">未显式配置</em></div>
      </section>
      <section>
        <h3>Exported components <small>{{ analysis.exportedComponents.length }}</small><button type="button" class="help-dot" :aria-expanded="help === 'exported'" @click.stop="help = help === 'exported' ? '' : 'exported'">?</button></h3>
        <p v-if="help === 'exported'" class="inline-help">导出组件是外部入口，不一定是漏洞；无权限保护、接受外部 URI/Intent 或触发敏感操作时风险更高。</p>
        <div class="tag-list"><span v-for="component in analysis.exportedComponents" :key="component" :class="`risk-tag-${componentRisk(component)}`" :title="componentHint(component)">{{ component }}</span><em v-if="!analysis.exportedComponents.length">未发现 exported=true</em></div>
      </section>
      <section>
        <h3>Intent Filters / Deep Links <small>{{ analysis.intentFilters.length }}</small><button type="button" class="help-dot" :aria-expanded="help === 'intent'" @click.stop="help = help === 'intent' ? '' : 'intent'">?</button></h3>
        <p v-if="help === 'intent'" class="inline-help">重点检查 Scheme、HTTP(S) App Link 的 host/path 限制、参数校验和登录态。</p>
        <div class="tag-list"><span v-for="filter in analysis.intentFilters" :key="filter" class="risk-tag-review">{{ filter }}</span><em v-if="!analysis.intentFilters.length">未发现自定义 Intent Filter</em></div>
      </section>
      <section>
        <h3>Third-party SDKs / Libraries <small>{{ analysis.thirdPartyLibraries.length }}</small><button type="button" class="help-dot" :aria-expanded="help === 'sdk'" @click.stop="help = help === 'sdk' ? '' : 'sdk'">?</button></h3>
        <p v-if="help === 'sdk'" class="inline-help">结果用于建立依赖清单；准确版本和 CVE 仍需结合构建元数据或 SBOM 确认。</p>
        <div class="tag-list"><span v-for="library in analysis.thirdPartyLibraries" :key="library" class="risk-tag-normal">{{ library }}</span><em v-if="!analysis.thirdPartyLibraries.length">未识别到已知 SDK 特征</em></div>
      </section>
    </div>
  </details>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import type { AppAnalysis } from '@/types'

const props = defineProps<{ analysis: AppAnalysis }>()
const help = ref('')
const totalItems = computed(() => props.analysis.permissions.length
  + props.analysis.components.length
  + props.analysis.manifestFlags.length
  + props.analysis.exportedComponents.length
  + props.analysis.intentFilters.length
  + props.analysis.thirdPartyLibraries.length)

const highPermissions = ['READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'MANAGE_EXTERNAL_STORAGE', 'REQUEST_INSTALL_PACKAGES', 'SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS', 'PACKAGE_USAGE_STATS', 'QUERY_ALL_PACKAGES', 'BIND_ACCESSIBILITY_SERVICE']
const reviewPermissions = ['READ_PHONE_STATE', 'READ_MEDIA_', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'BLUETOOTH_', 'BODY_SENSORS', 'POST_NOTIFICATIONS', 'FOREGROUND_SERVICE', 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS', 'USE_BIOMETRIC', 'NFC']

function permissionRisk(permission: string) {
  if (highPermissions.some((value) => permission.includes(value))) return 'high'
  if (reviewPermissions.some((value) => permission.includes(value)) || !permission.startsWith('android.permission.')) return 'review'
  return 'normal'
}

function permissionHint(permission: string) {
  const risk = permissionRisk(permission)
  if (risk === 'high') return '高敏感权限：确认业务必要性、最小授权、运行时请求和数据保护'
  if (risk === 'review') return '需要结合 Android 版本、厂商 ROM 和实际调用场景复核'
  return '未按内置规则标为高风险；仍需结合业务用途判断'
}

function componentRisk(component: string) {
  if (component.includes('exported=true') && !component.includes('permission=')) return 'high'
  if (component.includes('exported=true') || component.includes('implicit/unspecified')) return 'review'
  return 'normal'
}

function componentHint(component: string) {
  if (componentRisk(component) === 'high') return '导出且未发现组件级权限保护，建议手动构造 Intent/Provider 请求验证'
  if (componentRisk(component) === 'review') return '需要结合 intent-filter、targetSdk、调用权限和业务逻辑确认'
  return '当前未发现显式外部暴露；仍需检查动态注册和代码逻辑'
}

function manifestRisk(flag: string) {
  if (/^(debuggable|allowBackup|usesCleartextTraffic)=true$/i.test(flag)) return 'high'
  if (/networkSecurityConfig|extractNativeLibs/i.test(flag)) return 'review'
  return 'normal'
}

function manifestHint(flag: string) {
  return manifestRisk(flag) === 'high' ? '发布配置存在明显安全风险，请结合 targetSdk 与业务数据确认' : '需要结合系统版本和配置文件内容进一步判断'
}
</script>
