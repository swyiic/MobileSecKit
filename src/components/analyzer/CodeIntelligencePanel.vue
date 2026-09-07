<template>
  <details v-if="items.length" class="code-intelligence analyzer-disclosure">
    <summary class="analyzer-disclosure-summary">
      <div>
        <div class="eyebrow">CODE INTELLIGENCE</div>
        <h3>反编译 / Native 代码入口 <small>{{ filteredItems.length }} / {{ items.length }}</small></h3>
        <p>按需展开检索类、方法、地址、Selector、源码和 Frida 目标。</p>
      </div>
      <span class="material-symbols-outlined disclosure-chevron">expand_more</span>
    </summary>
    <div class="analyzer-disclosure-body">
      <div class="code-intelligence-title">
        <p>APK 展示 JADX 恢复结果；IPA 展示 Objective-C 类/方法、IMP 地址、模块偏移与入口反汇编。</p>
        <input v-model.trim="query" placeholder="搜索类、方法、地址、URL、Selector、源码文件…" />
      </div>
      <div class="code-kind-filters">
        <button :class="{ active: !selectedKind }" @click="selectedKind = ''">全部</button>
        <button
          v-for="kind in kinds"
          :key="kind"
          :class="{ active: selectedKind === kind }"
          @click="selectedKind = selectedKind === kind ? '' : kind"
        >{{ kindLabel(kind) }} ({{ kindCount(kind) }})</button>
      </div>
      <div class="code-table">
        <div class="code-head"><span>类 / 方法</span><span>地址 / 源文件</span></div>
        <template v-for="item in visibleItems" :key="itemKey(item)">
          <button class="code-row" :class="{ expanded: selected === item }" @click="selected = selected === item ? null : item">
            <span>
              <b>{{ kindLabel(item.kind) }}</b>
              <strong>{{ item.className ? `${item.className} :: ` : '' }}{{ item.name }}</strong>
              <small>{{ item.signature || item.references.join(' · ') || item.binary }}</small>
            </span>
            <code>{{ location(item) }}</code>
          </button>
          <div v-if="selected === item" class="code-detail">
            <header><div><strong>{{ item.className ? `${item.className} :: ` : '' }}{{ item.name }}</strong><code>{{ location(item) }}</code></div><button class="icon-button" @click.stop="selected = null">×</button></header>
            <dl>
              <template v-if="item.runtimeTarget"><dt>Frida target</dt><dd><code>{{ item.runtimeTarget }}</code></dd></template>
              <template v-if="item.references.length"><dt>References</dt><dd><code v-for="reference in item.references" :key="reference">{{ reference }}</code></dd></template>
            </dl>
            <pre v-if="item.snippet.length">{{ item.snippet.join('\n') }}</pre>
            <p v-else>已恢复定位信息，但该条目没有附带反汇编或反编译片段。</p>
          </div>
        </template>
      </div>
      <p v-if="filteredItems.length > visibleItems.length" class="empty-hint">当前只渲染前 {{ visibleItems.length }} 条；输入更精确的关键词可筛选全部结果。</p>
    </div>
  </details>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import type { CodeInsight } from '@/types'

const props = defineProps<{ items: CodeInsight[]; focusOnly: boolean }>()
const query = ref('')
const selectedKind = ref('')
const selected = ref<CodeInsight | null>(null)

const lowSignalNames = new Set([
  'tx', 'misuse', 'error', 's', 'local', 'illegal', 'either', 'group', 'task', 'isincluded',
  'allocwithzone', 'automaticallynotifiesobserversforkey', 'initwithcoder', 'swift', 'std', 'http',
  'https', 'isempty', 'iscancelled', 'hastaskgroupstatusrecord', 'distribution', 'sd', 'a',
])
const signalMarkers = [
  'baseurl', 'endpoint', 'request', 'response', 'session', 'urlsession', 'afnetwork', 'alamofire',
  'moya', 'retrofit', 'okhttp', 'socket', 'challenge', 'trust', 'certificate', 'pinning', 'keychain',
  'secureenclave', 'encrypt', 'decrypt', 'signature', 'verify', 'authentication', 'authorize', 'login',
  'logout', 'token', 'password', 'credential', 'fido', 'webview', 'javascript', 'openurl', 'jailbreak',
  'ptrace', 'sysctl', 'dlopen', 'dlsym', 'sectrust', 'secitem', 'cccrypt', 'crypto',
]

function highSignal(item: CodeInsight) {
  if (!props.focusOnly) return true
  const name = item.name.replace(/^[+\- ]+|:+$/g, '').toLocaleLowerCase()
  if (lowSignalNames.has(name)) return false
  if (!['ios-objc-class', 'ios-objc-method', 'android-class', 'android-method', 'ios-native-symbol'].includes(item.kind)) return true
  const searchable = [item.name, item.className, item.signature, item.binary, ...item.references].filter(Boolean).join(' ').toLocaleLowerCase()
  if (signalMarkers.some((marker) => searchable.includes(marker))) return true
  if (/\/Frameworks\/|\/Pods\/|libswift|swiftstdlib|\.dylib$/i.test(item.binary)) return false
  if (item.kind.endsWith('-class')) return name.length >= 4 && /[a-z]/i.test(name)
  return name.length >= 4 && (item.className?.length || 0) >= 4
}

const kinds = computed(() => [...new Set(props.items.filter(highSignal).map((item) => item.kind))]
  .sort((left, right) => kindLabel(left).localeCompare(kindLabel(right))))
const filteredItems = computed(() => {
  const normalizedQuery = query.value.toLocaleLowerCase()
  return props.items.filter((item) => {
    if (!highSignal(item) || (selectedKind.value && item.kind !== selectedKind.value)) return false
    if (!normalizedQuery) return true
    return [item.kind, item.binary, item.className, item.name, item.signature, item.address, item.moduleOffset, item.sourceFile, item.runtimeTarget, ...item.references]
      .filter(Boolean)
      .some((value) => String(value).toLocaleLowerCase().includes(normalizedQuery))
  })
})
const visibleItems = computed(() => filteredItems.value.slice(0, props.focusOnly ? 500 : 800))

function kindCount(kind: string) {
  return props.items.filter((item) => item.kind === kind && highSignal(item)).length
}

function kindLabel(kind: string) {
  const labels: Record<string, string> = {
    'android-class': 'Android 类', 'android-method': 'Android 方法', 'android-network-entry': 'Android 网络入口',
    'android-tls-entry': 'Android TLS 入口', 'android-webview-entry': 'Android WebView 入口', 'android-crypto-entry': 'Android 加密入口',
    'android-storage-entry': 'Android 存储入口', 'android-loader-entry': 'Android 动态加载入口', 'ios-objc-class': 'Objective-C 类',
    'ios-objc-method': 'Objective-C 方法', 'ios-network-entry': 'iOS 网络入口', 'ios-tls-entry': 'iOS TLS 入口',
    'ios-webview-entry': 'iOS WebView 入口', 'ios-crypto-entry': 'iOS 加密入口', 'ios-security-entry': 'iOS 安全检查入口',
    'ios-native-symbol': 'iOS Native 符号', 'ios-native-import': 'iOS Native 导入', 'ios-codeprotect-map': 'JMCodeProtect 映射',
  }
  return labels[kind] || kind
}

function location(item: CodeInsight) {
  if (item.sourceFile) return `${item.sourceFile}${item.lineNumber ? `:${item.lineNumber}` : ''}`
  return [item.address, item.moduleOffset ? `module+${item.moduleOffset}` : '', item.binary].filter(Boolean).join(' · ')
}

function itemKey(item: CodeInsight) {
  return [item.platform, item.kind, item.binary, item.className, item.name, item.address, item.sourceFile, item.lineNumber].join(':')
}
</script>
