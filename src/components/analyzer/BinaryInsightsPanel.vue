<template>
  <details v-if="items.length" class="binary-insights analyzer-disclosure">
    <summary class="analyzer-disclosure-summary">
      <div>
        <div class="eyebrow">BINARY INTELLIGENCE</div>
        <h3>Framework / Native 证据 <small>{{ groups.length }} 类 / {{ items.length }} 个目标</small></h3>
        <p>按类别整理二进制入口；展开后查看逐文件证据。</p>
      </div>
      <span class="material-symbols-outlined disclosure-chevron">expand_more</span>
    </summary>
    <div class="analyzer-disclosure-body">
      <details v-for="group in groups" :key="group.category" class="binary-insight-group">
        <summary class="binary-group-header">
          <h4>{{ group.category }}</h4>
          <small>{{ group.items.length }} 个文件 / 模块</small>
          <span class="material-symbols-outlined">expand_more</span>
        </summary>
        <details v-for="insight in group.items" :key="`${insight.category}:${insight.target}`" class="binary-target">
          <summary>
            <b :class="`finding-${insight.severity}`">{{ insight.severity }}</b>
            <strong>{{ insight.target }}</strong>
            <small>{{ insight.evidence.length }} 条证据</small>
            <span class="material-symbols-outlined">chevron_right</span>
          </summary>
          <div class="binary-target-detail">
            <p>{{ insight.detail }}</p>
            <ol class="binary-evidence"><li v-for="value in insight.evidence" :key="value"><code>{{ value }}</code></li></ol>
          </div>
        </details>
      </details>
    </div>
  </details>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { BinaryInsight } from '@/types'

const props = defineProps<{ items: BinaryInsight[]; focusOnly: boolean }>()

const categoryOrder = [
  'Objective-C 类结构', '二进制 BaseURL / Endpoint', 'Objective-C 方法/Selector',
  'AFNetworking 网络入口', 'AFNetworking TLS 配置', 'TLS / Pinning 入口',
  'WebView / URL 跳转入口', 'iOS 第三方代码保护', '动态加载 / 存储 / 加密入口',
  'Flutter AOT/Channel', 'Flutter MethodChannel 候选', 'Alamofire 网络入口',
  'Alamofire TLS / Pinning', 'Moya 网络 / Endpoint 入口', 'URLSession / CFNetwork 网络入口',
  'NIOSSL / NIOTLS TLS 入口', 'SwiftNIO 网络 / EventLoop 入口', 'Keychain / Secure Enclave 入口',
  'WebKit / JavaScriptCore 桥接', 'FaceLive / 活体检测 SDK', '第三方代码保护 / 运行时恢复',
]

function hasPlaceholder(value: string) {
  const lower = value.toLocaleLowerCase()
  return ['%@', '%d', '%ld', '%lu', '%s', '${', '$(', '{{', '}}', '{host}', '{domain}', '{baseurl}'].some((marker) => lower.includes(marker))
}

function highSignal(value: string) {
  const trimmed = value.trim()
  const lower = trimmed.toLocaleLowerCase()
  if (!trimmed || hasPlaceholder(trimmed)) return false
  if (lower.includes('/runner/work/') || lower.includes('/deriveddata/')) return false
  if (lower.includes('/modules/') && /\.(cpp|cc|cxx)(?:$|\s)/.test(lower)) return false
  return trimmed.length > 2 || /[/:.]/.test(trimmed)
}

const groups = computed(() => {
  const grouped = new Map<string, BinaryInsight[]>()
  for (const insight of props.items) {
    const evidence = props.focusOnly ? insight.evidence.filter(highSignal).slice(0, 80) : insight.evidence
    if (!evidence.length) continue
    grouped.set(insight.category, [...(grouped.get(insight.category) || []), { ...insight, evidence }])
  }
  return [...grouped.entries()]
    .map(([category, groupedItems]) => ({ category, items: groupedItems }))
    .sort((left, right) => {
      const leftIndex = categoryOrder.indexOf(left.category)
      const rightIndex = categoryOrder.indexOf(right.category)
      return (leftIndex < 0 ? Number.MAX_SAFE_INTEGER : leftIndex)
        - (rightIndex < 0 ? Number.MAX_SAFE_INTEGER : rightIndex)
        || left.category.localeCompare(right.category)
    })
})
</script>
