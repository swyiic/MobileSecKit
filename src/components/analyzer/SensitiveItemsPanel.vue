<template>
  <details class="sensitive-panel analyzer-disclosure" open>
    <summary class="analyzer-disclosure-summary">
      <div>
        <div class="eyebrow">SENSITIVE EVIDENCE</div>
        <h3>敏感信息与位置 <small>{{ visibleItems.length }} / {{ activeCount }} 有效候选</small></h3>
        <p>点击单条结果可查看完整值和上下文；规则过滤项不会被删除，可随时复核。</p>
      </div>
      <span class="material-symbols-outlined disclosure-chevron">expand_more</span>
    </summary>
    <div class="analyzer-disclosure-body">
      <div v-if="filteredCount" class="sensitive-filter-toolbar">
        <span>已由低噪声规则过滤 {{ filteredCount }} 条</span>
        <label><input v-model="showFiltered" type="checkbox" /> 显示过滤项</label>
      </div>
      <div v-if="visibleItems.length" class="sensitive-table">
        <div class="sensitive-head"><span>敏感信息 / 预览</span><span>地址</span></div>
        <template v-for="(item, itemIndex) in visibleItems" :key="`${item.item}:${item.location}:${item.value}`">
          <button class="sensitive-row" :class="{ expanded: selected === item, filtered: item.filtered }" @click="selected = selected === item ? null : item">
            <span><b :class="`finding-${item.severity}`">{{ item.item }}</b><em v-if="item.source === 'binary-strings'">二进制字符串</em><em v-if="item.filtered">已过滤噪声</em><small>{{ valuePreview(item) }}</small></span>
            <code>{{ item.location }}{{ item.lineNumber ? `:${item.lineNumber}` : '' }}</code>
          </button>
          <div v-if="selected === item" class="sensitive-detail sensitive-detail-row">
            <header>
              <div><strong>{{ item.item }}</strong><code>{{ item.location }}{{ item.lineNumber ? `:${item.lineNumber}` : '' }}</code></div>
              <button class="icon-button" @click.stop="selected = null">×</button>
            </header>
            <p v-if="item.source" class="sensitive-source-note">扫描来源：{{ sourceLabel(item.source) }}</p>
            <div v-if="item.value" class="sensitive-detail-actions">
              <button class="ghost-button compact-button" @click="copyValue(item)">复制完整值</button>
              <button v-if="isPrivateKey(item)" class="ghost-button compact-button" @click="exportValue(item, itemIndex)">导出 PEM</button>
              <span v-if="isPrivateKey(item)">完整私钥只在当前本地详情中显示；HTML / Data Boundaries / AI Context 不会内联原文。</span>
            </div>
            <pre v-if="item.value" class="sensitive-full-value">{{ item.value }}</pre>
            <p v-else>仅命中文件名规则，没有可复制的扫描值。</p>
            <p v-if="item.filterReason" class="sensitive-filter-reason"><strong>过滤原因：</strong>{{ item.filterReason }}</p>
            <details v-if="item.context" class="sensitive-context"><summary>查看命中上下文</summary><pre>{{ item.context }}</pre></details>
          </div>
        </template>
      </div>
      <p v-else class="empty-hint">未发现按名称或文本模式匹配的线索；请结合运行时测试复核。</p>
    </div>
  </details>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { save } from '@tauri-apps/plugin-dialog'
import { backend, readableError } from '@/services/backend'
import type { SensitiveItem } from '@/types'

const props = defineProps<{ items: SensitiveItem[]; fileName: string; focusOnly: boolean }>()
const emit = defineEmits<{ message: [message: string] }>()
const selected = ref<SensitiveItem | null>(null)
const showFiltered = ref(false)
const filteredCount = computed(() => props.items.filter((item) => item.filtered).length)
const activeCount = computed(() => props.items.length - filteredCount.value)

function hasPlaceholder(value: string) {
  const lower = value.toLocaleLowerCase()
  return ['%@', '%d', '%ld', '%lu', '%s', '${', '$(', '{{', '}}', '{host}', '{domain}', '{baseurl}'].some((marker) => lower.includes(marker))
}

const visibleItems = computed(() => props.items.filter((item) => {
  if (item.filtered && !showFiltered.value) return false
  if (!props.focusOnly) return true
  const value = item.value || ''
  const lowerLocation = item.location.toLocaleLowerCase()
  if (hasPlaceholder(value)) return false
  if (lowerLocation.includes('/runner/work/') || lowerLocation.includes('/deriveddata/')) return false
  if (item.kind === 'ip' && /opencv|version|podspec|gradle|maven|\/modules\/|\.(cpp|cc|cxx)/i.test(`${item.context || ''} ${item.location}`)) return false
  return item.severity === 'high' || ['url', 'api-endpoint', 'ip', 'email', 'crypto'].includes(item.kind)
}))

function isPrivateKey(item: SensitiveItem) {
  return item.kind === 'private-key'
}

function valuePreview(item: SensitiveItem) {
  if (!item.value) return '文件名线索'
  if (isPrivateKey(item)) {
    const complete = item.value.includes('-----END ') && item.value.includes('PRIVATE KEY-----')
    return `${complete ? '完整 PEM' : 'PEM 开头（未找到 END）'} · ${item.value.length.toLocaleString()} 字符`
  }
  const singleLine = item.value.replace(/\s+/g, ' ').trim()
  return singleLine.length > 180 ? `${singleLine.slice(0, 180)}…` : singleLine
}

function sourceLabel(source: string) {
  return ({ 'binary-strings': 'SO / DEX / Mach-O 可见字符串', 'text-resource': '文本资源或反编译源码', 'archive-entry': '归档文件名规则' } as Record<string, string>)[source] || source
}

async function copyValue(item: SensitiveItem) {
  if (!item.value) return
  try {
    await navigator.clipboard.writeText(item.value)
    emit('message', `${item.item} 的完整值已复制到剪贴板。`)
  } catch (cause) {
    emit('message', `复制失败：${readableError(cause)}`)
  }
}

async function exportValue(item: SensitiveItem, itemIndex: number) {
  if (!item.value) return
  const baseName = props.fileName.replace(/\.(apk|ipa)$/i, '') || 'app'
  const outputPath = await save({
    defaultPath: `${baseName}-private-key-${itemIndex + 1}.pem`,
    filters: [{ name: 'PEM private key', extensions: ['pem', 'key'] }],
  })
  if (!outputPath) return
  try {
    const written = await backend.exportSensitiveValue(item.value, outputPath)
    emit('message', `PEM 已导出（本机权限 0600）：${written}`)
  } catch (cause) {
    emit('message', `PEM 导出失败：${readableError(cause)}`)
  }
}
</script>
