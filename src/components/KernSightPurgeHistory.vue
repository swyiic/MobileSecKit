<template>
  <details v-if="reports.length" class="purge-history" :open="visible.some(r => r.state !== 'completed' && r.state !== 'prepared')">
    <summary>永久清理记录 · 显示 {{ visible.length }} · 已隐藏 {{ hidden.length }}</summary>
    <p>隐藏可恢复，原日志保留。历史 pending 不表示当前仍有残留。设备处理需新预览并确认。</p>
    <p v-if="storageError" role="alert">{{ storageError }}</p>
    <article v-for="report in visible" :key="report.id">
      <strong>{{ purgeReportLabel(report) }}</strong>
      <FullValue label="清理父会话 ID" :value="report.parentId" monospace /><FullValue label="清理设备" :value="report.serial" monospace /><FullValue label="清理包名" :value="report.package" monospace />
      <p>本地 {{ report.localState }} · 手机 {{ report.deviceState }} · 更新 {{ new Date(report.updatedUnixMs).toLocaleString() }}</p>
      <p v-if="report.error">{{ report.error }}</p><p v-for="warning in report.warnings" :key="warning">{{ warning }}</p>
      <button v-if="report.state !== 'completed' && report.state !== 'prepared'" :disabled="busy || report.state === 'running'" @click="emit('retry', report)">重新预览剩余清理</button>
      <button :disabled="busy || report.state === 'running'" @click="setHidden(report, true)">隐藏历史（保留日志）</button>
    </article>
    <details v-if="hidden.length"><summary>恢复已隐藏历史（{{ hidden.length }}）</summary>
      <article v-for="report in hidden" :key="report.id"><FullValue label="已隐藏清理父会话 ID" :value="report.parentId" monospace /><p>{{ purgeReportLabel(report) }} · 手机 {{ report.deviceState }}</p><button @click="setHidden(report, false)">恢复显示</button></article>
    </details>
    <button :disabled="busy" @click="emit('refresh')">刷新清理记录</button>
  </details>
</template>
<script setup lang="ts">
import { computed, ref } from 'vue'
import FullValue from '@/components/FullValue.vue'
import { purgeReportLabel } from '@/services/kernsightGroupPurge'
import type { KernSightGroupPurgeReport } from '@/types/monitoring'
import { purgeHistoryKey as key, updateHiddenPurgeKeys } from '@/services/kernsightPurgeHistory'
const props = defineProps<{ reports: KernSightGroupPurgeReport[]; busy: boolean }>()
const emit = defineEmits<{ retry: [report: KernSightGroupPurgeReport]; refresh: [] }>()
const storageKey = 'mobilee.purge-history-hidden.v1'
const storageError = ref('')
const hiddenKeys = ref<string[]>([])
try {
  const saved: unknown = JSON.parse(localStorage.getItem(storageKey) || '[]')
  if (Array.isArray(saved)) hiddenKeys.value = saved.filter((s): s is string => typeof s === 'string' && s.length < 160).slice(-1024)
} catch { storageError.value = '隐藏记录无法读取；显示全部原始状态。' }
const hidden = computed(() => props.reports.filter(r => hiddenKeys.value.includes(key(r))))
const visible = computed(() => props.reports.filter(r => !hiddenKeys.value.includes(key(r))))
function setHidden(report: KernSightGroupPurgeReport, hide: boolean) {
  const next = updateHiddenPurgeKeys(hiddenKeys.value, report, hide)
  try { localStorage.setItem(storageKey, JSON.stringify(next.slice(-1024))); hiddenKeys.value = next.slice(-1024); storageError.value = '' }
  catch { storageError.value = '隐藏记录无法保存；原始状态和日志未改变。' }
}
</script>
<style scoped>
.purge-history { margin: 12px 0; padding: 12px; border: 1px solid var(--line, #354252); overflow-wrap: anywhere; }
article { margin: 12px 0; padding: 8px; border-top: 1px solid var(--line, #354252); }
button { margin: 4px; }
</style>
