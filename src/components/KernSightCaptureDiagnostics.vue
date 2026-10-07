<template>
  <section v-if="diagnostics.visible" class="ks-capture-diagnostics" aria-label="阶段失败诊断">
    <header>
      <strong>失败诊断</strong>
      <button type="button" class="ghost-button" :disabled="copying" @click.stop="copyDiagnostics">{{ copying ? '复制中…' : '复制已留存诊断 JSON' }}</button>
    </header>
    <p class="diagnostic-source">{{ diagnostics.sourceLabel }}</p>
    <p v-if="diagnostics.scopeLabel" class="diagnostic-note">{{ diagnostics.scopeLabel }}</p>
    <pre v-if="diagnostics.cause" class="diagnostic-cause">{{ diagnostics.cause }}</pre>
    <dl v-if="diagnostics.kind !== null || diagnostics.errno !== null" class="diagnostic-fields">
      <template v-if="diagnostics.kind !== null"><dt>失败类型</dt><dd>{{ diagnostics.kind }}</dd></template>
      <template v-if="diagnostics.errno !== null"><dt>errno</dt><dd>{{ diagnostics.errno }}</dd></template>
    </dl>
    <details v-if="diagnostics.expected !== null || diagnostics.observed !== null">
      <summary>预期与实际来源</summary>
      <p>预期（expected）</p><pre>{{ diagnostics.expected ?? '未知（缺字段）' }}</pre>
      <p>实际（observed）</p><pre>{{ diagnostics.observed ?? '未知（缺字段）' }}</pre>
    </details>
    <p class="diagnostic-note">{{ diagnostics.producerExitLabel }} · {{ diagnostics.targetExitLabel }}。生产者退出不等于目标进程退出，未确认也不代表仍存活。</p>
    <p v-for="warning in diagnostics.warnings" :key="warning" class="diagnostic-warning">{{ warning }}</p>
    <p v-if="diagnostics.byteLabel" class="diagnostic-note">{{ diagnostics.byteLabel }}</p>
    <p v-if="copyStatus" :role="copyFailed ? 'alert' : 'status'" :class="copyFailed ? 'diagnostic-warning' : 'diagnostic-note'">{{ copyStatus }}</p>
    <details v-if="diagnostics.rawTail">
      <summary>原始输出尾部（已留存部分）</summary>
      <pre>{{ diagnostics.rawTail }}</pre>
    </details>
    <details>
      <summary>已留存诊断 JSON</summary>
      <p class="diagnostic-note">含父会话 / 阶段 / attempt ID、状态、错误、结构化诊断、生命周期与原始尾部。不是完整原始 stdout / stderr。</p>
      <pre tabindex="0" aria-label="可手动复制的已留存阶段诊断 JSON">{{ retainedJson }}</pre>
    </details>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import type { KernSightCaptureAttempt, KernSightCaptureGroup } from '@/types/monitoring'
import { captureAttemptDiagnostics, retainedStageDiagnosticsJson, copyRetainedStageDiagnostics } from '@/services/kernsightCaptureDiagnostics'

const props = defineProps<{ group: KernSightCaptureGroup; attempt: KernSightCaptureAttempt }>()
const diagnostics = computed(() => captureAttemptDiagnostics(props.group, props.attempt))
const retainedJson = computed(() => retainedStageDiagnosticsJson(props.group, props.attempt))
const copying = ref(false)
const copyStatus = ref('')
const copyFailed = ref(false)
watch(retainedJson, () => { copyStatus.value = ''; copyFailed.value = false })
async function copyDiagnostics() {
  if (copying.value) return
  copying.value = true
  copyStatus.value = ''
  const copiedJson = retainedJson.value
  try {
    const result = await copyRetainedStageDiagnostics(copiedJson)
    if (retainedJson.value === copiedJson) {
      copyStatus.value = result.message
      copyFailed.value = !result.ok
    }
  } finally {
    copying.value = false
  }
}
</script>

<style scoped>
.ks-capture-diagnostics { min-width: 0; margin-top: 10px; padding: 10px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-soft); font-size: 11px; }
header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
header strong { font-size: 12px; }
button { white-space: normal; max-width: 100%; }
p { margin: 7px 0; line-height: 1.55; overflow-wrap: anywhere; }
.diagnostic-source { color: var(--muted); }
.diagnostic-cause { padding: 9px; color: var(--red); background: var(--surface); border-radius: 6px; }
.diagnostic-note { color: var(--muted); }
.diagnostic-warning { color: var(--amber); }
.diagnostic-fields { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 5px 10px; margin: 8px 0; }
dt { color: var(--muted); }
dd { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; }
details { min-width: 0; margin-top: 8px; }
summary { cursor: pointer; line-height: 1.55; overflow-wrap: anywhere; }
pre { max-width: 100%; max-height: 280px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 11px; line-height: 1.55; user-select: text; }
@media (max-width: 650px) { header { align-items: flex-start; } header button { font-size: 11px; } }
</style>
