<template>
  <div class="full-value" :class="{ 'full-value-mono': monospace }">
    <p class="full-value-text" :title="value || undefined">{{ value || emptyText }}</p>
    <button v-if="value" type="button" class="full-value-copy" :disabled="copying" :aria-label="`复制完整${label}`" @click.stop="copy">{{ copying ? '复制中…' : '复制' }}</button>
    <p v-if="feedback" class="full-value-feedback" :role="failed ? 'alert' : 'status'">{{ feedback }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
const props = withDefaults(defineProps<{ value?: string | null; label: string; monospace?: boolean; emptyText?: string }>(), { emptyText: '未知（未提供）' })
const copying = ref(false)
const feedback = ref('')
const failed = ref(false)
let revision = 0
watch(() => props.value, () => { revision++; feedback.value = ''; failed.value = false; copying.value = false })
async function copy() {
  if (copying.value || !props.value) return
  const current = revision
  copying.value = true
  feedback.value = ''
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable')
    await navigator.clipboard.writeText(props.value)
    if (current === revision) { failed.value = false; feedback.value = '已复制完整值' }
  } catch {
    if (current === revision) { failed.value = true; feedback.value = '复制失败，请选择上方完整文本手动复制' }
  } finally {
    if (current === revision) copying.value = false
  }
}
</script>

<style scoped>
.full-value { display:flex; flex-wrap:wrap; align-items:flex-start; gap:5px 8px; min-width:0; max-width:100%; }
.full-value .full-value-text { flex:1 1 140px; min-width:0; margin:0; color:var(--text); font-size:11px; font-weight:550; line-height:1.6; white-space:pre-wrap; overflow-wrap:anywhere; word-break:normal; user-select:text; }
.full-value-mono .full-value-text { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
.full-value-copy { flex:0 0 auto; padding:2px 5px; border:1px solid var(--line-strong); border-radius:5px; color:var(--primary); background:transparent; font-size:10px; line-height:1.6; cursor:pointer; }
.full-value-copy:focus-visible { outline:2px solid var(--primary); outline-offset:2px; }
.full-value .full-value-feedback { flex-basis:100%; margin:0; font-size:10px; line-height:1.5; color:var(--muted); overflow-wrap:anywhere; }
.full-value .full-value-feedback[role='alert'] { color:var(--amber); }
</style>
