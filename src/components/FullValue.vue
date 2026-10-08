<template>
  <div ref="container" class="full-value" :class="{ 'full-value-mono': monospace }" @mouseenter="showPreview" @mouseleave="deferHide" @focusin="showPreview" @focusout="deferHide">
    <button v-if="value" type="button" class="full-value-text" :disabled="copying" :aria-label="`复制完整${label}`" :aria-describedby="previewVisible ? previewId : undefined" :title="`${label}：点击或按 Enter 复制完整值`" @click.stop="copy" @keydown.esc.stop="hidePreview">{{ value }}</button>
    <p v-else class="full-value-empty">{{ emptyText }}</p>
    <span v-if="feedback" class="full-value-feedback" :role="failed ? 'alert' : 'status'">{{ feedback }}</span>
    <Teleport to="body">
      <div v-if="previewVisible && value" :id="previewId" class="full-value-preview" :class="{ 'full-value-mono': monospace }" :style="previewStyle" @mouseenter="cancelHide" @mouseleave="deferHide">
        <small>{{ label }} · 点击字段或按 Enter 复制完整值；也可选择下方文本</small>
        <pre>{{ value }}</pre>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
const props = withDefaults(defineProps<{ value?: string | null; label: string; monospace?: boolean; emptyText?: string }>(), { emptyText: '未知（未提供）' })
const container = ref<HTMLElement>()
const previewId = useId()
const previewVisible = ref(false)
const previewStyle = ref<Record<string, string>>({})
const copying = ref(false)
const feedback = ref('')
const failed = ref(false)
let revision = 0
let hideTimer: ReturnType<typeof setTimeout> | undefined
let feedbackTimer: ReturnType<typeof setTimeout> | undefined
function cancelHide() { clearTimeout(hideTimer) }
function hidePreview() { cancelHide(); previewVisible.value = false }
function showPreview() {
  cancelHide()
  if (!props.value || !container.value) return
  window.dispatchEvent(new CustomEvent('me-full-value-preview', { detail: previewId }))
  const rect = container.value.getBoundingClientRect()
  const width = Math.max(1, Math.min(480, window.innerWidth - 24))
  const top = Math.max(12, Math.min(rect.bottom + 6, window.innerHeight - 240))
  previewStyle.value = { left: `${Math.max(12, Math.min(rect.left, window.innerWidth - width - 12))}px`, top: `${top}px`, width: `${width}px`, maxHeight: `${Math.max(60, window.innerHeight - top - 12)}px` }
  previewVisible.value = true
}
function deferHide() {
  cancelHide()
  hideTimer = setTimeout(() => {
    if (!container.value?.contains(document.activeElement)) previewVisible.value = false
  }, 120)
}
watch(() => props.value, () => { revision++; clearTimeout(feedbackTimer); hidePreview(); feedback.value = ''; failed.value = false; copying.value = false })
async function copy(event: MouseEvent) {
  // Drag selection and modifier clicks must not overwrite the clipboard.
  if (event.detail > 1 || event.ctrlKey || event.metaKey || event.altKey || event.shiftKey || window.getSelection()?.toString()) return
  if (copying.value || !props.value) return
  const current = revision
  const original = props.value
  copying.value = true
  feedback.value = ''
  clearTimeout(feedbackTimer)
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable')
    await navigator.clipboard.writeText(original)
    if (current === revision) {
      failed.value = false; feedback.value = '已复制完整值'
      feedbackTimer = setTimeout(() => { feedback.value = '' }, 1800)
    }
  } catch {
    if (current === revision) { failed.value = true; feedback.value = '复制失败，请选择预览中的完整文本手动复制'; showPreview() }
  } finally {
    if (current === revision) copying.value = false
  }
}
function previewChanged(event: Event) { if ((event as CustomEvent<string>).detail !== previewId) hidePreview() }
function resizePreview() { if (previewVisible.value) showPreview() }
function scrollPreview(event: Event) { if (!(event.target instanceof Element && event.target.closest('.full-value-preview')) && previewVisible.value) { const rect = container.value?.getBoundingClientRect(); if (!rect || rect.bottom < 0 || rect.top > window.innerHeight) hidePreview(); else showPreview() } }
onMounted(() => { window.addEventListener('me-full-value-preview', previewChanged); window.addEventListener('resize', resizePreview); window.addEventListener('scroll', scrollPreview, true) })
onBeforeUnmount(() => { revision++; clearTimeout(hideTimer); clearTimeout(feedbackTimer); window.removeEventListener('me-full-value-preview', previewChanged); window.removeEventListener('resize', resizePreview); window.removeEventListener('scroll', scrollPreview, true) })
</script>

<style scoped>
.full-value { position:relative; min-width:0; max-width:100%; }
.full-value .full-value-text, .full-value-empty { display:block; width:100%; min-width:0; margin:0; padding:0; border:0; border-radius:3px; color:var(--text); background:transparent; font-family:inherit; font-size:11px; font-weight:550; line-height:1.6; text-align:left; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.full-value .full-value-text { cursor:copy; user-select:text; }
.full-value .full-value-text:hover { color:var(--primary); }
.full-value .full-value-text:focus-visible { outline:2px solid var(--primary); outline-offset:2px; }
.full-value-mono .full-value-text, .full-value-mono pre { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
.full-value-feedback { display:block; margin-top:3px; font-size:10px; line-height:1.5; color:var(--muted); overflow-wrap:anywhere; }
.full-value-feedback[role='alert'] { color:var(--amber); }
.full-value-preview { position:fixed; z-index:10000; box-sizing:border-box; overflow:auto; padding:10px 12px; border:1px solid var(--line-strong); border-radius:8px; background:var(--panel, #141b27); color:var(--text); box-shadow:0 8px 28px #0004; }
.full-value-preview small { display:block; color:var(--muted); font-size:10px; line-height:1.5; }
.full-value-preview pre { margin:6px 0 0; font-size:11px; line-height:1.6; white-space:pre-wrap; overflow-wrap:anywhere; user-select:text; }
</style>
