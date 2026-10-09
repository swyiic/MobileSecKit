<template>
  <div v-if="message && !dismissed" class="operation-error" role="alert">
    <div class="operation-error-heading"><strong>本次操作失败</strong><button type="button" aria-label="关闭本次操作错误" @click="dismiss">关闭</button></div>
    <pre>{{ message }}</pre>
    <button type="button" @click="copy">{{ copied ? '已复制详情' : '复制错误详情' }}</button>
    <small v-if="copyError">{{ copyError }}</small>
  </div>
</template>
<script setup lang="ts">
import { ref, watch } from 'vue'
const props = defineProps<{ message?: string }>()
const emit = defineEmits<{ dismiss: [] }>()
const copied = ref(false)
const copyError = ref('')
const dismissed = ref(false)
watch(() => props.message, () => { copied.value = false; copyError.value = ''; dismissed.value = false })
function dismiss() { dismissed.value = true; emit('dismiss') }
async function copy() {
  const message = props.message || ''
  try { await navigator.clipboard.writeText(message); if (props.message === message) copied.value = true }
  catch { if (props.message === message) copyError.value = '复制失败；可直接选择上方错误详情。' }
}
</script>
<style scoped>
.operation-error { width: 100%; min-width: 0; max-width: 100%; box-sizing: border-box; padding: 10px; color: var(--red); background: var(--surface); border: 1px solid currentColor; border-radius: 8px; }
.operation-error-heading { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
pre { max-height: 240px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; user-select: text; }
button { cursor: pointer; color: var(--text); background: var(--surface-soft); border: 1px solid var(--line); border-radius: 6px; padding: 5px 8px; }
small { display: block; }
</style>
