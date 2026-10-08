<template>
  <div v-if="message" class="operation-error" role="alert">
    <strong>本次操作失败</strong><pre>{{ message }}</pre>
    <button type="button" @click="copy">{{ copied ? '已复制详情' : '复制错误详情' }}</button>
    <small v-if="copyError">{{ copyError }}</small>
  </div>
</template>
<script setup lang="ts">
import { ref, watch } from 'vue'
const props = defineProps<{ message?: string }>()
const copied = ref(false)
const copyError = ref('')
watch(() => props.message, () => { copied.value = false; copyError.value = '' })
async function copy() {
  const message = props.message || ''
  try { await navigator.clipboard.writeText(message); if (props.message === message) copied.value = true }
  catch { if (props.message === message) copyError.value = '复制失败；可直接选择上方错误详情。' }
}
</script>
<style scoped>
.operation-error { width: 100%; padding: 10px; color: var(--red); background: var(--surface); border: 1px solid currentColor; border-radius: 8px; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; user-select: text; }
button { cursor: pointer; } small { display: block; }
</style>
