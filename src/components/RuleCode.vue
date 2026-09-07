<template>
  <section class="rule-code">
    <strong>{{ label }}</strong>
    <div v-if="values.length">
      <code v-for="value in values" :key="value">{{ value }}</code>
    </div>
    <small v-else>{{ emptyText }}</small>
  </section>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ label: string; values: string[]; emptyText?: string }>(), { emptyText: '无' })
</script>

<style scoped>
.rule-code{display:grid;min-width:0;gap:4px;padding-top:9px}.rule-code>strong{color:#8998ad;font-size:7px}.rule-code>div{display:grid;min-width:0;gap:4px}.rule-code code{display:block;max-width:100%;padding:5px 7px;border-radius:6px;background:#060b12;color:#8ca5c4;font:8px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;white-space:pre-wrap;word-break:break-word;user-select:text}.rule-code>small{color:#637187;font-size:7px}
</style>
