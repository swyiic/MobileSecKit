<template>
  <div v-if="open" class="external-result-overlay" @click.self="emit('close')">
    <aside class="external-result-dialog" role="dialog" aria-modal="true" aria-label="导入外部模型结果">
      <header><div><div class="eyebrow">ADVANCED · EXTERNAL MODEL</div><h3>导入外部模型结果</h3><p>仅在把 Context Pack 交给其他模型或内网模型时使用；直接运行 AI 审查不需要操作 JSON。</p></div><button class="icon-button" title="关闭" @click="emit('close')"><span class="material-symbols-outlined">close</span></button></header>
      <div class="external-result-note"><span class="material-symbols-outlined">fact_check</span><p>导入时会校验 MobileE Schema、Evidence ID 和静态/运行时状态，不能导入任意 JSON。</p></div>
      <textarea :value="modelValue" spellcheck="false" placeholder='粘贴 {"schemaVersion":"mobilee.ai-analysis-result/v1", ...}' @input="emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"></textarea>
      <p v-if="error" class="external-result-error">{{ error }}</p>
      <footer><button class="ghost-button" @click="emit('copy-template')">复制结果模板</button><button class="primary-button" :disabled="validating || !modelValue.trim()" @click="emit('validate')">{{ validating ? '校验中…' : '导入并校验' }}</button></footer>
    </aside>
  </div>
</template>

<script setup lang="ts">
defineProps<{ open: boolean; modelValue: string; validating: boolean; error?: string }>()
const emit = defineEmits<{ close: []; validate: []; 'copy-template': []; 'update:modelValue': [value: string] }>()
</script>

<style scoped>
.external-result-overlay{position:fixed;inset:0;z-index:150;display:grid;place-items:center;padding:20px;background:rgba(1,4,9,.7);backdrop-filter:blur(4px)}.external-result-dialog{display:grid;gap:12px;width:min(760px,94vw);max-height:88vh;padding:16px;border:1px solid rgba(124,92,255,.3);border-radius:14px;background:#0b111a;box-shadow:0 28px 80px rgba(0,0,0,.5)}.external-result-dialog>header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.external-result-dialog h3{margin:3px 0;font-size:15px}.external-result-dialog header p{margin:0;color:#78879b;font-size:8px}.external-result-note{display:flex;align-items:center;gap:8px;padding:8px;border:1px solid rgba(88,145,235,.18);border-radius:8px;background:rgba(57,125,246,.045)}.external-result-note span{color:#83aef0}.external-result-note p{margin:0;color:#8494aa;font-size:8px}.external-result-dialog textarea{width:100%;min-height:300px;max-height:55vh;padding:11px;resize:vertical;border:1px solid var(--line);border-radius:9px;outline:0;background:#060a10;color:#a9bad0;font:8px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}.external-result-dialog textarea:focus{border-color:rgba(124,92,255,.55)}.external-result-error{margin:0;color:#ef8c93;font-size:8px;line-height:1.5;overflow-wrap:anywhere}.external-result-dialog footer{display:flex;justify-content:flex-end;gap:8px}
</style>
