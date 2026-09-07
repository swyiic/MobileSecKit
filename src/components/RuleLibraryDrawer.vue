<template>
  <div v-if="open" class="rule-overlay" @click.self="emit('close')">
    <aside class="rule-drawer" role="dialog" aria-modal="true" aria-label="MobileE 规则库">
      <header class="rule-header">
        <div>
          <div class="eyebrow">READ-ONLY RULE INVENTORY</div>
          <h3>规则库</h3>
          <p>展示当前扫描实际加载的内置规则与本机排除规则。这里仅供检查，规则编辑仍通过 JSON 文件完成。</p>
        </div>
        <button class="icon-button" title="关闭规则库" aria-label="关闭规则库" @click="emit('close')">
          <span class="material-symbols-outlined">close</span>
        </button>
      </header>

      <nav class="rule-tabs" aria-label="规则分类">
        <button v-for="tab in tabs" :key="tab.key" :class="{ active: activeCategory === tab.key }" @click="activeCategory = tab.key">
          <span class="material-symbols-outlined">{{ tab.icon }}</span>
          <strong>{{ tab.label }}</strong>
          <em>{{ tab.count }}</em>
        </button>
      </nav>

      <div class="rule-search">
        <span class="material-symbols-outlined">search</span>
        <input v-model="query" type="search" :placeholder="`搜索${activeTabLabel}的名称、信号、正则或说明`" />
        <button v-if="query" title="清空搜索" aria-label="清空搜索" @click="query = ''">
          <span class="material-symbols-outlined">cancel</span>
        </button>
      </div>

      <p v-if="error" class="rule-status error">{{ error }}</p>
      <div v-if="loading" class="rule-empty"><span class="material-symbols-outlined spinning">sync</span>正在读取当前规则…</div>
      <div v-else-if="!inventory" class="rule-empty">规则尚未加载。</div>
      <div v-else-if="!visibleCount" class="rule-empty">当前分类没有符合搜索条件的规则。</div>

      <section v-else-if="activeCategory === 'sensitive'" class="rule-list">
        <details v-for="rule in filteredSensitive" :key="`${rule.kind}-${rule.label}`" class="rule-card">
          <summary>
            <span class="rule-severity" :class="`severity-${rule.severity.toLowerCase()}`">{{ rule.severity }}</span>
            <div><strong>{{ rule.label }}</strong><small>{{ rule.kind }}</small></div>
            <span class="material-symbols-outlined">expand_more</span>
          </summary>
          <div class="rule-body">
            <RuleCode label="匹配正则" :values="[rule.pattern]" />
            <RuleCode label="必需上下文" :values="rule.requireContext" empty-text="无额外上下文要求" />
            <RuleCode label="排除信号" :values="rule.excludeSignals" empty-text="未配置" />
            <RuleCode label="排除正则" :values="rule.excludePatterns" empty-text="未配置" />
            <details class="rule-json"><summary>查看完整 JSON</summary><pre>{{ JSON.stringify(rule, null, 2) }}</pre></details>
          </div>
        </details>
      </section>

      <section v-else-if="activeCategory === 'exclusions'" class="rule-list">
        <details v-for="rule in filteredExclusions" :key="rule.exclusionId" class="rule-card">
          <summary>
            <span class="rule-kind">{{ rule.appliesToKind }}</span>
            <div><strong>{{ rule.reason }}</strong><small>{{ rule.exclusionId }}</small></div>
            <span class="material-symbols-outlined">expand_more</span>
          </summary>
          <div class="rule-body">
            <RuleCode label="排除信号" :values="rule.excludeSignals" empty-text="未配置" />
            <RuleCode label="排除正则" :values="rule.excludePatterns" empty-text="未配置" />
            <RuleCode label="已验证 App" :values="rule.verifiedIn" empty-text="暂无验证记录" />
            <details class="rule-json"><summary>查看完整 JSON</summary><pre>{{ JSON.stringify(rule, null, 2) }}</pre></details>
          </div>
        </details>
      </section>

      <section v-else class="rule-list">
        <details v-for="rule in filteredSignals" :key="`${activeCategory}-${rule.label}`" class="rule-card">
          <summary>
            <span class="rule-kind">{{ rule.scope || 'global' }}</span>
            <div><strong>{{ rule.label }}</strong><small>{{ rule.triggerSignals.length }} 个触发信号</small></div>
            <span class="material-symbols-outlined">expand_more</span>
          </summary>
          <div class="rule-body">
            <p v-if="rule.indicator" class="rule-indicator">{{ rule.indicator }}</p>
            <RuleCode label="触发信号" :values="rule.triggerSignals" />
            <details class="rule-json"><summary>查看完整 JSON</summary><pre>{{ JSON.stringify(rule, null, 2) }}</pre></details>
          </div>
        </details>
      </section>
    </aside>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { aiBackend } from '@/services/backend'
import type { RuleCategory, RuleInventory, SignalRuleDefinition } from '@/types'
import RuleCode from '@/components/RuleCode.vue'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ close: [] }>()

const inventory = ref<RuleInventory | null>(null)
const activeCategory = ref<RuleCategory>('sensitive')
const query = ref('')
const loading = ref(false)
const error = ref('')

const countFor = (category: RuleCategory) => inventory.value
  ? (category === 'antiInstrumentation' ? inventory.value.antiInstrumentation.length : inventory.value[category].length)
  : 0

const tabs = computed(() => [
  { key: 'sensitive' as const, label: '敏感规则', icon: 'manage_search', count: countFor('sensitive') },
  { key: 'protection' as const, label: '加固规则', icon: 'shield_lock', count: countFor('protection') },
  { key: 'frameworks' as const, label: '框架规则', icon: 'extension', count: countFor('frameworks') },
  { key: 'antiInstrumentation' as const, label: '反插桩', icon: 'security', count: countFor('antiInstrumentation') },
  { key: 'exclusions' as const, label: '排除规则', icon: 'filter_alt_off', count: countFor('exclusions') },
])

const activeTabLabel = computed(() => tabs.value.find((tab) => tab.key === activeCategory.value)?.label || '规则')
const normalizedQuery = computed(() => query.value.trim().toLowerCase())
const matches = (value: unknown) => !normalizedQuery.value || JSON.stringify(value).toLowerCase().includes(normalizedQuery.value)

const filteredSensitive = computed(() => (inventory.value?.sensitive || []).filter(matches))
const filteredExclusions = computed(() => (inventory.value?.exclusions || []).filter(matches))
const activeSignals = computed<SignalRuleDefinition[]>(() => {
  if (!inventory.value) return []
  if (activeCategory.value === 'frameworks') return inventory.value.frameworks
  if (activeCategory.value === 'protection') return inventory.value.protection
  if (activeCategory.value === 'antiInstrumentation') return inventory.value.antiInstrumentation
  return []
})
const filteredSignals = computed(() => activeSignals.value.filter(matches))
const visibleCount = computed(() => {
  if (activeCategory.value === 'sensitive') return filteredSensitive.value.length
  if (activeCategory.value === 'exclusions') return filteredExclusions.value.length
  return filteredSignals.value.length
})

async function loadRules() {
  loading.value = true
  error.value = ''
  try {
    inventory.value = await aiBackend.listRules()
  } catch (reason) {
    inventory.value = null
    error.value = `读取规则库失败：${String(reason)}`
  } finally {
    loading.value = false
  }
}

watch(() => props.open, (open) => {
  if (open) void loadRules()
}, { immediate: true })
</script>

<style scoped>
.rule-overlay{position:fixed;inset:0;z-index:145;display:flex;justify-content:flex-end;background:rgba(1,4,9,.7);backdrop-filter:blur(3px)}
.rule-drawer{display:flex;flex-direction:column;gap:12px;width:min(820px,94vw);height:100%;min-height:0;overflow:hidden;padding:18px;border-left:1px solid rgba(67,155,232,.32);background:#0a1019;box-shadow:-24px 0 60px rgba(0,0,0,.42)}
.rule-header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.rule-header h3{margin:3px 0;font-size:17px}.rule-header p{max-width:620px;margin:0;color:#78879b;font-size:8px;line-height:1.5}
.rule-tabs{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:6px}.rule-tabs button{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:5px;min-width:0;padding:8px;border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.018);color:#8290a5;text-align:left}.rule-tabs button.active{border-color:rgba(67,155,232,.55);background:rgba(67,155,232,.1);color:#b9daf5}.rule-tabs .material-symbols-outlined{font-size:15px}.rule-tabs strong{overflow:hidden;font-size:8px;text-overflow:ellipsis;white-space:nowrap}.rule-tabs em{padding:2px 5px;border-radius:999px;background:rgba(255,255,255,.05);font-size:7px;font-style:normal}
.rule-search{display:flex;align-items:center;gap:7px;padding:0 10px;border:1px solid var(--line);border-radius:9px;background:#070c13}.rule-search>span{color:#66758a;font-size:16px}.rule-search input{width:100%;height:35px;border:0;outline:0;background:transparent;color:#aebbd0;font-size:9px}.rule-search button{display:grid;padding:0;border:0;background:transparent;color:#66758a;cursor:pointer}.rule-search button span{font-size:15px}
.rule-status{margin:0;color:#77cfa8;font-size:8px}.rule-status.error{color:#ef858b}.rule-empty{display:grid;min-height:180px;place-content:center;gap:7px;color:#718097;font-size:9px;text-align:center}.rule-empty span{justify-self:center}
.rule-list{display:grid;flex:1 1 auto;align-content:start;gap:8px;min-height:0;overflow:auto;padding:0 7px 18px 0;scrollbar-gutter:stable}.rule-card{min-width:0;border:1px solid var(--line);border-radius:10px;background:linear-gradient(145deg,rgba(20,27,40,.92),rgba(8,13,21,.92));overflow:clip}.rule-card[open]{border-color:rgba(67,155,232,.28)}.rule-card summary{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:9px;padding:10px;cursor:pointer;list-style:none}.rule-card summary::-webkit-details-marker{display:none}.rule-card summary>div{display:grid;gap:2px;min-width:0}.rule-card summary strong{font-size:9px;overflow-wrap:anywhere}.rule-card summary small{color:#6f7d91;font:7px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.rule-card summary>.material-symbols-outlined{color:#607087;font-size:17px;transition:transform .18s ease}.rule-card[open] summary>.material-symbols-outlined{transform:rotate(180deg)}
.rule-severity,.rule-kind{min-width:52px;padding:3px 6px;border-radius:999px;background:rgba(124,92,255,.1);color:#a998f7;font-size:7px;text-align:center;text-transform:uppercase}.rule-severity.severity-high,.rule-severity.severity-critical{background:rgba(232,99,108,.11);color:#ef8d94}.rule-severity.severity-medium,.rule-severity.severity-review{background:rgba(233,167,75,.1);color:#d9aa67}.rule-kind{background:rgba(67,155,232,.1);color:#82bce9}
.rule-body{display:grid;gap:9px;padding:0 10px 11px;border-top:1px solid rgba(255,255,255,.045)}.rule-indicator{margin:9px 0 0;padding:8px;border-radius:7px;background:rgba(233,167,75,.055);color:#c69b63;font-size:8px;line-height:1.55}
.rule-json{margin-top:3px;color:#74849a;font-size:8px}.rule-json summary{display:block;padding:7px 0;color:#7f9bc1;font-size:8px}.rule-json pre{max-height:320px;margin:0;padding:9px;overflow:auto;border:1px solid rgba(255,255,255,.06);border-radius:7px;background:#05090f;color:#8fa4bf;font:8px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-word}
@media(max-width:760px){.rule-drawer{width:100vw;padding:12px}.rule-tabs{grid-template-columns:repeat(2,minmax(0,1fr))}.rule-tabs button:last-child{grid-column:1/-1}}
</style>
