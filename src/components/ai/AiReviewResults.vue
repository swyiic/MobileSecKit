<template>
  <section class="ai-review-results">
    <header class="review-result-header">
      <div><div class="eyebrow">AI REVIEW RESULT</div><h3>证据约束后的审查结论</h3><p>MobileE 已在后台完成 Schema、Evidence ID 和静态/运行时状态校验。</p></div>
      <button class="ghost-button" @click="emit('copy-normalized')">复制规范化结果</button>
    </header>
    <div class="review-validation-summary" :class="validation.valid ? 'valid' : 'invalid'">
      <span class="material-symbols-outlined">{{ validation.valid ? 'verified' : 'report' }}</span>
      <div><strong>{{ validation.valid ? '结构与证据引用通过' : '结果存在校验问题' }}</strong><small>已引用 {{ validation.citedEvidenceCount }} 条证据 · {{ validation.issues.length }} 个校验消息</small></div>
    </div>
    <ul v-if="validation.issues.length" class="review-issues"><li v-for="(issue, index) in validation.issues" :key="`${issue.code}-${index}`" :class="issue.level"><code>{{ issue.code }}</code><span>{{ issue.message }}</span><small v-if="issue.evidenceId">{{ issue.evidenceId }}</small></li></ul>
    <section class="review-conclusion">
      <div><span>总体结论</span><b :data-confidence="validation.normalizedResult.confidence">{{ confidenceLabel(validation.normalizedResult.confidence) }}</b></div>
      <p>{{ validation.normalizedResult.summary || '模型没有提供总体结论。' }}</p>
    </section>
    <div class="review-claims-grid">
      <section>
        <header><div><strong>已验证结论</strong><small>必须有运行时或人工证据支撑</small></div><span>{{ validation.normalizedResult.findings.length }}</span></header>
        <details v-for="(claim, index) in validation.normalizedResult.findings" :key="`${claim.title}-${index}`" class="review-claim" :open="index === 0">
          <summary><span class="claim-severity" :data-severity="claim.severity">{{ severityLabel(claim.severity) }}</span><strong>{{ claim.title }}</strong><small>{{ confidenceLabel(claim.confidence) }}</small><span class="material-symbols-outlined">expand_more</span></summary>
          <div class="review-claim-body"><p>{{ claim.description }}</p><div v-if="claim.evidenceIds.length" class="claim-evidence"><span>证据引用</span><code v-for="id in claim.evidenceIds" :key="id">{{ id }}</code></div><p v-else class="claim-warning">没有 Evidence ID；此结论不应视为已验证。</p></div>
        </details>
        <p v-if="!validation.normalizedResult.findings.length" class="muted">没有由运行时证据支撑的已验证结论。</p>
      </section>
      <section>
        <header><div><strong>待验证假设</strong><small>静态线索与关联证据，不等同漏洞</small></div><span>{{ validation.normalizedResult.hypotheses.length }}</span></header>
        <details v-for="(claim, index) in validation.normalizedResult.hypotheses" :key="`${claim.title}-${index}`" class="review-claim" :open="index === 0">
          <summary><span class="claim-severity" :data-severity="claim.severity">{{ severityLabel(claim.severity) }}</span><strong>{{ claim.title }}</strong><small>{{ confidenceLabel(claim.confidence) }}</small><span class="material-symbols-outlined">expand_more</span></summary>
          <div class="review-claim-body"><p>{{ claim.description }}</p><div v-if="claim.evidenceIds.length" class="claim-evidence"><span>证据引用</span><code v-for="id in claim.evidenceIds" :key="id">{{ id }}</code></div><p v-else class="claim-warning">当前没有可回溯的 Evidence ID。</p></div>
        </details>
        <p v-if="!validation.normalizedResult.hypotheses.length" class="muted">没有待验证假设。</p>
      </section>
    </div>
    <div class="review-followups">
      <section><strong>缺失证据</strong><ul><li v-for="item in validation.normalizedResult.missingEvidence" :key="item">{{ item }}</li></ul><p v-if="!validation.normalizedResult.missingEvidence.length" class="muted">模型未声明额外证据缺口。</p></section>
      <section class="review-next"><strong>下一步观察建议</strong><ol><li v-for="item in validation.normalizedResult.recommendedNextObservations" :key="item">{{ item }}</li></ol><p v-if="!validation.normalizedResult.recommendedNextObservations.length" class="muted">模型没有提出额外运行时观察建议。</p></section>
    </div>
    <section v-if="validation.normalizedResult.proposedPatterns?.length" class="review-patterns">
      <header><strong>AI 提议的知识模式</strong><small>人工确认后才写入本地知识库</small></header>
      <article v-for="pattern in validation.normalizedResult.proposedPatterns" :key="pattern.patternId">
        <div><strong>{{ pattern.title }}</strong><code>{{ pattern.patternId }}</code></div>
        <p>{{ pattern.boundary }} · {{ pattern.triggerSignals.join(' · ') || '缺少可复用触发信号' }}</p>
        <p v-if="!hasMeaningfulTitle(pattern)" class="invalid-pattern-note">该提议无法入库：模型没有提供明确、可区分的知识模式名称。</p>
        <p v-else-if="!hasTriggerSignals(pattern)" class="invalid-pattern-note">该提议无法入库：模型没有提供可字面匹配的 triggerSignals。</p>
        <p v-if="!pattern.verifiedIn.length" class="static-note">STATIC PATTERN · 只复用检测信号和验证步骤</p>
        <span v-if="confirmedPatternIds.has(pattern.patternId)" class="pattern-confirmed"><span class="material-symbols-outlined">check_circle</span>已入库</span>
        <button v-else class="ghost-button" :disabled="!canStorePattern(pattern)" :title="canStorePattern(pattern) ? '人工确认后写入本地知识库' : '缺少明确名称或 triggerSignals，不能入库'" @click="emit('confirm-pattern', pattern)">确认入库</button>
      </article>
    </section>
    <section v-if="validation.normalizedResult.proposedExclusions?.length" class="review-patterns review-exclusions">
      <header><strong>AI 提议的低噪声排除规则</strong><small>人工确认后持久化；原始命中仍保留为 filtered</small></header>
      <article v-for="rule in validation.normalizedResult.proposedExclusions" :key="rule.exclusionId">
        <div><strong>{{ rule.reason }}</strong><code>{{ rule.appliesToKind }}</code></div>
        <p>信号：{{ rule.excludeSignals.join(' · ') || '无' }}</p>
        <p v-if="rule.excludePatterns.length">正则：{{ rule.excludePatterns.join(' · ') }}</p>
        <p v-else class="static-note">字面量上下文已归入信号，不依赖正则编译。</p>
        <span v-if="confirmedExclusionIds.has(rule.exclusionId)" class="pattern-confirmed"><span class="material-symbols-outlined">check_circle</span>已写入排除库</span>
        <button v-else class="ghost-button" @click="emit('confirm-exclusion', rule)">确认加入排除库</button>
      </article>
    </section>
  </section>
</template>

<script setup lang="ts">
import type { AiValidationReport, ExclusionRule, KnowledgePattern } from '@/types'

defineProps<{ validation: AiValidationReport; confirmedPatternIds: Set<string>; confirmedExclusionIds: Set<string> }>()
const emit = defineEmits<{ 'copy-normalized': []; 'confirm-pattern': [pattern: KnowledgePattern]; 'confirm-exclusion': [rule: ExclusionRule] }>()
const hasTriggerSignals = (pattern: KnowledgePattern) => pattern.triggerSignals.some((signal) => signal.trim().length > 0)
const hasMeaningfulTitle = (pattern: KnowledgePattern) => {
  const title = pattern.title.trim().toLowerCase()
  return !!title && !['未命名', '未命名模式', '无标题', 'untitled', 'unknown', 'n/a', 'none'].includes(title)
}
const canStorePattern = (pattern: KnowledgePattern) => hasMeaningfulTitle(pattern) && hasTriggerSignals(pattern)
const confidenceLabel = (value: string) => ({ high: '高置信度', medium: '中置信度', low: '低置信度' }[value] || value || '未标注')
const severityLabel = (value: string) => ({ critical: '严重', high: '高', medium: '中', low: '低', info: '信息', review: '复核' }[value] || value || '复核')
</script>

<style scoped>
.ai-review-results{display:grid;gap:12px;padding:16px;border:1px solid var(--line-strong);border-radius:16px;color:var(--text);background:var(--surface);box-shadow:0 16px 42px rgba(0,0,0,.12)}
.review-result-header,.review-validation-summary,.review-patterns>header,.review-patterns article>div{display:flex;align-items:center;justify-content:space-between;gap:12px}.review-result-header h3{margin:3px 0;font-size:14px}.review-result-header p{margin:0;color:var(--muted);font-size:9px}.review-validation-summary{justify-content:flex-start;padding:11px;border:1px solid color-mix(in srgb,var(--green) 32%,var(--line));border-radius:10px;background:color-mix(in srgb,var(--green) 7%,var(--surface))}.review-validation-summary.invalid{border-color:color-mix(in srgb,var(--red) 32%,var(--line));background:color-mix(in srgb,var(--red) 7%,var(--surface))}.review-validation-summary>span{color:var(--green)}.review-validation-summary.invalid>span{color:var(--red)}.review-validation-summary strong,.review-validation-summary small{display:block}.review-validation-summary small{margin-top:2px;color:var(--muted);font-size:8px}
.review-issues{display:grid;gap:5px;margin:0;padding:0;list-style:none}.review-issues li{display:grid;grid-template-columns:minmax(120px,160px) minmax(0,1fr) auto;gap:8px;padding:8px 10px;border-left:3px solid var(--amber);border-radius:6px;background:color-mix(in srgb,var(--amber) 7%,var(--surface));color:var(--text);font-size:8px}.review-issues li.error{border-color:var(--red)}.review-issues code,.review-issues small{color:var(--muted)}
.review-conclusion{display:grid;gap:7px;padding:12px;border:1px solid var(--line);border-radius:11px;background:var(--surface-soft)}.review-conclusion>div{display:flex;align-items:center;justify-content:space-between}.review-conclusion span{color:var(--muted);font-size:8px}.review-conclusion b{padding:3px 7px;border-radius:999px;color:var(--primary);background:var(--primary-soft);font-size:8px}.review-conclusion p{margin:0;color:var(--text);font-size:9px;line-height:1.6}
.review-claims-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.review-claims-grid>section,.review-followups>section{min-width:0;padding:11px;border:1px solid var(--line);border-radius:11px;background:var(--surface-soft)}.review-claims-grid section>header{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:7px}.review-claims-grid section>header strong,.review-claims-grid section>header small{display:block}.review-claims-grid section>header strong{font-size:10px}.review-claims-grid section>header small{margin-top:2px;color:var(--muted);font-size:7px}.review-claims-grid section>header>span{display:grid;min-width:24px;height:24px;place-items:center;border-radius:999px;color:var(--primary);background:var(--primary-soft);font-size:8px}
.review-claim{overflow:hidden;margin-top:7px;border:1px solid var(--line);border-radius:9px;color:var(--text);background:var(--surface)}.review-claim>summary{display:grid;grid-template-columns:auto minmax(0,1fr) auto auto;align-items:center;gap:7px;padding:9px;cursor:pointer;list-style:none}.review-claim>summary::-webkit-details-marker{display:none}.review-claim>summary strong{font-size:9px;overflow-wrap:anywhere}.review-claim>summary small{color:var(--muted);font-size:7px;white-space:nowrap}.review-claim>summary>.material-symbols-outlined{color:var(--muted);font-size:16px;transition:transform .18s ease}.review-claim[open]>summary>.material-symbols-outlined{transform:rotate(180deg)}.claim-severity{padding:3px 6px;border-radius:999px;color:var(--amber);background:color-mix(in srgb,var(--amber) 12%,var(--surface));font-size:7px}.claim-severity[data-severity='critical'],.claim-severity[data-severity='high']{color:var(--red);background:color-mix(in srgb,var(--red) 10%,var(--surface))}.claim-severity[data-severity='low'],.claim-severity[data-severity='info']{color:var(--primary);background:var(--primary-soft)}.review-claim-body{display:grid;gap:8px;padding:0 9px 10px;border-top:1px solid var(--line)}.review-claim-body>p{margin:9px 0 0;color:var(--text);font-size:8px;line-height:1.6}.claim-evidence{display:grid;gap:4px}.claim-evidence span{color:var(--muted);font-size:7px}.claim-evidence code{padding:4px 6px;border-radius:5px;color:var(--primary);background:var(--primary-soft);font-size:7px;overflow-wrap:anywhere}.claim-warning{color:var(--amber)!important}.muted{color:var(--muted)!important;font-size:8px;line-height:1.5}
.review-followups{display:grid;grid-template-columns:1fr 1fr;gap:10px}.review-followups strong{font-size:9px}.review-followups ul,.review-followups ol{display:grid;gap:5px;margin:7px 0 0;padding-left:18px;color:var(--muted);font-size:8px;line-height:1.5}
.review-patterns{display:grid;gap:8px;padding:10px;border:1px solid color-mix(in srgb,var(--primary) 24%,var(--line));border-radius:10px;background:color-mix(in srgb,var(--primary) 4%,var(--surface))}.review-patterns header small{color:var(--muted);font-size:7px}.review-patterns article{display:grid;gap:6px;padding:9px;border:1px solid var(--line);border-radius:8px;color:var(--text);background:var(--surface)}.review-patterns article p{margin:0;color:var(--muted);font-size:8px}.review-patterns article code{color:var(--muted);font-size:7px}.review-patterns button,.pattern-confirmed{justify-self:start}.review-patterns button:disabled{cursor:not-allowed;opacity:.45}.static-note{color:var(--amber)!important}.invalid-pattern-note{color:var(--amber)!important}.pattern-confirmed{display:inline-flex;align-items:center;gap:4px;color:var(--green);font-size:8px}.pattern-confirmed span{font-size:14px}
@media(max-width:760px){.review-claims-grid,.review-followups{grid-template-columns:1fr}.review-result-header{align-items:flex-start;flex-direction:column}.review-issues li{grid-template-columns:1fr}.review-claim>summary{grid-template-columns:auto minmax(0,1fr) auto}.review-claim>summary small{display:none}}
</style>
