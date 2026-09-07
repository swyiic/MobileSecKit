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
    <div class="review-claims-grid">
      <section><header><strong>Verified findings</strong><span>{{ validation.normalizedResult.findings.length }}</span></header><article v-for="claim in validation.normalizedResult.findings" :key="claim.title"><b>{{ claim.title }}</b><p>{{ claim.description }}</p><code v-for="id in claim.evidenceIds" :key="id">{{ id }}</code></article><p v-if="!validation.normalizedResult.findings.length" class="muted">没有由运行时证据支撑的 verified finding。</p></section>
      <section><header><strong>Hypotheses</strong><span>{{ validation.normalizedResult.hypotheses.length }}</span></header><article v-for="claim in validation.normalizedResult.hypotheses" :key="claim.title"><b>{{ claim.title }}</b><p>{{ claim.description }}</p><code v-for="id in claim.evidenceIds" :key="id">{{ id }}</code></article><p v-if="!validation.normalizedResult.hypotheses.length" class="muted">没有静态假设。</p></section>
    </div>
    <div class="review-next"><strong>下一步观察建议</strong><ol><li v-for="item in validation.normalizedResult.recommendedNextObservations" :key="item">{{ item }}</li></ol><p v-if="!validation.normalizedResult.recommendedNextObservations.length" class="muted">模型没有提出额外运行时观察建议。</p></div>
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
</script>

<style scoped>
.ai-review-results{display:grid;gap:10px;padding:14px;border:1px solid rgba(124,92,255,.24);border-radius:13px;background:linear-gradient(145deg,rgba(15,20,32,.92),rgba(8,13,21,.92))}.review-result-header,.review-validation-summary,.review-patterns>header,.review-patterns article>div{display:flex;align-items:center;justify-content:space-between;gap:12px}.review-result-header h3{margin:3px 0;font-size:13px}.review-result-header p{margin:0;color:#748298;font-size:8px}.review-validation-summary{justify-content:flex-start;padding:9px;border:1px solid rgba(65,197,135,.22);border-radius:9px;background:rgba(65,197,135,.05)}.review-validation-summary.invalid{border-color:rgba(234,88,96,.24);background:rgba(234,88,96,.05)}.review-validation-summary>span{color:#6fd2a0}.review-validation-summary.invalid>span{color:#ef858b}.review-validation-summary strong,.review-validation-summary small{display:block}.review-validation-summary small{color:#748397;font-size:8px}.review-issues{display:grid;gap:4px;margin:0;padding:0;list-style:none}.review-issues li{display:grid;grid-template-columns:150px minmax(0,1fr) auto;gap:7px;padding:6px 8px;border-left:2px solid #d29a4c;background:rgba(210,154,76,.04);color:#9eabba;font-size:8px}.review-issues li.error{border-color:#e8636c}.review-issues code{color:#c99c62}.review-issues small{color:#6f7d91}.review-claims-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.review-claims-grid>section,.review-next{padding:9px;border:1px solid var(--line);border-radius:9px}.review-claims-grid section>header{display:flex;justify-content:space-between;color:#a7b5c8;font-size:9px}.review-claims-grid article{margin-top:7px;padding-top:7px;border-top:1px solid var(--line)}.review-claims-grid b{font-size:8px}.review-claims-grid p,.review-next li{color:#748397;font-size:8px;line-height:1.45}.review-claims-grid code{display:block;color:#728db7;font-size:7px}.review-next strong{font-size:9px}.review-next ol{display:grid;gap:4px;margin:6px 0 0;padding-left:18px}.review-patterns{display:grid;gap:7px;padding:9px;border:1px solid rgba(124,92,255,.2);border-radius:9px;background:rgba(124,92,255,.035)}.review-patterns header small{color:#78879c;font-size:7px}.review-patterns article{display:grid;gap:5px;padding:8px;border:1px solid var(--line);border-radius:7px;background:rgba(5,9,15,.5)}.review-patterns article p{margin:0;color:#8190a5;font-size:7px}.review-patterns article code{color:#66758d;font-size:7px}.review-patterns button,.pattern-confirmed{justify-self:start}.review-patterns button:disabled{cursor:not-allowed;opacity:.45}.static-note{color:#d0a35f!important}.invalid-pattern-note{color:#e9a160!important}.pattern-confirmed{display:inline-flex;align-items:center;gap:4px;color:#72d1a4;font-size:8px}.pattern-confirmed span{font-size:14px}.muted{color:#637187!important}@media(max-width:720px){.review-claims-grid{grid-template-columns:1fr}.review-result-header{align-items:flex-start;flex-direction:column}.review-issues li{grid-template-columns:1fr}}
</style>
