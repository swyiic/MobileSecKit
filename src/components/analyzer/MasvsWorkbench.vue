<template>
  <details class="masvs-workbench analyzer-disclosure">
    <summary class="analyzer-disclosure-summary">
      <div>
        <div class="eyebrow">TEST CLOSURE</div>
        <h3>
          MASVS 验证矩阵
          <small>测试线索 {{ evidenceCount }} / {{ observations.length }} · 人工已判定 {{ reviewedCount }} / {{ observations.length }}</small>
        </h3>
        <p>静态命中只是待验证的测试入口，不代表漏洞成立或验证通过。KernSight 的 confirmed / correlated 是证据强度，不会自动改成这里的“确认存在风险”。</p>
      </div>
      <span class="material-symbols-outlined disclosure-chevron">expand_more</span>
    </summary>

    <div class="analyzer-disclosure-body">
      <p v-if="dirty" class="assessment-unsaved">
        <span class="material-symbols-outlined">edit_note</span>
        人工结论或复核备注已修改，尚未保存到项目快照。
      </p>

      <div class="masvs-grid">
        <article
          v-for="item in observations"
          :key="item.controlId"
          :class="[`masvs-${item.status}`, verdicts[item.controlId] ? `verdict-${verdicts[item.controlId]}` : '']"
        >
          <div class="masvs-card-head">
            <span>{{ item.controlId }}</span>
            <div>
              <b>{{ statusLabel(item.status) }}</b>
              <b v-if="verdicts[item.controlId]" class="manual-verdict">{{ verdictLabel(verdicts[item.controlId]) }}</b>
            </div>
          </div>
          <strong>{{ item.title }}</strong>
          <p>{{ item.summary }}</p>
          <details>
            <summary>证据 {{ item.evidence.length }} 条 · 验证步骤 {{ item.verificationSteps.length }} 项</summary>
            <code v-for="evidence in item.evidence" :key="evidence">{{ evidence }}</code>
            <ol><li v-for="step in item.verificationSteps" :key="step">{{ step }}</li></ol>
          </details>
          <label>
            <span>人工结论</span>
            <select :value="verdicts[item.controlId] || ''" @change="changeVerdict(item.controlId, $event)">
              <option value="">待验证</option>
              <option value="confirmed">确认存在风险</option>
              <option value="rejected">误报 / 已排除</option>
              <option value="not-applicable">不适用</option>
              <option value="passed">已验证通过</option>
            </select>
          </label>
        </article>
      </div>

      <details class="verification-recipes">
        <summary>运行时验证计划（{{ recipes.length }}）</summary>
        <article v-for="recipe in recipes" :key="recipe.id">
          <header><strong>{{ recipe.title }}</strong><span>{{ recipe.platform }}</span></header>
          <p>{{ recipe.goal }}</p>
          <ol><li v-for="step in recipe.steps" :key="step">{{ step }}</li></ol>
        </article>
      </details>

      <label class="assessment-notes">
        <span>项目复核备注</span>
        <textarea
          :value="notes"
          placeholder="记录测试账号、覆盖流程、误报原因、未完成项或复测结论；保存项目快照时一并写入。"
          @input="$emit('update:notes', ($event.target as HTMLTextAreaElement).value)"
        ></textarea>
      </label>
    </div>
  </details>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { MasvsObservation, VerificationRecipe } from '@/types'

const props = defineProps<{
  observations: MasvsObservation[]
  recipes: VerificationRecipe[]
  verdicts: Record<string, string>
  notes: string
  dirty: boolean
}>()

const emit = defineEmits<{
  verdict: [controlId: string, verdict: string]
  'update:notes': [notes: string]
}>()

const evidenceCount = computed(() => props.observations.filter((item) => item.status !== 'not-assessed').length)
const reviewedCount = computed(() => props.observations.filter((item) => Boolean(props.verdicts[item.controlId])).length)

function changeVerdict(controlId: string, event: Event) {
  emit('verdict', controlId, (event.target as HTMLSelectElement).value)
}

function statusLabel(status: string) {
  if (status === 'runtime-observed') return '运行时观察'
  if (status === 'static-candidate') return '静态候选'
  return '未评估'
}

function verdictLabel(verdict: string) {
  if (verdict === 'confirmed') return '人工确认风险'
  if (verdict === 'rejected') return '人工排除'
  if (verdict === 'not-applicable') return '不适用'
  if (verdict === 'passed') return '人工验证通过'
  return '待验证'
}
</script>
