<template>
  <details :key="revision" class="ks-dex-index">
    <summary>DEX 类索引与独立来源 · {{ projection.objects.length }} 个可展开结构对象<span v-if="projection.status === 'reported_count_only'"> · 报告计数 {{ projection.reportedCount }}，明细未载入</span><span v-else-if="projection.status === 'unknown'"> · 明细未知</span></summary>
    <p v-if="projection.status === 'reported_count_only'">报告有 DEX 计数，但当前来源没有可展开对象明细；类索引与本地文件是否可用未知。</p>
    <p v-else-if="projection.status === 'unknown'">当前来源未提供 DEX 对象明细；这不是已测得的 0 个 DEX。</p>
    <p v-else-if="projection.status === 'empty'">当前来源明确列示 0 个结构对象；不证明原始进程不存在 DEX。</p>
    <p v-for="warning in projection.warnings" :key="warning" class="ks-dex-warning">{{ warning }}</p>
    <template v-if="projection.objects.length">
      <p>结构对象、物理文件与类名匹配分别计数；容器内的 DEX 切片不代表整个文件是完整可读 DEX。生产者记录保留，未知归属不会升级。</p>
      <label>检索已索引类名<input v-model="query" placeholder="输入类名片段" /></label>
      <section v-for="bucket in buckets" :key="bucket.kind" :data-dex-group="bucket.kind">
        <h4>{{ bucket.label }} · {{ bucket.entries.length }} 对象</h4>
        <article v-for="{ object, matches } in bucket.entries" :key="objectKey(object)" data-dex-object>
          <p>{{ object.sha256 }} · {{ object.sources.length }} 来源 · {{ object.indexed_classes ?? '未知' }} / {{ object.declared_classes ?? '未知' }} 类 · {{ object.class_index_status || '索引状态未知' }} · {{ object.validation_status || '校验未知（旧字段）' }} · {{ object.ownership || '归属未知' }}</p>
          <p>扫描范围：{{ dexScanSummaryForObject(dump.local_storage_accounting?.runtime_observations, object.sha256) }}</p>
          <pre v-if="object.class_hints">{{ object.class_hints }}</pre>
          <details><summary>来源与实例</summary><pre>{{ object.sources }}</pre><pre v-if="object.legacy_observations.length">{{ object.legacy_observations }}</pre></details>
          <p v-if="matches.status === 'unlinked'" data-dex-index-status="unlinked">类索引未链接：当前来源/范围或对象没有精确匹配；匹配数未知。</p>
          <p v-else-if="matches.status === 'unknown'" data-dex-index-status="unknown">类索引未知或未载入；匹配数未知。</p>
          <template v-else>
            <p data-dex-index-status="indexed">匹配 {{ matches.total }} · 当前页 {{ matches.classes.length }} · 其他页 {{ matches.omitted }}。仅检索已保存类索引；无匹配不代表原始进程里不存在。</p>
            <div class="ks-dex-pages"><button v-if="matches.offset > 0" type="button" @click="offsets[objectKey(object)] = Math.max(0, matches.offset - 500)">上一页类名</button><button v-if="matches.nextOffset !== null" type="button" @click="offsets[objectKey(object)] = matches.nextOffset">下一页类名</button></div>
            <pre>{{ matches.classes.join('\n') }}</pre>
          </template>
        </article>
      </section>
    </template>
  </details>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { dexObjectGroups, projectDexEvidence, runtimeDexClassMatches, dexScanSummaryForObject } from '@/services/kernsightCodeEvidence'
import type { KernSightPackageDumpReport } from '@/types/monitoring'

const props = defineProps<{ dump: KernSightPackageDumpReport }>()
const query = ref('')
const offsets = ref<Record<string, number>>({})
const revision = ref(0)
const objectKey = (object: any) => `${object.sha256}:${object.bytes}`
const projection = computed(() => projectDexEvidence(props.dump))
watch(() => props.dump, () => { query.value = ''; offsets.value = {}; revision.value++ })
watch(query, () => { offsets.value = {} })
const buckets = computed(() => dexObjectGroups(projection.value.objects).map(bucket => ({
  kind: bucket.kind,
  label: bucket.label,
  entries: bucket.objects.map(object => ({
    object, matches: runtimeDexClassMatches(props.dump.local_storage_accounting, object, query.value, offsets.value[objectKey(object)] || 0),
  })),
})))
</script>

<style scoped>
.ks-dex-index { min-width: 0; margin: 12px 0; padding: 12px; border: 1px solid var(--line); border-radius: 9px; background: var(--surface); font-size: 12px; }
summary { cursor: pointer; overflow-wrap: anywhere; }
label { display: grid; gap: 6px; margin: 10px 0; }
input { min-width: 0; width: 100%; padding: 8px; border: 1px solid var(--line-strong); border-radius: 6px; color: var(--text); background: var(--surface-soft); }
article { min-width: 0; padding: 8px 0; border-top: 1px solid var(--line); }
p { line-height: 1.6; overflow-wrap: anywhere; }
pre { max-width: 100%; max-height: 360px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 11px; }
.ks-dex-pages { display: flex; gap: 8px; }
.ks-dex-pages button { padding: 6px 10px; border: 1px solid var(--line-strong); border-radius: 6px; background: var(--surface-soft); color: var(--text); }
</style>
