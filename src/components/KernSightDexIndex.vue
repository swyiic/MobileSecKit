<template>
  <details class="ks-dex-index">
    <summary>DEX 类索引与独立来源 · {{ dump.content_dex_class_index?.objects.length ?? '未知' }} 结构对象</summary>
    <p v-if="!dump.content_dex_class_index">旧数据：类索引未知</p>
    <template v-else>
      <p>校验状态、索引状态与采集覆盖分别展示；类名未匹配不代表原始进程里不存在。</p>
      <label>检索已索引类名<input v-model="query" placeholder="输入类名片段" /></label>
      <section v-for="bucket in buckets" :key="bucket.kind" :data-dex-group="bucket.kind">
        <h4>{{ bucket.label }}</h4>
        <article v-for="{ object, matches } in bucket.entries" :key="`${object.sha256}:${object.bytes}`">
          <p>{{ object.sha256 }} · {{ object.sources.length }} 来源 · {{ object.indexed_classes ?? '未知' }} / {{ object.declared_classes ?? '未知' }} 类 · {{ object.class_index_status }} · {{ object.validation_status || '校验未知（旧字段）' }} · {{ object.ownership }}</p>
          <p>扫描范围：{{ dexScanSummaryForObject(dump.local_storage_accounting?.runtime_observations, object.sha256) }}</p>
          <pre>{{ object.class_hints }}</pre>
          <details><summary>来源与实例</summary><pre>{{ object.sources }}</pre></details>
          <p>匹配 {{ matches.total }} · 本页 {{ matches.classes.length }} · 未展开 {{ matches.omitted }}。未展开的类名仍在索引里，可用片段继续检索。</p>
          <pre>{{ matches.classes.join('\n') }}</pre>
        </article>
      </section>
    </template>
  </details>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { dexObjectGroups, runtimeDexClassMatches, dexScanSummaryForObject } from '@/services/kernsightCodeEvidence'
import type { KernSightPackageDumpReport } from '@/types/monitoring'

const props = defineProps<{ dump: KernSightPackageDumpReport }>()
const query = ref('')
const buckets = computed(() => dexObjectGroups(props.dump.content_dex_class_index?.objects).map(bucket => ({
  kind: bucket.kind,
  label: bucket.label,
  entries: bucket.objects.map(object => ({
    object, matches: runtimeDexClassMatches(props.dump.local_storage_accounting, object, query.value),
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
</style>
