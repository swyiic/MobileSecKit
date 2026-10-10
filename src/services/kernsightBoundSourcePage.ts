import type { KernSightBoundSourcePage, KernSightRuntimeRangeInventoryEntry } from '@/types/monitoring'

const object = (value: unknown): value is Record<string, any> => value !== null && typeof value === 'object' && !Array.isArray(value)
const count = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value)
const array = (value: unknown): Record<string, any>[] => Array.isArray(value) ? value.filter(object) : []

export function boundSourceReports(ledger?: Record<string, any>): string[] {
  return [...new Set([
    ...array(ledger?.runtime_source_diagnostics),
    ...array(ledger?.runtime_range_inventory),
    ...array(ledger?.runtime_observations),
  ].map(row => row.source_report).filter((path): path is string => typeof path === 'string' && path.length > 0))]
}

export function validateBoundSourcePage(value: unknown, sourceReport: string, offset: number, expectedSha256: string | null): KernSightBoundSourcePage {
  if (!object(value) || value.schema !== 'mobilee.bound-source-page/v1' || value.sourceReport !== sourceReport
      || !hash(value.sourceSha256) || !count(value.offset) || value.offset !== offset || !count(value.limit) || value.limit < 1 || value.limit > 100
      || !count(value.totalRecords) || value.totalRecords > 65_536 || !Array.isArray(value.records)
      || value.records.length > value.limit || offset > value.totalRecords
      || (expectedSha256 !== null && value.sourceSha256.toLowerCase() !== expectedSha256.toLowerCase())) {
    throw new Error('原始范围页的来源或分页回执无法核实')
  }
  for (const [index, row] of value.records.entries()) {
    if (!object(row) || row.sourceRecordIndex !== offset + index || !Object.prototype.hasOwnProperty.call(row, 'producerRecord') || row.sourceRecordIndex >= value.totalRecords) {
      throw new Error('原始范围页的记录顺序无法核实')
    }
  }
  const end = offset + value.records.length
  if (value.nextOffset !== (end < value.totalRecords ? end : null) || (end < value.totalRecords && end === offset)) {
    throw new Error('原始范围页的后续位置无法核实')
  }
  return value as KernSightBoundSourcePage
}

function equal(left: unknown, right: unknown): boolean {
  if (left === right) return true
  if (Array.isArray(left) && Array.isArray(right)) return left.length === right.length && left.every((value, index) => equal(value, right[index]))
  if (!object(left) || !object(right)) return false
  const keys = Object.keys(left)
  return keys.length === Object.keys(right).length && keys.every(key => Object.prototype.hasOwnProperty.call(right, key) && equal(left[key], right[key]))
}

function rangePath(sourceReport: string, record: Record<string, any>): string | null {
  const raw = record.raw_evidence
  if (typeof raw !== 'string' || !raw || raw.includes('/') || raw.includes('\\') || raw === '.' || raw === '..') return null
  const parent = sourceReport.slice(0, sourceReport.lastIndexOf('/') + 1)
  return parent + raw
}

export function boundSourceLocalAnalysis(ledger: Record<string, any> | undefined, page: KernSightBoundSourcePage, row: KernSightBoundSourcePage['records'][number]): KernSightRuntimeRangeInventoryEntry | null {
  const producer = row.producerRecord
  if (!object(producer) || !object(producer.source) || !object(producer.read) || !object(producer.mapping)) return null
  const path = rangePath(page.sourceReport, producer)
  if (path === null) return null
  const inventory = Array.isArray(ledger?.runtime_range_inventory) ? ledger.runtime_range_inventory : ledger?.runtime_observations
  const matches = array(inventory).filter(local => local.schema === 'mobilee.bound-runtime-range/v1' && local.source_report === page.sourceReport
    && hash(local.source_report_sha256) && local.source_report_sha256.toLowerCase() === page.sourceSha256.toLowerCase()
    && local.source_record_index === row.sourceRecordIndex && local.relative_path === path
    && equal(local.source, producer.source) && equal(local.mapping, producer.mapping) && equal(local.read, producer.read))
  if (matches.length !== 1) return null
  const local = matches[0]
  if (local.local_content_status === 'unknown_or_failed') return local as KernSightRuntimeRangeInventoryEntry
  if (local.local_content_status !== 'complete_range_hash_verified' || !hash(producer.read.sha256)
      || !count(producer.read.actual_length) || producer.read.actual_length === 0) return null
  return local as KernSightRuntimeRangeInventoryEntry
}

export function boundSourceInspection(ledger: Record<string, any> | undefined, local: KernSightRuntimeRangeInventoryEntry | null): Record<string, any> | null {
  if (!local || local.local_content_status !== 'complete_range_hash_verified' || !count(local.inspection_ref)
      || !hash(local.read?.sha256) || !count(local.read?.actual_length) || local.read.actual_length === 0
      || local.inspection_content_key !== `${local.read.sha256}:${local.read.actual_length}`) return null
  const heavy = ledger?.runtime_observations?.[local.inspection_ref]
  if (!object(heavy) || heavy.local_content_status !== 'complete_range_hash_verified'
      || heavy.read?.sha256 !== local.read.sha256 || heavy.read?.actual_length !== local.read.actual_length) return null
  return object(heavy.object_inspection) ? heavy.object_inspection : null
}

export function boundSourceAnalysisLabel(local: KernSightRuntimeRangeInventoryEntry | null): string {
  if (!local) return '本地分析关联未核实'
  if (local.local_content_status === 'complete_range_hash_verified') return '范围 hash 已验证'
  return `本地验证未知${local.content_verification_failure_reason ? `：${local.content_verification_failure_reason}` : '（原记录未提供原因）'}`
}

export function runtimeRangeCounts(ledger?: Record<string, any>) {
  const inventory = Array.isArray(ledger?.runtime_range_inventory) ? ledger.runtime_range_inventory : undefined
  const supplied = (key: string, fallback: unknown): unknown => ledger && Object.prototype.hasOwnProperty.call(ledger, key) ? ledger[key] : fallback
  const verified = inventory?.filter(row => object(row) && row.local_content_status === 'complete_range_hash_verified').length
  const inspectedRows = inventory?.filter(row => object(row)
    && ['bounded_candidate_inspection', 'no_dex_or_elf_header_in_retained_range', 'inspected'].includes(row.inspection_status))
  const inspected = inspectedRows?.length
  const contentKeys = inspectedRows?.map(row => row.inspection_content_key)
  const validKey = (key: unknown): key is string => typeof key === 'string' && /^[a-f0-9]{64}:[1-9]\d*$/i.test(key)
    && Number.isSafeInteger(Number(key.slice(65)))
  const uniqueInspections = contentKeys?.every(validKey) ? new Set(contentKeys.map(key => key.toLowerCase())).size : undefined
  return {
    inventory: supplied('runtime_range_inventory_records', inventory?.length),
    verified: supplied('runtime_verified_ranges', verified),
    unverified: supplied('runtime_unverified_ranges', inventory && verified !== undefined ? inventory.length - verified : undefined),
    inspected: supplied('runtime_inspected_ranges', inspected),
    uninspected: supplied('runtime_uninspected_ranges', inventory && inspected !== undefined ? inventory.length - inspected : undefined),
    uniqueInspections: supplied('runtime_inspection_unique_contents', uniqueInspections),
    savedInspectionPool: Array.isArray(ledger?.runtime_observations) ? ledger.runtime_observations.length : undefined,
    omittedInspections: supplied('runtime_inspection_rows_omitted', ledger?.runtime_heavy_results_omitted_records),
  }
}

export function runtimeCoverageSummary(ledger?: Record<string, any>): string {
  const n = (value: unknown) => count(value) ? value.toLocaleString('en-US') : '未知'
  const status = (value: unknown) => value === true ? '完整（已列示范围）' : value === false ? '不完整' : '未知'
  if (Array.isArray(ledger?.runtime_range_inventory)) {
    const counts = runtimeRangeCounts(ledger)
    return `范围清单 ${n(counts.inventory)} 条；hash 已验证 ${n(counts.verified)} 条，验证未知 ${n(counts.unverified)} 条。有界检查记录 ${n(counts.inspected)} 条，检查未知或未执行 ${n(counts.uninspected)} 条；独立内容检查 ${n(counts.uniqueInspections)} 份；保存的共享检查结果池 ${n(counts.savedInspectionPool)} 条，检查结果省略 ${n(counts.omittedInspections)} 条。来源报告上限 ${n(ledger.runtime_source_limit)} 份，另省略 ${n(ledger.runtime_sources_omitted)} 份。来源账本${status(ledger.runtime_source_ledger_complete)}；代码分析${status(ledger.runtime_analysis_complete)}。统计仅限当前已载入库存；有界检查不等于完整分析。`
  }
  const loaded = Array.isArray(ledger?.runtime_observations) ? String(ledger.runtime_observations.length) : '未知'
  const plain = (value: unknown) => count(value) ? String(value) : '未知'
  return `已载入范围 ${loaded} 条；范围上限 ${plain(ledger?.runtime_observation_limit)} 条，另省略 ${plain(ledger?.omitted_observations)} 条。来源报告上限 ${plain(ledger?.runtime_source_limit)} 份，另省略 ${plain(ledger?.runtime_sources_omitted)} 份。来源账本${status(ledger?.runtime_source_ledger_complete)}；代码分析${status(ledger?.runtime_analysis_complete)}。`
}
