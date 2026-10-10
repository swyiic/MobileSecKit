export function codeEvidenceLabel(notes?: Array<Record<string, any>>): string {
  if (!notes?.length) return ''
  return notes.map(note => {
    if (note.schema === 'mobilee.bound-runtime-range/v1') {
      const read = note.read || {}
      const analysis = note.inventory_role === 'lightweight_range_ledger' ? `代码检查 ${note.inspection_status || '未知'}（详情按已验证内容关联）` : 'DEX/SO 解析与分类未知'
      return `${note.mapping?.path || '映射来源未知'} · 请求 ${read.requested_length ?? '未知'} B / 实际读 ${read.actual_length ?? '未知'} B / 留存 ${note.retained_file_bytes ?? '未知'} B · ${note.local_content_status === 'complete_range_hash_verified' ? '完整范围 hash 已核对' : '范围内容未验证'} · 读取 ${read.read_status || '未知'} / 落盘 ${read.write_status || '未知'} · torn ${typeof read.torn === 'boolean' ? String(read.torn) : '未知'} · ${note.source_identity_status || '实例来源未知'} · ${analysis}（范围 hash 不证明完整映射）`
    }
    if (note.schema === 'kernsight.bounded-code-range/v1') {
      const read = note.read || {}
      const count = (n:unknown) => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0
      const valid = read.schema === 'kernsight.memory-read/v1' && count(read.requested_start) && count(read.actual_start) && count(note.start) && count(note.end) && note.end > note.start && read.requested_bytes === note.admitted_bytes && count(note.unadmitted_bytes) && note.unadmitted_bytes === note.end - note.start - note.admitted_bytes && count(read.requested_bytes) && count(read.actual_bytes) && read.actual_bytes <= read.requested_bytes && read.actual_start === read.requested_start && read.requested_start === note.start && (read.read_status === 'read_failed' ? typeof read.read_error === 'string' && !!read.read_error : read.read_error === null)
      const status = !valid ? '读取状态未知' : read.read_status === 'read_failed' ? '读取失败' : read.read_status === 'short_read' && read.actual_bytes < read.requested_bytes ? '短读' : read.read_status === 'complete' && read.actual_bytes === read.requested_bytes && read.read_error === null ? '准入范围读全' : '读取状态未知'
      return `${note.path || '来源未知'} · ${status} · 准入 ${note.admitted_bytes ?? '未知'} B / 未准入 ${note.unadmitted_bytes ?? '未知'} B · 保留 ${note.retained_bytes ?? '未知'} B · ${note.local_content_status === 'complete_file_hash_verified' ? '保留文件 hash 已核对' : '内容未验证'} · ${note.write_status === 'retained' ? '已落盘' : '落盘失败或未知'} · 归属未知（只读安装代码容器采样）`
    }
    if (note.schema !== 'kernsight.apk-member-evidence/v1') return '代码来源未知'
    const source = note.source || {}
    const local = note.local_content_status === 'complete_file_hash_verified' ? '保留文件完整 hash 已核对' : '保留内容未验证'
    const ownership = note.ownership || {}
    const labels: Record<string,string> = {business:'业务线索', internal_component:'内部组件线索', third_party_sdk:'SDK 线索', mixed:'混合', unknown:'未知'}
    return `${source.zip_member || 'ZIP 成员未知'} · APK ${(source.apk_sha256 || '').slice(0,12) || '未知'} · 原始成员 ${(note.raw_member_sha256 || '').slice(0,12) || '未知'} → 保留 ${(note.sha256 || '').slice(0,12) || '未知'} · 来源偏移 ${source.member_offset ?? (note.transformation === 'identity' ? 0 : '未知')} · ${note.transformation || '变换未知'} · ${local} · 归属 ${labels[ownership.category] || '未知'}（${(ownership.reasons || []).join('；') || '依据未知'}）· APK 原成员未在本地重解包核对`
  }).join('；')
}

export function allocatedEvidenceLabel(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? `${value.toLocaleString()} B` : '未知'
}

function presentByte(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
}

function formatScanBytes(value: unknown): string {
  const amount = presentByte(value)
  if (amount == null) return '未知'
  if (amount === 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let size = amount
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1 }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`
}

type ScanInspection = {
  file_bytes?: unknown
  scanned_bytes?: unknown
  scanned_through_offset?: unknown
  unscanned_tail_bytes?: unknown
  candidate_stop_reason?: unknown
  status?: unknown
  [key: string]: unknown
}

/** Scan range, stop reason, and unread tail. A missing field stays 未知. */
export function dexScanSummary(inspection?: ScanInspection | null): string {
  if (!inspection) return '未知（旧数据未检查）'
  const file = formatScanBytes(inspection.file_bytes)
  const scanned = formatScanBytes(inspection.scanned_through_offset ?? inspection.scanned_bytes)
  const tail = formatScanBytes(inspection.unscanned_tail_bytes)
  const stop = typeof inspection.candidate_stop_reason === 'string' && inspection.candidate_stop_reason.trim()
    ? inspection.candidate_stop_reason
    : '未知'
  const status = typeof inspection.status === 'string' && inspection.status.trim() ? inspection.status : '未知'
  return `${status} · 文件 ${file} · DEX 扫描到 ${scanned} · 停止 ${stop} · 未扫描尾部 ${tail}`
}

function scanSourceLabel(range: Record<string, any>): string {
  const mapping = range.mapping && typeof range.mapping === 'object' ? range.mapping.path : undefined
  const path = typeof mapping === 'string' && mapping
    ? mapping
    : typeof range.raw_evidence === 'string' && range.raw_evidence
      ? range.raw_evidence
      : typeof range.relative_path === 'string' && range.relative_path
        ? range.relative_path
        : '来源未知'
  const source = range.source && typeof range.source === 'object' ? range.source : {}
  const pid = source.pid ?? '未知'
  const exec = source.exec_id ?? '未知'
  return `${path} · pid ${pid} · exec ${exec}`
}

function observationArtifactPath(range: Record<string, any>): string {
  // The local ledger resolves this path against the bundle root. Device mapping
  // paths and matching basenames do not identify the retained local artifact.
  if (typeof range.relative_path === 'string' && range.relative_path) return range.relative_path
  const raw = range.raw_evidence
  if (typeof raw !== 'string' || !raw) return ''
  const report = range.source_report
  if (typeof report !== 'string' || !report) return raw
  // Older records can still identify an artifact relative to its source report.
  // The producer accepts only a filename here, not an arbitrary relative path.
  if (raw.includes('/') || raw.includes('\\') || raw === '.' || raw === '..') return ''
  const cut = Math.max(report.lastIndexOf('/'), report.lastIndexOf('\\'))
  return report.slice(0, cut + 1) + raw
}

/** An exact artifact gets its own rows; otherwise preserve every matching object source. */
function scanLines(observations: unknown, shas: string[], filePath: string, preferPath: boolean, retainedShas: string[] = []): string[] {
  if (!Array.isArray(observations)) return []
  const byPath: string[] = []
  const bySha: string[] = []
  for (const range of observations) {
    if (!range || typeof range !== 'object') continue
    const row = range as Record<string, any>
    const inspection = row.object_inspection as ScanInspection | undefined
    const derived = Array.isArray(inspection?.derived_objects) ? inspection.derived_objects as Array<{ sha256?: string }> : []
    const shaHit = derived.some(object => typeof object?.sha256 === 'string' && shas.includes(object.sha256))
    const rangeSha = row.read?.sha256
    // A range/container hash is not a derived DEX hash. Only compare it with
    // known retained-file hashes when deciding whether a path is still current.
    const conflictingHash = typeof rangeSha === 'string' && rangeSha.length > 0 && retainedShas.length > 0 && !retainedShas.includes(rangeSha)
    const pathHit = filePath.length > 0 && filePath === observationArtifactPath(row) && !conflictingHash
    const line = `${scanSourceLabel(row)} · ${dexScanSummary(inspection)}`
    if (pathHit) byPath.push(line)
    else if (shaHit) bySha.push(line)
  }
  if (preferPath && byPath.length) return byPath
  return byPath.concat(bySha)
}

export function dexScanSummaryForObject(observations: unknown, sha: unknown): string {
  if (typeof sha !== 'string' || !sha || !Array.isArray(observations)) return dexScanSummary(null)
  const lines = scanLines(observations, [sha], '', false)
  return lines.length ? lines.join('；') : '未知（没有对应的扫描记录）'
}

/** Scan position, stop reason, and unread tail for this file. Missing fields stay 未知. */
export function fileScanLabel(observations: unknown, file: { relativePath?: string; relative_path?: string; codeEvidence?: Array<Record<string, any>>; code_evidence?: Array<Record<string, any>>; sha256?: string }, ledger?: any): string {
  const filePath = file.relativePath || file.relative_path || ''
  const noteValues = file.codeEvidence || file.code_evidence
  const notes = Array.isArray(noteValues) ? noteValues : []
  const shas: string[] = []
  const retainedShas: string[] = []
  if (typeof file.sha256 === 'string' && file.sha256) shas.push(file.sha256)
  for (const note of notes) {
    for (const value of [note?.sha256, note?.read?.sha256]) {
      if (typeof value === 'string' && value && !retainedShas.includes(value)) retainedShas.push(value)
    }
    for (const key of ['sha256', 'raw_member_sha256'] as const) {
      const value = note?.[key]
      if (typeof value === 'string' && value && !shas.includes(value)) shas.push(value)
    }
  }
  const aliasRows = notes.flatMap(note => {
    const resolved = runtimeInventoryInspection(ledger, note)
    return resolved ? [{ ...resolved.range, object_inspection:resolved.inspection }] : []
  })
  const rows = aliasRows.length ? aliasRows.concat(Array.isArray(observations) ? observations.filter(row => !record(row) || observationArtifactPath(row) !== filePath) : []) : observations
  const lines = scanLines(rows, shas, filePath, true, file.sha256 ? [file.sha256] : retainedShas)
  return lines.length ? lines.join('；') : `来源未知 · ${dexScanSummary({})}`
}

export function ownershipEvidenceEntries(schema: unknown, entries: Array<Record<string, any>>): any[] {
  return schema === 'mobilee.kernsight-dex-ownership/v4' ? entries : entries.map(entry => ({...entry, category:'unknown',confidence:0,reasons:['旧归属 schema 缺少本轮可重建依据；原记录保留，不能当作已验证归属']}))
}

/** Display only. Merge verified complete retained content and keep every source/status row. */
export function codeNoiseLayers(files: Array<Record<string, any>>): Array<{ key: string; label: string; groups: Array<{ key: string; paths: string[]; rows: Array<Record<string, any>>; sha256: string | null }> }> {
  const layers = [
    { key: 'attention', label: 'partial / 失败 / 来源状态未知（不折叠隐藏）', groups: [] as any[] },
    { key: 'business', label: '业务候选（类线索，不是已验证所有权）', groups: [] as any[] },
    { key: 'system', label: '系统代码（平台内容签名依据）', groups: [] as any[] },
    { key: 'sdk', label: '第三方 SDK（内容签名依据）', groups: [] as any[] },
    { key: 'mixed', label: '混合 / 未知（包名、文件名、SDK 命名空间不足以排除业务）', groups: [] as any[] },
  ]
  const merged = new Map<string, any>()
  files.forEach((file, index) => {
    const notes = file.codeEvidence || file.code_evidence || []
    if (!notes.length && !['dex', 'elf'].includes(file.content_class || file.category)) return
    const verified = notes.find((n: any) => n.local_content_status === 'complete_file_hash_verified' && /^[a-f0-9]{64}$/.test(n.sha256 || ''))
    const incomplete = notes.some((n: any) => n.source_complete === false || ['short_read', 'read_failed'].includes(n.read?.read_status || n.read_status) || ['write_failed', 'failed'].includes(n.write_status))
    const complete = !incomplete && verified && verified.source_complete === true && ['retained', 'hard_link', 'existing_verified'].includes(verified.write_status)
    const ownership = notes.find((n: any) => n.ownership)?.ownership
    const layer = !complete ? 'attention' : ownership?.category === 'mixed' ? 'mixed' : ownership?.category === 'business' || ownership?.category === 'internal_component' ? 'business' : 'mixed'
    const key = complete ? `${verified.sha256}:${file.bytes}` : `source:${index}`
    const row = { path: file.relativePath || file.relative_path || '来源未知', bytes: file.bytes, notes }
    if (complete && merged.has(key)) {
      const group = merged.get(key)
      group.paths.push(row.path); group.rows.push(row)
      if (group.layer !== layer) group.layer = 'mixed'
    } else {
      const group = { key, layer, paths: [row.path], rows: [row], sha256: complete ? verified.sha256 : null }
      merged.set(key, group)
    }
  })
  for (const group of Array.from(merged.values())) layers.find(l => l.key === group.layer)!.groups.push(group)
  return layers
}

export function archiveCoverageLabel(coverage?: Record<string, unknown>): string {
  return coverage?.status === 'partial' ? 'partial：有效归档仅包含已留存路径，缺段未补齐' : '未知：旧schema或尚无归档覆盖依据'
}

export function elfLoadCoverageLabel(value: unknown): string {
  return value === true ? '列示范围全部覆盖' : value === false ? '仍有缺口' : '未知（缺字段）'
}

export type DexClassMatchResult = {
  total: number | null
  classes: string[]
  omitted: number
  status: 'indexed' | 'unlinked' | 'unknown'
  offset: number
  nextOffset: number | null
}

const record = (value: any): value is Record<string, any> => Boolean(value) && typeof value === 'object' && !Array.isArray(value)
const finiteCount = (value: any): value is number => Number.isSafeInteger(value) && value >= 0
const dexKey = (value: any): string | null => record(value) && /^[a-f0-9]{64}$/i.test(value.sha256 || '') && finiteCount(value.bytes) ? `${value.sha256.toLowerCase()}:${value.bytes}` : null
const strings = (value: any): value is string[] => Array.isArray(value) && value.every(item => typeof item === 'string')

/** The same object inventory drives the headline and independent object list. */
export function projectDexEvidence(dump: any): { objects: any[]; reportedCount: number | null; status: 'objects' | 'reported_count_only' | 'empty' | 'unknown'; warnings: string[] } {
  const objects = new Map<string, any>()
  const warnings: string[] = []
  const sourceProjection = dump?.content_dex_class_index?.runtime_inventory_projection
  if (record(sourceProjection) && sourceProjection.complete !== true) {
    const count = (value: unknown) => finiteCount(value) ? String(value) : '未知'
    warnings.push(`已验证 DEX 范围的来源关联${sourceProjection.complete === false ? '不完整' : '状态未知'}：无效 ${count(sourceProjection.invalid_rows)} 条，未列入 ${count(sourceProjection.omitted_links)} 条，未匹配 ${count(sourceProjection.unmatched_dex_links)} 条；这只说明来源关联，不代表所有范围已验证或代码分析完成。`)
  }
  const content = dump?.content_dex_class_index?.objects
  const sets = dump?.dex_sets
  if (content !== undefined && !Array.isArray(content)) warnings.push('本地结构对象明细格式无效，原记录仍保留。')
  if (sets !== undefined && !Array.isArray(sets)) warnings.push('生产者 DEX Set 明细格式无效，原记录仍保留。')
  for (const object of Array.isArray(content) ? content : []) {
    const key = dexKey(object)
    if (!key) { warnings.push('结构对象缺少有效 SHA-256/长度，未计入可展开对象。'); continue }
    if (!Array.isArray(object.sources)) warnings.push('结构对象来源明细未知。')
    const previous = objects.get(key)
    const sources = Array.isArray(object.sources) ? object.sources.filter(record) : []
    if (previous) { previous.sources.push(...sources); continue }
    objects.set(key, { ...object, sources, legacy_observations: [], display_index_origin: 'local_content_index' })
  }
  for (const set of Array.isArray(sets) ? sets : []) {
    const key = dexKey(set)
    if (!key) { warnings.push('DEX Set 缺少有效 SHA-256/长度，未计入可展开对象。'); continue }
    const observations = Array.isArray(set.observations) ? set.observations.filter(record) : []
    const source = { kind: 'producer_dex_set', relative_path: typeof set.canonical_relative_path === 'string' ? set.canonical_relative_path : null, observations, verification: 'producer_record_only_not_reverified_here' }
    const previous = objects.get(key)
    if (previous) { previous.legacy_observations.push(source); continue }
    const semantic = record(set.semantic) ? set.semantic : null
    const classes = strings(semantic?.class_descriptors) ? semantic.class_descriptors : undefined
    objects.set(key, {
      sha256: set.sha256, bytes: set.bytes, sources: [source], legacy_observations: [],
      classes, declared_classes: finiteCount(semantic?.class_defs) ? semantic.class_defs : null,
      indexed_classes: classes ? classes.length : null,
      class_index_status: classes ? (semantic?.class_descriptors_truncated ? 'producer_class_samples_truncated' : 'producer_class_samples') : 'unknown',
      validation_status: 'unknown; producer_record_only_not_reverified_here', ownership: 'unknown',
      display_index_origin: 'producer_dex_set',
    })
  }
  const rows = Array.from(objects.values())
  const old = dump?.dex_index?.unique_dex ?? dump?.readable_dex
  const reported = rows.length || (finiteCount(old) ? old : (Array.isArray(content) || Array.isArray(sets) ? 0 : null))
  return {
    objects: rows, reportedCount: reported,
    status: rows.length ? 'objects' : reported === null ? 'unknown' : reported > 0 ? 'reported_count_only' : 'empty',
    warnings: Array.from(new Set(warnings)),
  }
}

function sameMetadata(left: any, right: any): boolean {
  if (left === right) return true
  if (Array.isArray(left) && Array.isArray(right)) return left.length === right.length && left.every((value, index) => sameMetadata(value, right[index]))
  if (!record(left) || !record(right)) return false
  const keys = Object.keys(left)
  return keys.length === Object.keys(right).length && keys.every(key => Object.prototype.hasOwnProperty.call(right, key) && sameMetadata(left[key], right[key]))
}

function isInventorySource(source: any): boolean {
  return record(source) && (source.kind === 'runtime_range_inventory' || source.kind === 'runtime' && (source.inventory_row_index !== undefined || source.source_projection_verification !== undefined))
}

/** A lightweight alias retains its own identity; only its verified content inspection is shared. */
export function runtimeInventoryInspection(ledger: any, source: any): { range: Record<string, any>; inspection: Record<string, any> } | null {
  if (!record(source) || !Array.isArray(ledger?.runtime_range_inventory)) return null
  const alias = isInventorySource(source)
  const projectionVerification = source.kind === 'runtime' ? source.source_projection_verification : source.verification
  if (alias && (projectionVerification !== 'current_verified_range_and_shared_content_inspection' || !finiteCount(source.inventory_row_index))) return null
  if (!alias && (source.inventory_role !== 'lightweight_range_ledger' || source.schema !== 'mobilee.bound-runtime-range/v1')) return null
  const candidates = alias ? [ledger.runtime_range_inventory[source.inventory_row_index]] : ledger.runtime_range_inventory
  const sha = source.source_report_sha256
  if (!/^[a-f0-9]{64}$/i.test(sha || '') || !finiteCount(source.source_record_index) || !record(source.source) || typeof source.relative_path !== 'string' || !source.relative_path) return null
  if (!Array.isArray(ledger.runtime_source_diagnostics) || !ledger.runtime_source_diagnostics.some((diagnostic: any) => record(diagnostic) && diagnostic.source_report === source.source_report && diagnostic.source_report_sha256 === sha)) return null
  const rows = candidates.filter((row: any) => record(row) && row.schema === 'mobilee.bound-runtime-range/v1' && row.inventory_role === 'lightweight_range_ledger'
    && row.source_report === source.source_report && row.source_report_sha256 === sha && row.source_record_index === source.source_record_index
    && row.relative_path === source.relative_path && sameMetadata(row.source, source.source)
    && (alias ? row.read?.sha256 === source.range_sha256 && row.inspection_ref === source.inspection_ref && row.inspection_content_key === source.inspection_content_key : sameMetadata(row.read, source.read) && sameMetadata(row.mapping, source.mapping)))
  if (rows.length !== 1) return null
  const row = rows[0]
  const identity = row.source
  if (typeof identity.package !== 'string' || !identity.package || typeof identity.boot_id !== 'string' || !identity.boot_id || !['pid','uid','birth_ns','exec_id'].every(key => finiteCount(identity[key])) || !identity.pid || !identity.birth_ns) return null
  if (row.local_content_status !== 'complete_range_hash_verified' || !finiteCount(row.inspection_ref) || !/^[a-f0-9]{64}$/i.test(row.read?.sha256 || '') || !finiteCount(row.read?.actual_length)
      || row.inspection_content_key !== `${row.read.sha256}:${row.read.actual_length}`) return null
  const heavy = ledger.runtime_observations?.[row.inspection_ref]
  if (!record(heavy) || heavy.local_content_status !== 'complete_range_hash_verified' || heavy.read?.sha256 !== row.read.sha256 || heavy.read?.actual_length !== row.read.actual_length || !record(heavy.object_inspection)) return null
  return { range:row, inspection:heavy.object_inspection }
}

function inventoryHasDex(ledger: any, source: any): boolean {
  const resolved = runtimeInventoryInspection(ledger, source)
  return Boolean(resolved && Array.isArray(resolved.inspection.derived_objects) && resolved.inspection.derived_objects.some((dex: any) => record(dex) && dex.kind === 'dex' && /^[a-f0-9]{64}$/i.test(dex.sha256 || '') && finiteCount(dex.length) && finiteCount(dex.source_offset) && dex.source_offset + dex.length <= resolved.range.read.actual_length))
}

/** File inventory is separate from logical objects; a container is included only through an exact selected-report or retained-note DEX relationship. */
export function matchesReadableDexEvidence(file: any, dump: any): boolean {
  const path = file?.relativePath || file?.relative_path
  if (typeof path !== 'string' || !path) return false
  if (/^(?:readable-dex\/|(?:runtime\/)?blob-dex\/|runtime\/mem-).*\.dex$/i.test(path)) return true
  if (Array.isArray(dump?.artifacts) && dump.artifacts.some((artifact: any) => record(artifact) && artifact.kind === 'dex' && artifact.relative_path === path)) return true
  if (Array.isArray(dump?.dex_sets) && dump.dex_sets.some((set: any) => dexKey(set) && set.canonical_relative_path === path)) return true
  if (Array.isArray(dump?.content_dex_class_index?.objects) && dump.content_dex_class_index.objects.some((object: any) => dexKey(object) && Array.isArray(object.sources) && object.sources.some((source: any) => record(source) && source.relative_path === path && (!isInventorySource(source) || inventoryHasDex(dump?.local_storage_accounting, source))))) return true
  const notes = file?.codeEvidence || file?.code_evidence
  if (Array.isArray(notes) && notes.some((note: any) => note?.relative_path === path && inventoryHasDex(dump?.local_storage_accounting, note))) return true
  return Array.isArray(notes) && notes.some((note: any) => record(note) && note.inventory_role !== 'lightweight_range_ledger' && note.relative_path === path && note.local_content_status === 'complete_range_hash_verified' && Array.isArray(note.object_inspection?.derived_objects) && note.object_inspection.derived_objects.some((object: any) => record(object) && object.kind === 'dex' && /^[a-f0-9]{64}$/i.test(object.sha256 || '') && finiteCount(object.length)))
}

/** Missing/unlinked class indexes have no measured match count. Exact qualified source identity and range/content hashes remain required. */
export function runtimeDexClassMatches(ledger: any, object: any, query: string, offset = 0): DexClassMatchResult {
  const unavailable = (status: 'unlinked' | 'unknown'): DexClassMatchResult => ({ total: null, classes: [], omitted: 0, status, offset: 0, nextOffset: null })
  if (!record(object)) return unavailable('unknown')
  let classes: string[] | undefined
  if (object.classes !== undefined) {
    if (!strings(object.classes)) return unavailable('unknown')
    classes = object.classes
  }
  let qualified = false
  if (!classes) {
    const runtime = Array.isArray(ledger?.runtime_observations) ? ledger.runtime_observations.filter(record) : []
    for (const source of Array.isArray(object.sources) ? object.sources : []) {
      if (!record(source)) continue
      if (isInventorySource(source)) {
        qualified = true
        const resolved = runtimeInventoryInspection(ledger, source)
        if (!resolved || !finiteCount(source.source_offset) || !finiteCount(object.bytes) || source.source_offset + object.bytes > resolved.range.read.actual_length) continue
        if (source.source_absolute_start != null && (!finiteCount(resolved.range.read.actual_start) || source.source_absolute_start !== resolved.range.read.actual_start + source.source_offset)) continue
        for (const dex of Array.isArray(resolved.inspection.derived_objects) ? resolved.inspection.derived_objects : []) {
          if (!record(dex) || dex.sha256 !== object.sha256 || dex.length !== object.bytes || dex.source_offset !== source.source_offset) continue
          if (strings(dex.class_index?.classes)) { classes = dex.class_index.classes; break }
        }
        if (classes) break
        continue
      }
      if (source.kind !== 'runtime') continue
      const identity = source.source
      const validIdentity = record(identity) && typeof identity.package === 'string' && !!identity.package && typeof identity.boot_id === 'string' && !!identity.boot_id && ['pid', 'uid', 'birth_ns', 'exec_id'].every(key => finiteCount(identity[key]))
      if (!validIdentity || typeof source.source_report !== 'string' || !source.source_report || !/^[a-f0-9]{64}$/i.test(source.range_sha256 || '')) continue
      qualified = true
      const indexed = finiteCount(source.row_index) ? ledger?.runtime_observations?.[source.row_index] : null
      const rows = record(indexed) ? [indexed, ...runtime.filter((row: any) => row !== indexed)] : runtime
      for (const row of rows) {
        if (row.source_report !== source.source_report || row.read?.sha256 !== source.range_sha256 || !record(row.source) || ['package', 'pid', 'uid', 'birth_ns', 'exec_id', 'boot_id'].some(key => row.source[key] !== identity[key])) continue
        for (const dex of Array.isArray(row.object_inspection?.derived_objects) ? row.object_inspection.derived_objects : []) {
          if (!record(dex) || dex.sha256 !== object.sha256 || dex.length !== object.bytes) continue
          if (source.source_offset != null && (!finiteCount(source.source_offset) || dex.source_offset !== source.source_offset)) continue
          const rangeLength = row.read?.actual_length ?? row.read?.actual_bytes
          if (source.source_offset != null && finiteCount(rangeLength) && source.source_offset + object.bytes > rangeLength) continue
          if (strings(dex.class_index?.classes)) { classes = dex.class_index.classes; break }
        }
        if (classes) break
      }
      if (classes) break
    }
  }
  if (!classes) return unavailable(qualified ? 'unlinked' : 'unknown')
  const needle = String(query || '').toLowerCase()
  const matches = classes.filter(value => value.toLowerCase().includes(needle))
  const start = finiteCount(offset) ? Math.min(offset, Math.max(0, matches.length - 1)) : 0
  const shown = matches.slice(start, start + 500)
  const nextOffset = start + shown.length < matches.length ? start + shown.length : null
  return { total: matches.length, classes: shown, omitted: Math.max(0, matches.length - shown.length), status: 'indexed', offset: start, nextOffset }
}

export function indexedDexCount(dump: any): number | null {
  return projectDexEvidence(dump).reportedCount
}

export function indexedElfModuleCount(dump:any):number|null {
  const modules=dump?.local_storage_accounting?.elf_module_observations
  if(Array.isArray(modules)) return new Set(modules.map((m:any)=>m.path).filter((p:any)=>typeof p==='string')).size
  return Number.isSafeInteger(dump?.runtime_libs) && dump.runtime_libs>=0 ? dump.runtime_libs : null
}

/** Diagnostic objects stay searchable but never enter the checksum/declared-span verified group. */
export function dexObjectGroups(objects:any[] = []):Array<{kind:string;label:string;objects:any[]}> {
  const entries = Array.isArray(objects) ? objects.filter(record) : []
  const verified=(o:any)=>o.sha1_signature_verified===true && o.adler32_checksum_verified===true && o.validation_status==='checksum_and_bounded_structure_verified' && o.layout_diagnostics?.status==='declared_spans_cover_file'
  return [
    {kind:'verified',label:'校验通过的结构对象（有界检查，仍不证明完整业务恢复）',objects:entries.filter(verified)},
    {kind:'diagnostic',label:'诊断对象：校验失败、布局异常或未知（不进入校验通过计数）',objects:entries.filter(o=>!verified(o))},
  ].filter(g=>g.objects.length>0)
}
export function verifiedDexObjectCount(dump:any):number|null {
  const objects=dump?.content_dex_class_index?.objects
  if(!Array.isArray(objects))return null
  return new Set((dexObjectGroups(objects).find(g=>g.kind==='verified')?.objects||[]).map(o=>`${o.sha256}:${o.bytes}`)).size
}
