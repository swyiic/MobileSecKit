export function codeEvidenceLabel(notes?: Array<Record<string, any>>): string {
  if (!notes?.length) return ''
  return notes.map(note => {
    if (note.schema === 'mobilee.bound-runtime-range/v1') {
      const read = note.read || {}
      return `${note.mapping?.path || '映射来源未知'} · 请求 ${read.requested_length ?? '未知'} B / 实际读 ${read.actual_length ?? '未知'} B / 留存 ${note.retained_file_bytes ?? '未知'} B · ${note.local_content_status === 'complete_range_hash_verified' ? '完整范围 hash 已核对' : '范围内容未验证'} · 读取 ${read.read_status || '未知'} / 落盘 ${read.write_status || '未知'} · torn ${typeof read.torn === 'boolean' ? String(read.torn) : '未知'} · ${note.source_identity_status || '实例来源未知'} · DEX/SO 解析与分类未知（范围 hash 不证明完整映射）`
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

function sourceBasename(value: string): string {
  const cut = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'))
  return cut >= 0 ? value.slice(cut + 1) : value
}

function sameSourcePath(filePath: string, candidate: string): boolean {
  if (!filePath || !candidate) return false
  if (filePath === candidate) return true
  const left = sourceBasename(filePath)
  const right = sourceBasename(candidate)
  return left.length > 0 && left === right
}

function observationPaths(range: Record<string, any>): string[] {
  const mapping = range.mapping && typeof range.mapping === 'object' ? range.mapping.path : undefined
  return [mapping, range.raw_evidence, range.relative_path].filter((value): value is string => typeof value === 'string' && value.length > 0)
}

/** Every matching source, not the first SHA hit. A path match hides other SHA hits. */
function scanLines(observations: unknown, shas: string[], filePath: string, preferPath: boolean): string[] {
  if (!Array.isArray(observations)) return []
  const byPath: string[] = []
  const bySha: string[] = []
  for (const range of observations) {
    if (!range || typeof range !== 'object') continue
    const row = range as Record<string, any>
    const inspection = row.object_inspection as ScanInspection | undefined
    const derived = Array.isArray(inspection?.derived_objects) ? inspection.derived_objects as Array<{ sha256?: string }> : []
    const shaHit = derived.some(object => typeof object?.sha256 === 'string' && shas.includes(object.sha256))
    const pathHit = filePath.length > 0 && observationPaths(row).some(candidate => sameSourcePath(filePath, candidate))
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
export function fileScanLabel(observations: unknown, file: { relativePath?: string; relative_path?: string; codeEvidence?: Array<Record<string, any>>; code_evidence?: Array<Record<string, any>>; sha256?: string }): string {
  const filePath = file.relativePath || file.relative_path || ''
  const notes = file.codeEvidence || file.code_evidence || []
  const shas: string[] = []
  if (typeof file.sha256 === 'string' && file.sha256) shas.push(file.sha256)
  for (const note of notes) {
    for (const key of ['sha256', 'raw_member_sha256'] as const) {
      const value = note?.[key]
      if (typeof value === 'string' && value && !shas.includes(value)) shas.push(value)
    }
  }
  const lines = scanLines(observations, shas, filePath, true)
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

/** Resolve a full class index through the exact displayed runtime source, never a stale row pointer. */
export function runtimeDexClassMatches(ledger: any, object: any, query: string): {total:number;classes:string[];omitted:number} {
  const direct:string[] = Array.isArray(object?.classes) ? object.classes : []
  let classes = direct
  if (!classes.length) {
    const source=object?.sources?.find((s:any)=>s.kind==='runtime')
    const row=source ? ledger?.runtime_observations?.[source.row_index] : undefined
    const identityOk = row && row.source_report===source.source_report && row.read?.sha256===source.range_sha256 && !['package','pid','uid','birth_ns','exec_id','boot_id'].some(k=>row.source?.[k]!==source.source?.[k])
    const dex=identityOk ? row.object_inspection?.derived_objects?.find((d:any)=>d.sha256===object.sha256 && d.length===object.bytes) : undefined
    classes = dex?.class_index?.classes || []
  }
  const needle = query.toLowerCase()
  const matches=classes.filter(c=>c.toLowerCase().includes(needle))
  // The stored index is complete up to the producer cap. This window is only
  // the on-screen list; `total` and `omitted` stay visible beside it.
  const shown = matches.slice(0, 500)
  return {total:matches.length,classes:shown,omitted:Math.max(0, matches.length-shown.length)}
}

export function indexedDexCount(dump:any):number|null {
  const sets=[...(dump?.dex_sets || []),...(dump?.content_dex_class_index?.objects || [])]
  const keys=new Set(sets.filter((s:any)=>/^[a-f0-9]{64}$/i.test(s.sha256 || '') && Number.isSafeInteger(s.bytes) && s.bytes>=0).map((s:any)=>`${s.sha256}:${s.bytes}`))
  if(keys.size || dump?.content_dex_class_index) return keys.size
  const old=dump?.dex_index?.unique_dex ?? dump?.readable_dex
  return Number.isSafeInteger(old) && old>=0 ? old : null
}

export function indexedElfModuleCount(dump:any):number|null {
  const modules=dump?.local_storage_accounting?.elf_module_observations
  if(Array.isArray(modules)) return new Set(modules.map((m:any)=>m.path).filter((p:any)=>typeof p==='string')).size
  return Number.isSafeInteger(dump?.runtime_libs) && dump.runtime_libs>=0 ? dump.runtime_libs : null
}

/** Diagnostic objects stay searchable but never enter the checksum/declared-span verified group. */
export function dexObjectGroups(objects:any[] = []):Array<{kind:string;label:string;objects:any[]}> {
  const verified=(o:any)=>o.sha1_signature_verified===true && o.adler32_checksum_verified===true && o.validation_status==='checksum_and_bounded_structure_verified' && o.layout_diagnostics?.status==='declared_spans_cover_file'
  return [
    {kind:'verified',label:'校验通过的结构对象（有界检查，仍不证明完整业务恢复）',objects:objects.filter(verified)},
    {kind:'diagnostic',label:'诊断对象：校验失败、布局异常或未知（不进入校验通过计数）',objects:objects.filter(o=>!verified(o))},
  ].filter(g=>g.objects.length>0)
}
export function verifiedDexObjectCount(dump:any):number|null {
  const objects=dump?.content_dex_class_index?.objects
  if(!Array.isArray(objects))return null
  return new Set((dexObjectGroups(objects).find(g=>g.kind==='verified')?.objects||[]).map(o=>`${o.sha256}:${o.bytes}`)).size
}
