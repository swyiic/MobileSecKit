export function codeEvidenceLabel(notes?: Array<Record<string, any>>): string {
  if (!notes?.length) return ''
  return notes.map(note => {
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

export function ownershipEvidenceEntries(schema: unknown, entries: Array<Record<string, any>>): any[] {
  return schema === 'mobilee.kernsight-dex-ownership/v4' ? entries : entries.map(entry => ({...entry, category:'unknown',confidence:0,reasons:['旧归属 schema 缺少本轮可重建依据；原记录保留，不能当作已验证归属']}))
}
