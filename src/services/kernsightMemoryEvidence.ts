/** Completeness is about the requested read only; marker windows remain unparsed. */
export function memoryEvidenceLabel(path: string, notes?: Array<Record<string, any>>): string {
  if (!/^runtime\/(plaintext|crypto-windows)\//.test(path)) return ''
  if (!notes?.length) return '旧证据／未知读取与落盘状态'
  return notes.map(note => {
    const read = note.schema === 'kernsight.memory-read/v1' ? note : note.read
    const valid = read?.schema === 'kernsight.memory-read/v1'
    const requested = read?.requested_bytes, actual = read?.actual_bytes
    const lengths = Number.isSafeInteger(requested) && Number.isSafeInteger(actual) && requested >= 0 && actual >= 0 && actual <= requested
    const starts = Number.isSafeInteger(read?.requested_start) && read.requested_start >= 0 && read.actual_start === read.requested_start
    const errorKnown = valid && Object.prototype.hasOwnProperty.call(read, 'read_error')
    const readStatus = valid && errorKnown && read.read_status === 'read_failed' && typeof read.read_error === 'string' && read.read_error.length > 0 ? '读取失败'
      : valid && lengths && starts && read.read_status === 'short_read' && actual < requested && errorKnown && read.read_error === null ? '短读'
      : valid && lengths && starts && read.read_status === 'complete' && actual === requested && errorKnown && read.read_error === null ? '请求范围读全'
      : '读取状态未知'
    const range = lengths ? ` · 请求 ${requested} B／实际 ${actual} B${starts ? ` @0x${read.requested_start.toString(16)}` : ' · 地址未知'}` : ''
    if (note.schema === 'kernsight.memory-read/v1') return readStatus + range
    if (note.schema !== 'kernsight.memory-window/v1') return '证据 schema 未知'
    const readContract = valid && lengths && starts && errorKnown && ((read.read_status === 'complete' && actual === requested && read.read_error === null) || (read.read_status === 'short_read' && actual < requested && read.read_error === null) || (read.read_status === 'read_failed' && typeof read.read_error === 'string' && read.read_error.length > 0))
    const windowContract = readContract && note.source_start === note.requested_start && Number.isSafeInteger(note.source_start) && note.source_start >= read.actual_start && Number.isSafeInteger(note.requested_bytes) && Number.isSafeInteger(note.actual_bytes) && note.requested_bytes >= note.actual_bytes && note.actual_bytes === note.source_bytes && note.source_start + note.source_bytes <= read.actual_start + actual && ((note.window_status === 'complete' && note.actual_bytes === note.requested_bytes) || (note.window_status === 'short_read' && note.actual_bytes < note.requested_bytes))
    const identity = windowContract && typeof note.source_relative_path === 'string' && note.source_relative_path.length > 0 && typeof note.relative_path === 'string' && note.relative_path.length > 0 && /^[0-9a-f]{64}$/.test(note.source_sha256 || '') && /^[0-9a-f]{64}$/.test(note.sha256 || '') && Number.isSafeInteger(note.source_bytes) && Number.isSafeInteger(note.derived_offset) && Number.isSafeInteger(note.derived_bytes) && note.derived_offset >= 0 && note.derived_bytes >= 0 && note.derived_offset + note.derived_bytes <= note.source_bytes
    const write = note.write_status === 'write_failed' ? '落盘失败' : note.write_status === 'retained' && identity ? '已保留' : '落盘状态未知'
    const source = typeof note.source_relative_path === 'string' ? ` · 原始 ${note.source_relative_path} → ${note.relative_path || '?'} [${note.derived_offset ?? '?'}, ${note.derived_bytes ?? '?'} B]` : ' · 派生来源未知'
    const windowRange = Number.isSafeInteger(note.requested_bytes) && Number.isSafeInteger(note.actual_bytes) ? ` · 窗口请求 ${note.requested_bytes} B／实际 ${note.actual_bytes} B` : ' · 窗口范围未知'
    return `${readStatus}${range}${windowRange} · ${write} · 未解析${note.duplicate === true ? ' · 内容重复' : ''}${source}`
  }).join('；')
}

/** Older recataloguers may default absent counters to zero. A zero needs a
 * supported read observation; positive failure counts remain explicit evidence. */
export function memoryCounterLabel(value: unknown, files?: Array<{relativePath: string; memoryEvidence?: Array<Record<string, any>>}>): number | '未知' {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return '未知'
  if (value > 0) return value
  const observed = files?.some(file => {
    const label = memoryEvidenceLabel(file.relativePath, file.memoryEvidence)
    return label.startsWith('请求范围读全') || label.startsWith('短读') || label.startsWith('读取失败')
  })
  return observed ? 0 : '未知'
}
