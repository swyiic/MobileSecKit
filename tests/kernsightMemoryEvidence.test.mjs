import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('../src/services/kernsightMemoryEvidence.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { memoryEvidenceLabel, memoryCounterLabel } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
const path = 'runtime/plaintext/window.txt'
const read = { schema: 'kernsight.memory-read/v1', requested_start: 4096, actual_start: 4096, requested_bytes: 128, actual_bytes: 128, read_status: 'complete', read_error: null }
const note = { schema: 'kernsight.memory-window/v1', read, write_status: 'retained', source_start:4096, requested_start:4096, requested_bytes:128, actual_bytes:128, window_status:'complete', source_relative_path: 'raw.bin', relative_path: 'window.txt', derived_offset: 0, derived_bytes: 128, source_bytes: 128, source_sha256: 'a'.repeat(64), sha256: 'b'.repeat(64) }
test('legacy and incomplete schemas remain unknown', () => {
  assert.match(memoryEvidenceLabel(path), /未知/)
  assert.match(memoryEvidenceLabel(path, [{...note, read: {read_status:'complete'}}]), /读取状态未知/)
  assert.match(memoryEvidenceLabel(path, [{...note, write_status:undefined}]), /落盘状态未知/)
  assert.match(memoryEvidenceLabel(path, [{...note, source_sha256:undefined}]), /落盘状态未知/)
  assert.match(memoryEvidenceLabel(path, [{...note, read:{...read,read_error:undefined}}]), /读取状态未知/)
  assert.match(memoryEvidenceLabel(path, [{...note,window_status:undefined}]), /落盘状态未知/)
  for (const read_status of ['complete','short_read','read_failed']) {
    assert.match(memoryEvidenceLabel(path,[{...note,read:{...read,read_status,actual_bytes:read_status === 'short_read' ? 7 : 128,read_error:undefined}}]), /读取状态未知.*落盘状态未知/)
  }
  assert.match(memoryEvidenceLabel(path, [{...note,actual_bytes:129}]), /落盘状态未知/)
  assert.match(memoryEvidenceLabel(path, [{...note,read:{...read,read_error:'PermissionDenied'}}]), /读取状态未知.*落盘状态未知/)
  assert.match(memoryEvidenceLabel(path, [{...note, read:{...read,requested_start:undefined}}]), /读取状态未知/)
})
test('short reads and failures remain explicit with original relationship', () => {
  assert.match(memoryEvidenceLabel(path,[{...note,read:{...read,actual_bytes:7,read_status:'short_read'}}]), /短读.*请求 128 B／实际 7 B.*raw.bin/)
  assert.match(memoryEvidenceLabel(path,[{...note,read:{...read,read_status:'read_failed',read_error:'PermissionDenied'},write_status:'write_failed'}]), /读取失败.*落盘失败/)
  assert.match(memoryEvidenceLabel(path,[{...note,duplicate:true}]), /请求范围读全.*未解析.*内容重复/)
  assert.match(memoryEvidenceLabel(path,[{...note,read:{...read,actual_bytes:7}}]), /读取状态未知/)
})

test('legacy zero defaults require supported read observations', () => {
  assert.equal(memoryCounterLabel(undefined), '未知')
  assert.equal(memoryCounterLabel(0), '未知')
  assert.equal(memoryCounterLabel(0, [{relativePath:path}]), '未知')
  assert.equal(memoryCounterLabel(0, [{relativePath:path,memoryEvidence:[{...note,read:{}}]}]), '未知')
  assert.equal(memoryCounterLabel(0, [{relativePath:path,memoryEvidence:[{...note,read:{},source_relative_path:'短读'}]}]), '未知')
  assert.equal(memoryCounterLabel(0, [{relativePath:path,memoryEvidence:[note]}]), 0)
  assert.equal(memoryCounterLabel(1), 1)
})
