import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const code = ts.transpileModule(readFileSync(new URL('../src/services/kernsightCaptureDiagnostics.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { captureAttemptDiagnostics, retainedStageDiagnosticsJson, copyRetainedStageDiagnostics } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
const relation = (key = 'l1', count = 1) => ({ parentId: 'parent-a', stageId: `stage-${key}`, attemptId: `attempt-${key}-${count}`, attempt: count, stageKey: key })
const wire = r => ({ parent_id: r.parentId, stage_id: r.stageId, attempt_id: r.attemptId, attempt: r.attempt, stage_key: r.stageKey })
const record = (r = relation()) => ({ schema: 'kernsight.qualified-source-failure/v1', token: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', relation: wire(r), failure: { kind: 'source_identity_mismatch', cause: 'expected pidfd identity; observed changed source', errno: 3, expected: { pid: 42, birth_ns: 99 }, observed: { pid: 42, birth_ns: 100 }, target_exit_confirmed: null } })
const lifecycle = (r = relation()) => ({ schema: 'kernsight.capture-lifecycle/v1', token: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', relation: wire(r), agent_exited_confirmed: true, qualification_failure: record(r) })
const diagnostic = overrides => ({ schema: 'mobilee.capture-diagnostic/v1', source: 'remote_lifecycle', record: record(), errorExcerpt: 'Error: lower-priority output excerpt', stdoutBytes: 9000, stderrBytes: 30000, rawTailTruncated: false, errorExcerptTruncated: false, structuredRecordOmitted: false, ...overrides })
function fixture(overrides = {}) {
  const attempt = { relation: relation(), state: 'failed', startedUnixMs: 1, finishedUnixMs: 2, sessionId: 'session-a', error: 'generic command failure', diagnosticTail: '[stderr tail]\nraw trailing lifecycle JSON', captureDiagnostic: diagnostic(), remoteArtifactRoot: '/diagnostics', remoteLifecycle: lifecycle(), processInstances: [], observationError: null, omittedProcessInstances: 0, stageRecords: [], ...overrides }
  const group = { schema: 'mobilee.capture-group/v1', id: 'parent-a', serial: 'fixture', package: 'org.example.app', state: 'failed', createdUnixMs: 1, cancelRequested: false, unified: false, base: {}, stages: [{ id: 'stage-l1', key: 'l1', mode: 'inspect', durationSeconds: 90, launchAfterAttach: true, required: true, attempts: [attempt] }] }
  return { attempt, group, view: () => captureAttemptDiagnostics(group, attempt) }
}

test('structured cause comes before excerpt and raw tail, keeping producer/target separate', () => {
  const f = fixture(), view = f.view()
  assert.equal(view.primary, 'structured')
  assert.equal(view.cause, record().failure.cause)
  assert.equal(view.kind, 'source_identity_mismatch')
  assert.equal(view.errno, '3')
  assert.deepEqual(JSON.parse(view.expected), { pid: 42, birth_ns: 99 })
  assert.deepEqual(JSON.parse(view.observed), { pid: 42, birth_ns: 100 })
  assert.match(view.sourceLabel, /已匹配生命周期/)
  assert.match(view.producerExitLabel, /已确认退出/)
  assert.match(view.targetExitLabel, /未知/)
  assert.match(view.byteLabel, /stdout 9000 B.*stderr 30000 B/)
  assert.equal(view.rawTail, f.attempt.diagnosticTail)
  assert.equal(view.warnings.length, 0)
})

test('an old persisted matching lifecycle receipt remains useful without captureDiagnostic', () => {
  const f = fixture({ captureDiagnostic: undefined, diagnosticTail: null })
  const view = f.view()
  assert.equal(view.primary, 'structured')
  assert.equal(view.cause, record().failure.cause)
  assert.match(view.warnings.join(' '), /本记录未保存独立错误摘要/)
  assert.equal(view.byteLabel, null)
})

test('relation matching is by exact values, not JSON property order', () => {
  const f = fixture({ captureDiagnostic: null })
  f.attempt.remoteLifecycle.qualification_failure.relation = { stage_key: 'l1', attempt: 1, attempt_id: 'attempt-l1-1', stage_id: 'stage-l1', parent_id: 'parent-a' }
  assert.equal(f.view().primary, 'structured')
})

test('foreign receipt identity or token cannot become a trusted failure', () => {
  for (const mutate of [
    r => { r.token = 'different-owner' },
    r => { delete r.token },
    r => { r.relation.parent_id = 'foreign-parent' },
    r => { r.relation.stage_id = 'foreign-stage' },
    r => { r.relation.attempt_id = 'foreign-attempt' },
    r => { r.relation.attempt = 2 },
    r => { r.relation.stage_key = 'linker' },
    r => { r.relation.attempt = '1' },
  ]) {
    const f = fixture({ captureDiagnostic: null })
    mutate(f.attempt.remoteLifecycle.qualification_failure)
    assert.equal(f.view().primary, 'missing')
    assert.equal(f.view().cause, null)
    assert.match(f.view().warnings.join(' '), /身份未匹配/)
    assert.match(f.view().targetExitLabel, /未知/)
  }
})

test('a matching receipt and lifecycle with the wrong parent or attempt are still rejected', () => {
  for (const r of [{ ...relation(), parentId: 'foreign-parent' }, { ...relation(), attemptId: 'foreign-attempt' }]) {
    const f = fixture({ remoteLifecycle: lifecycle(r), captureDiagnostic: diagnostic({ record: record(r), errorExcerpt: 'Error: actual command failed' }) })
    assert.equal(f.view().primary, 'excerpt')
    assert.equal(f.view().cause, 'Error: actual command failed')
    assert.match(f.view().producerExitLabel, /未知/)
    assert.match(f.view().targetExitLabel, /未知/)
  }
  const f = fixture()
  f.group.id = 'foreign-parent'
  assert.equal(f.view().primary, 'excerpt')
  assert.match(f.view().producerExitLabel, /未知/)
})

test('unified controller failures remain controller-scoped across stages', () => {
  const controller = relation('l0')
  const f = fixture({ remoteLifecycle: lifecycle(controller), captureDiagnostic: diagnostic({ record: record(controller) }) })
  f.group.unified = true
  f.group.stages.unshift({ id: 'stage-l0', key: 'l0', attempts: [{ relation: controller }] })
  assert.equal(f.view().primary, 'structured')
  assert.match(f.view().scopeLabel, /统一采集控制器.*不是本阶段独立回执/)
  assert.match(f.view().producerExitLabel, /已确认退出/)
  f.group.unified = false
  assert.equal(f.view().primary, 'excerpt')
  f.group.unified = true
  f.group.stages.shift()
  assert.equal(f.view().primary, 'excerpt')
})

test('unified receipt from an earlier controller round or a dump stage is not attributed', () => {
  const controller = relation('l0')
  for (const current of [relation('l1', 2), relation('dump')]) {
    const f = fixture({ relation: current, remoteLifecycle: lifecycle(controller), captureDiagnostic: diagnostic({ record: record(controller) }) })
    f.group.unified = true
    f.group.stages.unshift({ id: 'stage-l0', key: 'l0', attempts: [{ relation: controller }] })
    assert.equal(f.view().primary, 'excerpt')
    assert.equal(f.view().scopeLabel, '')
  }
})

test('unmatched new record can fall back to a matching saved lifecycle receipt', () => {
  const foreign = record(); foreign.token = 'foreign'
  const f = fixture({ captureDiagnostic: diagnostic({ record: foreign }) })
  assert.equal(f.view().primary, 'structured')
  assert.equal(f.view().cause, record().failure.cause)
  assert.match(f.view().warnings.join(' '), /身份未匹配/)
})

test('stderr and stdout structured records remain diagnostic-only, even if they claim target exit', () => {
  for (const source of ['stderr', 'stdout']) {
    const value = record(); value.failure.target_exit_confirmed = true
    delete value.relation; delete value.token
    const f = fixture({ remoteLifecycle: null, captureDiagnostic: diagnostic({ source, record: value }) })
    assert.equal(f.view().primary, 'structured')
    assert.match(f.view().sourceLabel, new RegExp(`${source} 结构化诊断输出`))
    assert.match(f.view().targetExitLabel, /未知/)
    assert.match(f.view().producerExitLabel, /未知/)
    assert.match(f.view().warnings.join(' '), /仅作诊断输出.*不能确认目标退出/)
  }
})

test('target exit true, false, null, missing and string values are never conflated', () => {
  for (const [value, expected] of [[true, /已确认退出/], [false, /未确认退出（false）/], [null, /未知/], [undefined, /未知/], ['true', /未知/]]) {
    const r = record(); r.failure.target_exit_confirmed = value
    const f = fixture({ captureDiagnostic: diagnostic({ record: r }) })
    assert.match(f.view().targetExitLabel, expected)
    assert.match(f.view().producerExitLabel, /已确认退出/)
  }
})

test('excerpt is independent of tail and survives verbose or truncated output', () => {
  const f = fixture({ remoteLifecycle: null, diagnosticTail: '[stderr tail; earlier output omitted]\n' + JSON.stringify({ schema: 'kernsight.capture-lifecycle/v1', noisy: 'x'.repeat(12000) }), captureDiagnostic: diagnostic({ source: null, record: null, errorExcerpt: 'Error: pidfd_open failed\nCaused by: permission denied' }) })
  assert.equal(f.view().primary, 'excerpt')
  assert.match(f.view().cause, /pidfd_open/)
  assert.doesNotMatch(f.view().cause, /noisy/)
  assert.match(f.view().warnings.join(' '), /较早输出已省略.*无法恢复/)
})

test('truncation and record omission have explicit, distinct notices', () => {
  const r = record(); r.cause_truncated = true
  const f = fixture({ captureDiagnostic: diagnostic({ record: r, rawTailTruncated: true, errorExcerptTruncated: true, structuredRecordOmitted: true }) })
  const warnings = f.view().warnings.join(' ')
  assert.match(warnings, /结构化失败原因已截断/)
  assert.match(warnings, /错误摘要已截断/)
  assert.match(warnings, /原始输出尾部已截断/)
  assert.match(warnings, /超出大小限制、格式无效或生命周期身份不匹配/)
})

test('legacy-only tails and missing records explain limits without inventing an installed-version diagnosis', () => {
  for (const tail of ['[stderr tail; earlier output omitted]\nverbose lifecycle JSON', null]) {
    const f = fixture({ captureDiagnostic: undefined, remoteLifecycle: null, diagnosticTail: tail })
    const view = f.view()
    assert.equal(view.visible, true)
    assert.equal(view.primary, 'missing')
    assert.equal(view.cause, null)
    assert.match(view.warnings.join(' '), /缺失原因无法从本记录恢复/)
    assert.doesNotMatch(view.warnings.join(' '), /旧记录|旧二进制|安装.*旧|stale binary|升级客户端/)
    assert.equal(view.rawTail, tail)
  }
})

test('unknown or malformed fields remain unknown and do not crash presentation', () => {
  for (const value of [[], null, 'wrong type', 42, { schema: 'unknown/v2', failure: { cause: 'foreign cause' } }, { schema: 'kernsight.qualified-source-failure/v1', failure: [] }]) {
    const f = fixture({ captureDiagnostic: diagnostic({ source: 'stderr', record: value }), remoteLifecycle: { qualification_failure: value } })
    assert.equal(f.view().primary, 'excerpt')
    assert.equal(f.view().kind, null)
    assert.match(f.view().targetExitLabel, /未知/)
  }
  const f = fixture({ captureDiagnostic: { schema: 'future/v2' }, remoteLifecycle: null })
  assert.equal(f.view().primary, 'missing')
})

test('successful attempts without diagnostics do not gain a failure panel', () => {
  const f = fixture({ state: 'succeeded', error: null, captureDiagnostic: null, diagnosticTail: null, remoteLifecycle: null })
  assert.equal(f.view().visible, false)
})

test('copy payload retains every existing attempt diagnostic field, IDs and complete retained strings', () => {
  const f = fixture({ diagnosticTail: 'retained-' + '中'.repeat(20000), futureDiagnosticField: { keep: true } })
  const payload = JSON.parse(retainedStageDiagnosticsJson(f.group, f.attempt))
  assert.equal(payload.group.id, 'parent-a')
  assert.equal(payload.stage.id, 'stage-l1')
  assert.deepEqual(payload.attempt.relation, f.attempt.relation)
  assert.equal(payload.attempt.state, 'failed')
  assert.equal(payload.attempt.error, f.attempt.error)
  assert.deepEqual(payload.attempt.captureDiagnostic, f.attempt.captureDiagnostic)
  assert.deepEqual(payload.attempt.remoteLifecycle, f.attempt.remoteLifecycle)
  assert.equal(payload.attempt.diagnosticTail, f.attempt.diagnosticTail)
  assert.deepEqual(payload.attempt.futureDiagnosticField, { keep: true })
  assert.match(payload.retentionScope, /not complete original stdout\/stderr/)
  const legacy = fixture({ captureDiagnostic: undefined, remoteLifecycle: undefined, diagnosticTail: undefined })
  const copied = JSON.parse(retainedStageDiagnosticsJson(legacy.group, legacy.attempt))
  assert.equal(copied.attempt.captureDiagnostic, null)
  assert.equal(copied.attempt.remoteLifecycle, null)
  assert.equal(copied.attempt.diagnosticTail, null)
})

test('clipboard copy waits for the write and reports asynchronous denial instead of success', async () => {
  let resolveWrite, received, settled = false
  const pending = copyRetainedStageDiagnostics('{"retained":true}', { writeText: value => { received = value; return new Promise(resolve => { resolveWrite = resolve }) } }).then(value => { settled = true; return value })
  await Promise.resolve()
  assert.equal(settled, false)
  assert.equal(received, '{"retained":true}')
  resolveWrite()
  assert.equal((await pending).ok, true)
  const rejected = await copyRetainedStageDiagnostics('json', { writeText: async () => { await Promise.resolve(); throw new Error('permission denied') } })
  assert.equal(rejected.ok, false)
  assert.match(rejected.message, /复制失败.*手动复制/)
  assert.equal((await copyRetainedStageDiagnostics('json', null)).ok, false)
})

test('runtime uses the reusable component and copy controls do not toggle a parent details group', () => {
  const view = readFileSync(new URL('../src/views/AndroidRuntimeMonitorView.vue', import.meta.url), 'utf8')
  const component = readFileSync(new URL('../src/components/KernSightCaptureDiagnostics.vue', import.meta.url), 'utf8')
  assert.match(view, /<KernSightCaptureDiagnostics :group="group" :attempt="attempt"/)
  assert.doesNotMatch(view, /失败诊断 · 原始输出尾部/)
  assert.match(component, /type="button"[^>]*@click\.stop="copyDiagnostics"/)
  assert.match(component, /copyFailed \? 'alert' : 'status'/)
  assert.match(component, /await copyRetainedStageDiagnostics\(copiedJson\)/)
})


test('unknown output counts stay unknown while measured zero is retained', () => {
  const f = fixture({ captureDiagnostic: diagnostic({ stdoutBytes: null, stderrBytes: 0 }) })
  assert.match(f.view().byteLabel, /stdout 未知.*stderr 0 B/)
  assert.equal(JSON.parse(retainedStageDiagnosticsJson(f.group, f.attempt)).attempt.captureDiagnostic.stdoutBytes, null)
})

test('unified L0 displays controller scope even on its own attempt row', () => {
  const r = relation('l0')
  const f = fixture({ relation: r, remoteLifecycle: lifecycle(r), captureDiagnostic: diagnostic({ record: record(r) }) })
  f.group.unified = true
  assert.equal(f.view().primary, 'structured')
  assert.match(f.view().scopeLabel, /统一采集控制器/)
})


test('receipt relation equality includes unknown fields without depending on key order', () => {
  const f = fixture({ captureDiagnostic: null })
  f.attempt.remoteLifecycle.relation.extra = { b: 2, a: 1 }
  f.attempt.remoteLifecycle.qualification_failure.relation.extra = { a: 1, b: 2 }
  assert.equal(f.view().primary, 'structured')
  f.attempt.remoteLifecycle.qualification_failure.relation.extra.b = 3
  assert.equal(f.view().primary, 'missing')
  delete f.attempt.remoteLifecycle.qualification_failure.relation.extra
  assert.equal(f.view().primary, 'missing')
})

test('a malformed legacy failure cannot claim confirmed target exit', () => {
  const f = fixture({ captureDiagnostic: null })
  f.attempt.remoteLifecycle.qualification_failure.failure = { target_exit_confirmed: true }
  assert.equal(f.view().primary, 'missing')
  assert.match(f.view().targetExitLabel, /未知/)
  assert.match(f.view().warnings.join(' '), /格式无效/)
})


test('matching empty, nil or malformed lifecycle tokens stay unconfirmed', () => {
  for (const token of ['', '00000000-0000-0000-0000-000000000000', 'owner-token', 'gaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'aaaaaaaabbbb4ccc8dddeeeeeeeeeeee']) {
    for (const legacy of [false, true]) {
      const r = record(); r.token = token; r.failure.target_exit_confirmed = true
      const note = lifecycle(); note.token = token; note.qualification_failure = r
      const f = fixture({ remoteLifecycle: note, captureDiagnostic: legacy ? null : diagnostic({ record: r }) })
      const view = f.view()
      assert.equal(view.primary, legacy ? 'missing' : 'excerpt')
      assert.match(view.producerExitLabel, /未知/)
      assert.match(view.targetExitLabel, /未知/)
      assert.doesNotMatch(view.sourceLabel, /已匹配生命周期/)
      assert.match(view.warnings.join(' '), /身份未匹配/)
      assert.equal(JSON.parse(retainedStageDiagnosticsJson(f.group, f.attempt)).attempt.remoteLifecycle.token, token)
    }
  }
})

const terminalRecord = note => ({ schema: 'mobilee.capture-terminal/v1', source: 'matched_remote_lifecycle',
  relation: note.relation, token: note.token, exit_code: 1,
  ...Object.fromEntries(['stop_reason', 'collection_returned', 'collection_status', 'agent_exited_confirmed', 'cleanup', 'target_pause', 'dump_coverage'].map(key => [key, note[key] ?? null])) })

test('matched partial terminal preserves complete structured causes and counters independently of stderr truncation', () => {
  const note = { ...lifecycle(), qualification_failure: null, collection_returned: true, collection_status: 'partial',
    stop_reason: 'perf_poll_backlog_or_scope_gap_at_observation_end', cleanup: 'producer_scope_returned', target_pause: 'forbidden' }
  const budget = { schema: 'kernsight.output-budget/v1', partial: true, failure_reasons: ['perf_loss', 'unread_tail'] }
  const drain = { schema: 'kernsight.capture-drain/v1', lost_samples: 169234, unknown_tail: true }
  const poll = { schema: 'kernsight.perf-poll-budget/v1', budget_skipped_raw: 7773, coverage_reasons: { perf_loss: true, unread_tail: true } }
  const f = fixture({ state: 'partial', remoteLifecycle: note, captureDiagnostic: diagnostic({ source: null, record: null,
    terminalRecord: terminalRecord(note), coverageRecords: [drain, poll, budget], rawTailTruncated: true }) })
  const view = f.view()
  assert.equal(view.primary, 'terminal')
  assert.equal(view.cause, note.stop_reason)
  assert.equal(view.coveragePartial, true)
  assert.match(view.sourceLabel, /已匹配生命周期终态/)
  assert.deepEqual(JSON.parse(view.coverageRecords), [drain, poll, budget])
  assert.equal(JSON.parse(view.terminalFacts).collection_status, 'partial')
  assert.match(view.targetExitLabel, /未知/)
  assert.equal(f.attempt.state, 'partial')
})

function dumpTerminalFixture() {
  const r = relation('dump')
  const coverage = { schema: 'kernsight.dump-coverage/v1', catalog_complete: true, payload_coverage_complete: false,
    coverage_causes: Array.from({ length: 16 }, (_, i) => `${i}${'x'.repeat(253)}`) }
  const note = { ...lifecycle(r), qualification_failure: null, collection_returned: true, collection_status: 'partial',
    stop_reason: 'bound_code_copy_partial', dump_coverage: coverage }
  const record = terminalRecord(note); delete record.dump_coverage; record.dumpCoverageOmitted = true
  const f = fixture({ relation: r, state: 'partial', remoteLifecycle: note,
    captureDiagnostic: diagnostic({ source: null, record: null, terminalRecord: record, structuredRecordOmitted: true }) })
  f.group.stages[0].id = r.stageId; f.group.stages[0].key = 'dump'
  return f
}

test('legal oversized dump proof omission preserves base terminal facts and the complete source proof', () => {
  const f = dumpTerminalFixture(), original = JSON.stringify(f.attempt.remoteLifecycle)
  const view = f.view()
  assert.equal(view.primary, 'terminal')
  assert.equal(view.cause, 'bound_code_copy_partial')
  assert.equal(view.coveragePartial, true)
  assert.equal(JSON.parse(view.terminalFacts).dumpCoverageOmitted, true)
  assert.equal(JSON.parse(view.terminalFacts).dump_coverage, undefined)
  assert.match(view.warnings.join(' '), /覆盖证明超过终态摘要额度.*不能授权继续采集/)
  assert.equal(JSON.stringify(f.attempt.remoteLifecycle), original)
  assert.equal(f.attempt.state, 'partial')
})

test('dump proof omission cannot bypass base identity or result checks or hide a present proof', () => {
  for (const mutate of [
    f => { delete f.attempt.captureDiagnostic.terminalRecord.dumpCoverageOmitted },
    f => { f.attempt.captureDiagnostic.terminalRecord.dumpCoverageOmitted = false },
    f => { f.attempt.captureDiagnostic.terminalRecord.dump_coverage = f.attempt.remoteLifecycle.dump_coverage },
    f => { f.attempt.remoteLifecycle.dump_coverage = { schema: 'kernsight.dump-coverage/v1' } },
    f => { f.attempt.remoteLifecycle.dump_coverage.schema = 'foreign/v1' },
    f => { f.attempt.captureDiagnostic.terminalRecord.token = 'foreign' },
    f => { f.attempt.captureDiagnostic.terminalRecord.collection_status = 'completed' },
    f => { f.attempt.captureDiagnostic.terminalRecord.stop_reason = 'different' },
  ]) {
    const f = dumpTerminalFixture(); mutate(f)
    assert.equal(f.view().primary, 'excerpt')
    assert.equal(f.view().terminalFacts, null)
    assert.match(f.view().warnings.join(' '), /结构化终态未匹配/)
  }
})

test('projected counters preserve all bounded failure reasons and explicitly omitted quota detail', () => {
  const reasons = Array.from({ length: 16 }, (_, i) => `${i}${'🙂'.repeat(253)}`)
  const budget = { schema: 'kernsight.output-budget/v1', diagnostic_projection: true, failure_reasons: reasons }
  const poll = { schema: 'kernsight.perf-poll-budget/v1', diagnostic_projection: true, budget_skipped_raw: 7773,
    coverage_reasons: { perf_loss: true }, quota_stops_count: 2, quota_stops_omitted: true }
  const f = fixture({ remoteLifecycle: null, captureDiagnostic: diagnostic({ source: null, record: null, coverageRecords: [poll, budget] }) })
  assert.deepEqual(JSON.parse(f.view().coverageRecords), [poll, budget])
  assert.equal(f.view().terminalFacts, null)
})

test('a matched terminal without a stop reason keeps the specific original error excerpt', () => {
  const note = { ...lifecycle(), qualification_failure: null, collection_returned: true, collection_status: 'partial', stop_reason: null }
  const f = fixture({ remoteLifecycle: note, captureDiagnostic: diagnostic({ source: null, record: null,
    terminalRecord: terminalRecord(note), errorExcerpt: 'Error: physical observation denied (os error 13)' }) })
  assert.equal(f.view().primary, 'excerpt')
  assert.match(f.view().cause, /physical observation denied/)
  assert.equal(JSON.parse(f.view().terminalFacts).stop_reason, null)
})

test('foreign terminal token, relation, status and output-only claims cannot confirm terminal facts', () => {
  const note = { ...lifecycle(), qualification_failure: null, collection_returned: true, collection_status: 'partial', stop_reason: 'perf_loss' }
  for (const mutate of [r => { r.token = 'foreign' }, r => { r.relation = { ...r.relation, attempt_id: 'foreign' } },
    r => { r.collection_status = 'completed' }, r => { r.agent_exited_confirmed = false }, r => { r.source = 'stderr' }]) {
    const record = terminalRecord(note); mutate(record)
    const f = fixture({ remoteLifecycle: note, captureDiagnostic: diagnostic({ source: null, record: null, terminalRecord: record }) })
    assert.equal(f.view().primary, 'excerpt')
    assert.equal(f.view().terminalFacts, null)
    assert.match(f.view().warnings.join(' '), /结构化终态未匹配/)
  }
  const old = fixture({ remoteLifecycle: note, captureDiagnostic: diagnostic({ source: null, record: null, errorExcerpt: null }) })
  assert.equal(old.view().primary, 'missing')
  assert.equal(old.view().terminalFacts, null)
  const output = fixture({ remoteLifecycle: null, captureDiagnostic: diagnostic({ source: 'stderr', record: terminalRecord(note), errorExcerpt: null }) })
  assert.equal(output.view().primary, 'missing')
})

test('unknown and oversized coverage records stay diagnostic-only and are never displayed as terminal facts', () => {
  const f = fixture({ remoteLifecycle: null, captureDiagnostic: diagnostic({ source: null, record: null, errorExcerpt: null,
    coverageRecords: [{ schema: 'foreign/v1', collection_status: 'completed' }, { schema: 'kernsight.output-budget/v1', reason: 'x'.repeat(21000) }] }) })
  assert.equal(f.view().coverageRecords, null)
  assert.equal(f.view().terminalFacts, null)
  assert.equal(f.view().primary, 'missing')
})

test('retained partial coverage is distinct from failure without altering raw cause or state', () => {
  const f = fixture({ state: 'partial', remoteLifecycle: null, captureDiagnostic: diagnostic({ source: 'stderr', record: null, errorExcerpt: 'Error: capture coverage partial: perf_poll_backlog_or_scope_gap_at_observation_end' }) })
  assert.equal(f.view().title, '覆盖不足诊断')
  assert.equal(f.view().coveragePartial, true)
  assert.match(f.view().cause, /capture coverage partial/)
  assert.equal(f.attempt.state, 'partial')
  assert.equal(fixture().view().title, '失败诊断')
  // A concrete qualification failure must still be shown as a failure.
  assert.equal(fixture({ state: 'partial' }).view().title, '失败诊断')
})
