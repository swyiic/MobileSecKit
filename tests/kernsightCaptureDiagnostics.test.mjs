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
