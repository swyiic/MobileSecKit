import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const code = ts.transpileModule(readFileSync(new URL('../src/services/kernsightCaptureRunner.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { captureReceiptStateLabel, captureSavedOutcome, runCaptureGroupPlan, mergeCaptureResults, latestGroupSession } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
const initial = unified => ({ id: 'parent-a', serial: 'mock', package: 'org.example.app', unified, stages: (unified ? ['l0', 'l1', 'linker', 'dump'] : ['l0', 'l1', 'dump', 'linker']).map(key => ({ key, launchAfterAttach: !unified && key !== 'dump', attempts: [] })) })
const result = (key, exitCode = 0) => ({ sessionId: key === 'dump' ? null : `session-${key}`, startedUnixMs: 1, finishedUnixMs: 2, stdout: `stdout-${key}`, stderr: exitCode ? `stderr-${key}` : '', commandPreview: key, exitCode })
function harness(group, states = {}) {
  const calls = [], receipts = [], groups = [], unified = []
  let current = structuredClone(group)
  const backend = {
    async runKernSightGroupStage(id, key) {
      calls.push([id, key])
      current = structuredClone(current)
      const options = states[key] || {}
      const state = options.state || 'succeeded'
      current.stages.find(stage => stage.key === key).attempts.push({ state, sessionId: key === 'dump' ? null : `session-${key}`, relation: { attemptId: `${key}-${calls.length}` } })
      if (options.cancel) current.cancelRequested = true
      return { group: current, result: result(key, state === 'succeeded' ? 0 : 1), error: options.noError ? null : state === 'succeeded' ? null : `failed-${key}`, continueAfterPartial: options.continueAfterPartial, continuationPolicy: options.continuationPolicy }
    },
    async runKernSightUnifiedGroup(id) {
      calls.push([id, 'session'])
      current = structuredClone(current)
      for (const stage of current.stages.filter(stage => stage.key !== 'dump')) stage.attempts.push({ state: states.session?.state || 'succeeded', sessionId: 'unified-session', relation: { attemptId: stage.key } })
      if (states.session?.cancel) current.cancelRequested = true
      if (states.session?.throw) throw Error('unified transport failed')
      return { group: current, result: result('session'), error: states.session?.error || null }
    },
  }
  const hooks = { group: value => groups.push(value), phase: () => {}, result: (value, key) => receipts.push({ value, key }), unified: value => unified.push(value) }
  return { calls, receipts, groups, unified, backend, hooks }
}
test('one click runs all four production stages under one parent in startup order', async () => {
  const g = initial(false), h = harness(g)
  await runCaptureGroupPlan(g, h.backend, h.hooks)
  assert.deepEqual(h.calls, ['l0', 'l1', 'dump', 'linker'].map(key => ['parent-a', key]))
  assert.equal(h.receipts.length, 4)
  assert.equal(new Set(h.groups.map(group => group.id)).size, 1)
})
test('L1 failure preserves both receipts and does not run dependent snapshot or Linker', async () => {
  const g = initial(false), h = harness(g, { l1: { state: 'failed' } })
  await assert.rejects(runCaptureGroupPlan(g, h.backend, h.hooks), /failed-l1/)
  assert.deepEqual(h.calls.map(call => call[1]), ['l0', 'l1'])
  assert.equal(h.receipts[1].value.stderr, 'stderr-l1')
  assert.equal(h.groups.at(-1).stages[1].attempts[0].state, 'failed')
})
test('missing error text cannot turn an unconfirmed receipt into success', async () => {
  const g = initial(false), h = harness(g, { l0: { state: 'running', noError: true } })
  await assert.rejects(runCaptureGroupPlan(g, h.backend, h.hooks), /未确认成功/)
  assert.equal(h.calls.length, 1)
})
test('only explicitly authorized settled partial continues, and remains partial', async () => {
  const g = initial(false), h = harness(g, { l0: { state: 'partial', continueAfterPartial: true } })
  const last = await runCaptureGroupPlan(g, h.backend, h.hooks)
  assert.equal(h.calls.length, 4)
  assert.equal(last.stages[0].attempts[0].state, 'partial')
})
test('partial without backend continuation authority stops', async () => {
  const g = initial(false), h = harness(g, { l0: { state: 'partial' } })
  await assert.rejects(runCaptureGroupPlan(g, h.backend, h.hooks), /failed-l0/)
  assert.equal(h.calls.length, 1)
})
test('a continuation flag cannot turn failed state into a safe partial', async () => {
  const g = initial(false), h = harness(g, { l1: { state: 'failed', continueAfterPartial: true } })
  await assert.rejects(runCaptureGroupPlan(g, h.backend, h.hooks), /failed-l1/)
  assert.equal(h.calls.length, 2)
})
test('retry preserves parent and old attempts while skipping successful stages', async () => {
  const g = initial(false)
  g.stages[0].attempts.push({ state: 'succeeded', sessionId: 'old-l0' })
  g.stages[1].attempts.push({ state: 'failed', sessionId: 'old-l1' })
  const h = harness(g)
  const last = await runCaptureGroupPlan(g, h.backend, h.hooks)
  assert.deepEqual(h.calls.map(call => call[1]), ['l1', 'dump', 'linker'])
  assert.equal(last.id, g.id)
  assert.equal(last.stages[1].attempts.length, 2)
  assert.equal(last.stages[1].attempts[0].state, 'failed')
})
test('cancellation stops scheduling subsequent stages and preserves current receipt', async () => {
  const g = initial(false), h = harness(g, { l0: { cancel: true } })
  const last = await runCaptureGroupPlan(g, h.backend, h.hooks)
  assert.equal(h.calls.length, 1)
  assert.equal(h.receipts.length, 1)
  assert.equal(last.cancelRequested, true)
})
test('a cancelled parent never starts or resumes device work', async () => {
  const g = { ...initial(false), cancelRequested: true }, h = harness(g)
  await runCaptureGroupPlan(g, h.backend, h.hooks)
  assert.equal(h.calls.length, 0)
})
test('unified production path runs once then snapshot and clears progress state', async () => {
  const g = initial(true), h = harness(g)
  await runCaptureGroupPlan(g, h.backend, h.hooks)
  assert.deepEqual(h.calls.map(call => call[1]), ['session', 'dump'])
  assert.deepEqual(h.unified, [true, false])
})
test('unified failure never falls back to independent launches or snapshot', async () => {
  const g = initial(true), h = harness(g, { session: { state: 'failed', error: 'unified failed' } })
  await assert.rejects(runCaptureGroupPlan(g, h.backend, h.hooks), /unified failed/)
  assert.deepEqual(h.calls.map(call => call[1]), ['session'])
  assert.deepEqual(h.unified, [true, false])
})
test('unknown unified stage status stops even without an error field', async () => {
  const g = initial(true), h = harness(g, { session: { state: 'running' } })
  await assert.rejects(runCaptureGroupPlan(g, h.backend, h.hooks), /未确认所有阶段成功/)
  assert.equal(h.calls.length, 1)
})
test('unified transport rejection still clears progress state', async () => {
  const g = initial(true), h = harness(g, { session: { throw: true } })
  await assert.rejects(runCaptureGroupPlan(g, h.backend, h.hooks), /transport/)
  assert.deepEqual(h.unified, [true, false])
})
test('terminal snapshot cannot erase the retained child session or accumulated logs', () => {
  const merged = mergeCaptureResults([result('session'), result('dump')])
  assert.equal(merged.sessionId, 'session-session')
  assert.match(merged.stdout, /stdout-session\n\nstdout-dump/)
  assert.equal(mergeCaptureResults([]), null)
})
test('outcome selects newest actual child rather than a nonexistent dump session', () => {
  const g = initial(true)
  g.stages[2].attempts.push({ sessionId: 'unified-child' })
  g.stages[3].attempts.push({ sessionId: null })
  assert.equal(latestGroupSession(g), 'unified-child')
})
test('mismatched parent reply cannot replace the active parent or run another stage', async () => {
  const g = initial(false), h = harness(g)
  h.backend.runKernSightGroupStage = async () => ({ group: { ...g, id: 'unrelated-parent' }, result: null, error: null })
  await assert.rejects(runCaptureGroupPlan(g, h.backend, h.hooks), /不同的主会话/)
  assert.equal(h.groups.length, 1)
})

test('even a mistaken continuation flag cannot run the snapshot after partial L1', async () => {
  const g = initial(false), h = harness(g, { l1: { state: 'partial', continueAfterPartial: true } })
  await assert.rejects(runCaptureGroupPlan(g, h.backend, h.hooks), /failed-l1/)
  assert.deepEqual(h.calls.map(call => call[1]), ['l0', 'l1'])
})

 test('typed sealed coverage partial reaches snapshot and independent Linker without upgrading state',async()=>{
  const g=initial(false),h=harness(g,{l1:{state:'partial',continueAfterPartial:true,continuationPolicy:'sealed_partial_snapshot'}});
  const done=await runCaptureGroupPlan(g,h.backend,h.hooks);
  assert.deepEqual(h.calls.map(c=>c[1]),['l0','l1','dump','linker']);assert.equal(done.stages[1].attempts[0].state,'partial');
 });
 test('typed original source absence skips unavailable Dump and permits independent Linker',async()=>{
  const g=initial(false),h=harness(g,{l1:{state:'partial',continueAfterPartial:true,continuationPolicy:'sealed_partial_snapshot'},dump:{state:'unavailable',continueAfterPartial:true,continuationPolicy:'source_absent_independent_start'}});
  const done=await runCaptureGroupPlan(g,h.backend,h.hooks);
  assert.deepEqual(h.calls.map(c=>c[1]),['l0','l1','dump','linker']);assert.equal(done.stages[2].attempts[0].state,'unavailable');
 });

test('saved partial evidence remains usable and is never described as complete capture', () => {
  const group = { ...initial(false), state: 'partial' }
  const before = JSON.stringify(group)
  const message = captureSavedOutcome(group, '/retained/cmb.pb')
  assert.match(message, /已保存并导入/)
  assert.match(message, /覆盖不足（partial）/)
  assert.equal(JSON.stringify(group), before)
  assert.match(captureSavedOutcome({ ...group, state: 'failed' }, '/retained'), /采集未全部完成/)
})

test('real 676bd086 partial stage receipts do not claim failure or stopped follow-up', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/kernsight-parent-676bd086-receipts.json', import.meta.url), 'utf8'))
  const group = fixture.group
  const original = JSON.stringify(group)
  assert.equal(group.id, '676bd086-f077-431d-8a97-1a01ed060afd')
  for (const key of ['l1', 'dump']) {
    const attempt = group.stages.find(stage => stage.key === key).attempts.at(-1)
    assert.equal(attempt.state, 'partial')
    assert.equal(attempt.remoteLifecycle.collection_returned, true)
    assert.equal(attempt.remoteLifecycle.collection_status, 'partial')
    assert.equal(attempt.remoteLifecycle.agent_exited_confirmed, true)
    assert.equal(attempt.qualificationFailureRetained, false)
    const label = captureReceiptStateLabel(group, key)
    assert.match(label, /覆盖不足（partial）/)
    assert.doesNotMatch(label, /失败|后续停止|命令成功/)
  }
  assert.equal(captureReceiptStateLabel(group, 'linker'), '执行结束')
  const saved = captureSavedOutcome(group, fixture.savedEvidence.root)
  assert.match(saved, /已保存并导入.*覆盖不足（partial）/)
  assert.equal(JSON.stringify(group), original)
})

test('receipt display preserves mixed unified outcomes and unknown or failed facts', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/kernsight-parent-676bd086-receipts.json', import.meta.url), 'utf8'))
  const group = fixture.group
  const unified = captureReceiptStateLabel(group, 'session')
  assert.match(unified, /L0 内核观察：执行结束/)
  assert.match(unified, /L1 TLS \/ JNI \/ Binder：覆盖不足（partial）/)
  assert.match(unified, /Linker 加载观察：执行结束/)
  assert.doesNotMatch(unified, /代码快照/)
  group.stages.find(stage => stage.key === 'l1').attempts.at(-1).state = 'failed'
  assert.equal(captureReceiptStateLabel(group, 'l1'), '采集失败')
  group.stages.find(stage => stage.key === 'l1').attempts = []
  assert.equal(captureReceiptStateLabel(group, 'l1'), '状态未知')
  assert.equal(captureReceiptStateLabel(group, 'missing'), '状态未知')
})
