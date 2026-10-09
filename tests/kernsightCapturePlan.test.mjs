import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

// Compile the production module in memory using the project's existing TypeScript.
// Node 20 in CI can execute this without experimental TypeScript loader flags.
const source = readFileSync(new URL('../src/services/kernsightCapturePlan.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
}).outputText
const { captureTimeAllocation, buildAutoCaptureStages, runAutoCapturePlan, runUnifiedCapturePlan, buildUnifiedStageSpec, captureIPCCommand, captureCodeOnlyChoice, startupEvidenceLabel, qualifiedSourceLabel, captureGroupIPC } =
  await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)

const base = {
  serial: 'offline-fixture', package: 'com.example.fixture', durationSeconds: 15,
  files: true, filesFd: false, network: true, networkIo: false,
  memory: true, memoryAll: false, binder: true, sched: false, includeThreads: false,
  inspectTls: false, inspectJni: false, inspectLinker: false, inspectAdapter: null,
  hideDebug: false, sampleOneIn: 1, inspectMaxBytes: 65536, inspectMaxHits: 0,
}
const durations = { l0: 15, l1: 90, linker: 15 }
function fixture(failAt = '', failure = 'exit') {
  const calls = [], receipts = [], starts = []
  const backend = {
    async startKernSightCapture(request) {
      const key = request.inspectLinker ? 'linker' : request.inspectTls ? 'l1' : 'l0'
      calls.push({ key, request })
      if (failAt === key && failure === 'throw') throw new Error('offline failure')
      return { sessionId: `fixture-${key}`, startedUnixMs: 1, finishedUnixMs: 2, commandPreview: key,
        stdout: '', stderr: '', exitCode: failAt === key ? failure === 'unknown' ? null : 1 : 0, hideDebug: false }
    },
    async dumpKernSightPackage(...args) {
      calls.push({ key: 'dump', args })
      if (failAt === 'dump') throw new Error('live target not confirmed; no restart')
      return { startedUnixMs: 1, finishedUnixMs: 2, commandPreview: 'dump', stdout: '', stderr: '', exitCode: 0, hideDebug: false }
    },
  }
  return { calls, receipts, starts, run: (input = base, times = durations) => runAutoCapturePlan(input, times, backend,
    stage => starts.push(stage.key), receipt => receipts.push(receipt)) }
}

test('production plan keeps one cold start and snapshots after subsequent module observations', async () => {
  const f = fixture(); await f.run()
  assert.deepEqual(f.calls.map(c => c.key), ['l0', 'l1', 'linker', 'dump'])
  assert.deepEqual(f.calls.slice(0, 3).map(c => c.request.launchAfterAttach), [true, false, false])
  assert.deepEqual(f.calls.slice(0, 3).map(c => c.request.durationSeconds), [15, 90, 15])
  assert.deepEqual(f.calls[3].args, ['offline-fixture', 'com.example.fixture', false, true, true])
  assert.equal(f.receipts.length, 4)
})

test('low-volume memory selection and scope pass through without being silently expanded', async () => {
  const f = fixture(); await f.run()
  for (const { request } of f.calls.slice(0, 3)) {
    assert.equal(request.package, base.package); assert.equal(request.serial, base.serial)
    assert.equal(request.memory, true); assert.equal(request.memoryAll, false)
    assert.equal(request.networkIo, false); assert.equal(request.sampleOneIn, 1)
  }
  assert.deepEqual(f.calls.slice(0, 3).map(c => [c.request.inspectTls, c.request.inspectJni, c.request.inspectLinker, c.request.inspectAdapter]),
    [[false, false, false, null], [true, true, false, 'binder_userspace'], [false, false, true, null]])
})

test('invalid duration anywhere prevents every backend call', async () => {
  for (const value of [0, 301, 1.5, NaN, Infinity]) {
    const f = fixture(); await assert.rejects(f.run(base, { ...durations, linker: value }))
    assert.equal(f.calls.length, 0); assert.equal(f.starts.length, 0)
  }
  assert.equal(buildAutoCaptureStages(1, 300, 1).length, 4)
})

test('invalid scope prevents every backend call', async () => {
  for (const input of [{ ...base, package: '' }, { ...base, package: 'bad;command' }, { ...base, serial: '' }]) {
    const f = fixture(); await assert.rejects(f.run(input)); assert.equal(f.calls.length, 0)
  }
})

test('nonzero and unknown exits stop before Linker or dump and retain returned receipts', async () => {
  for (const mode of ['exit', 'unknown']) {
    const f = fixture('l1', mode); await assert.rejects(f.run())
    assert.deepEqual(f.calls.map(c => c.key), ['l0', 'l1'])
    assert.deepEqual(f.receipts.map(r => r.succeeded), [true, false])
    assert.equal(f.receipts[0].result.sessionId, 'fixture-l0')
  }
})

test('backend rejection keeps earlier session receipts and does not retry or advance', async () => {
  const f = fixture('linker', 'throw'); await assert.rejects(f.run())
  assert.deepEqual(f.calls.map(c => c.key), ['l0', 'l1', 'linker'])
  assert.deepEqual(f.receipts.map(r => r.result.sessionId), ['fixture-l0', 'fixture-l1'])
})

test('failed required-live snapshot preserves all preceding sessions and does not cold start again', async () => {
  const f = fixture('dump'); await assert.rejects(f.run())
  assert.equal(f.calls.length, 4); assert.equal(f.calls[3].args[4], true)
  assert.equal(f.receipts.length, 3)
  assert.equal(f.calls.filter(c => c.request?.launchAfterAttach).length, 1)
})


test('explicit startup replay preserves all three startup windows and L1 snapshot position', async () => {
  const calls=[], receipts=[]
  const backend={
    async startKernSightCapture(request) { calls.push(request); return {sessionId:`fixture-${calls.length}`,exitCode:0,stdout:'',stderr:''} },
    async dumpKernSightPackage(...args) { calls.push({dump:args}); return {exitCode:0,stdout:'',stderr:''} },
  }
  await runAutoCapturePlan(base,durations,backend,()=>{},r=>receipts.push(r),true)
  assert.deepEqual(calls.map(c=>c.dump?'dump':c.inspectLinker?'linker':c.inspectTls?'l1':'l0'),['l0','l1','dump','linker'])
  assert.equal(calls.filter(c=>c.launchAfterAttach).length,3)
  assert.deepEqual(receipts.map(r=>r.stage.key),['l0','l1','dump','linker'])
  assert.equal(calls[2].dump[4],true)
})
function unifiedFixture(mutator = result => result) {
  const calls=[], receipts=[]
  const records=['l0','l1','linker'].flatMap((stage,index)=>['started','window_elapsed'].map(state=>({
    schema:'kernsight.capture-stage/v1',session:'one-fixture-session',index,stage,state,
    planned_seconds:[15,90,15][index],pid:42,process_start_ticks:'77',coverage:'not_attested',restart:false,
  })))
  const result={sessionId:'one-fixture-session',exitCode:0,stdout:'',stderr:records.map(r=>JSON.stringify(r)).join('\n'),commandPreview:'one capture'}
  const backend={
    async startKernSightCapture(request) { calls.push({type:'capture',request}); return mutator({...result},records) },
    async dumpKernSightPackage(...args) { calls.push({type:'dump',args}); return {exitCode:0,stdout:'',stderr:''} },
  }
  return {calls,receipts,run:(times=durations)=>runUnifiedCapturePlan(base,times,backend,()=>{},r=>receipts.push(r))}
}
test('unified production plan makes one capture call, no simultaneous Inspect flags, then one live snapshot',async()=>{
  const f=unifiedFixture(); await f.run()
  assert.deepEqual(f.calls.map(c=>c.type),['capture','dump'])
  const r=f.calls[0].request
  assert.equal(r.inspectStages,'l0:15,l1:90,linker:15');assert.equal(r.durationSeconds,120)
  assert.equal(r.launchAfterAttach,true); assert.equal(r.inspectTls,false);assert.equal(r.inspectJni,false);assert.equal(r.inspectLinker,false);assert.equal(r.inspectAdapter,null)
  assert.equal(r.memoryAll,false);assert.equal(r.memory,true);assert.equal(r.networkIo,false);assert.equal(r.package,base.package)
  assert.deepEqual(f.receipts.map(r=>r.stage.key),['session','l0','l1','linker','dump'])
  assert.equal(f.calls[1].args[4],true)
})
test('legacy exit success without staged evidence is refused, never silently downgraded',async()=>{
  const f=unifiedFixture(r=>({...r,stderr:''}));await assert.rejects(f.run())
  assert.equal(f.calls.length,1);assert.equal(f.receipts.length,4)
  assert.ok(f.receipts.slice(1).every(r=>!r.succeeded))
})
test('failed, not-started, duplicate or wrong-session phase evidence prevents final snapshot',async()=>{
  for(const mutation of [
    records=>{records[3].state='failed';records[4].state='not_started';records.splice(5,1)},
    records=>records.push({...records[3]}),
    records=>{records[3].session='other-session'},
    records=>{records[3].planned_seconds=91},
  ]){
    const f=unifiedFixture((r,records)=>{mutation(records);return {...r,stderr:records.map(v=>JSON.stringify(v)).join('\n')}})
    await assert.rejects(f.run());assert.equal(f.calls.length,1);assert.equal(f.receipts[0].result.sessionId,'one-fixture-session')
  }
})
test('PID reuse, missing birth identity and nonzero capture exit do not count as a unified completed instance',async()=>{
  for(const mutation of [records=>{records[5].process_start_ticks='78'},records=>{records[3].process_start_ticks=null}]){
    const f=unifiedFixture((r,records)=>{mutation(records);return {...r,stderr:records.map(v=>JSON.stringify(v)).join('\n')}})
    await assert.rejects(f.run());assert.equal(f.calls.length,1)
  }
  const f=unifiedFixture(r=>({...r,exitCode:1}));await assert.rejects(f.run());assert.equal(f.calls.length,1)
})
test('unified durations are validated before any call and old/new IPC commands are explicit',async()=>{
  const f=unifiedFixture();await assert.rejects(f.run({...durations,l1:301}));assert.equal(f.calls.length,0)
  assert.equal(buildUnifiedStageSpec({l0:300,l1:300,linker:300}),'l0:300,l1:300,linker:300')
  assert.equal(captureIPCCommand(base),'start_kernsight_capture')
  assert.equal(captureIPCCommand({...base,inspectStages:'l1:1'}),'start_kernsight_staged_capture')
})

test('code-only is an explicit independent choice, not inferred from auto mode', () => {
  assert.equal(captureCodeOnlyChoice(false), false); assert.equal(captureCodeOnlyChoice(true), true)
  const view = readFileSync(new URL('../src/views/AndroidRuntimeMonitorView.vue', import.meta.url),'utf8')
  assert.ok(view.includes('codeOnly:captureCodeOnlyChoice(captureForm.codeOnly)'))
  assert.ok(!view.includes("codeOnly:captureForm.plan==='auto'"))
})

test('actual attach display keeps missing and old startup records unknown', () => {
  assert.match(startupEvidenceLabel(), /未知/)
  assert.match(startupEvidenceLabel({startup:{schema:'legacy'}}), /未知/)
  const label = startupEvidenceLabel({startup:{schema:'kernsight.startup/v1',generation_state:'new_instance_observed',timing:{force_stop_status:'completed',launcher_status:'completed',launcher_started_ms:10,first_attach_ms:{tls:25}}}})
  assert.match(label, /tls=25ms/); assert.match(label, /可能缺失/)
})

test('production qualification display leaves old data unknown and refuses foreign ancestry', () => {
  assert.match(qualifiedSourceLabel(null), /未知/)
  assert.match(qualifiedSourceLabel({ complete: true }), /未知/)
  const note = { token: 't', relation: { attempt_id: 'a' }, qualification: { schema: 'kernsight.qualified-source/v1', token: 't', relation: { attempt_id: 'a' }, source: 'MetadataObserver physical pidfd lease', sources: [{ package: 'p', pid: 1, uid: 10001, birth_ns: 2, exec_id: 0, boot_id: 'b' }] } }
  assert.match(qualifiedSourceLabel(note), /此前生产者/)
  note.qualification.token = 'foreign'
  assert.match(qualifiedSourceLabel(note), /未知/)
})

test('isolation uses a new native IPC so old Me cannot silently run the default agent',()=>{
 assert.equal(captureGroupIPC({}), 'begin_kernsight_group')
 const request={runtimePaths:{root:'/data/local/tmp/ksight-candidate',agentPath:'/data/local/tmp/ksight-candidate/ksightd',expectedSha256:'a'.repeat(64)}}
 let deviceActions=0
 const oldBackend={begin_kernsight_group(){deviceActions++}}
 assert.throws(()=>{const fn=oldBackend[captureGroupIPC(request)];if(!fn) throw new Error('unknown IPC');fn()},/unknown IPC/)
 assert.equal(deviceActions,0)
})

test('new-parent time admission matches separate and unified reserved phases', () => {
  const separate = captureTimeAllocation({l0:5,l1:30,linker:10},300,true)
  assert.equal(separate.valid,true); assert.equal(separate.minimumSeconds,300); assert.equal(separate.transferSeconds,30)
  assert.deepEqual(separate.producer.map(p=>p.seconds),[15,40,20])
  const unified = captureTimeAllocation({l0:5,l1:30,linker:10},300,false)
  assert.equal(unified.minimumSeconds,280); assert.equal(unified.transferSeconds,50)
  assert.equal(unified.archiveSeconds+unified.importSeconds+unified.terminalSeconds,140)
})
test('insufficient time never silently shortens persisted windows', () => {
  const original = {l0:15,l1:90,linker:15}
  const plan = captureTimeAllocation(original,300,true)
  assert.equal(plan.valid,false); assert.equal(plan.minimumSeconds,375)
  assert.deepEqual(original,{l0:15,l1:90,linker:15})
  assert.equal(captureTimeAllocation({l0:5,l1:30,linker:10},299,true).valid,false)
  assert.equal(captureTimeAllocation({l0:5,l1:30,linker:10},375,true).transferSeconds,105)
  for (const total of [NaN,Infinity,29,3601,300.1]) assert.throws(()=>captureTimeAllocation({l0:5,l1:30,linker:10},total,true))
  for (const l0 of [0,301,1.5,NaN]) assert.throws(()=>captureTimeAllocation({l0,l1:30,linker:10},300,true))
})


test('new600s closeout profile retains90s observation with bounded archive and import', () => {
  for (const [separate, transfer] of [[true,105],[false,125]]) {
    const plan = captureTimeAllocation({l0:15,l1:90,linker:15},600,separate)
    assert.equal(plan.valid,true)
    assert.equal(plan.longPlan,true)
    assert.equal(plan.transferSeconds,transfer)
    assert.equal(plan.finalSeconds,245)
    assert.equal(plan.archiveSeconds,120)
    assert.equal(plan.importSeconds,120)
    assert.equal(plan.dumpSeconds,95)
  }
  assert.equal(captureTimeAllocation({l0:15,l1:90,linker:15},300,true).valid,false)
  assert.equal(captureTimeAllocation({l0:15,l1:90,linker:15},599,true).finalSeconds,140)
})

test('larger new deadlines share finite time with dump and retain final work', () => {
  for (const [seconds, dump, transfer] of [[900,245,255],[901,245.5,255.5],[1200,300,500],[3600,300,2900]]) {
    const plan = captureTimeAllocation({l0:15,l1:90,linker:15},seconds,true)
    assert.equal(plan.valid,true)
    assert.equal(plan.dumpSeconds,dump)
    assert.equal(plan.transferSeconds,transfer)
    assert.equal(plan.archiveSeconds,120)
    assert.equal(plan.importSeconds,120)
    assert.equal(plan.producer.reduce((sum,p)=>sum+p.seconds,0)+plan.dumpSeconds+plan.transferSeconds+plan.finalSeconds,seconds)
  }
})


test('minimum total resolves the growing dump allowance instead of repeating insufficient advice', () => {
  const durations = {l0:100,l1:100,linker:100}
  const preview = captureTimeAllocation(durations,700,true)
  assert.equal(preview.valid,false)
  assert.equal(preview.minimumSeconds,810)
  const admitted = captureTimeAllocation(durations,preview.minimumSeconds,true)
  assert.equal(admitted.valid,true)
  assert.equal(admitted.transferSeconds,30)
  assert.equal(captureTimeAllocation(durations,809,true).valid,false)
  assert.deepEqual(durations,{l0:100,l1:100,linker:100})
})

test('minimum total re-solves the 600s transition and the capped dump boundary', () => {
  const short = {l0:114,l1:115,linker:115}
  assert.equal(captureTimeAllocation(short,599,true).minimumSeconds,599)
  assert.equal(captureTimeAllocation(short,599,true).valid,true)
  const crossing = {l0:115,l1:115,linker:115}
  assert.equal(captureTimeAllocation(crossing,599,true).minimumSeconds,900)
  assert.equal(captureTimeAllocation(crossing,899,true).valid,false)
  assert.equal(captureTimeAllocation(crossing,900,true).transferSeconds,30)
  for (const [durations,separate,minimum] of [
    [{l0:200,l1:100,linker:100},true,1010],
    [{l0:201,l1:100,linker:100},true,1011],
    [{l0:200,l1:120,linker:100},false,1010],
    [{l0:201,l1:120,linker:100},false,1011],
  ]) {
    assert.equal(captureTimeAllocation(durations,700,separate).minimumSeconds,minimum)
    assert.equal(captureTimeAllocation(durations,minimum,separate).transferSeconds,30)
    assert.equal(captureTimeAllocation(durations,minimum-1,separate).valid,false)
  }
})

test('suggested minimum admits all valid observation sums in the selected deadline regime', () => {
  for (const separate of [false,true]) {
    for (let sum=3;sum<=900;sum++) {
      const l0=Math.min(300,sum-2),l1=Math.min(300,sum-l0-1)
      const durations={l0,l1,linker:sum-l0-l1}
      for (const total of [30,599,600,700,1009,1010,3600]) {
        const preview=captureTimeAllocation(durations,total,separate)
        const minimum=preview.minimumSeconds
        assert.equal(Number.isInteger(minimum),true)
        assert.equal(captureTimeAllocation(durations,minimum,separate).valid,true)
        if ((preview.longPlan && minimum>600) || (!preview.longPlan && minimum!==600)) {
          assert.equal(captureTimeAllocation(durations,minimum-1,separate).valid,false)
        }
      }
    }
  }
})
