import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('../src/services/kernsightGroupPurge.ts', import.meta.url), 'utf8')
const code = ts.transpileModule(source, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText
const {createPurgeOperation, purgeConfirmationBlockReason, canConfirmPurge, createPurgeRequestGate, purgePlanMatches, purgeTargetKey, bundleRemovedByPurge, purgeReportLabel} = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
const target = {parentId:'parent-a',serial:'serial-a',package:'org.example.fixture',importedRoots:['/local/one','/local/two']}
const plan = {schema:'mobilee.group-purge-plan/v1',id:'plan-a',...target,createdUnixMs:1000,expiresUnixMs:301000,confirmationToken:'one-use-random-token',confirmationText:'永久清理 parent-a',localEntries:[],device:{status:'ready',entries:[],warnings:[]},warnings:[],localOnly:false}
const confirm = (p=plan,t=target,now=2000,busy=false)=>canConfirmPurge(p,t,now,busy)
const report = {id:'plan-a',...target,state:'completed',localState:'completed',deviceState:'completed',removedLocalFiles:1,removedLocalAllocatedBytes:null,updatedUnixMs:2000,warnings:[],error:null,importedRoots:['/local/one']}
const bundle = (root='/local/one',group=target)=>({root,package:group.package,sessionReport:{mobilee_capture_group:{id:group.parentId,serial:group.serial,package:group.package}}})
test('one confirmation permits only a fresh bound identity',()=>{
 assert.equal(confirm(),true)
 for(const field of ['parentId','serial','package']) {assert.equal(confirm(plan,{...target,[field]:'foreign'}),false);assert.equal(purgePlanMatches(plan,{...target,[field]:'foreign'}),false)}
 assert.equal(confirm(null),false);assert.equal(confirm(plan,null),false);assert.equal(confirm(plan,target,2000,true),false)
})
test('expired, future and malformed timestamps fail closed at the exact boundary',()=>{
 assert.equal(confirm(plan,target,301000),false)
 assert.equal(confirm(plan,target,300999),true)
 for(const p of [{...plan,createdUnixMs:3000},{...plan,expiresUnixMs:302000},{...plan,createdUnixMs:NaN},{...plan,expiresUnixMs:Infinity},{...plan,expiresUnixMs:900}])assert.equal(confirm(p),false)
})
test('offline or blocked paired plans cannot execute; local-only requires a separately generated plan',()=>{
 for(const device of [null,{status:'offline'},{status:'blocked'}]) {
  assert.equal(confirm({...plan,device}),false)
  assert.equal(confirm({...plan,device,localOnly:true}),true)
 }
 assert.equal(confirm({...plan,device:{status:'not_required'}}),true)
})
test('cancel and newer target invalidate late previews; repeated execution is single-flight',()=>{
 const gate=createPurgeRequestGate(); const first=gate.begin();assert.equal(gate.current(first),true)
 gate.invalidate();assert.equal(gate.current(first),false)
 const second=gate.begin();const third=gate.begin();assert.equal(gate.current(second),false);assert.equal(gate.current(third),true)
 assert.equal(gate.startExecution(),true);assert.equal(gate.startExecution(),false);assert.equal(gate.executing(),true)
 gate.invalidate();assert.equal(gate.startExecution(),false);gate.finishExecution();assert.equal(gate.startExecution(),true)
})
test('selection binding includes precise roots and retry identity, independent of ordering',()=>{
 assert.equal(purgeTargetKey(target),purgeTargetKey({...target,importedRoots:[...target.importedRoots].reverse()}))
 for(const t of [{...target,importedRoots:['/local/one']},{...target,retryPlanId:'another'}])assert.notEqual(purgeTargetKey(t),purgeTargetKey(target))
})
test('successful local cleanup removes only approved matching import copies',()=>{
 assert.equal(bundleRemovedByPurge(bundle(),plan,report),true)
 assert.equal(bundleRemovedByPurge(bundle('/local/two'),plan,report),false)
 for(const field of ['parentId','serial','package'])assert.equal(bundleRemovedByPurge(bundle('/local/one',{...target,[field]:'other'}),plan,report),false)
 assert.equal(bundleRemovedByPurge(bundle(),plan,{...report,parentId:'other'}),false)
 assert.equal(bundleRemovedByPurge(bundle(),plan,{...report,serial:'other'}),false)
 assert.equal(bundleRemovedByPurge(bundle(),plan,{...report,package:'other'}),false)
 for(const localState of ['pending','failed','not_required'])assert.equal(bundleRemovedByPurge(bundle(),plan,{...report,localState}),false)
})
test('pending/failed/device-only/local-only receipts never claim paired completion or reclaimed bytes',()=>{
 assert.match(purgeReportLabel(report),/本地与设备.*完成/)
 assert.match(purgeReportLabel({...report,state:'partial',deviceState:'pending'}),/设备待清理/)
 assert.match(purgeReportLabel({...report,state:'partial',localState:'failed'}),/本地待清理/)
 for(const r of [{...report,state:'failed',localState:'failed',deviceState:'pending'},{...report,state:'prepared',localState:'pending',deviceState:'pending'}])assert.doesNotMatch(purgeReportLabel(r),/核验完成|已释放/)
})
test('frontend IPC keeps irreversible execution separate from preview, retry and recoverable trash',()=>{
 const backend=readFileSync(new URL('../src/services/backend/monitoring.ts',import.meta.url),'utf8')
 for(const name of ['prepare_kernsight_group_purge','execute_kernsight_group_purge','list_kernsight_group_purges','prepare_kernsight_group_purge_retry','trash_kernsight_group'])assert.ok(backend.includes(`'${name}'`))
 assert.match(backend,/executeKernSightGroupPurge:[^\n]+\{ planId, confirmationToken \}/)
 const vue=readFileSync(new URL('../src/components/KernSightGroupPurge.vue',import.meta.url),'utf8')
 assert.match(vue,/if \(!canExecute.value \|\| !plan.value \|\| !gate.startExecution\(\)\) return/)
 assert.match(vue,/!gate.current\(ticket\) \|\| !props.active/)
 assert.match(vue,/是，永久删除本地与手机/)
 assert.match(vue,/不是已释放空间/)
 const app=readFileSync(new URL('../src/App.vue',import.meta.url),'utf8')
 assert.match(app,/:active="activeTab === 'android-runtime'"/)
})

test('retry execution passes only the new preview nonce',()=>{
 const retry={...plan,confirmationToken:'fresh-retry-nonce'}
 assert.equal(confirm(retry),true)
 assert.equal(confirm(retry,target,2000,true),false)
 const vue=readFileSync(new URL('../src/components/KernSightGroupPurge.vue',import.meta.url),'utf8')
 assert.match(vue,/executeKernSightGroupPurge\(approvedPlan.id, approvedPlan.confirmationToken\)/)
 assert.doesNotMatch(vue,/executeKernSightGroupPurge\([^\n]+typedConfirmation/)
 assert.match(vue,/nextTick\(prepare\)/)
})

test('one paired yes/no confirmation automatically selects all known roots and never offers scope input',()=>{
 const vue=readFileSync(new URL('../src/components/KernSightGroupPurge.vue',import.meta.url),'utf8')
 assert.match(vue,/const selectedRoots = \[\.\.\.target.importedRoots\]/)
 assert.match(vue,/const requestedLocalOnly = false/)
 assert.match(vue,/prepareKernSightGroupPurgeRetry\(retryPlanId, requestedLocalOnly, requestId\)/)
 assert.match(vue,/!purgePlanMatches\(result, target\) \|\| result.localOnly !== requestedLocalOnly/)
 assert.doesNotMatch(vue,/type="checkbox"|v-model="localOnly"|v-model="roots"|type="text"/)
 assert.match(vue,/>否<\/button>/)
 assert.match(vue,/未执行删除/)
 assert.match(vue,/重新核对并重试/)
 assert.match(vue,/textarea readonly :value="error"/)
 assert.match(vue,/failedPlanId.value = approvedPlan.id/)
 assert.match(vue,/failedPlanId.value = report.id/)
 assert.match(vue,/const retryPlanId = failedPlanId.value \|\| target.retryPlanId/)
})

test('every safety denial has a nearby reason without granting confirmation',()=>{
 const state={active:true,busy:false,preparing:false,executing:false}
 const why=(p=plan,t=target,time=2000,s=state)=>purgeConfirmationBlockReason(p,t,time,s)
 assert.equal(why(),'')
 assert.match(why(null),/尚无/)
 assert.match(why(plan,target,2000,{...state,active:false}),/未激活/)
 assert.match(why(plan,target,2000,{...state,busy:true}),/尚未结束/)
 assert.match(why(plan,target,2000,{...state,preparing:true}),/最长20秒/)
 assert.match(why(plan,target,2000,{...state,executing:true}),/正在执行/)
 for(const p of [{...plan,confirmationToken:''},{...plan,parentId:'foreign'},{...plan,expiresUnixMs:NaN},{...plan,createdUnixMs:3000},{...plan,expiresUnixMs:1999},{...plan,device:{status:'offline',warnings:['fixture reason']}}]) {
  assert.equal(confirm(p),false);assert.ok(why(p).length)
 }
 assert.match(why({...plan,device:{status:'blocked',warnings:['device inspect timeout']}}),/device inspect timeout/)
})

test('operation deadline cancels backend before releasing result and ignores late execute success',async()=>{
 let finishRun, finishAbort, stopped=0
 const run=new Promise(resolve=>{finishRun=resolve})
 const abort=new Promise(resolve=>{finishAbort=resolve})
 const op=createPurgeOperation(()=>run,reason=>{assert.equal(reason,'timeout');stopped++;return abort},10)
 let settled=false;op.result.then(()=>{settled=true})
 await new Promise(resolve=>setTimeout(resolve,20));assert.equal(stopped,1);assert.equal(settled,false)
 finishRun('late success');await Promise.resolve();assert.equal(settled,false)
 finishAbort('durable interrupted');assert.equal(await op.result,'durable interrupted')
})
test('repeated cancellation is single flight, and failed cancellation never claims completion',async()=>{
 let count=0, finishAbort
 const op=createPurgeOperation(()=>new Promise(()=>{}),()=>{count++;return new Promise(resolve=>{finishAbort=resolve})},1000)
 const a=op.cancel('user'), b=op.cancel('unmount');assert.equal(a,b)
 await Promise.resolve();assert.equal(count,1);finishAbort('interrupted');assert.equal(await op.result,'interrupted')
 const unknown=createPurgeOperation(()=>new Promise(()=>{}),async()=>{throw Error('backend outcome unknown')},1000)
 const failed=assert.rejects(unknown.result,/outcome unknown/)
 await assert.rejects(unknown.cancel(),/outcome unknown/);await failed
})

test('started resume reads original plan and never rotates its consumed nonce',()=>{
 const vue=readFileSync(new URL('../src/components/KernSightGroupPurge.vue',import.meta.url),'utf8')
 assert.match(vue,/if \(prior && prior.state !== 'prepared'\) return monitoringBackend.kernSightGroupPurgePlan\(retryPlanId\)/)
 assert.match(vue,/continuing \? monitoringBackend.resumeKernSightGroupPurge\(approvedPlan.id\)/)
 assert.match(vue,/plan.value = \{ \.\.\.approvedPlan, confirmationToken: '' \}/)
})

test('immediate cancel prevents an invoke that has not started from being issued later',async()=>{
 let invokes=0,aborts=0
 const operation=createPurgeOperation(async()=>{invokes++;return 'unsafe late invoke'},async()=>{aborts++;return 'cancelled'},1000)
 await operation.cancel('unmount')
 assert.equal(await operation.result,'cancelled');assert.equal(invokes,0);assert.equal(aborts,1)
})
