import { launchMe } from './mockedMeHarness.mjs'
import assert from 'node:assert/strict'
import { mkdirSync,writeFileSync } from 'node:fs'
const out=process.env.ME_PURGE_QA_OUTPUT || '/tmp/me-purge-qa';mkdirSync(out,{recursive:true})
const id='11111111-1111-4111-8111-111111111111', neighbor='22222222-2222-4222-8222-222222222222'
const group=(id,extra={})=>({schema:'mobilee.capture-group/v1',id,serial:'mock-only-no-device',package:'org.example.cleanup',createdUnixMs:1791350000000,cancelRequested:false,state:'failed',unified:false,base:{},stages:[{id:'stage-a',key:'l0',mode:'none',durationSeconds:15,launchAfterAttach:true,required:true,attempts:[]}],...extra})
let groups=[group(id),group(neighbor)]
let reports=[];let mode='ready';let resolvePreview,resolveExecute;let nextPlan=0;let importRoot='/local/selected-copy'
const makePlan=(args,extra={})=>{const stamp=Date.now();return {schema:'mobilee.group-purge-plan/v1',id:`mock-plan-${++nextPlan}`,parentId:args.parentId,serial:'mock-only-no-device',package:'org.example.cleanup',createdUnixMs:stamp,expiresUnixMs:stamp+300000,confirmationToken:`random-preview-token-${nextPlan}`,confirmationText:`永久清理 ${args.parentId}`,localEntries:[{path:`/local/groups/${args.parentId}.json`,kind:'managed_group',logicalBytes:4096,allocatedBytes:4096,files:1},...(args.importedRoots||[]).map(path=>({path,kind:'imported_root',logicalBytes:5000,allocatedBytes:8192,files:4}))],device:{status:mode==='offline'?'offline':'ready',entries:mode==='offline'?[]:[{path:`/data/local/tmp/kernsight-${args.parentId}/session`,kind:'session',logicalBytes:1024,allocatedBytes:null,files:3}],warnings:mode==='offline'?['设备不可达，范围尚未核验']:[]},warnings:[],localOnly:Boolean(args.localOnly),...extra}}
const makeReport=(plan,extra={})=>({id:plan.id,parentId:plan.parentId,serial:plan.serial,package:plan.package,importedRoots:plan.localEntries.filter(x=>x.kind==='imported_root').map(x=>x.path),retainedSessionIds:['owned-phone-child'],updatedUnixMs:Date.now(),state:'completed',localState:'completed',deviceState:'completed',removedLocalFiles:plan.localEntries.reduce((n,x)=>n+x.files,0),removedLocalAllocatedBytes:null,warnings:[],error:null,...extra})
let lastPlan;const checks=[];const record=(name)=>{checks.push({name,passed:true});console.log('PASS '+name)}
const h=await launchMe({handler:async(command,args)=>{
 if(command==='list_kernsight_groups')return groups
 if(command==='list_kernsight_group_purges')return reports
 if(command==='prepare_kernsight_group_purge'){
  lastPlan=makePlan(args)
  if(mode==='late')return await new Promise(resolve=>{resolvePreview=()=>resolve(lastPlan)})
  if(mode==='foreign')return {...lastPlan,parentId:neighbor}
  if(mode==='expired')return {...lastPlan,createdUnixMs:Date.now()-310000,expiresUnixMs:Date.now()-10000}
  return lastPlan
 }
 if(command==='prepare_kernsight_group_purge_retry'){
  const report=reports.find(x=>x.id===args.planId);lastPlan=makePlan({parentId:report.parentId,importedRoots:[],localOnly:args.localOnly},{id:report.id,...(report.localState==='completed'?{localEntries:[]}:{})});return lastPlan
 }
 if(command==='execute_kernsight_group_purge'){
  assert.equal(args.confirmationToken,lastPlan.confirmationToken)
  if(mode==='execute-fail')throw new Error('mock interrupted after journal write')
  const report=makeReport(lastPlan,mode==='offline'?{state:'partial',deviceState:'pending'}:{})
  reports=[report];groups=groups.filter(x=>x.id!==lastPlan.parentId)
  if(mode==='delayed-execute')return await new Promise(resolve=>{resolveExecute=()=>resolve(report)})
  return report
 }
 if(command==='plugin:dialog|open')return importRoot
 if(command==='import_kernsight_evidence_directory')return {root:args.path,package:'org.example.cleanup',fileCount:4,totalBytes:5000,files:[],captureText:'',dumpReport:{package:'org.example.cleanup',dump_id:args.path,entries:[],total_bytes:5000},sessionReport:{mobilee_capture_group:group(id)},importedUnixMs:Date.now()}
}})
const {page,calls,errors,close}=h
const dialog=()=>page.getByRole('dialog',{name:/永久清理/})
const executeCount=()=>calls.filter(x=>x.command==='execute_kernsight_group_purge').length
async function open(parent=id){const row=page.locator('.ks-capture-group').filter({has:page.locator(':scope > summary').filter({hasText:parent.slice(0,8)})});if(!await row.evaluate(e=>e.open))await row.locator(':scope > summary').click();await row.getByRole('button',{name:'永久清理本地与手机…',exact:true}).click();await dialog().waitFor()}
async function preview(){await dialog().getByRole('button',{name:'核对清理范围',exact:true}).click();await dialog().getByTestId('purge-preview').waitFor()}
async function confirm(parent=id){await dialog().getByRole('checkbox',{name:/我确认这些精确路径/}).check();await dialog().getByRole('textbox').fill(`永久清理 ${parent}`)}
async function restore(){groups=[group(id),group(neighbor)];reports=[];mode='ready';await page.getByRole('button',{name:'刷新本地记录',exact:true}).click();await page.waitForTimeout(60)}
try{
 await page.getByRole('button',{name:/KernSight.*采集、会话/}).click()
 await open();await preview();assert.equal(executeCount(),0)
 assert.match(await dialog().innerText(),new RegExp(id));assert.match(await dialog().innerText(),/mock-only-no-device/);assert.match(await dialog().innerText(),/3 个文件/);assert.match(await dialog().innerText(),/5 分钟内有效/);assert.match(await dialog().innerText(),/不是已释放空间/)
 const execute=()=>dialog().getByRole('button',{name:'确认永久清理本地与手机',exact:true})
 assert.equal(await execute().isDisabled(),true);await dialog().getByRole('textbox').fill(`永久清理 ${id}`);assert.equal(await execute().isDisabled(),true);await dialog().getByRole('checkbox',{name:/我确认这些精确路径/}).check();assert.equal(await execute().isEnabled(),true)
 await dialog().screenshot({path:out+'/01-paired-preview.png'})
 await dialog().getByRole('button',{name:'取消永久清理',exact:true}).click();assert.equal(await dialog().count(),0);assert.equal(executeCount(),0)
 record('Preview exact parent, serial, paths, counts and expiry; typing plus checkbox required; cancel does not execute')
 mode='late';await open();await dialog().getByRole('button',{name:'核对清理范围',exact:true}).click();await page.waitForTimeout(40);await dialog().getByRole('button',{name:'取消永久清理',exact:true}).click();resolvePreview();await page.waitForTimeout(80);assert.equal(await dialog().count(),0);assert.equal(executeCount(),0)
 record('Cancelled in-flight preview cannot reappear or execute')
 mode='late';await open();await dialog().getByRole('button',{name:'核对清理范围',exact:true}).click();await page.waitForTimeout(40);await page.getByRole('button',{name:/设备总览.*连接、状态/}).click();resolvePreview();await page.getByRole('button',{name:/KernSight.*采集、会话/}).click();await page.waitForTimeout(80);assert.equal(await dialog().count(),0);assert.equal(executeCount(),0)
 record('v-show navigation invalidates pending confirmation and late previews')
 mode='ready';await open();await preview();await confirm();await page.locator('.ks-capture-group').filter({has:page.locator(':scope > summary').filter({hasText:neighbor.slice(0,8)})}).locator(':scope > summary').click();assert.equal(await dialog().count(),0);assert.equal(executeCount(),0)
 record('Changing selected parent invalidates already typed confirmation')
 mode='foreign';await open();await dialog().getByRole('button',{name:'核对清理范围',exact:true}).click();await dialog().getByRole('alert').waitFor();assert.match(await dialog().getByRole('alert').innerText(),/不一致/);assert.equal(await dialog().getByTestId('purge-preview').count(),0);await dialog().getByRole('button',{name:'取消永久清理',exact:true}).click()
 record('Mismatched preview identity fails closed')
 mode='expired';await open();await preview();assert.match(await dialog().getByRole('alert').innerText(),/预览已失效/);assert.equal(await execute().isDisabled(),true);await dialog().getByRole('button',{name:'取消永久清理',exact:true}).click()
 record('Expired preview cannot execute')
 mode='offline';await open();await preview();assert.equal(await execute().isDisabled(),true);assert.match(await dialog().innerText(),/不能执行双端清理/);await dialog().getByRole('checkbox',{name:/仅永久清理本地/}).check();assert.equal(await dialog().getByTestId('purge-preview').count(),0);await preview();await confirm();await dialog().screenshot({path:out+'/02-local-only-preview.png'});await dialog().getByRole('button',{name:'确认永久清理本地（手机待清理）',exact:true}).click();await page.getByText(/本地清理已核验；设备待清理/).first().waitFor();assert.equal(executeCount(),1);assert.equal(await page.locator('.ks-capture-group').count(),1);assert.match(await page.locator('.ks-purge-journal').innerText(),/手机 pending/)
 record('Offline paired deletion blocked; explicit local-only requires fresh preview, reports phone pending and preserves neighbor')
 mode='ready';await page.getByRole('button',{name:'重新预览剩余清理',exact:true}).click();await preview();assert.match(await dialog().innerText(),/本次没有待删除的本地路径/);assert.equal(await execute().isDisabled(),true);await confirm();await execute().click();await page.waitForTimeout(80);assert.equal(executeCount(),2);assert.match(await page.locator('.ks-purge-journal').innerText(),/未完成 0/)
 const executions=calls.filter(x=>x.command==='execute_kernsight_group_purge');assert.equal(executions[0].args.planId,executions[1].args.planId);assert.notEqual(executions[0].args.confirmationToken,executions[1].args.confirmationToken);record('Durable pending retry fetches a new remaining-only plan and requires fresh confirmation; reused plan ID sends a rotated nonce')
 await restore();mode='delayed-execute';await open();await preview();await confirm();await execute().evaluate(el=>{el.click();el.click();el.click()});await page.waitForTimeout(40);assert.equal(executeCount(),3);assert.equal(await dialog().getByRole('button',{name:'正在清理并核验…',exact:true}).isDisabled(),true);await page.getByRole('button',{name:/设备总览.*连接、状态/}).click();resolveExecute();await page.waitForTimeout(60);await page.getByRole('button',{name:/KernSight.*采集、会话/}).click();await page.waitForTimeout(60);assert.equal(await dialog().count(),0);assert.equal(await page.locator('.ks-capture-group').count(),1)
 record('Repeated clicks execute once; late committed result reconciles exact parent without reopening after navigation')
 await restore();mode='execute-fail';await open();await preview();await confirm();await execute().click();await dialog().getByRole('alert').waitFor();assert.match(await dialog().getByRole('alert').innerText(),/结果未确认/);assert.equal(await dialog().getByTestId('purge-preview').count(),0);assert.equal(await page.locator('.ks-capture-group').count(),2);await dialog().getByRole('button',{name:'取消永久清理',exact:true}).click()
 record('Interrupted execution shows unconfirmed result, consumes typed confirmation and retains rows')
 mode='ready';await page.getByRole('button',{name:/导入本地证据.*选择/}).click();await page.waitForTimeout(100);importRoot='/local/unselected-copy';await page.getByRole('button',{name:/导入本地证据.*选择/}).click();await page.waitForTimeout(100);await open();assert.equal(await dialog().getByRole('checkbox',{name:'/local/selected-copy',exact:true}).count(),1);await dialog().getByRole('checkbox',{name:'/local/unselected-copy',exact:true}).uncheck();await preview();const lastPrepare=calls.filter(x=>x.command==='prepare_kernsight_group_purge').at(-1);assert.deepEqual(lastPrepare.args.importedRoots,['/local/selected-copy']);assert.match(await dialog().innerText(),/5 个文件/)
 for(const width of [720,390]){await page.setViewportSize({width,height:900});const bounds=await dialog().evaluate(el=>({client:el.clientWidth,scroll:el.scrollWidth,left:el.getBoundingClientRect().left,right:el.getBoundingClientRect().right}));assert.ok(bounds.scroll<=bounds.client+1,JSON.stringify(bounds));assert.ok(bounds.left>=0&&bounds.right<=width,JSON.stringify(bounds));await dialog().screenshot({path:out+`/03-narrow-${width}.png`})}
 record('Exact import-root selection reaches IPC and preview wraps at 720px/390px')
 await confirm();await execute().click();await page.waitForTimeout(100);assert.equal(await page.locator('.ks-capture-group').count(),2);assert.equal(await page.getByText('/local/selected-copy',{exact:true}).count(),0);assert.ok(await page.getByText('/local/unselected-copy',{exact:true}).count()>=1)
 record('Verified local completion removes only selected imported copy while same-parent unselected copy and neighboring capture remain')
 await page.setViewportSize({width:1440,height:1000});await restore();mode='offline';reports=[makeReport(makePlan({parentId:id,importedRoots:[]}),{state:'partial',localState:'failed',deviceState:'pending',error:'mock local unlink failure'})];await page.getByRole('button',{name:'刷新本地记录',exact:true}).click();await page.getByRole('button',{name:'重新预览剩余清理',exact:true}).click();await preview();assert.equal(await execute().isDisabled(),true);const priorRetryNonce=lastPlan.confirmationToken;await dialog().getByRole('checkbox',{name:/仅永久清理本地/}).check();assert.equal(await dialog().getByTestId('purge-preview').count(),0);await preview();assert.notEqual(lastPlan.confirmationToken,priorRetryNonce);assert.equal(calls.filter(x=>x.command==='prepare_kernsight_group_purge_retry').at(-1).args.localOnly,true);assert.equal(await dialog().getByRole('button',{name:'确认永久清理本地（手机待清理）',exact:true}).isDisabled(),true);await confirm();const beforeLocalRetry=executeCount();await dialog().screenshot({path:out+'/04-offline-local-retry.png'});await dialog().getByRole('button',{name:'确认永久清理本地（手机待清理）',exact:true}).click();await page.waitForTimeout(100);assert.equal(executeCount(),beforeLocalRetry+1);assert.match(await page.locator('.ks-purge-journal').innerText(),/本地 completed.*手机 pending/);assert.match(await page.locator('.ks-purge-journal').innerText(),/设备待清理/)
 record('Offline partially failed local retry permits explicit local-only re-preview, rotates nonce, requires fresh confirmation and leaves phone pending')
 assert.equal(errors.length,0,errors.join('\n'));const unsafe=calls.filter(x=>/^(cleanup_|start_|run_kernsight|dump_|cancel_|trash_|restore_)/.test(x.command));assert.deepEqual(unsafe,[])
 writeFileSync(out+'/browser-results.json',JSON.stringify({passed:true,checks,errors,commands:[...new Set(calls.map(x=>x.command))],executionCalls:executeCount(),note:'All Tauri IPC mocked. Chromium runs on assistant cloud computer; no phone or real user data touched.'},null,2));console.log(JSON.stringify({passed:true,checks:checks.length,out}))
}catch(error){await page.screenshot({path:out+'/failure.png',fullPage:true});writeFileSync(out+'/failure.txt',String(error)+'\n'+JSON.stringify({calls,errors},null,2));throw error}finally{await close()}
