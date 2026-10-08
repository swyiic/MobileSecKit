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
const h=await launchMe({serve:process.env.ME_PURGE_EXISTING_SERVER!=='1',handler:async(command,args)=>{
 if(command==='cancel_kernsight_group_purge_preparation')return null
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
 if(command==='get_kernsight_group_purge_plan'){assert.equal(args.planId,lastPlan.id);return {...lastPlan,confirmationToken:'',expiresUnixMs:Date.now()-1}}
 if(command==='resume_kernsight_group_purge'){assert.equal(args.planId,lastPlan.id);const report=makeReport(lastPlan);reports=[report];return report}
 if(command==='execute_kernsight_group_purge'){
  assert.equal(args.confirmationToken,lastPlan.confirmationToken)
  if(mode==='execute-fail')throw new Error('mock interrupted after journal write')
  const report=makeReport(lastPlan,mode==='offline'?{state:'partial',deviceState:'pending'}:mode==='fallback'?{state:'partial',localState:'completed',deviceState:'failed',error:'fixture phone interrupted'}:{})
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
async function open(parent=id){const row=page.locator('.ks-capture-group').filter({has:page.locator(':scope > summary').filter({hasText:parent.slice(0,8)})});if(!await row.evaluate(e=>e.open))await row.locator(':scope > summary').click();await page.waitForTimeout(150);await row.getByRole('button',{name:'永久清理本地与手机…',exact:true}).click();await dialog().waitFor()}
async function preview(){await dialog().getByTestId('purge-preview').waitFor()}
async function confirm(){assert.equal(await dialog().locator('input').count(),0)}
async function restore(){groups=[group(id),group(neighbor)];reports=[];mode='ready';await page.getByRole('button',{name:'刷新本地记录',exact:true}).click();await page.waitForTimeout(60)}
try{
 if(process.env.ME_PURGE_THEME_ONLY==='1'){
  await page.getByRole('button',{name:/KernSight.*采集、会话/}).click();mode='offline';await open();await preview();
  for(const theme of ['light','dark']){
   await page.evaluate(theme=>{document.documentElement.dataset.theme=theme},theme)
   for(const width of [1440,390]){
    await page.setViewportSize({width,height:900})
    await dialog().locator('.danger-button').hover();await page.waitForTimeout(250)
    const result=await dialog().evaluate(el=>{
     const colors=getComputedStyle(document.documentElement)
     const resolve=v=>{const probe=document.createElement('span');probe.style.color=colors.getPropertyValue(v);document.body.appendChild(probe);const c=getComputedStyle(probe).color;probe.remove();return c}
     const rect=el.getBoundingClientRect();return {background:getComputedStyle(el).backgroundColor,surface:resolve('--surface'),warning:getComputedStyle(el.querySelector('.ks-purge-warning')).color,amber:resolve('--amber'),muted:getComputedStyle(el.querySelector('.ks-purge-identity dt')).color,expectedMuted:resolve('--muted'),hoverBackground:getComputedStyle(el.querySelector('.danger-button')).backgroundColor,expectedHover:resolve('--surface-soft'),dangerColor:getComputedStyle(el.querySelector('.danger-button')).color,expectedDanger:resolve('--red'),client:el.clientWidth,scroll:el.scrollWidth,left:rect.left,right:rect.right}
    })
    assert.equal(result.background,result.surface);assert.equal(result.warning,result.amber);assert.equal(result.muted,result.expectedMuted);assert.equal(result.hoverBackground,result.expectedHover);assert.equal(result.dangerColor,result.expectedDanger);assert.ok(result.scroll<=result.client+1,JSON.stringify(result));assert.ok(result.left>=0&&result.right<=width,JSON.stringify(result));assert.equal(executeCount(),0)
    await dialog().screenshot({path:out+`/purge-theme-${theme}-${width}.png`});record(`Purge ${theme} surface/warning/muted and ${width}px bounds; no execution`)
   }
  }
  assert.equal(errors.length,0);writeFileSync(out+'/browser-results.json',JSON.stringify({passed:true,checks,executionCalls:executeCount(),note:'Mocked IPC only; no files deleted or devices called.'},null,2));await close();process.exit(0)
 }
 await page.getByRole('button',{name:/KernSight.*采集、会话/}).click()
 const cancel=()=>dialog().getByRole('button',{name:'否',exact:true}).click()
 const execute=()=>dialog().getByRole('button',{name:'是，永久删除本地与手机',exact:true})
 await open();await preview();assert.equal(executeCount(),0);assert.match(await dialog().innerText(),new RegExp(id));assert.match(await dialog().innerText(),/mock-only-no-device/);assert.match(await dialog().innerText(),/5 分钟内有效/);assert.match(await dialog().innerText(),/不是已释放空间/);await confirm();assert.equal(await execute().isEnabled(),true);await cancel();assert.equal(executeCount(),0);record('Automatic exact preview and explicit confirmation; cancellation never executes')
 mode='late';await open();await page.waitForTimeout(80);await cancel();resolvePreview();await page.waitForTimeout(80);assert.equal(await dialog().count(),0);assert.equal(executeCount(),0);record('Cancelled in-flight automatic preview cannot reopen')
 mode='foreign';await open();await dialog().getByRole('alert').first().waitFor();assert.match(await dialog().getByRole('alert').first().innerText(),/不一致/);assert.equal(await dialog().getByTestId('purge-preview').count(),0);await cancel();record('Foreign preview fails closed')
 mode='expired';await open();await preview();assert.equal(await execute().isDisabled(),true);assert.match(await dialog().getByRole('alert').first().innerText(),/预览已失效/);await cancel();record('Expired preview refuses execution')
 mode='offline';await open();await preview();assert.equal(await execute().isDisabled(),true);assert.equal(await dialog().getByRole('checkbox').count(),0);assert.match(await dialog().innerText(),/未执行删除/);const nonce=lastPlan.confirmationToken;mode='ready';await dialog().getByRole('button',{name:'重新核对并重试',exact:true}).click();await preview();assert.notEqual(lastPlan.confirmationToken,nonce);assert.equal(await execute().isEnabled(),true);await cancel();assert.equal(executeCount(),0);record('Offline paired cleanup refuses deletion, no local-only bypass, explicit retry refreshes nonce')
 await restore();mode='execute-fail';await open();await preview();await execute().click();await dialog().getByRole('alert').first().waitFor();assert.match(await dialog().getByRole('alert').first().innerText(),/未确认/);assert.equal(await page.locator('.ks-capture-group').count(),2);await cancel();mode='ready';await open();await preview();record('Unconfirmed failure preserves normal sessions; subsequent cleanup requires a fresh preview')
 for(const width of [720,390]){await page.setViewportSize({width,height:900});const b=await dialog().evaluate(el=>({client:el.clientWidth,scroll:el.scrollWidth,left:el.getBoundingClientRect().left,right:el.getBoundingClientRect().right}));assert.ok(b.scroll<=b.client+1,JSON.stringify(b));assert.ok(b.left>=0&&b.right<=width,JSON.stringify(b));await dialog().screenshot({path:out+`/preview-${width}.png`})}record('Fresh preview is bounded at 720px and 390px')
 mode='delayed-execute';await execute().evaluate(el=>{el.click();el.click();el.click()});await page.waitForTimeout(80);assert.equal(executeCount(),2);assert.equal(await dialog().getByRole('button',{name:'正在清理并核验…',exact:true}).isDisabled(),true);resolveExecute();await page.waitForTimeout(150);assert.equal(await dialog().count(),0);assert.equal(await page.locator('.ks-capture-group').count(),1);assert.equal(await page.locator('.ks-purge-journal').count(),0);record('Repeated explicit clicks execute once; normal neighboring session remains without history area')
 await restore();mode='ready';await open();await preview();const beforeFallbackPrepare=calls.filter(c=>c.command==='prepare_kernsight_group_purge').length;mode='fallback';await execute().click();await page.getByRole('button',{name:'继续已确认清理',exact:true}).waitFor();assert.equal(await page.locator('.ks-capture-group').count(),1);assert.ok(calls.some(c=>c.command==='get_kernsight_group_purge_plan'));assert.equal(calls.filter(c=>c.command==='prepare_kernsight_group_purge').length,beforeFallbackPrepare);assert.match(await dialog().innerText(),/fixture phone interrupted/);const beforeResumeExecute=executeCount();await page.getByRole('button',{name:'继续已确认清理',exact:true}).click();await page.waitForTimeout(150);assert.equal(executeCount(),beforeResumeExecute);assert.ok(calls.some(c=>c.command==='resume_kernsight_group_purge'));assert.equal(await dialog().count(),0);record('Removed local row remounts fallback from original consumed-nonce plan; resume never prepares broader scope or asks confirmation again')
 assert.equal(errors.length,0,errors.join('\n'));const unsafe=calls.filter(x=>/^(cleanup_|start_|run_kernsight|dump_|cancel_kernsight_group$|trash_|restore_)/.test(x.command));assert.deepEqual(unsafe,[])
 writeFileSync(out+'/browser-results.json',JSON.stringify({passed:true,checks,errors,commands:[...new Set(calls.map(x=>x.command))],executionCalls:executeCount(),note:'All Tauri IPC mocked. Chromium runs on assistant cloud computer; no phone or real user data touched.'},null,2));console.log(JSON.stringify({passed:true,checks:checks.length,out}))
}catch(error){await page.screenshot({path:out+'/failure.png',fullPage:true});writeFileSync(out+'/failure.txt',String(error)+'\n'+JSON.stringify({calls,errors},null,2));throw error}finally{await close()}
