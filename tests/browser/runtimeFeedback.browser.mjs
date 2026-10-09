import assert from 'node:assert/strict'
import {mkdirSync,writeFileSync} from 'node:fs'
import {launchMe} from './mockedMeHarness.mjs'
const out=process.env.ME_RUNTIME_QA_OUTPUT||'/tmp/me-runtime-feedback-qa';mkdirSync(out,{recursive:true})
const ids=['11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222']
const group=id=>({schema:'mobilee.capture-group/v1',id,serial:'mock-only-no-device',package:'org.example.app',createdUnixMs:1791500000000,state:'partial',cancelRequested:false,unified:false,base:{},budget:{limits:{totalBytes:805306368,maxSeconds:900},timePlan:{schema:'mobilee.session-time-plan/v4',phases:[{kind:'l0',capMs:25000},{kind:'l1',capMs:105000},{kind:'linker',capMs:25000},{kind:'dump',capMs:245000},{kind:'transfer',capMs:255000},{kind:'archive',capMs:120000},{kind:'import',capMs:120000},{kind:'terminal',capMs:5000}]},reservations:[{id:'output-a',kind:'inspect',status:'sealed',reservedBytes:134217728,chargedBytes:99887766}]},stages:[{id:`stage-${id}`,key:'l1',mode:'tls',durationSeconds:90,launchAfterAttach:false,required:true,attempts:[{relation:{parentId:id,stageId:`stage-${id}`,attemptId:`attempt-${id}`,attempt:1,stageKey:'l1'},state:'partial',startedUnixMs:1791500000000,finishedUnixMs:1791500090000,sessionId:`child-${id}`,error:'fixture measured loss remains partial'}]}]})
const groups=ids.map(group)
let mode='success',resolveRead,importFails=true
const report=id=>({sessionId:`child-${id}`,reportSchema:'fixture',report:{session_id:`child-${id}`,execution_complete:true,mode_counts:{observe:5,inspect:2},quality:{lost_records:17},processes:[],limitations:['fixture coverage remains partial'],plaintext:[],network_peers:[],binder_relations:[]}})
const imported={root:'/mock/local/'+('long-source-path/'.repeat(25)),package:'org.example.app',fileCount:7,totalBytes:99999999,files:[],captureText:'',dumpReport:{package:'org.example.app',dump_id:'fixture-dump',entries:[],total_bytes:99999999,local_storage_accounting:{logical_file_bytes:99999999,unique_inode_bytes:88888888,allocated_bytes:77777777,verified_code_unique_bytes:66666666,runtime_source_diagnostics:[{source_path:'/mock/'+('source/'.repeat(90)),state:'partial',sha256:'a'.repeat(64)}],runtime_observations:[]}},sessionReport:{...report(ids[0]).report,mobilee_capture_group:groups[0]},importedUnixMs:Date.now()}
const h=await launchMe({handler:async(command,args)=>{
 if(command==='list_kernsight_groups')return groups
 if(command==='list_kernsight_group_purges')return []
 if(command==='get_kernsight_group_session_report'){
  if(mode==='error')throw new Error('fixture child report unavailable')
  if(mode==='pending')return new Promise(resolve=>{resolveRead=()=>resolve(report(args.parentId))})
  return report(args.parentId)
 }
 if(command==='plugin:dialog|open'){if(importFails)throw new Error('fixture import unavailable');return '/mock/fixture'}
 if(command==='import_kernsight_evidence_directory')return imported
 if(command==='local_kernsight_evidence_present')return true
}})
const {page,calls,errors,close}=h
const checks=[],record=name=>{checks.push({name,passed:true});console.log('PASS '+name)}
const row=id=>page.locator('.ks-capture-group').filter({has:page.locator(':scope > summary').filter({hasText:id.slice(0,8)})})
const child=id=>row(id).locator(`button[aria-controls="ks-child-${id}-attempt-${id}"]`)
async function open(id){if(!await row(id).evaluate(e=>e.open))await row(id).locator(':scope > summary').click()}
const bounds=()=>page.locator('.runtime-monitor-layout').evaluate(el=>({width:el.getBoundingClientRect().width,client:el.clientWidth,scroll:el.scrollWidth,pageScroll:document.documentElement.scrollWidth,pageClient:document.documentElement.clientWidth}))
try{
 await page.getByRole('button',{name:/KernSight.*采集、会话/}).click()
 await page.locator('.ks-capture-group').first().waitFor()
 const before=await bounds()
 await page.getByRole('button',{name:/导入本地证据/}).click()
 const error=page.locator('.operation-error');await error.waitFor()
 assert.equal(await error.evaluate(el=>Boolean(el.parentElement.querySelector('button.import-local'))),true)
 assert.match(await error.innerText(),/fixture import unavailable/)
 await page.locator('.ks-workspace-switcher').screenshot({path:out+'/import-error-local-panel.png'});await page.screenshot({path:out+'/import-error-near-button.png',fullPage:true})
 await error.getByRole('button',{name:'关闭本次操作错误'}).click();assert.equal(await error.count(),0)
 await page.getByRole('button',{name:/打开证据.*兼容旧格式/}).click();await error.waitFor()
 assert.match(await error.locator('..').innerText(),/打开证据/)
 await error.getByRole('button',{name:'关闭本次操作错误'}).click();record('Import errors belong to the originating button, close, and next failure appears')
 await open(ids[0]);await child(ids[0]).click();await page.locator('.ks-inline-session-detail').waitFor()
 const detail=page.locator('.ks-inline-session-detail')
 assert.equal(await detail.evaluate(el=>el.parentElement.id),`ks-child-${ids[0]}-attempt-${ids[0]}`)
 assert.match(await detail.innerText(),/丢失 17/)
 assert.equal(await child(ids[0]).getAttribute('aria-expanded'),'true')
 const height=await detail.evaluate(el=>({height:el.getBoundingClientRect().height,max:innerHeight*.7,scroll:el.scrollHeight,client:el.clientHeight}))
 assert.ok(height.height<=height.max+1,JSON.stringify(height))
 const selected=await bounds();assert.ok(Math.abs(selected.width-before.width)<1,JSON.stringify({before,selected}))
 assert.ok(selected.scroll<=selected.client+1,JSON.stringify(selected))
 await detail.screenshot({path:out+'/child-evidence-inline.png'})
 await child(ids[0]).click();assert.equal(await detail.count(),0);record('Child evidence opens directly below its own button, is bounded and toggles closed without resizing workspace')
 await child(ids[0]).click();await detail.waitFor();await open(ids[1]);assert.equal(await detail.count(),0)
 assert.equal(await row(ids[0]).locator('.ks-group-information').count(),0)
 mode='pending';await child(ids[1]).click();await detail.waitFor();await open(ids[0]);resolveRead();await page.waitForTimeout(100);assert.equal(await detail.count(),0);mode='success';record('Session switch removes prior details; late report cannot reopen old session')
 await row(ids[0]).locator('.ks-group-budget > summary').click();await row(ids[0]).locator('.ks-group-technical > summary').click()
 await open(ids[1]);await open(ids[0]);assert.equal(await row(ids[0]).locator('.ks-group-budget').evaluate(e=>e.open),false);assert.equal(await row(ids[0]).locator('.ks-group-technical').evaluate(e=>e.open),false);record('Nested technical and budget details reset on session switch')
 mode='error';await child(ids[0]).click();const childError=row(ids[0]).locator('.ks-stage-attempt .operation-error');await childError.waitFor();assert.match(await childError.innerText(),/fixture child report unavailable/);assert.match(await row(ids[0]).innerText(),/fixture measured loss remains partial/);await childError.getByRole('button',{name:'关闭本次操作错误'}).click();mode='success';record('Child read errors remain under the child button and real loss label stays partial')
 importFails=false;await page.getByRole('button',{name:/导入本地证据/}).click();await page.locator('.ks-operation-message').first().waitFor();await open(ids[0]);await row(ids[0]).locator('.ks-group-technical > summary').click();await row(ids[0]).locator('.ks-group-budget > summary').click()
 for(const theme of ['light','dark']){
  await page.evaluate(theme=>{document.documentElement.dataset.theme=theme},theme)
  for(const width of [1440,720,390]){
   await page.setViewportSize({width,height:1000})
   const measured=await bounds();assert.ok(measured.scroll<=measured.client+1,JSON.stringify({width,...measured}));assert.ok(measured.pageScroll<=measured.pageClient+1,JSON.stringify({width,...measured}))
   const cards=await row(ids[0]).locator('.ks-group-information > details').evaluateAll(els=>els.map(el=>({left:el.getBoundingClientRect().left,top:el.getBoundingClientRect().top,right:el.getBoundingClientRect().right})))
   assert.equal(cards.length,2);if(width===1440)assert.ok(Math.abs(cards[0].top-cards[1].top)<1,JSON.stringify(cards));else assert.ok(Math.abs(cards[0].left-cards[1].left)<1,JSON.stringify(cards))
   await row(ids[0]).scrollIntoViewIfNeeded();await row(ids[0]).locator('.ks-group-information').screenshot({path:out+`/time-and-evidence-cards-${theme}-${width}.png`});await page.screenshot({path:out+`/grouped-evidence-${theme}-${width}.png`});record(`${theme} ${width}px budget/source groups align, long source paths do not overflow`)
  }
 }
 const ledger=await row(ids[0]).locator('.ks-time-ledger').innerText();assert.match(ledger,/mobilee.session-time-plan\/v4/);assert.match(ledger,/L2 快照\s*上限 245s/);assert.match(ledger,/保存传输\s*上限 255s/);assert.match(ledger,/阶段执行耗时/);record('Original time caps and attempt elapsed time are distinct; 900s is a parent deadline, not L2 duration')
 assert.equal(errors.length,0,errors.join('\n'))
 const unsafe=calls.filter(c=>/^(provision_|run_kernsight|start_|dump_|execute_|trash_|restore_|cleanup_|cancel_kernsight_group$)/.test(c.command));assert.deepEqual(unsafe,[])
 writeFileSync(out+'/browser-results.json',JSON.stringify({passed:true,checks,errors,commands:[...new Set(calls.map(c=>c.command))],note:'Actual local headless Chromium renders the modified Vue view. All Tauri IPC mocked; no native ME app, phone, deployment, capture or user evidence was changed.'},null,2))
 console.log(JSON.stringify({passed:true,checks:checks.length,out}))
}catch(error){await page.screenshot({path:out+'/failure.png',fullPage:true});writeFileSync(out+'/failure.txt',String(error)+'\n'+JSON.stringify({calls,errors},null,2));throw error}finally{await close()}
