import assert from 'node:assert/strict'
import {mkdirSync,writeFileSync} from 'node:fs'
import {launchMe} from './mockedMeHarness.mjs'
import {fileURLToPath} from 'node:url'
import {resolve} from 'node:path'
import {tmpdir} from 'node:os'
const projectRoot=fileURLToPath(new URL('../../',import.meta.url))
const out=resolve(process.env.ME_MANUAL_TIMING_QA_OUTPUT||resolve(tmpdir(),'me-manual-timing-qa'));mkdirSync(out,{recursive:true})
const ids=['2b1dafca-1234-4234-8234-123456789abc','7fffffff-1234-4234-8234-123456789abc']
const childIds=['355e3390-1234-4234-8234-123456789abc','355e3391-1234-4234-8234-123456789abc']
const created=Date.UTC(2026,9,9,21,31,22)
const group=(id,i)=>({schema:'mobilee.capture-group/v1',id,serial:'mock-only-no-device',package:'org.example.app',createdUnixMs:created,state:'partial',cancelRequested:false,unified:false,base:{},budget:{limits:{totalBytes:805306368,maxSeconds:900},reservations:[],timePlan:i?{schema:'mobilee.session-time-plan/v4',phases:[{kind:'transfer',capMs:255000}]}:{schema:'mobilee.session-time-plan/v5',captureMaxMs:400000,l2MaxMs:245000,captureStopAtParentRemainingMs:500000,phases:[{kind:'transfer',capMs:255000,startedUnixMs:created+400000,finishedUnixMs:created+412500,elapsedMs:12500,completed:true},{kind:'archive',capMs:120000,completed:false},{kind:'import',capMs:120000,startedUnixMs:created+412500,completed:false}]}},stages:[{id:'stage-'+id,key:'linker',mode:'linker',durationSeconds:15,launchAfterAttach:false,required:true,attempts:[{relation:{parentId:id,stageId:'stage-'+id,attemptId:'attempt-'+id,attempt:1,stageKey:'linker'},state:'partial',startedUnixMs:created,finishedUnixMs:created+25000,sessionId:childIds[i],error:'fixture lost remains partial'}]}]})
const groups=ids.map(group)
const device={platform:'android',serial:'mock-only-no-device',status:'device',model:'Independent QA fixture',product:'mock'}
const details={...device,manufacturer:'fixture',androidVersion:'14',sdkVersion:'34',buildNumber:'mock-build',architecture:'aarch64',architectureFamily:'arm64',kernelVersion:'mock-kernel',abiList:['arm64-v8a'],brand:'fixture',rootStatus:'Root',selinuxStatus:'Enforcing',bootloaderStatus:'Unlocked'}
const overview={agentVersion:'fixture',protocolMajor:1,protocolMinor:0,status:{last_batch_sequence:0,session_count:0,spool_used_bytes:0,heartbeat_monotonic_ns:1},sessions:[],privatePackageBytes:0,publicPackageBytes:0}
let mode='success',resolveRead
const report=id=>({sessionId:childIds[ids.indexOf(id)],reportSchema:'fixture',report:{session_id:childIds[ids.indexOf(id)],execution_complete:true,mode_counts:{observe:27826,inspect:20},quality:{lost_records:0},mobilee_capture_group:groups[ids.indexOf(id)],mobilee_capture_edges:[],processes:[],plaintext:[],network_peers:[],binder_relations:[]}})
const h=await launchMe({root:projectRoot,fixtures:{list_devices:[device],get_device_details:details,get_kernsight_overview:overview,probe_android_monitor_capabilities:{...details,agentStatus:'Installed',btfStatus:'available',recommendedMode:'development',trustLevel:'dev',checks:[],warnings:[]},list_kernsight_package_dumps:[],list_kernsight_groups:groups,list_kernsight_group_purges:[]},handler:async(command,args)=>{
 if(command==='get_kernsight_group_session_report'){if(mode==='error')throw new Error('fixture unavailable');if(mode==='pending')return new Promise(resolve=>{resolveRead=()=>resolve(report(args.parentId))});return report(args.parentId)}
}})
const {page,calls,errors,close}=h,checks=[],measurements=[]
const record=name=>{checks.push(name);console.log('PASS '+name)}
const row=id=>page.locator('.ks-capture-group').filter({has:page.locator(':scope > summary').filter({hasText:id.slice(0,8)})})
const child=id=>row(id).locator('.ks-child-actions > button[aria-controls]')
async function open(id){if(!await row(id).evaluate(el=>el.open))await row(id).locator(':scope > summary').click()}
const field=label=>page.locator('.ks-manual-timing label').filter({has:page.locator('span').filter({hasText:label})}).locator('input')
async function capturePanel(){await page.locator('.ks-workspace-switcher > button').filter({hasText:'新建采集'}).click();await page.locator('.ks-manual-timing').waitFor()}
async function evidencePanel(){await page.locator('.ks-workspace-switcher > button').filter({hasText:'证据链'}).click();await page.locator('.ks-capture-group').first().waitFor()}
async function visibleText(el){return el.evaluate(el=>{const rect=el.getBoundingClientRect(),range=document.createRange();range.selectNodeContents(el);const text=[...range.getClientRects()].filter(r=>r.width&&r.height);const clipped=[];for(let p=el;p;p=p.parentElement){const s=getComputedStyle(p);if(/hidden|clip/.test(s.overflowX)||/hidden|clip/.test(s.overflowY)){const pr=p.getBoundingClientRect();if(text.some(r=>r.left<pr.left-1||r.right>pr.right+1||r.top<pr.top-1||r.bottom>pr.bottom+1))clipped.push(p.className)}}return {text:el.textContent,width:rect.width,height:rect.height,client:el.clientWidth,scroll:el.scrollWidth,clipped}})}
try{
 await page.getByRole('button',{name:/KernSight.*采集、会话/}).click()
 await page.getByRole('button',{name:/检测设备能力/}).first().click()
 await capturePanel()
 for(const [label,value] of [['总采集时限','400'],['L2 快照上限','245'],['保存传输上限','255'],['归档上限','120'],['导入上限','120']])assert.equal(await field(label).inputValue(),value)
 assert.match(await page.locator('.ks-whole-wait').innerText(),/整体等待上限 900 秒 = 采集 400 \+ 传输 255 \+ 归档 120 \+ 导入 120 \+ 终态 5/)
 const preview=page.locator('.ks-capture-plan details code'),plan=JSON.parse(await preview.textContent());assert.deepEqual(plan.captureTime,{maxSeconds:400,l2MaxSeconds:245});assert.deepEqual(plan.saveTime,{transferMaxSeconds:255,archiveMaxSeconds:120,importMaxSeconds:120});assert.equal(plan.sessionBudget.maxSeconds,900)
 await page.locator('.ks-manual-timing').screenshot({path:out+'/manual-timing-default.png'});record('Default acquisition, L2 and three saving caps are visible; whole parent contract remains 900')
 await field('总采集时限').fill('120');assert.match(await page.locator('.ks-manual-timing').innerText(),/时间设置无效/)
 await field('L2 快照上限').fill('60');await field('保存传输上限').fill('40');await field('归档上限').fill('20');await field('导入上限').fill('10')
 assert.match(await page.locator('.ks-whole-wait').innerText(),/整体等待上限 195 秒 = 采集 120 \+ 传输 40 \+ 归档 20 \+ 导入 10 \+ 终态 5/)
 assert.match(await page.locator('.ks-manual-timing').innerText(),/时间设置有效/)
 const stored=await page.evaluate(()=>JSON.parse(localStorage.getItem('mobilee.kernsightManualTiming/v1')));assert.deepEqual(stored,{captureMaxSeconds:120,l2MaxSeconds:60,transferMaxSeconds:40,archiveMaxSeconds:20,importMaxSeconds:10})
 const changed=JSON.parse(await preview.textContent());assert.deepEqual(changed.captureTime,{maxSeconds:120,l2MaxSeconds:60});assert.equal(changed.sessionBudget.maxSeconds,195)
 await page.locator('.ks-manual-timing').screenshot({path:out+'/manual-timing-explicit-120.png'});record('Explicit capture cap can equal requested observation sum, never re-expanded; L2 bounds validate and all caps persist')
 await page.reload({waitUntil:'networkidle'});await page.getByRole('button',{name:/KernSight.*采集、会话/}).click();await page.getByRole('button',{name:/检测设备能力/}).first().click();await capturePanel();assert.equal(await field('总采集时限').inputValue(),'120');assert.match(await page.locator('.ks-whole-wait').innerText(),/195 秒/);record('Manual settings survive reload without changing original observation windows')
 await evidencePanel();await open(ids[0]);await row(ids[0]).locator('.ks-group-technical > summary').click();assert.match(await row(ids[0]).locator('.ks-group-technical').innerText(),/尚未导入本地技术证据/)
 await row(ids[0]).locator('.ks-group-budget > summary').click();let ledger=await row(ids[0]).locator('.ks-time-ledger').innerText();assert.match(ledger,/保存传输\s*配置上限 255s\s*实际耗时 12.5s/);assert.match(ledger,/归档\s*配置上限 120s\s*尚未开始/);assert.match(ledger,/导入\s*配置上限 120s\s*计时中/)
 await open(ids[1]);await row(ids[1]).locator('.ks-group-budget > summary').click();assert.match(await row(ids[1]).locator('.ks-time-ledger').innerText(),/实际耗时未知/);await open(ids[0]);record('New actual timings, pending phases and old unknown timings retain distinct evidence states')
 await page.evaluate(()=>{window.__copied=[];Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>window.__copied.push(text)}})})
 const parentCopy=row(ids[0]).getByRole('button',{name:'复制完整主会话 ID',exact:true});assert.match(await parentCopy.getAttribute('title'),new RegExp(ids[0]));await parentCopy.click();assert.equal(await page.evaluate(()=>window.__copied.at(-1)),ids[0]);assert.equal(await row(ids[0]).evaluate(el=>el.open),true)
 const childCopy=row(ids[0]).getByRole('button',{name:'复制完整子会话 ID',exact:true});assert.match(await childCopy.getAttribute('title'),new RegExp(childIds[0]));await childCopy.click();assert.equal(await page.evaluate(()=>window.__copied.at(-1)),childIds[0]);record('Compact IDs expose complete titles and copy originals without toggling parent or child evidence')
 for(const theme of ['light','dark'])for(const width of [1440,1100,980,850,720,650,390]){
  await page.evaluate(theme=>document.documentElement.dataset.theme=theme,theme);await page.setViewportSize({width,height:1000});await open(ids[0])
  await row(ids[0]).scrollIntoViewIfNeeded();const date=await visibleText(row(ids[0]).locator(':scope > summary time')),action=await visibleText(child(ids[0]));assert.ok(date.clipped.length===0,JSON.stringify({width,date}));assert.ok(action.clipped.length===0,JSON.stringify({width,action}));assert.ok(date.scroll<=date.client+1);assert.equal(action.text,'展开子证据');assert.match(date.text,/\d{1,2}:31:22 [AP]M$/)
  const bounds=await row(ids[0]).evaluate(el=>({width:el.getBoundingClientRect().width,parentWidth:el.parentElement.getBoundingClientRect().width,scroll:el.scrollWidth,client:el.clientWidth,pageScroll:document.documentElement.scrollWidth,pageClient:document.documentElement.clientWidth}));assert.ok(bounds.scroll<=bounds.client+1,JSON.stringify({width,bounds}));assert.ok(bounds.pageScroll<=bounds.pageClient+1,JSON.stringify({width,bounds}));measurements.push({theme,viewport:width,date,action,bounds})
  await child(ids[0]).click();await page.locator('.ks-inline-session-detail').waitFor();assert.equal(await page.locator('.ks-parent-links').count(),0);assert.match(await page.locator('.ks-inline-session-detail').innerText(),/父会话引用为 0 条/);await page.locator('.ks-inline-session-detail > header > button').click();assert.equal(await page.locator('.ks-inline-session-detail').count(),0)
  await row(ids[0]).screenshot({path:out+`/parent-child-labels-${theme}-${width}.png`})
 }
 record('Long complete dates and independent child action text remain inside real container bounds across seven widths and both themes')
 for(let round=0;round<3;round++){await open(ids[0]);await child(ids[0]).click();await page.locator('.ks-inline-session-detail').waitFor();await open(ids[1]);assert.equal(await page.locator('.ks-inline-session-detail').count(),0);await child(ids[1]).click();await page.locator('.ks-inline-session-detail').waitFor();await child(ids[1]).click();assert.equal(await page.locator('.ks-inline-session-detail').count(),0)}
 mode='pending';await child(ids[1]).click();await page.locator('.ks-loading').waitFor();await open(ids[0]);resolveRead();await page.waitForTimeout(50);assert.equal(await page.locator('.ks-inline-session-detail').count(),0)
 mode='error';await child(ids[0]).click();await row(ids[0]).locator('.operation-error').waitFor();assert.match(await row(ids[0]).innerText(),/fixture unavailable/);await row(ids[0]).getByRole('button',{name:'关闭本次操作错误'}).click();mode='success';record('Repeated expand, switch and close never accumulate old reports; loading/error and late response states remain local')
 assert.equal(errors.length,0,errors.join('\n'));assert.deepEqual(calls.filter(c=>/^(begin_|provision_|run_kernsight|start_|dump_|execute_|trash_|restore_|cleanup_|cancel_kernsight_group$)/.test(c.command)),[])
 writeFileSync(out+'/browser-results.json',JSON.stringify({passed:true,checks,measurements,errors,commands:[...new Set(calls.map(c=>c.command))],note:'Independent local headless Chromium rendered actual Vue source with mocked IPC; no installed native ME/WebKit, capture, device, bank operations or deployment were performed. External icon fonts blocked by harness.'},null,2));console.log(JSON.stringify({passed:true,checks:checks.length,out}))
}catch(error){await page.screenshot({path:out+'/failure.png',fullPage:true});writeFileSync(out+'/failure.txt',String(error)+'\n'+JSON.stringify({calls,errors},null,2));throw error}finally{await close()}
