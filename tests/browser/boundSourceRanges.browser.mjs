import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { launchMe } from './mockedMeHarness.mjs'

const root = fileURLToPath(new URL('../../', import.meta.url))
const out = resolve(process.env.ME_BOUND_SOURCE_QA_OUTPUT || resolve(tmpdir(), 'me-bound-source-ranges-qa'))
mkdirSync(out, {recursive:true})
const packageName = 'org.example.sourcefixture', sourceReport = 'runtime/bound-source-fixture.json'
const hash = 'a'.repeat(64), contentHash = 'b'.repeat(64)
const producer = index => ({admitted:true,raw_evidence:`bound-fixture-${index}.code`,source:{package:packageName,pid:7,uid:10234,birth_ns:123456789,exec_id:2,boot_id:'fixture-boot'},mapping:{start:index*100+100,end:index*100+200,path:`/fixture/lib-${index}.so`},read:{sha256:contentHash,actual_length:100,requested_length:100,read_status:'complete',write_status:'complete',read_error:null,write_error:null}})
function bundle(name,total=1390,sourceHash=hash) {
  const inventory = Array.from({length:total},(_,index)=>{const raw=producer(index);return {schema:'mobilee.bound-runtime-range/v1',inventory_role:'lightweight_range_ledger',source_report:sourceReport,source_report_sha256:sourceHash,source_record_index:index,relative_path:'runtime/'+raw.raw_evidence,source:raw.source,mapping:raw.mapping,read:raw.read,local_content_status:index===0?'complete_range_hash_verified':'unknown_or_failed',content_verification_failure_reason:index===0?null:'range_hash_budget_exhausted',inspection_status:index===0?'inspected':'not_inspected',inspection_ref:index===0?0:null,inspection_content_key:index===0?contentHash+':100':null}})
  return {root:'/mock/'+name,package:packageName,fileCount:0,totalBytes:0,files:[],captureText:'',dumpReport:{package:packageName,dump_id:name,dex_sets:[],local_storage_accounting:{logical_file_bytes:0,allocated_bytes:0,verified_code_duplicate_bytes:0,runtime_range_inventory:inventory,runtime_range_inventory_records:total,runtime_verified_ranges:total?1:0,runtime_unverified_ranges:Math.max(0,total-1),runtime_inspected_ranges:total?1:0,runtime_uninspected_ranges:Math.max(0,total-1),runtime_inspection_unique_contents:total?1:0,runtime_inspection_rows_omitted:0,runtime_source_ledger_complete:true,runtime_analysis_complete:false,runtime_source_diagnostics:[{source_report:sourceReport,source_report_sha256:sourceHash,records_seen:total}],runtime_observations:total?[{...inventory[0],object_inspection:{status:'fixture_shared_inspection',scanned_bytes:100,unscanned_tail_bytes:0}}]:[]}}}
}
const a=bundle('range-A'), b=bundle('range-B',1,'c'.repeat(64)), empty=bundle('range-empty',0)
const failed=bundle('range-failed-metadata',1),failedProducer=producer(0)
delete failedProducer.read.sha256
Object.assign(failedProducer.read,{actual_length:0,read_status:'read_failed',write_status:'not_attempted',read_error:'fixture_EFAULT'})
const failedLedger=failed.dumpReport.local_storage_accounting
const failedRange={...failedLedger.runtime_range_inventory[0],read:failedProducer.read,local_content_status:'unknown_or_failed',content_verification_failure_reason:'missing_or_inconsistent_range',inspection_status:'not_inspected',inspection_ref:null,inspection_content_key:null}
Object.assign(failedLedger,{runtime_range_inventory:[failedRange],runtime_observations:[],runtime_verified_ranges:0,runtime_unverified_ranges:1,runtime_inspected_ranges:0,runtime_uninspected_ranges:1,runtime_inspection_unique_contents:0})
failed.files=[{relativePath:failedRange.relative_path,bytes:0,category:'runtime',codeEvidence:[failedRange]}];failed.fileCount=1
let nextImport=a, mode='short', resolvePending
const recordsPage = args => {
  const current = [a,b,empty,failed].find(item=>item.root===args.root) || nextImport
  const ledger=current.dumpReport.local_storage_accounting,total=ledger.runtime_range_inventory_records,offset=args.offset
  const count=Math.min(args.limit,total-offset,mode==='short'&&offset===0?17:100)
  return {schema:'mobilee.bound-source-page/v1',sourceReport:args.sourceReport,sourceSha256:ledger.runtime_source_diagnostics[0].source_report_sha256,offset,limit:args.limit,totalRecords:total,nextOffset:offset+count<total?offset+count:null,records:Array.from({length:count},(_,i)=>({sourceRecordIndex:offset+i,producerRecord:current===failed?failedProducer:producer(offset+i)}))}
}
const h=await launchMe({root,fixtures:{list_kernsight_group_purges:[]},handler:async(command,args)=>{
  if(command==='plugin:dialog|open')return nextImport.root
  if(command==='import_kernsight_evidence_directory')return nextImport
  if(command==='local_kernsight_evidence_present')return true
  if(command==='read_local_kernsight_bound_source_page') {
    if(mode==='unsupported')throw new Error('Unknown command read_local_kernsight_bound_source_page')
    if(mode==='error')throw new Error('fixture source metadata unavailable')
    if(mode==='pending')return new Promise(resolve=>{resolvePending=()=>resolve(recordsPage(args))})
    const result=recordsPage(args)
    if(mode==='changed')result.sourceSha256='d'.repeat(64)
    return result
  }
}})
const {page,calls,errors,close}=h,checks=[]
const record=name=>{checks.push(name);console.log('PASS '+name)}
const panel=page.locator('.ks-package-evidence-panel'), sourceDetails=panel.locator('.ks-source-diagnostics'), ranges=sourceDetails.locator('.ks-bound-source-pages')
const rows=()=>ranges.locator('.ks-bound-source-rows > details')
async function importBundle(item){nextImport=item;await page.getByRole('button',{name:/导入本地证据/}).click();await page.locator('.ks-package-list article').filter({hasText:packageName}).first().click();await panel.waitFor()}
async function openRanges(){if(!await sourceDetails.evaluate(el=>el.open))await sourceDetails.locator(':scope > summary').click();if(!await ranges.evaluate(el=>el.open))await ranges.locator(':scope > summary').click()}
async function waitOffset(offset){await page.waitForFunction(expected=>document.querySelector('.ks-bound-source-rows > details')?.getAttribute('data-source-record-index')===String(expected),offset)}
try {
  await page.getByRole('button',{name:/KernSight.*采集、会话/}).click();await importBundle(a)
  assert.equal(await ranges.evaluate(el=>el.open),false)
  assert.equal(calls.filter(call=>call.command==='read_local_kernsight_bound_source_page').length,0)
  await openRanges();await waitOffset(0);assert.equal(await rows().count(),17);assert.match(await ranges.innerText(),/原始记录共 1390 条 · 当前 0–16/)
  assert.equal(await ranges.locator('select').count(),0)
  await ranges.getByRole('button',{name:'下一页范围',exact:true}).click();await waitOffset(17);assert.equal(await rows().count(),100)
  await ranges.getByRole('button',{name:'上一页范围',exact:true}).click();await waitOffset(0);assert.equal(await rows().count(),17)
  const sourceCalls=calls.filter(call=>call.command==='read_local_kernsight_bound_source_page')
  assert.deepEqual(sourceCalls.map(call=>[call.args.offset,call.args.expectedSha256]),[[0,null],[17,hash],[0,hash]])
  record('Source reads stay lazy; a 17-row byte-limited page uses nextOffset and cursor history, never offset-minus-100')

  await ranges.getByLabel('转到记录序号').fill('1389');await ranges.getByRole('button',{name:'转到记录',exact:true}).click();await waitOffset(1389)
  assert.equal(await rows().count(),1);assert.match(await rows().first().innerText(),/本地验证未知：range_hash_budget_exhausted/)
  await rows().first().locator(':scope > summary').click()
  await rows().first().getByText('原始生产者记录',{exact:true}).click()
  assert.match(await rows().first().locator('pre').last().innerText(),/bound-fixture-1389\.code/)
  assert.equal(await ranges.getByRole('button',{name:'下一页范围',exact:true}).isDisabled(),true)
  assert.match(await panel.locator('.ks-runtime-coverage').innerText(),/范围清单 1,390 条/)
  assert.match(await panel.locator('.ks-runtime-coverage').innerText(),/唯一内容检查 1 份/)
  await ranges.screenshot({path:out+'/synthetic-tail-1389-1440.png'})
  record('All 1390 synthetic original records are addressable; tail 1389 retains an explicit unknown verification reason and raw note')

  await ranges.getByLabel('转到记录序号').fill('0');await ranges.getByRole('button',{name:'转到记录',exact:true}).click();await waitOffset(0)
  assert.equal(await ranges.getByRole('button',{name:'上一页范围',exact:true}).isDisabled(),true)
  const first=rows().first();await first.locator(':scope > summary').click();assert.match(await first.innerText(),/范围 hash 已验证/)
  const inspectionDetails=first.locator(':scope > details').filter({has:page.locator(':scope > summary').filter({hasText:'关联的代码检查详情'})})
  await inspectionDetails.locator(':scope > summary').click();assert.match(await inspectionDetails.locator('pre').innerText(),/fixture_shared_inspection/)
  mode='changed';await ranges.getByRole('button',{name:'下一页范围',exact:true}).click();await ranges.locator('[role="alert"]').waitFor();assert.match(await ranges.locator('[role="alert"]').innerText(),/来源或分页回执无法核实/);assert.equal(await rows().first().getAttribute('data-source-record-index'),'0')
  assert.match(await ranges.locator('[role="alert"]').innerText(),/上次成功读取的页/)
  mode='error';await ranges.getByRole('button',{name:'重试读取',exact:true}).click();await page.waitForFunction(()=>document.querySelector('.ks-bound-source-error')?.textContent.includes('fixture source metadata unavailable'))
  assert.equal(await rows().count(),17);mode='short'
  record('Shared inspection requires an exact verified content key; changed SHA and read failures preserve only the prior successful page')

  const legacy=bundle('range-legacy',1);delete legacy.dumpReport.local_storage_accounting.runtime_range_inventory[0].source_report_sha256
  mode='normal';await importBundle(legacy);await openRanges();await waitOffset(0);assert.match(await rows().first().innerText(),/本地分析关联未核实/)
  assert.equal(await ranges.getByText('关联的代码检查详情',{exact:true}).count(),0)
  const mismatch=bundle('range-mismatch',1);mismatch.dumpReport.local_storage_accounting.runtime_range_inventory[0].source.boot_id='unmatched-boot'
  await importBundle(mismatch);await openRanges();await waitOffset(0);assert.match(await rows().first().innerText(),/本地分析关联未核实/)
  record('Missing import-source SHA and a full-source identity mismatch stay unlinked, even with matching path/index')

  await importBundle(failed);await openRanges();await waitOffset(0)
  assert.equal(await rows().count(),1)
  const failedRow=rows().first()
  assert.match(await failedRow.innerText(),/本地验证未知：missing_or_inconsistent_range/)
  assert.doesNotMatch(await failedRow.innerText(),/范围 hash 已验证|本地分析关联未核实/)
  await failedRow.locator(':scope > summary').click()
  assert.match(await failedRow.innerText(),/代码检查：not_inspected/)
  const failedLocalDetails=failedRow.locator(':scope > details').filter({has:page.locator(':scope > summary').filter({hasText:'本地范围状态与检查依据'})})
  await failedLocalDetails.locator(':scope > summary').click()
  const failedRendered=JSON.parse(await failedLocalDetails.locator('pre').innerText())
  assert.equal(failedRendered.content_verification_failure_reason,'missing_or_inconsistent_range')
  assert.deepEqual(failedRendered.read,failedProducer.read)
  await failedRow.getByText('原始生产者记录',{exact:true}).click()
  assert.deepEqual(JSON.parse(await failedRow.locator(':scope > details').last().locator('pre').innerText()),failedProducer)
  assert.equal(await ranges.getByText('关联的代码检查详情',{exact:true}).count(),0)
  assert.doesNotMatch(await failedRow.innerText(),/按已验证内容关联共享检查结果/)
  const failedDexCard=panel.locator('.ks-forensic-grid > article').filter({has:page.locator('strong').filter({hasText:'DEX 文件 / 容器'})})
  assert.equal(await failedDexCard.locator(':scope > b').innerText(),'0')
  await ranges.screenshot({path:out+'/failed-read-metadata-local-reason.png'})
  record('An exact failed-read record without payload SHA retains its local unknown reason and raw note, without shared inspection or a physical DEX upgrade')

  mode='pending';await importBundle(a);await openRanges();await page.waitForFunction(()=>document.querySelector('.ks-bound-source-pages [role="status"]'))
  mode='normal';await importBundle(b);resolvePending();await page.waitForTimeout(50)
  assert.equal(await ranges.evaluate(el=>el.open),false);assert.equal(await rows().count(),0)
  await openRanges();await waitOffset(0);assert.equal(await rows().count(),1);assert.match(await ranges.locator('.ks-bound-source-digest').innerText(),new RegExp('c'.repeat(64)))
  record('Changing the selected same-package root closes the original pager and fences off a late response')

  mode='unsupported';const old=bundle('range-old-backend',1);await importBundle(old);await openRanges();await ranges.locator('[role="alert"]').waitFor()
  assert.match(await ranges.locator('[role="alert"]').innerText(),/当前安装不支持原始范围分页/);assert.equal(await rows().count(),0)
  assert.equal(calls.filter(call=>call.command==='read_local_kernsight_evidence_file').length,0)
  mode='normal';await importBundle(empty);await openRanges();await ranges.locator('.ks-bound-source-page-count').waitFor();assert.match(await ranges.innerText(),/明确列示 0 条原始记录/)
  assert.equal(await ranges.locator('select').count(),0)
  record('Old-backend unsupported and measured-empty records are separate states, with no truncated-preview fallback')

  const aliases=bundle('range-alias-consumer',2)
  const aliasLedger=aliases.dumpReport.local_storage_accounting
  aliasLedger.runtime_range_inventory[1]={...aliasLedger.runtime_range_inventory[1],source:{...aliasLedger.runtime_range_inventory[1].source,pid:8},local_content_status:'complete_range_hash_verified',content_verification_failure_reason:null,inspection_status:'reused_verified_content',inspection_ref:0,inspection_content_key:contentHash+':100'}
  const dexSha='e'.repeat(64)
  aliasLedger.runtime_observations[0].object_inspection={status:'fixture_shared_inspection',file_bytes:100,scanned_through_offset:100,unscanned_tail_bytes:0,derived_objects:[{kind:'dex',sha256:dexSha,length:16,source_offset:5,class_index:{classes:['Lfixture/Alias;']}}]}
  const aliasSources=aliasLedger.runtime_range_inventory.map((range,i)=>({kind:'runtime_range_inventory',inventory_row_index:i,source_record_index:range.source_record_index,source_report:range.source_report,source_report_sha256:range.source_report_sha256,source:range.source,relative_path:range.relative_path,range_sha256:range.read.sha256,source_offset:5,inspection_ref:0,inspection_content_key:contentHash+':100',verification:'current_verified_range_and_shared_content_inspection'}))
  aliasSources[0]={...aliasSources[0],kind:'runtime',verification:'checksum_failed_or_unknown',source_projection_verification:'current_verified_range_and_shared_content_inspection'}
  aliases.dumpReport.content_dex_class_index={schema:'fixture-content-index',scope:'synthetic alias consumer regression only',objects:[{sha256:dexSha,bytes:16,sources:aliasSources,indexed_classes:1,declared_classes:1,class_index_status:'complete_class_def_index',validation_status:'unknown'}]}
  aliases.files=aliasLedger.runtime_range_inventory.map(range=>({relativePath:range.relative_path,bytes:100,category:'runtime',codeEvidence:[range]}));aliases.fileCount=2
  await importBundle(aliases)
  const dexCard=panel.locator('.ks-forensic-grid > article').filter({has:page.locator('strong').filter({hasText:'DEX 文件 / 容器'})})
  assert.equal(await dexCard.locator(':scope > b').innerText(),'2');await dexCard.click();assert.equal(await panel.locator('.ks-evidence-file-list > button').count(),2)
  const dexIndex=panel.locator('.ks-code-analysis > .ks-dex-index');await dexIndex.locator(':scope > summary').click();assert.equal(await dexIndex.locator('[data-dex-object]').count(),1);assert.match(await dexIndex.locator('[data-dex-index-status="indexed"]').innerText(),/匹配 1/)
  assert.equal(await dexIndex.locator('[data-dex-group="diagnostic"] [data-dex-object]').count(),1)
  const dexObject=dexIndex.locator('[data-dex-object]');await dexObject.getByText('来源与实例',{exact:true}).click();const sourcesRendered=JSON.parse(await dexObject.locator(':scope > details > pre').first().innerText());assert.deepEqual(sourcesRendered.map(ref=>ref.source.pid),[7,8]);assert.deepEqual(sourcesRendered.map(ref=>ref.relative_path),aliases.files.map(file=>file.relativePath))
  await dexIndex.screenshot({path:out+'/two-alias-paths-one-shared-dex.png'})
  record('Two verified physical alias paths stay in the same-source DEX list while one shared object/class index preserves both original process identities')

  await importBundle(a);await openRanges();await waitOffset(0)
  for(const width of [1440,821,390]){await page.setViewportSize({width,height:1000});const bounds=await ranges.evaluate(el=>({client:el.clientWidth,scroll:el.scrollWidth,pageClient:document.documentElement.clientWidth,pageScroll:document.documentElement.scrollWidth}));assert.ok(bounds.scroll<=bounds.client+1&&bounds.pageScroll<=bounds.pageClient+1,JSON.stringify({width,bounds}));await ranges.screenshot({path:out+`/source-ranges-${width}.png`})}
  await ranges.locator('.ks-bound-source-jump').screenshot({path:out+'/source-pager-controls-390.png'})
  await ranges.locator(':scope > summary').click();assert.equal(await rows().first().isVisible(),false)
  await ranges.screenshot({path:out+'/source-entry-closed-390.png'})
  record('Wide, medium and narrow actual Vue layouts keep the source path, count and local pager readable; closing collapses the list')
  assert.deepEqual(errors,[])
  assert.deepEqual(calls.filter(call=>/^(begin_|provision_|run_kernsight|start_|dump_|execute_|trash_|restore_|cleanup_|cancel_)/.test(call.command)),[])
  writeFileSync(out+'/browser-results.json',JSON.stringify({passed:true,checks,errors,fixtureKind:'synthetic_source_paging_regression',commands:[...new Set(calls.map(call=>call.command))],note:'Independent Chromium rendering real Vue UI with mocked Tauri and blocked external network. Synthetic 1390 metadata records, not actual analysis counts, Rust reader API validation, native WebKit or user screenshot reproduction.'},null,2))
  console.log(JSON.stringify({passed:true,checks:checks.length,out}))
} catch(error){await page.screenshot({path:out+'/failure.png',fullPage:true});writeFileSync(out+'/failure.txt',String(error)+'\n'+JSON.stringify({calls,errors},null,2));throw error} finally {await close()}
