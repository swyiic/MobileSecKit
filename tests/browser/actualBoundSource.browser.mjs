import assert from 'node:assert/strict'
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { tmpdir } from 'node:os'
import ts from 'typescript'
import { launchMe } from './mockedMeHarness.mjs'

const bundlePath=process.env.ME_ACTUAL_EVIDENCE_FIXTURE, recordsPath=process.env.ME_BOUND_SOURCE_RECORDS_FIXTURE, apiReceiptPath=process.env.ME_BOUND_SOURCE_API_RECEIPT
assert.ok(bundlePath&&recordsPath&&apiReceiptPath,'Set the actual imported bundle, consistently redacted producer records, and independent Rust API acceptance receipt paths')
const bytes=readFileSync(bundlePath), producerBytes=readFileSync(recordsPath), receiptBytes=readFileSync(apiReceiptPath)
const bundle=JSON.parse(bytes), source=JSON.parse(producerBytes), apiReceipt=JSON.parse(receiptBytes)
const ledger=bundle.dumpReport?.local_storage_accounting
assert.ok(bundle.root&&bundle.package&&Array.isArray(ledger?.runtime_range_inventory),'Requires an actual new light-inventory snapshot; no synthetic fallback')
assert.ok(source.sourceReport&&/^[a-f0-9]{64}$/.test(source.sourceSha256)&&Array.isArray(source.records))
assert.equal(apiReceipt.metadataOnly,true);assert.equal(apiReceipt.payloadBytesRead,0)
assert.equal(apiReceipt.sourceReport,source.sourceReport);assert.equal(apiReceipt.sourceSha256,source.sourceSha256)
assert.equal(apiReceipt.totalRecords,source.records.length)
for(const [i,row] of source.records.entries())assert.equal(row.sourceRecordIndex,i)
const relevant=ledger.runtime_range_inventory.filter(row=>row.source_report===source.sourceReport)
assert.equal(relevant.length,source.records.length,'The actual source records and retained light inventory have the same original scope')
const helperText=ts.transpileModule(readFileSync(new URL('../../src/services/kernsightBoundSourcePage.ts',import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2020}}).outputText
const {boundSourceLocalAnalysis,boundSourceAnalysisLabel,boundSourceInspection,runtimeCoverageSummary,runtimeRangeCounts}=await import(`data:text/javascript;base64,${Buffer.from(helperText).toString('base64')}`)
function response(offset,limit){const result={schema:'mobilee.bound-source-page/v1',sourceReport:source.sourceReport,sourceSha256:source.sourceSha256,offset,limit,totalRecords:source.records.length,nextOffset:null,records:[]};for(const row of source.records.slice(offset,offset+limit)){const end=row.sourceRecordIndex+1,candidate={...result,records:[...result.records,row],nextOffset:end<source.records.length?end:null};if(Buffer.byteLength(JSON.stringify(candidate))>256*1024)break;Object.assign(result,candidate)}return result}
const matched=source.records.map(row=>({row,local:boundSourceLocalAnalysis(ledger,response(row.sourceRecordIndex,1),row)}))
assert.equal(matched.filter(entry=>entry.local).length,source.records.length,'Every retained original record has an exact local metadata association')
const inventoryCounts=runtimeRangeCounts(ledger)
const inspectedKeys=ledger.runtime_range_inventory.filter(row=>['bounded_candidate_inspection','no_dex_or_elf_header_in_retained_range','inspected'].includes(row.inspection_status)).map(row=>row.inspection_content_key)
if(!Object.prototype.hasOwnProperty.call(ledger,'runtime_inspection_unique_contents')&&inspectedKeys.every(key=>typeof key==='string'&&/^[a-f0-9]{64}:[1-9]\d*$/i.test(key)&&Number.isSafeInteger(Number(key.slice(65)))))assert.equal(inventoryCounts.uniqueInspections,new Set(inspectedKeys.map(key=>key.toLowerCase())).size)
assert.equal(inventoryCounts.savedInspectionPool,ledger.runtime_observations?.length)
const digest=value=>createHash('sha256').update(value).digest('hex')
const out=resolve(process.env.ME_ACTUAL_SOURCE_QA_OUTPUT||resolve(tmpdir(),'me-actual-source-ranges-qa'));mkdirSync(out,{recursive:true})
let sourceReads=0
const h=await launchMe({root:fileURLToPath(new URL('../../',import.meta.url)),fixtures:{list_kernsight_group_purges:[]},handler:async(command,args)=>{
 if(command==='plugin:dialog|open')return bundle.root
 if(command==='import_kernsight_evidence_directory')return bundle
 if(command==='local_kernsight_evidence_present')return true
 if(command==='read_local_kernsight_bound_source_page'){
  assert.equal(args.root,bundle.root);assert.equal(args.package,bundle.package);assert.equal(args.sourceReport,source.sourceReport)
  assert.equal(args.expectedSha256,sourceReads++===0?null:source.sourceSha256)
  return response(args.offset,args.limit)
 }
}})
const {page,calls,errors,close}=h,checks=[]
const record=name=>{checks.push(name);console.log('PASS '+name)}
const panel=page.locator('.ks-package-evidence-panel'),details=panel.locator('.ks-source-diagnostics'),ranges=details.locator('.ks-bound-source-pages'),rows=()=>ranges.locator('.ks-bound-source-rows > details')
const waitOffset=offset=>page.waitForFunction(index=>document.querySelector('.ks-bound-source-rows > details')?.getAttribute('data-source-record-index')===String(index),offset)
async function jump(index){await ranges.getByLabel('转到记录序号').fill(String(index));await ranges.getByRole('button',{name:'转到记录',exact:true}).click();await waitOffset(index)}
try {
 await page.getByRole('button',{name:/KernSight.*采集、会话/}).click();await page.getByRole('button',{name:/导入本地证据/}).click();await page.locator('.ks-package-list article').filter({hasText:bundle.package}).first().click();await panel.waitFor()
 assert.equal(await ranges.evaluate(el=>el.open),false);assert.equal(calls.filter(call=>call.command==='read_local_kernsight_bound_source_page').length,0)
 assert.equal(await panel.locator('.ks-runtime-coverage').textContent(),runtimeCoverageSummary(ledger))
 await details.locator(':scope > summary').click();await ranges.locator(':scope > summary').click();await waitOffset(0)
 const visited=[];let offset=0
 while(true){const expected=response(offset,100);assert.equal(await rows().count(),expected.records.length);assert.match(await ranges.locator('.ks-bound-source-digest').innerText(),new RegExp(source.sourceSha256));visited.push(...await rows().evaluateAll(elements=>elements.map(el=>Number(el.dataset.sourceRecordIndex))));if(expected.nextOffset===null)break;await ranges.getByRole('button',{name:'下一页范围',exact:true}).click();offset=expected.nextOffset;await waitOffset(offset)}
 assert.deepEqual(visited,source.records.map(row=>row.sourceRecordIndex))
 const tail=source.records.at(-1);await rows().last().locator(':scope > summary').click();await rows().last().getByText('原始生产者记录',{exact:true}).click();assert.deepEqual(JSON.parse(await rows().last().locator(':scope > details').last().locator('pre').innerText()),tail.producerRecord)
 await ranges.screenshot({path:out+'/actual-original-range-tail-1440.png'})
 record(`Actual ${source.records.length} producer metadata records traverse all pages through ${tail.sourceRecordIndex}, with the original source SHA pinned to the independent Rust API receipt`)

 const unknown=matched.find(entry=>entry.local?.local_content_status==='unknown_or_failed')
 if(unknown){await jump(unknown.row.sourceRecordIndex);const row=rows().first();assert.match(await row.innerText(),/本地验证未知/);assert.ok((await row.innerText()).includes(boundSourceAnalysisLabel(unknown.local)));await row.locator(':scope > summary').click();if(!unknown.local.inspection_status)assert.match(await row.innerText(),/未知（未记录检查状态）/);const localDetails=row.locator(':scope > details').filter({has:page.locator(':scope > summary').filter({hasText:'本地范围状态与检查依据'})});await localDetails.locator(':scope > summary').click();const rendered=JSON.parse(await localDetails.locator('pre').innerText());assert.equal(rendered.content_verification_failure_reason,unknown.local.content_verification_failure_reason);assert.equal(rendered.inspection_status,unknown.local.inspection_status);await ranges.screenshot({path:out+'/actual-unknown-range-details.png'});record(`Actual unknown range ${unknown.row.sourceRecordIndex} preserves its verification reason and independent inspection status`)}else{assert.equal(inventoryCounts.unverified,0);record('Actual inventory explicitly reports zero unknown verification rows; no unknown example is invented')}

 const inspected=matched.find(entry=>boundSourceInspection(ledger,entry.local))
 if(inspected){await jump(inspected.row.sourceRecordIndex);const row=rows().first();assert.ok((await row.innerText()).includes(boundSourceAnalysisLabel(inspected.local)));await row.locator(':scope > summary').click();const inspectionDetails=row.locator(':scope > details').filter({has:page.locator(':scope > summary').filter({hasText:'关联的代码检查详情'})});await inspectionDetails.locator(':scope > summary').click();assert.deepEqual(JSON.parse(await inspectionDetails.locator('pre').innerText()),boundSourceInspection(ledger,inspected.local));record(`Actual range ${inspected.row.sourceRecordIndex} resolves its verified content key to the saved shared inspection result`)}else{assert.equal(inventoryCounts.inspected,0);record('Actual inventory has no eligible saved heavy inspection to display; its absence stays explicit')}

 await ranges.locator(':scope > summary').click();assert.equal(await rows().first().isVisible(),false)
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});const bounds=await panel.evaluate(el=>({client:el.clientWidth,scroll:el.scrollWidth,pageClient:document.documentElement.clientWidth,pageScroll:document.documentElement.scrollWidth}));assert.ok(bounds.scroll<=bounds.client+1&&bounds.pageScroll<=bounds.pageClient+1,JSON.stringify({width,bounds}));await ranges.screenshot({path:out+`/actual-source-entry-closed-${width}.png`})}
 record('The actual source entry closes locally and retains a readable collapsed layout at wide and narrow widths')
 assert.deepEqual(errors,[]);assert.deepEqual(calls.filter(call=>/^(begin_|provision_|run_kernsight|start_|dump_|execute_|trash_|restore_|cleanup_|cancel_)/.test(call.command)),[])
 const counts={...inventoryCounts,heavyRows:ledger.runtime_observations?.length,ledgerComplete:ledger.runtime_source_ledger_complete,analysisComplete:ledger.runtime_analysis_complete,matchedRows:matched.filter(entry=>entry.local).length,matchedVerifiedRows:matched.filter(entry=>entry.local?.local_content_status==='complete_range_hash_verified').length,matchedUnknownRows:matched.filter(entry=>entry.local?.local_content_status==='unknown_or_failed').length,originalRecords:source.records.length}
 writeFileSync(out+'/browser-results.json',JSON.stringify({passed:true,checks,errors,bundleInput:{path:bundlePath,sha256:digest(bytes)},producerInput:{path:recordsPath,sha256:digest(producerBytes)},rustApiReceipt:{path:apiReceiptPath,sha256:digest(receiptBytes),sourceSha256:apiReceipt.sourceSha256,metadataOnly:apiReceipt.metadataOnly,payloadBytesRead:apiReceipt.payloadBytesRead},counts,commands:[...new Set(calls.map(call=>call.command))],note:'Actual production import/redacted metadata fixtures rendered by real Vue in independent Chromium; Tauri mocked. Original SHA refers to unredacted source bytes, not redacted JSON bytes. Exact redacted identity equality validates UI associations only. Independent Rust receipt validates reader; neither proves complete code analysis, native WebKit or reproduction of the unseen 40-object screenshot.'},null,2))
 console.log(JSON.stringify({passed:true,checks:checks.length,counts,out}))
}catch(error){await page.screenshot({path:out+'/failure.png',fullPage:true});writeFileSync(out+'/failure.txt',String(error)+'\n'+JSON.stringify({calls,errors},null,2));throw error}finally{await close()}
