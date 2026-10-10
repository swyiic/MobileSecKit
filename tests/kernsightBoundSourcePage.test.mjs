import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { build } from 'esbuild'

const source = readFileSync(new URL('../src/services/kernsightBoundSourcePage.ts', import.meta.url), 'utf8')
const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 } }).outputText
const { boundSourceReports, validateBoundSourcePage, boundSourceLocalAnalysis, boundSourceInspection, boundSourceAnalysisLabel, runtimeCoverageSummary, runtimeRangeCounts } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
const sourceReport = 'runtime/bound-source-test.json', sourceSha256 = 'a'.repeat(64), rangeHash = 'b'.repeat(64)
const producer = () => ({ raw_evidence:'bound-example.code', source:{package:'org.example.fixture',pid:7,uid:10234,birth_ns:123456789,exec_id:2,boot_id:'fixture-boot'}, mapping:{start:100,end:200,path:'/fixture/libexample.so'}, read:{sha256:rangeHash,actual_length:100,requested_length:100,read_status:'complete',write_status:'complete',read_error:null,write_error:null} })
const makePage = (offset=0, totalRecords=1390, size=100) => ({schema:'mobilee.bound-source-page/v1',sourceReport,sourceSha256,offset,limit:100,totalRecords,nextOffset:offset+Math.min(size,totalRecords-offset)<totalRecords ? offset+Math.min(size,totalRecords-offset):null,records:Array.from({length:Math.min(size,totalRecords-offset)},(_,index)=>({sourceRecordIndex:offset+index,producerRecord:producer()}))})
const local = row => ({schema:'mobilee.bound-runtime-range/v1',inventory_role:'lightweight_range_ledger',source_report:sourceReport,source_report_sha256:sourceSha256,source_record_index:row.sourceRecordIndex,relative_path:'runtime/bound-example.code',source:row.producerRecord.source,mapping:row.producerRecord.mapping,read:row.producerRecord.read,local_content_status:'complete_range_hash_verified',inspection_status:'inspected',inspection_ref:0,inspection_content_key:rangeHash+':100'})

test('a byte-bounded short page uses its actual next cursor and the tail remains addressable',()=>{
  const short=makePage(0,1390,17);assert.equal(validateBoundSourcePage(short,sourceReport,0,null).nextOffset,17)
  const tail=makePage(1389);assert.equal(validateBoundSourcePage(tail,sourceReport,1389,sourceSha256).records[0].sourceRecordIndex,1389)
  assert.equal(tail.nextOffset,null)
  const empty=makePage(0,0);assert.equal(validateBoundSourcePage(empty,sourceReport,0,null).records.length,0)
})

test('changed source, wrong source path, invalid sequence and non-advancing cursor fail closed',()=>{
  const page=makePage()
  assert.throws(()=>validateBoundSourcePage({...page,sourceSha256:'c'.repeat(64)},sourceReport,0,sourceSha256),/无法核实/)
  assert.throws(()=>validateBoundSourcePage({...page,sourceReport:'runtime/other.json'},sourceReport,0,null),/无法核实/)
  assert.throws(()=>validateBoundSourcePage({...page,records:[{sourceRecordIndex:1,producerRecord:{}}]},sourceReport,0,null),/顺序/)
  assert.throws(()=>validateBoundSourcePage({...page,records:[],nextOffset:0},sourceReport,0,null),/后续/)
  assert.throws(()=>validateBoundSourcePage({...page,totalRecords:65537},sourceReport,0,null),/无法核实/)
  assert.throws(()=>validateBoundSourcePage({...page,limit:101},sourceReport,0,null),/无法核实/)
})

test('source SHA, original index, physical path and full source/mapping/read must all agree',()=>{
  const page=makePage(),row=page.records[0],exact=local(row)
  assert.equal(boundSourceLocalAnalysis({runtime_range_inventory:[exact]},page,row),exact)
  for(const changed of [
    {...exact,source_report_sha256:'c'.repeat(64)}, {...exact,source_report:'runtime/other.json'},
    {...exact,source_record_index:1},{...exact,relative_path:'runtime/other.code'},
    {...exact,source:{...exact.source,boot_id:'another-boot'}},
    {...exact,source:{...exact.source,extra_unmatched_identity:true}},
    {...exact,mapping:{...exact.mapping,end:201}},
    {...exact,read:{...exact.read,actual_length:99}},
    {...exact,read:{...exact.read,sha256:'c'.repeat(64)}},
    {...exact,read:{...exact.read,read_status:'partial'}},
  ]) assert.equal(boundSourceLocalAnalysis({runtime_range_inventory:[changed]},page,row),null)
})

test('legacy rows missing source SHA and ambiguous duplicates are never upgraded',()=>{
  const page=makePage(),row=page.records[0],exact=local(row),{source_report_sha256,...legacy}=exact
  assert.equal(boundSourceLocalAnalysis({runtime_observations:[legacy]},page,row),null)
  assert.equal(boundSourceLocalAnalysis({runtime_range_inventory:[exact,exact]},page,row),null)
  assert.equal(boundSourceAnalysisLabel(null),'本地分析关联未核实')
  assert.match(boundSourceAnalysisLabel({...exact,local_content_status:'unknown_or_failed',content_verification_failure_reason:'range_hash_budget_exhausted'}),/验证未知：range_hash_budget_exhausted/)
})

test('exact failed-read metadata keeps its local unknown reason without payload SHA or shared inspection',()=>{
  const page=makePage(0,1),row=page.records[0]
  delete row.producerRecord.read.sha256
  Object.assign(row.producerRecord.read,{actual_length:0,read_status:'read_failed',write_status:'not_attempted',read_error:'fixture_EFAULT'})
  const failed={...local(row),local_content_status:'unknown_or_failed',content_verification_failure_reason:'missing_or_inconsistent_range',inspection_status:'not_inspected',inspection_ref:null,inspection_content_key:null}
  const heavy={local_content_status:'complete_range_hash_verified',read:{sha256:rangeHash,actual_length:100},object_inspection:{status:'bounded'}}
  const ledger={runtime_range_inventory:[failed],runtime_observations:[heavy]}
  assert.equal(boundSourceLocalAnalysis(ledger,page,row),failed)
  assert.match(boundSourceAnalysisLabel(failed),/本地验证未知：missing_or_inconsistent_range/)
  assert.equal(boundSourceInspection(ledger,failed),null)
  assert.equal(boundSourceInspection(ledger,{...failed,inspection_ref:0,inspection_content_key:rangeHash+':100'}),null)
  for(const changed of [{...failed,source_report_sha256:'c'.repeat(64)},{...failed,read:{...failed.read,read_error:'another_failure'}}]) {
    assert.equal(boundSourceLocalAnalysis({...ledger,runtime_range_inventory:[changed]},page,row),null)
  }
})

test('verified metadata still needs a valid payload hash and positive safe length; unsupported states stay unlinked',()=>{
  for(const read of [{sha256:undefined},{sha256:'invalid'},{actual_length:0},{actual_length:undefined},{actual_length:-1},{actual_length:1.5},{actual_length:Number.MAX_SAFE_INTEGER+1}]) {
    const page=makePage(0,1),row=page.records[0]
    Object.assign(row.producerRecord.read,read)
    const exact=local(row)
    assert.equal(boundSourceLocalAnalysis({runtime_range_inventory:[exact]},page,row),null)
  }
  const page=makePage(0,1),row=page.records[0],exact=local(row)
  for(const status of [undefined,'unknown','complete_file_hash_verified','']) {
    assert.equal(boundSourceLocalAnalysis({runtime_range_inventory:[{...exact,local_content_status:status}]},page,row),null)
  }
  const zero={...exact,read:{...exact.read,actual_length:0},inspection_content_key:rangeHash+':0'}
  assert.equal(boundSourceInspection({runtime_observations:[{...zero,object_inspection:{status:'bounded'}}]},zero),null)
})

test('unsafe or malformed producer paths cannot be joined to analysis metadata',()=>{
  const page=makePage(),row=page.records[0],exact=local(row)
  for(const raw of ['../escape.code','dir/file.code','a\\b.code','..','']) assert.equal(boundSourceLocalAnalysis({runtime_range_inventory:[exact]},page,{...row,producerRecord:{...row.producerRecord,raw_evidence:raw}}),null)
  assert.equal(boundSourceLocalAnalysis({},page,{...row,producerRecord:null}),null)
})

test('shared heavy inspection is shown only for an already verified identical content key',()=>{
  const page=makePage(),exact=local(page.records[0]),inspection={status:'bounded',scanned_bytes:100}
  const heavy={source_report:'runtime/different-canonical-source.json',local_content_status:'complete_range_hash_verified',read:{sha256:rangeHash,actual_length:100},object_inspection:inspection}
  const ledger={runtime_observations:[heavy]}
  assert.equal(boundSourceInspection(ledger,exact),inspection)
  assert.equal(boundSourceInspection(ledger,{...exact,local_content_status:'unknown_or_failed'}),null)
  assert.equal(boundSourceInspection(ledger,{...exact,inspection_content_key:rangeHash+':99'}),null)
  assert.equal(boundSourceInspection(ledger,{...exact,inspection_ref:5}),null)
  assert.equal(boundSourceInspection({runtime_observations:[{...heavy,read:{...heavy.read,sha256:'c'.repeat(64)}}]},exact),null)
})

test('light inventory coverage is distinct from heavy pool, verification, inspection and old omission totals',()=>{
  const ledger={runtime_range_inventory:[{}],runtime_range_inventory_records:1390,runtime_verified_ranges:73,runtime_unverified_ranges:1317,runtime_inspected_ranges:73,runtime_uninspected_ranges:1317,runtime_inspection_unique_contents:17,runtime_inspection_rows_omitted:0,runtime_source_ledger_complete:true,runtime_analysis_complete:false}
  assert.match(runtimeCoverageSummary(ledger),/范围清单 1,390 条/)
  assert.match(runtimeCoverageSummary(ledger),/hash 已验证 73 条，验证未知 1,317 条/)
  assert.match(runtimeCoverageSummary(ledger),/独立内容检查 17 份/)
  assert.match(runtimeCoverageSummary(ledger),/代码分析不完整/)
  assert.match(runtimeCoverageSummary({runtime_observations:[{}],runtime_observation_limit:256,omitted_observations:1134}),/范围上限 256 条，另省略 1134 条/)
  assert.match(runtimeCoverageSummary(),/已载入范围 未知/)
  assert.deepEqual(boundSourceReports({runtime_source_diagnostics:[{source_report:sourceReport},{source_report:''},null],runtime_range_inventory:[{source_report:sourceReport},{source_report:'runtime/b.json'}]}),[sourceReport,'runtime/b.json'])
})


test('current inventory supplies missing summary counts without treating no-heavy inspection rows as uninspected',()=>{
  const ledger={runtime_range_inventory:[
    {local_content_status:'complete_range_hash_verified',inspection_status:'bounded_candidate_inspection',inspection_ref:0,inspection_content_key:rangeHash+':100'},
    {local_content_status:'complete_range_hash_verified',inspection_status:'no_dex_or_elf_header_in_retained_range',inspection_ref:null,inspection_content_key:rangeHash+':100'},
    {local_content_status:'unknown_or_failed',inspection_status:null},
  ],runtime_observations:[{}],runtime_heavy_results_omitted_records:0,runtime_analysis_complete:false,runtime_source_ledger_complete:false}
  assert.deepEqual(runtimeRangeCounts(ledger),{inventory:3,verified:2,unverified:1,inspected:2,uninspected:1,uniqueInspections:1,savedInspectionPool:1,omittedInspections:0})
  assert.match(runtimeCoverageSummary(ledger),/hash 已验证 2 条，验证未知 1 条/)
  assert.match(runtimeCoverageSummary(ledger),/有界检查记录 2 条，检查未知或未执行 1 条/)
  assert.match(runtimeCoverageSummary(ledger),/统计仅限当前已载入库存；有界检查不等于完整分析/)
})

test('explicit counts retain their source values including unknown, rather than silently recomputing',()=>{
  const ledger={runtime_range_inventory:[],runtime_verified_ranges:7,runtime_unverified_ranges:null,runtime_inspected_ranges:0,runtime_inspection_unique_contents:9,runtime_inspection_rows_omitted:4,runtime_heavy_results_omitted_records:0}
  assert.deepEqual(runtimeRangeCounts(ledger),{inventory:0,verified:7,unverified:null,inspected:0,uninspected:0,uniqueInspections:9,savedInspectionPool:undefined,omittedInspections:4})
  assert.match(runtimeCoverageSummary(ledger),/hash 已验证 7 条，验证未知 未知 条/)
  assert.match(runtimeCoverageSummary(ledger),/独立内容检查 9 份；保存的共享检查结果池 未知 条，检查结果省略 4 条/)
})

test('missing inventory or heavy pool stays unknown; loaded empty and unsupported rows remain scoped to current inventory',()=>{
  assert.equal(runtimeRangeCounts({}).verified,undefined)
  const empty={runtime_range_inventory:[],runtime_source_diagnostics:[{records_seen:1390,omitted_records:1390}]}
  assert.equal(runtimeRangeCounts(empty).verified,0)
  assert.match(runtimeCoverageSummary(empty),/独立内容检查 0 份；保存的共享检查结果池 未知 条，检查结果省略 未知 条/)
  assert.match(runtimeCoverageSummary(empty),/统计仅限当前已载入库存/)
  const partial={runtime_range_inventory:[null,{}, {local_content_status:'unknown_or_failed',inspection_status:'not_inspected'}]}
  assert.equal(runtimeRangeCounts(partial).unverified,3)
  assert.equal(runtimeRangeCounts(partial).inspected,0)
  assert.equal(runtimeRangeCounts(partial).uninspected,3)
})


test('scope stops, budget exhaustion and unsupported inspection statuses are never counted as known bounded inspections',()=>{
  const states=['bounded_candidate_inspection','no_dex_or_elf_header_in_retained_range','unknown_scope_stopped','unknown_inspection_budget_exhausted','not_inspected',null,'unrecognized_future_status']
  const ledger={runtime_range_inventory:states.map(inspection_status=>({local_content_status:'complete_range_hash_verified',inspection_status}))}
  assert.equal(runtimeRangeCounts(ledger).inspected,2)
  assert.equal(runtimeRangeCounts(ledger).uninspected,5)
  assert.match(runtimeCoverageSummary(ledger),/有界检查记录 2 条，检查未知或未执行 5 条/)
})


test('independent inspected content keys deduplicate separately from the saved pool; missing keys stay unknown',()=>{
  const known=inspection_content_key=>({local_content_status:'complete_range_hash_verified',inspection_status:'bounded_candidate_inspection',inspection_content_key})
  const rows=[known(rangeHash+':100'),known(rangeHash+':100'),known('c'.repeat(64)+':200'),{local_content_status:'unknown_or_failed',inspection_status:null}]
  const ledger={runtime_range_inventory:rows,runtime_observations:[{}]}
  assert.equal(runtimeRangeCounts(ledger).uniqueInspections,2)
  assert.equal(runtimeRangeCounts(ledger).savedInspectionPool,1)
  assert.match(runtimeCoverageSummary(ledger),/独立内容检查 2 份；保存的共享检查结果池 1 条/)
  for(const key of [undefined,'invalid',rangeHash+':0',rangeHash+':01',rangeHash+':9007199254740992']) {
    assert.equal(runtimeRangeCounts({...ledger,runtime_range_inventory:[known(key)]}).uniqueInspections,undefined)
    assert.match(runtimeCoverageSummary({...ledger,runtime_range_inventory:[known(key)]}),/独立内容检查 未知 份/)
  }
  assert.equal(runtimeRangeCounts({...ledger,runtime_inspection_unique_contents:null}).uniqueInspections,null)
})

const compiled = await build({entryPoints:[new URL('../src/services/backend/monitoring.ts',import.meta.url).pathname],bundle:true,write:false,format:'esm',platform:'node',plugins:[{name:'mock-tauri',setup(b){b.onResolve({filter:/^@tauri-apps\/api\/core$/},()=>({path:'tauri',namespace:'mock'}));b.onLoad({filter:/.*/,namespace:'mock'},()=>({contents:'export const invoke = (...args) => globalThis.__boundSourceInvoke(...args)',loader:'js'}))}}]})
const {monitoringBackend} = await import(`data:text/javascript;base64,${Buffer.from(compiled.outputFiles[0].text).toString('base64')}`)
test('the actual gateway pins the expected SHA and an old backend refusal does not fall back to preview',async()=>{
  const calls=[];globalThis.__boundSourceInvoke=async(command,args)=>{calls.push({command,args});throw new Error('Unknown command read_local_kernsight_bound_source_page')}
  await assert.rejects(()=>monitoringBackend.localKernSightBoundSourcePage('/fixture/root','org.example.fixture',sourceReport,1389,100,sourceSha256),/Unknown command/)
  assert.deepEqual(calls,[{command:'read_local_kernsight_bound_source_page',args:{root:'/fixture/root',package:'org.example.fixture',sourceReport,offset:1389,limit:100,expectedSha256:sourceSha256}}])
})
