import assert from 'node:assert/strict'
import test from 'node:test'
import {readFileSync} from 'node:fs'
import ts from 'typescript'
const js=ts.transpileModule(readFileSync(new URL('../src/services/kernsightCodeEvidence.ts',import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2020}}).outputText
const {runtimeInventoryInspection,matchesReadableDexEvidence,runtimeDexClassMatches,fileScanLabel,codeEvidenceLabel,projectDexEvidence}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
const rangeHash='a'.repeat(64),docA='b'.repeat(64),docB='c'.repeat(64),dexHash='d'.repeat(64)
const row=(name,pid,report,doc,index)=>({schema:'mobilee.bound-runtime-range/v1',inventory_role:'lightweight_range_ledger',source_report:report,source_report_sha256:doc,source_record_index:index,relative_path:`runtime/bound-${name}.code`,source:{package:'org.example.fixture',pid,uid:10234,birth_ns:pid*1000,exec_id:2,boot_id:'fixture-boot-'+pid},mapping:{start:1000,end:1100,path:'/fixture/lib-'+name+'.so'},read:{sha256:rangeHash,actual_length:100,requested_length:100,actual_start:1000,requested_start:1000,read_status:'complete',write_status:'complete'},local_content_status:'complete_range_hash_verified',inspection_status:'reused_verified_content',inspection_ref:0,inspection_content_key:rangeHash+':100'})
const canonical=row('canonical',1,'runtime/bound-source-A.json',docA,0),alias=row('alias',7,'runtime/bound-source-B.json',docB,31)
const inspection={status:'bounded_scan',file_bytes:100,scanned_through_offset:100,unscanned_tail_bytes:0,candidate_stop_reason:'range_end',derived_objects:[{kind:'dex',sha256:dexHash,length:16,source_offset:5,class_index:{classes:['Lfixture/Alias;']}}]}
const ledger={runtime_range_inventory:[canonical,alias],runtime_source_diagnostics:[{source_report:canonical.source_report,source_report_sha256:docA},{source_report:alias.source_report,source_report_sha256:docB}],runtime_observations:[{...canonical,object_inspection:inspection}]}
const ref={kind:'runtime_range_inventory',inventory_row_index:1,source_record_index:31,source_report:alias.source_report,source_report_sha256:docB,source:alias.source,relative_path:alias.relative_path,range_sha256:rangeHash,source_offset:5,source_absolute_start:1005,inspection_ref:0,inspection_content_key:rangeHash+':100',verification:'current_verified_range_and_shared_content_inspection'}
const object={sha256:dexHash,bytes:16,sources:[ref],class_index_status:'complete_class_def_index'}
const file={relativePath:alias.relative_path,bytes:100,codeEvidence:[alias]}

test('a verified alias retains its own identity while resolving one canonical shared inspection',()=>{
 const resolved=runtimeInventoryInspection(ledger,ref)
 assert.equal(resolved.range,alias);assert.equal(resolved.range.source.pid,7);assert.equal(resolved.inspection,inspection)
 assert.equal(runtimeInventoryInspection(ledger,alias).range.relative_path,alias.relative_path)
 assert.equal(matchesReadableDexEvidence(file,{local_storage_accounting:ledger}),true)
 assert.equal(matchesReadableDexEvidence({relativePath:alias.relative_path},{local_storage_accounting:ledger,content_dex_class_index:{objects:[object]}}),true)
 assert.deepEqual(runtimeDexClassMatches(ledger,object,'Alias').classes,['Lfixture/Alias;'])
 const scan=fileScanLabel(ledger.runtime_observations,file,ledger)
 assert.match(scan,/lib-alias\.so · pid 7/);assert.doesNotMatch(scan,/lib-canonical|pid 1 ·/)
 assert.match(codeEvidenceLabel([alias]),/代码检查 reused_verified_content/)
 const canonicalRef={...ref,kind:'runtime',verification:'checksum_failed_or_unknown',source_projection_verification:'current_verified_range_and_shared_content_inspection'}
 assert.equal(runtimeInventoryInspection(ledger,canonicalRef).range,alias)
 assert.deepEqual(runtimeDexClassMatches(ledger,{...object,sources:[canonicalRef]},'Alias').classes,['Lfixture/Alias;'])
 assert.equal(runtimeInventoryInspection(ledger,{...canonicalRef,source_projection_verification:undefined}),null)
})

test('source document, index, path, full identity, verified hash/key and heavy ref failures all remain unlinked',()=>{
 for(const changed of [
  {...ref,source_report_sha256:docA},{...ref,source_record_index:0},{...ref,inventory_row_index:0},
  {...ref,relative_path:canonical.relative_path},{...ref,source:{...ref.source,boot_id:'another-boot'}},
  {...ref,source:{...ref.source,extra_identity:1}},{...ref,range_sha256:docA},
  {...ref,inspection_content_key:rangeHash+':99'},{...ref,inspection_ref:1},
  {...ref,verification:'not_verified'},
 ]) {assert.equal(runtimeInventoryInspection(ledger,changed),null);assert.equal(runtimeDexClassMatches(ledger,{...object,sources:[changed]},'').total,null);assert.equal(matchesReadableDexEvidence({relativePath:changed.relative_path},{local_storage_accounting:ledger,content_dex_class_index:{objects:[{...object,sources:[changed]}]}}),false)}
 const badDoc={...ledger,runtime_source_diagnostics:[ledger.runtime_source_diagnostics[0],{source_report:alias.source_report,source_report_sha256:docA}]}
 assert.equal(runtimeInventoryInspection(badDoc,ref),null)
 const unknown={...ledger,runtime_range_inventory:[canonical,{...alias,local_content_status:'unknown_or_failed'}]}
 assert.equal(runtimeInventoryInspection(unknown,ref),null)
 const badHeavy={...ledger,runtime_observations:[{...canonical,read:{...canonical.read,actual_length:99},object_inspection:inspection}]}
 assert.equal(runtimeInventoryInspection(badHeavy,ref),null)
})

test('DEX extraction offset and length remain bounded; a shared ELF-only inspection does not become a DEX file',()=>{
 for(const changed of [{...ref,source_offset:99},{...ref,source_offset:6},{...ref,source_absolute_start:1006}])assert.equal(runtimeDexClassMatches(ledger,{...object,sources:[changed]},'').total,null)
 const elfOnly={...ledger,runtime_observations:[{...canonical,object_inspection:{...inspection,derived_objects:[{kind:'elf',sha256:dexHash,length:16,source_offset:5}]}}]}
 assert.equal(matchesReadableDexEvidence(file,{local_storage_accounting:elfOnly}),false)
 const wrongNote={...file,codeEvidence:[{...alias,read:{...alias.read,write_status:'failed'}}]}
 assert.equal(matchesReadableDexEvidence(wrongNote,{local_storage_accounting:ledger}),false)
 const missingSha={...file,codeEvidence:[{...alias,source_report_sha256:undefined}]}
 assert.equal(matchesReadableDexEvidence(missingSha,{local_storage_accounting:ledger}),false)
 const badLightSummary={...file,codeEvidence:[{...alias,source_report_sha256:undefined,object_inspection:inspection}]}
 assert.equal(matchesReadableDexEvidence(badLightSummary,{local_storage_accounting:ledger}),false,'light summaries must not fall through to legacy inline-object inspection')
})

test('alias projection omissions stay separate from missing hash verification and full code-analysis coverage',()=>{
 const dump={dex_sets:[],content_dex_class_index:{objects:[object],runtime_inventory_projection:{complete:false,invalid_rows:2,omitted_links:3,unmatched_dex_links:4}}}
 assert.match(projectDexEvidence(dump).warnings.join('；'),/已验证 DEX 范围的来源关联不完整/)
 assert.match(projectDexEvidence(dump).warnings.join('；'),/未列入 3 条/)
 assert.equal(projectDexEvidence({...dump,content_dex_class_index:{...dump.content_dex_class_index,runtime_inventory_projection:{complete:true}}}).warnings.length,0)
})
