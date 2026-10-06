import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source=readFileSync(new URL('../src/services/kernsightCodeEvidence.ts',import.meta.url),'utf8')
const js=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext}}).outputText
const {dexObjectGroups,verifiedDexObjectCount,indexedElfModuleCount,indexedDexCount,runtimeDexClassMatches,codeEvidenceLabel,allocatedEvidenceLabel,ownershipEvidenceEntries,codeNoiseLayers,archiveCoverageLabel,elfLoadCoverageLabel}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
test('legacy code has no invented source or success',()=>{assert.equal(codeEvidenceLabel(), '');assert.equal(codeEvidenceLabel([{}]),'代码来源未知')})
test('member provenance is distinct from verified retained bytes and business ownership',()=>{const label=codeEvidenceLabel([{schema:'kernsight.apk-member-evidence/v1',source:{zip_member:'classes.dex',apk_sha256:'a'.repeat(64)},transformation:'repair_dex/v1',local_content_status:'complete_file_hash_verified',ownership:{category:'mixed',reasons:['1 SDK + 99 app']}}]);assert.match(label,/classes.dex.*repair_dex.*保留文件完整 hash 已核对.*混合/);assert.match(label,/APK 原成员未在本地重解包核对/)})

test('bounded legacy missing read fields remains unknown',()=>{assert.match(codeEvidenceLabel([{schema:'kernsight.bounded-code-range/v1',read:{read_status:'complete'},retained_bytes:1}]),/读取状态未知/);assert.match(codeEvidenceLabel([{schema:'kernsight.bounded-code-range/v1',read:{read_status:'short_read'}}]),/读取状态未知/)})

test('bounded complete needs numeric source range and admission relationship',()=>{assert.match(codeEvidenceLabel([{schema:'kernsight.bounded-code-range/v1',read:{schema:'kernsight.memory-read/v1',requested_bytes:1,actual_bytes:1,read_status:'complete',read_error:null}}]),/读取状态未知/)})

test('missing or non-Unix allocation remains unknown, measured zero is valid',()=>{assert.equal(allocatedEvidenceLabel(undefined),'未知');assert.equal(allocatedEvidenceLabel(null),'未知');assert.equal(allocatedEvidenceLabel(0),'0 B')})

test('old ownership is unknown without overwriting its original data',()=>{const old=[{category:'business',confidence:100}];const result=ownershipEvidenceEntries('mobilee.kernsight-dex-ownership/v3',old);assert.equal(result[0].category,'unknown');assert.equal(result[0].confidence,0);assert.equal(old[0].category,'business')})
test('rebuilt v4 ownership keeps its classification basis',()=>{const entries=[{category:'mixed',confidence:75,reasons:['99 app + 1 SDK']}];assert.deepEqual(ownershipEvidenceEntries('mobilee.kernsight-dex-ownership/v4',entries),entries)})

test('complete byte groups keep all sources, weak SDK filenames stay unknown and partial is visible',()=>{
 const note={local_content_status:'complete_file_hash_verified',sha256:'a'.repeat(64),source_complete:true,write_status:'retained',ownership:{category:'third_party_sdk',basis:'DEX namespace samples'}}
 const files=[{relativePath:'sdk-name.dex',bytes:4,codeEvidence:[note]},{relativePath:'business.dex',bytes:4,codeEvidence:[note]},{relativePath:'short.dex',bytes:2,codeEvidence:[{...note,source_complete:false}]}]
 const before=JSON.stringify(files), layers=codeNoiseLayers(files)
 const group=layers.find(l=>l.key==='mixed').groups[0];assert.equal(group.paths.length,2);assert.equal(group.rows.length,2)
 assert.equal(layers.find(l=>l.key==='sdk').groups.length,0);assert.equal(layers.find(l=>l.key==='attention').groups.length,1);assert.equal(JSON.stringify(files),before)
})
test('old missing completeness does not merge or become SDK and mixed keeps business candidate',()=>{
 const n={sha256:'a'.repeat(64),local_content_status:'complete_file_hash_verified',write_status:'retained'}
 assert.equal(codeNoiseLayers([{relativePath:'a',bytes:2,codeEvidence:[n]},{relativePath:'b',bytes:2,codeEvidence:[n]}])[0].groups.length,2)
 const complete={...n,source_complete:true,ownership:{category:'mixed',basis:'DEX namespace samples'}}
 assert.equal(codeNoiseLayers([{relativePath:'app',bytes:2,codeEvidence:[complete]}]).find(l=>l.key==='mixed').groups.length,1)
})

test('uncatalogued DEX and ELF stay visible as unknown without inventing proof',()=>{const layers=codeNoiseLayers([{relative_path:'unknown.dex',bytes:5,content_class:'dex'},{relative_path:'unknown.so',bytes:8,content_class:'elf'}]);assert.equal(layers[0].groups.length,2);assert.ok(layers[0].groups.every(g=>g.sha256===null))})

test('runtime range labels preserve torn and missing evidence without claiming DEX recovery',()=>{
 const old=codeEvidenceLabel([{schema:'mobilee.bound-runtime-range/v1'}]);assert.match(old,/实际读 未知.*范围内容未验证.*实例来源未知/)
 const note={schema:'mobilee.bound-runtime-range/v1',mapping:{path:'/memfd:jit-cache'},read:{requested_length:256,actual_length:256,read_status:'complete',write_status:'complete',torn:true},retained_file_bytes:256,local_content_status:'complete_range_hash_verified',source_identity_status:'producer_identity_recorded'}
 const before=JSON.stringify(note);assert.match(codeEvidenceLabel([note]),/完整范围 hash 已核对.*torn true.*解析与分类未知/);assert.equal(JSON.stringify(note),before)
 const layers=codeNoiseLayers([{relativePath:'runtime/bound-test.code',bytes:256,codeEvidence:[note]}]);assert.equal(layers.find(l=>l.key==='attention').groups.length,1)
})

test('archive hash integrity never implies full collection and old coverage remains unknown',()=>{
 assert.match(archiveCoverageLabel(),/^未知/);assert.match(archiveCoverageLabel({complete:true}),/^未知/)
 assert.match(archiveCoverageLabel({status:'partial'}),/有效归档.*缺段未补齐/)
})

test('ELF load coverage never upgrades missing fields or whole-file completeness',()=>{
  assert.equal(elfLoadCoverageLabel(true),'列示范围全部覆盖')
  assert.equal(elfLoadCoverageLabel(false),'仍有缺口')
  for (const value of [undefined,null,1,'complete']) assert.equal(elfLoadCoverageLabel(value),'未知（缺字段）')
})

test('class index search retains all classes and rejects stale instance pointers',()=>{
 const identity={package:'com.pkg',pid:1,birth_ns:2,uid:3,exec_id:4,boot_id:'boot'}
 const source={kind:'runtime',row_index:0,source_report:'window',range_sha256:'range',source:identity}
 const object={sha256:'object',bytes:10,sources:[source]}
 const row={source_report:'window',read:{sha256:'range'},source:identity,object_inspection:{derived_objects:[{sha256:'object',length:10,class_index:{classes:Array.from({length:8201},(_,i)=>`Lpkg/Class${i};`)}}]}}
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'').total,8201)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'').classes.length,500)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'').omitted,7701)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'Class8200;').total,1)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'Class8200;').classes.length,1)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'Class8200;').omitted,0)
 assert.equal(runtimeDexClassMatches({runtime_observations:[{...row,source:{...identity,pid:99}}]},object,'').total,0)
})

test('package DEX count includes runtime and deduplicates same static content',()=>{
 const o={sha256:'a'.repeat(64),bytes:10}
 assert.equal(indexedDexCount({dex_index:{unique_dex:0},dex_sets:[o],content_dex_class_index:{objects:[o]}}),1)
 assert.equal(indexedDexCount({dex_index:{unique_dex:0},content_dex_class_index:{objects:[o]}}),1)
 assert.equal(indexedDexCount({}),null)
})

test('package ELF view count preserves seven libraries without counting repeated windows twice',()=>{
 const modules=Array.from({length:7},(_,i)=>({path:`lib${i}.so`}))
 assert.equal(indexedElfModuleCount({runtime_libs:0,local_storage_accounting:{elf_module_observations:[...modules,modules[0]]}}),7)
 assert.equal(indexedElfModuleCount({}),null)
})

test('failed, layout-anomalous and old missing-field objects are diagnostic only',()=>{
 const verified={sha256:'a'.repeat(64),bytes:100,validation_status:'checksum_and_bounded_structure_verified',sha1_signature_verified:true,adler32_checksum_verified:true,layout_diagnostics:{status:'declared_spans_cover_file'}}
 const failed={...verified,sha256:'b'.repeat(64),sha1_signature_verified:false}
 const layout={...verified,sha256:'c'.repeat(64),layout_diagnostics:{status:'declared_spans_leave_unaccounted_tail'}}
 const old={sha256:'d'.repeat(64),bytes:100}
 const objects=[verified,failed,layout,old];const groups=dexObjectGroups(objects)
 assert.equal(groups[0].objects.length,1);assert.equal(groups[1].objects.length,3)
 assert.equal(verifiedDexObjectCount({content_dex_class_index:{objects}}),1)
 assert.equal(verifiedDexObjectCount({content_dex_class_index:{objects:[failed,layout,old]}}),0)
 assert.equal(verifiedDexObjectCount({}),null);assert.equal(objects.length,4)
})
