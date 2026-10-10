import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source=readFileSync(new URL('../src/services/kernsightCodeEvidence.ts',import.meta.url),'utf8')
const js=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext}}).outputText
const {projectDexEvidence,matchesReadableDexEvidence,dexObjectGroups,verifiedDexObjectCount,indexedElfModuleCount,indexedDexCount,runtimeDexClassMatches,codeEvidenceLabel,allocatedEvidenceLabel,ownershipEvidenceEntries,codeNoiseLayers,archiveCoverageLabel,elfLoadCoverageLabel,dexScanSummary,dexScanSummaryForObject,fileScanLabel}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
test('legacy code has no invented source or success',()=>{assert.equal(codeEvidenceLabel(), '');assert.equal(codeEvidenceLabel([{}]),'代码来源未知')})
test('member provenance is distinct from verified retained bytes and business ownership',()=>{const label=codeEvidenceLabel([{schema:'kernsight.apk-member-evidence/v1',source:{zip_member:'classes.dex',apk_sha256:'a'.repeat(64)},transformation:'repair_dex/v1',local_content_status:'complete_file_hash_verified',ownership:{category:'mixed',reasons:['1 SDK + 99 app']}}]);assert.match(label,/classes.dex.*repair_dex.*保留文件完整 hash 已核对.*混合/);assert.match(label,/APK 原成员未在本地重解包核对/)})

test('bounded legacy missing read fields remains unknown',()=>{assert.match(codeEvidenceLabel([{schema:'kernsight.bounded-code-range/v1',read:{read_status:'complete'},retained_bytes:1}]),/读取状态未知/);assert.match(codeEvidenceLabel([{schema:'kernsight.bounded-code-range/v1',read:{read_status:'short_read'}}]),/读取状态未知/)})

test('bounded complete needs numeric source range and admission relationship',()=>{assert.match(codeEvidenceLabel([{schema:'kernsight.bounded-code-range/v1',read:{schema:'kernsight.memory-read/v1',requested_bytes:1,actual_bytes:1,read_status:'complete',read_error:null}}]),/读取状态未知/)})

test('missing or non-Unix allocation remains unknown, measured zero is valid',()=>{assert.equal(allocatedEvidenceLabel(undefined),'未知');assert.equal(allocatedEvidenceLabel(null),'未知');assert.equal(allocatedEvidenceLabel(0),'0 B')})

test('dex scan summary does not invent zero bytes or a clean stop',()=>{
  assert.equal(dexScanSummary(undefined),'未知（旧数据未检查）')
  const missing=dexScanSummary({})
  assert.match(missing,/文件 未知/)
  assert.match(missing,/DEX 扫描到 未知/)
  assert.match(missing,/停止 未知/)
  assert.match(missing,/未扫描尾部 未知/)
  assert.doesNotMatch(missing,/0 B|无提前停止/)
  const stopped=dexScanSummary({status:'bounded_candidate_inspection',file_bytes:128,scanned_through_offset:64,unscanned_tail_bytes:64,candidate_stop_reason:'rejected_candidate_limit'})
  assert.match(stopped,/文件 128 B · DEX 扫描到 64 B · 停止 rejected_candidate_limit · 未扫描尾部 64 B/)
  const joined=dexScanSummaryForObject([{object_inspection:{file_bytes:0,scanned_bytes:0,unscanned_tail_bytes:0,candidate_stop_reason:'rejected_candidate_limit',derived_objects:[{sha256:'abc'}]}}],'abc')
  assert.match(joined,/文件 0 B · DEX 扫描到 0 B · 停止 rejected_candidate_limit · 未扫描尾部 0 B/)
  assert.match(dexScanSummaryForObject([],'abc'),/未知/)
  const sha='abc'
  const observations=[
    {mapping:{path:'/mem/a'},source:{pid:1,exec_id:2},relative_path:'runtime/a.code',raw_evidence:'a.code',object_inspection:{file_bytes:100,scanned_through_offset:40,unscanned_tail_bytes:60,candidate_stop_reason:'rejected_candidate_limit',derived_objects:[{sha256:sha}]}},
    {mapping:{path:'/mem/b'},source:{pid:1,exec_id:3},relative_path:'runtime/b.code',raw_evidence:'b.code',object_inspection:{file_bytes:100,scanned_through_offset:100,unscanned_tail_bytes:0,candidate_stop_reason:'complete',derived_objects:[{sha256:sha}]}},
  ]
  const both=dexScanSummaryForObject(observations,sha)
  assert.match(both,/\/mem\/a/)
  assert.match(both,/\/mem\/b/)
  assert.match(both,/停止 rejected_candidate_limit/)
  assert.match(both,/未扫描尾部 60 B/)
  assert.match(both,/未扫描尾部 0 B/)
  const fileA=fileScanLabel(observations,{relativePath:'runtime/a.code',sha256:sha})
  assert.match(fileA,/\/mem\/a/)
  assert.match(fileA,/停止 rejected_candidate_limit/)
  assert.doesNotMatch(fileA,/\/mem\/b/)
  const fileB=fileScanLabel(observations,{relativePath:'runtime/b.code',sha256:sha})
  assert.match(fileB,/停止 complete/)
  assert.doesNotMatch(fileB,/rejected_candidate_limit/)
  const unbound=fileScanLabel(observations,{relativePath:'apk-dex/classes.dex',sha256:sha})
  assert.match(unbound,/\/mem\/a/)
  assert.match(unbound,/\/mem\/b/)
  const absent=fileScanLabel(undefined,{relativePath:'notes.txt'})
  assert.match(absent,/停止 未知/)
  assert.match(absent,/未扫描尾部 未知/)
})

function scanObservation(path, sha, tail, extra = {}) {
  return {
    mapping: { path },
    source: { pid: 42, exec_id: 7 },
    object_inspection: {
      status: 'bounded_candidate_inspection', file_bytes: 1000,
      scanned_through_offset: 1000 - tail, unscanned_tail_bytes: tail,
      candidate_stop_reason: tail ? 'rejected_candidate_limit' : 'complete',
      derived_objects: [{ sha256: sha }],
    },
    ...extra,
  }
}

test('same basename with another SHA cannot hide the real unread tail in either file view', () => {
  const sha = 'a'.repeat(64)
  const observations = [
    scanObservation('/other/classes.dex', 'b'.repeat(64), 0, { raw_evidence: 'classes.dex', relative_path: 'other/classes.dex' }),
    scanObservation('/mem/target', sha, 600, { relative_path: 'runtime/bound-target.code' }),
  ]
  const file = { relative_path: 'apk-dex/classes.dex', sha256: sha, codeEvidence: [{ sha256: sha }] }
  const noiseRow = codeNoiseLayers([file])[0].groups[0].rows[0]
  const before = JSON.stringify(observations)
  for (const displayFile of [file, { relativePath: noiseRow.path, codeEvidence: noiseRow.notes }]) {
    const label = fileScanLabel(observations, displayFile)
    assert.match(label, /\/mem\/target · pid 42 · exec 7/)
    assert.match(label, /停止 rejected_candidate_limit · 未扫描尾部 600 B/)
    assert.doesNotMatch(label, /\/other\/classes.dex|停止 complete|未扫描尾部 0 B/)
  }
  assert.equal(JSON.stringify(observations), before)
})

test('a basename hit does not hide other sources of the same SHA', () => {
  const observations = [
    scanObservation('/other/classes.dex', 'shared', 0),
    scanObservation('/mem/target', 'shared', 600),
  ]
  const label = fileScanLabel(observations, { relativePath: 'apk-dex/classes.dex', sha256: 'shared' })
  assert.equal(label, dexScanSummaryForObject(observations, 'shared'))
  assert.match(label, /\/other\/classes.dex.*未扫描尾部 0 B；\/mem\/target.*未扫描尾部 600 B/)
})

test('exact retained artifact paths keep all source rows and their independent unknown fields', () => {
  const observations = [
    scanObservation('/mem/first', 'dex', 600, { relative_path: 'runtime/bound.code', source: { pid: 1, exec_id: 2 } }),
    scanObservation('/mem/second', 'dex', 0, { relative_path: 'runtime/bound.code', source: { pid: 1, exec_id: 3 }, object_inspection: {} }),
    scanObservation('/mem/elsewhere', 'dex', 0, { relative_path: 'runtime/other.code' }),
  ]
  const label = fileScanLabel(observations, { relativePath: 'runtime/bound.code', sha256: 'dex' })
  assert.match(label, /\/mem\/first · pid 1 · exec 2.*未扫描尾部 600 B/)
  assert.match(label, /\/mem\/second · pid 1 · exec 3.*停止 未知 · 未扫描尾部 未知/)
  assert.doesNotMatch(label, /\/mem\/elsewhere/)
})

test('device mapping paths and raw basenames cannot override an explicit retained artifact path', () => {
  const observations = [scanObservation('runtime/target.code', 'other', 0, {
    relative_path: 'runtime/other.code', raw_evidence: 'target.code',
  })]
  for (const relativePath of ['runtime/target.code', 'target.code', 'apk-dex/other.code']) {
    const label = fileScanLabel(observations, { relativePath })
    assert.match(label, /^来源未知/)
    assert.match(label, /停止 未知 · 未扫描尾部 未知/)
    assert.doesNotMatch(label, /停止 complete|未扫描尾部 0 B/)
  }
})

test('legacy raw artifacts are resolved relative to their source report, never by basename', () => {
  const observations = [scanObservation('/mem/legacy', 'dex', 600, {
    source_report: 'runtime/bound-source.json', raw_evidence: 'bound.code',
  })]
  assert.match(fileScanLabel(observations, { relativePath: 'runtime/bound.code' }), /未扫描尾部 600 B/)
  for (const relativePath of ['bound.code', 'apk-dex/bound.code']) {
    assert.match(fileScanLabel(observations, { relativePath }), /^来源未知/)
  }
  assert.match(fileScanLabel([{ ...observations[0], source_report: 'bound-source.json' }], { relativePath: 'bound.code' }), /未扫描尾部 600 B/)
})

test('an exact path with a conflicting retained hash cannot suppress matching object sources', () => {
  const observations = [
    scanObservation('/mem/stale', 'other', 0, { relative_path: 'runtime/bound.code', read: { sha256: 'stale-range' } }),
    scanObservation('/mem/target', 'expected', 600, { relative_path: 'runtime/target.code' }),
  ]
  for (const file of [
    { relativePath: 'runtime/bound.code', sha256: 'expected' },
    { relativePath: 'runtime/bound.code', code_evidence: [{ sha256: 'expected' }] },
  ]) {
    const label = fileScanLabel(observations, file)
    assert.match(label, /\/mem\/target.*未扫描尾部 600 B/)
    assert.doesNotMatch(label, /\/mem\/stale|停止 complete/)
    assert.match(fileScanLabel([observations[0]], file), /^来源未知/)
  }
})

test('container hashes and derived object hashes are different identities', () => {
  const observation = scanObservation('/mem/container', 'derived-dex', 600, {
    relative_path: 'runtime/bound.code', read: { sha256: 'container' },
  })
  assert.match(fileScanLabel([observation], { relativePath: 'runtime/bound.code', sha256: 'container' }), /未扫描尾部 600 B/)
  assert.match(fileScanLabel([observation], { relativePath: 'apk-dex/repaired.dex', codeEvidence: [{ sha256: 'repaired', raw_member_sha256: 'derived-dex' }] }), /未扫描尾部 600 B/)
})

test('unknown source evidence stays unknown without a path or SHA association', () => {
  for (const observations of [undefined, null, {}, [], [null, 'invalid', {}], [scanObservation('/other/classes.dex', 'other', 0)]]) {
    const label = fileScanLabel(observations, { relativePath: 'apk-dex/classes.dex' })
    assert.match(label, /^来源未知/)
    assert.match(label, /停止 未知 · 未扫描尾部 未知/)
    assert.doesNotMatch(label, /停止 complete|未扫描尾部 0 B/)
  }
})

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
 const source={kind:'runtime',row_index:0,source_report:'window',range_sha256:'a'.repeat(64),source:identity}
 const object={sha256:'object',bytes:10,sources:[source]}
 const row={source_report:'window',read:{sha256:'a'.repeat(64)},source:identity,object_inspection:{derived_objects:[{sha256:'object',length:10,class_index:{classes:Array.from({length:8201},(_,i)=>`Lpkg/Class${i};`)}}]}}
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'').total,8201)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'').classes.length,500)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'').omitted,7701)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'Class8200;').total,1)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'Class8200;').classes.length,1)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'Class8200;').omitted,0)
 assert.equal(runtimeDexClassMatches({runtime_observations:[{...row,source:{...identity,pid:99}}]},object,'').total,null)
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


test('forty logical objects drive the same headline and independent list, preserving diagnostic rows', () => {
 const objects = Array.from({length:40},(_,i)=>({sha256:i.toString(16).padStart(64,'0'),bytes:i+1,sources:[],classes:[],validation_status:'unknown'}))
 const dump={content_dex_class_index:{objects},dex_sets:[objects[0]]}
 assert.equal(indexedDexCount(dump),40)
 assert.equal(projectDexEvidence(dump).objects.length,40)
 assert.equal(dexObjectGroups(projectDexEvidence(dump).objects).find(x=>x.kind==='diagnostic').objects.length,40)
 for(const object of objects)assert.equal(runtimeDexClassMatches({},object,'unmatched').total,0)
})
test('producer sets still render when the local content index is absent or empty', () => {
 const set={sha256:'b'.repeat(64),bytes:50,canonical_relative_path:'runtime/bound-one.code',semantic:{class_defs:3,class_descriptors:['Llegacy/One;'],class_descriptors_truncated:true}}
 for(const content of [undefined,{objects:[]}]) {
  const dump={dex_sets:[set],content_dex_class_index:content}
  const projected=projectDexEvidence(dump)
  assert.equal(projected.objects.length,1);assert.equal(indexedDexCount(dump),1)
  assert.match(projected.objects[0].class_index_status,/truncated/)
  assert.match(projected.objects[0].validation_status,/unknown/)
  assert.equal(projected.objects[0].ownership,'unknown')
 }
 assert.equal(projectDexEvidence({readable_dex:40}).status,'reported_count_only')
 assert.equal(projectDexEvidence({readable_dex:40}).objects.length,0)
})
test('physical DEX relationships use the selected report and never every bound container', () => {
 const file=relativePath=>({relativePath,bytes:100})
 const report={artifacts:[{kind:'dex',relative_path:'runtime/bound-dex.code'}],dex_sets:[{sha256:'c'.repeat(64),bytes:5,canonical_relative_path:'runtime/another-dex.code'}]}
 assert.equal(matchesReadableDexEvidence(file('readable-dex/classes.dex'),report),true)
 assert.equal(matchesReadableDexEvidence(file('runtime/bound-dex.code'),report),true)
 assert.equal(matchesReadableDexEvidence(file('runtime/another-dex.code'),report),true)
 assert.equal(matchesReadableDexEvidence(file('runtime/bound-elf.code'),report),false)
 assert.equal(matchesReadableDexEvidence(file('runtime/bound-dex.code'),{}),false)
 assert.equal(matchesReadableDexEvidence(file('runtime/mem-only.bin'),{}),false)
 assert.equal(matchesReadableDexEvidence(file('readable-dex/note.json'),{}),false)
 const note={relative_path:'runtime/by-note.code',local_content_status:'complete_range_hash_verified',object_inspection:{derived_objects:[{kind:'dex',sha256:'d'.repeat(64),length:5}]}}
 assert.equal(matchesReadableDexEvidence({...file(note.relative_path),codeEvidence:[note]},{}),true)
 assert.equal(matchesReadableDexEvidence({...file('runtime/wrong.code'),codeEvidence:[note]},{}),false)
 assert.equal(matchesReadableDexEvidence({...file(note.relative_path),codeEvidence:[{...note,local_content_status:'unknown'}]},{}),false)
})
test('qualified independent sources and reordered rows remain searchable without PID or basename fallback', () => {
 const identity={package:'com.pkg',pid:1,birth_ns:2,uid:3,exec_id:4,boot_id:'boot'}
 const source={kind:'runtime',row_index:0,source_report:'runtime/report.json',range_sha256:'e'.repeat(64),source:identity,source_offset:10}
 const object={sha256:'f'.repeat(64),bytes:10,sources:[{...source,source_report:'stale'},source]}
 const row={source_report:source.source_report,read:{sha256:source.range_sha256,actual_length:100},source:identity,object_inspection:{derived_objects:[{sha256:object.sha256,length:10,source_offset:10,class_index:{classes:['Lexact/Found;']}}]}}
 const result=runtimeDexClassMatches({runtime_observations:[{},row]},object,'Found')
 assert.equal(result.status,'indexed');assert.equal(result.total,1)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},object,'absent').total,0)
 assert.equal(runtimeDexClassMatches({runtime_observations:[{...row,source:{...identity,exec_id:99}}]},object,'').status,'unlinked')
 assert.equal(runtimeDexClassMatches({runtime_observations:[{...row,source:{...identity,exec_id:99}}]},object,'').total,null)
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},{...object,sources:[{...source,source:{pid:1}}]},'').status,'unknown')
 assert.equal(runtimeDexClassMatches({runtime_observations:[row]},{...object,sources:[{...source,source_offset:90}]},'').total,null)
})
test('real class paging reaches the tail and a new query resets its own window', () => {
 const object={classes:Array.from({length:8201},(_,i)=>`Lpkg/Class${i};`)}
 const first=runtimeDexClassMatches({},object,'')
 assert.equal(first.total,8201);assert.equal(first.classes.length,500);assert.equal(first.nextOffset,500)
 const tail=runtimeDexClassMatches({},object,'',8000)
 assert.equal(tail.offset,8000);assert.equal(tail.classes.length,201);assert.equal(tail.nextOffset,null)
 const search=runtimeDexClassMatches({},object,'Class8200;')
 assert.deepEqual(search.classes,['Lpkg/Class8200;']);assert.equal(search.total,1)
})
test('malformed object and class/source fields stay unknown without rendering crashes', () => {
 const projection=projectDexEvidence({content_dex_class_index:{objects:[null,{sha256:'a'.repeat(64),bytes:1,sources:null,classes:['ok',null]}]},dex_sets:{}})
 assert.equal(projection.objects.length,1);assert.ok(projection.warnings.length)
 assert.equal(runtimeDexClassMatches({},projection.objects[0],'').status,'unknown')
 assert.equal(runtimeDexClassMatches({},null,'').total,null)
 assert.equal(projectDexEvidence({}).status,'unknown')
 assert.equal(projectDexEvidence({content_dex_class_index:{objects:[]}}).status,'empty')
})
