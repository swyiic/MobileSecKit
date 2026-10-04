import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source=readFileSync(new URL('../src/services/kernsightCodeEvidence.ts',import.meta.url),'utf8')
const js=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext}}).outputText
const {codeEvidenceLabel,allocatedEvidenceLabel,ownershipEvidenceEntries}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
test('legacy code has no invented source or success',()=>{assert.equal(codeEvidenceLabel(), '');assert.equal(codeEvidenceLabel([{}]),'代码来源未知')})
test('member provenance is distinct from verified retained bytes and business ownership',()=>{const label=codeEvidenceLabel([{schema:'kernsight.apk-member-evidence/v1',source:{zip_member:'classes.dex',apk_sha256:'a'.repeat(64)},transformation:'repair_dex/v1',local_content_status:'complete_file_hash_verified',ownership:{category:'mixed',reasons:['1 SDK + 99 app']}}]);assert.match(label,/classes.dex.*repair_dex.*保留文件完整 hash 已核对.*混合/);assert.match(label,/APK 原成员未在本地重解包核对/)})

test('bounded legacy missing read fields remains unknown',()=>{assert.match(codeEvidenceLabel([{schema:'kernsight.bounded-code-range/v1',read:{read_status:'complete'},retained_bytes:1}]),/读取状态未知/);assert.match(codeEvidenceLabel([{schema:'kernsight.bounded-code-range/v1',read:{read_status:'short_read'}}]),/读取状态未知/)})

test('bounded complete needs numeric source range and admission relationship',()=>{assert.match(codeEvidenceLabel([{schema:'kernsight.bounded-code-range/v1',read:{schema:'kernsight.memory-read/v1',requested_bytes:1,actual_bytes:1,read_status:'complete',read_error:null}}]),/读取状态未知/)})

test('missing or non-Unix allocation remains unknown, measured zero is valid',()=>{assert.equal(allocatedEvidenceLabel(undefined),'未知');assert.equal(allocatedEvidenceLabel(null),'未知');assert.equal(allocatedEvidenceLabel(0),'0 B')})

test('old ownership is unknown without overwriting its original data',()=>{const old=[{category:'business',confidence:100}];const result=ownershipEvidenceEntries('mobilee.kernsight-dex-ownership/v3',old);assert.equal(result[0].category,'unknown');assert.equal(result[0].confidence,0);assert.equal(old[0].category,'business')})
test('rebuilt v4 ownership keeps its classification basis',()=>{const entries=[{category:'mixed',confidence:75,reasons:['99 app + 1 SDK']}];assert.deepEqual(ownershipEvidenceEntries('mobilee.kernsight-dex-ownership/v4',entries),entries)})
