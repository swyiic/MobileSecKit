import assert from 'node:assert/strict'
import test from 'node:test'
import {readFileSync} from 'node:fs'
import ts from 'typescript'
const code=ts.transpileModule(readFileSync(new URL('../src/services/kernsightCaptureGroups.ts',import.meta.url),'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText
const {mergeCaptureGroups,groupSessionIds,sameImportedCapture}=await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
const group=(id,time,sessions)=>({id,package:'org.example.fixture',createdUnixMs:time,stages:[{attempts:sessions.map(sessionId=>({sessionId}))}]})
test('same package captures remain two parent rows and disjoint children',()=>{
 const a=group('parent-a',1,['a-1','a-2']),b=group('parent-b',2,['b-1'])
 const rows=mergeCaptureGroups([a,b],[]);assert.equal(rows.length,2);assert.deepEqual(rows.map(g=>g.id),['parent-b','parent-a']);assert.deepEqual([...groupSessionIds([a])],['a-1','a-2']);assert.ok(!groupSessionIds([a]).has('b-1'))
})
test('duplicate import and shared session references count once',()=>{
 const a=group('parent-a',1,['a-1','a-1',null]);assert.equal(mergeCaptureGroups([a],[a,a]).length,1);assert.equal(groupSessionIds([a]).size,1)
})
test('same package is never import identity and legacy does not gain parent',()=>{
 const bundle=(root,id,dump)=>({root,package:'org.example.fixture',sessionReport:id?{mobilee_capture_group:{id}}:{},dumpReport:{dump_id:dump}})
 assert.equal(sameImportedCapture(bundle('a','pa','dump-a'),bundle('b','pb','dump-b')),false)
 assert.equal(sameImportedCapture(bundle('a','pa','dump-a'),bundle('b','pa','dump-a')),true)
 assert.equal(sameImportedCapture(bundle('a',null,'dump-a'),bundle('b',null,'dump-a')),false)
 assert.equal(sameImportedCapture(bundle('a','pa','dump-a'),bundle('b','pa','dump-new')),false)
})
