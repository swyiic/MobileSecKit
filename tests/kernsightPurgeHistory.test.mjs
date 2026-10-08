import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('../src/services/kernsightPurgeHistory.ts', import.meta.url), 'utf8')
const code = ts.transpileModule(source, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText
const {purgeHistoryKey, updateHiddenPurgeKeys} = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
const report=Object.freeze({id:'journal-a',updatedUnixMs:1,state:'partial',localState:'completed',deviceState:'pending'})
test('partial history hides reversibly without changing cleanup state; update resurfaces',()=>{
 const keys=updateHiddenPurgeKeys([],report,true)
 assert.equal(keys.includes(purgeHistoryKey(report)),true)
 assert.equal(report.deviceState,'pending')
 assert.equal(keys.includes(purgeHistoryKey({...report,updatedUnixMs:2})),false)
 assert.equal(keys.includes(purgeHistoryKey({...report,deviceState:'completed'})),false)
 assert.deepEqual(updateHiddenPurgeKeys(keys,report,false),[])
})
test('running records cannot hide and retained preference count is bounded',()=>{
 assert.deepEqual(updateHiddenPurgeKeys([],{...report,state:'running'},true),[])
 assert.equal(updateHiddenPurgeKeys(Array.from({length:1100},(_,i)=>'key'+i),report,true).length,1024)
 assert.equal(updateHiddenPurgeKeys([purgeHistoryKey(report)],report,true).length,1)
})
