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

const { captureGroupCanTrash, captureGroupImportIsTrashed } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
test('failed, successful, partial and interrupted parents may be removed after collection stops', () => {
 for (const state of ['failed','succeeded','partial','interrupted','cancelled','planned']) {
  const g = {...group('parent-a',1,['child-a']), state}
  assert.equal(captureGroupCanTrash(g),true)
  assert.equal(captureGroupCanTrash(g,'parent-a'),false)
  assert.equal(captureGroupCanTrash(g,'',true),false)
 }
})
test('running attempts stay protected even with stale terminal summary or cancellation requested', () => {
 const g = {...group('parent-a',1,[]), state:'failed',cancelRequested:true,stages:[{attempts:[{state:'running'}]}]}
 assert.equal(captureGroupCanTrash(g),false)
 assert.equal(captureGroupCanTrash({...g,state:'running',stages:[]}),false)
})
test('import trash is exact parent, serial, package and source root rather than package-wide', () => {
 const g = {...group('parent-a',1,['child-a']),serial:'device-a'}
 const trash = [{group:g,managed:false,importedRoots:['/evidence/capture-a']}]
 assert.equal(captureGroupImportIsTrashed(g,'/evidence/capture-a',trash),true)
 assert.equal(captureGroupImportIsTrashed(g,'/evidence/other-copy',trash),false)
 for (const field of ['id','serial','package']) assert.equal(captureGroupImportIsTrashed({...g,[field]:'different'},'/evidence/capture-a',trash),false)
})
test('trashed parent references continue to suppress children from the legacy delete list', () => {
 const current = group('parent-a',1,['child-new'])
 const archived = group('parent-a',1,['child-old','child-new'])
 const neighbor = group('parent-b',2,['child-b'])
 const known = groupSessionIds([current, archived, neighbor])
 assert.deepEqual(['child-old','child-new','child-b','legacy'].filter(id=>!known.has(id)),['legacy'])
 assert.equal(archived.stages[0].attempts.length,2)
})
test('UI loads local parents independently of device handshake and exposes a recoverable confirmation', () => {
 const vue = readFileSync(new URL('../src/views/AndroidRuntimeMonitorView.vue',import.meta.url),'utf8')
 const remote = vue.slice(vue.indexOf('async function loadKernSight()'),vue.indexOf('async function importLocalEvidence()'))
 assert.match(remote,/void loadLocalCaptureGroups\(\)/)
 assert.doesNotMatch(remote,/captureGroups\.value\s*=/)
 assert.match(vue,/确认移入回收站/)
 assert.match(vue,/恢复主会话/)
 assert.match(vue,/不会释放设备或本地空间/)
})

test('legacy rows require loaded ownership and expose viewing without destructive cleanup', () => {
 const vue = readFileSync(new URL('../src/views/AndroidRuntimeMonitorView.vue',import.meta.url),'utf8')
 assert.match(vue,/const legacyDeviceSessions=computed\(\(\)=>localOwnershipConfirmed.value \?/)
 assert.match(vue,/仅支持查看，清理不可用/)
 assert.match(vue,/缺少父会话归属，需先核对所有权；不会执行删除/)
 assert.doesNotMatch(vue,/confirmDeleteDeviceSession|armDeleteDeviceSession|cleanupKernSightSession/)
 assert.match(vue,/@click="loadSessionReport\(session.session_id\)"/)
 const load = vue.slice(vue.indexOf('async function loadLocalCaptureGroups('),vue.indexOf('function canTrashCaptureGroup('))
 assert.match(load,/localOwnershipConfirmed.value = false/)
 assert.match(load,/localOwnershipConfirmed.value = true/)
})

test('restored import marker no longer hides sources while retaining child ownership', () => {
 const g = {...group('parent-a',1,['child-a']),serial:'device-a'}
 const restored = {group:g,managed:true,trashed:false,importedRoots:['/evidence/a'],retainedSessionIds:['child-a','imported-extra']}
 assert.equal(captureGroupImportIsTrashed(g,'/evidence/a',[restored]),false)
 const known = new Set([...groupSessionIds([g]), ...restored.retainedSessionIds])
 assert.ok(known.has('imported-extra'))
})

test('package evidence preserves open and pull while retiring unowned package-wide cleanup',()=>{
 const vue=readFileSync(new URL('../src/views/AndroidRuntimeMonitorView.vue',import.meta.url),'utf8')
 assert.match(vue,/整包清理不可用：包名不足以确认父会话归属/)
 assert.match(vue,/@click="pullSelectedPackageEvidence\(\)"/)
 assert.match(vue,/@click="selectPackage\(dump.package\)"/)
 assert.doesNotMatch(vue,/confirmDeleteCurrentPackageEvidence|cleanupKernSightPackageDump/)
 const backend=readFileSync(new URL('../src/services/backend/monitoring.ts',import.meta.url),'utf8')
 assert.doesNotMatch(backend,/cleanup_kernsight_session|cleanup_kernsight_package_dump/)
})
