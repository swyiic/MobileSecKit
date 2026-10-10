import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'
import { build } from 'esbuild'
import { parse, compileScript } from '@vue/compiler-sfc'
import { createRenderer, nextTick } from 'vue'

// Exercise the actual Vue component with an in-memory renderer. All device, dialog,
// filesystem and clipboard operations are mocked. This does not verify browser geometry.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const require = createRequire(import.meta.url)
const vueUrl = pathToFileURL(require.resolve('vue/dist/vue.runtime.esm-bundler.js')).href
const compiled = await build({
  entryPoints: [resolve(root, 'src/views/AndroidRuntimeMonitorView.vue')],
  bundle: true, write: false, format: 'esm', platform: 'node', external: ['vue'],
  alias: { '@': resolve(root, 'src') },
  plugins: [{name:'mocked-vue-components', setup(b) {
    b.onResolve({filter: /(?:^|\/)services\/backend$/}, () => ({path:'backend',namespace:'test-mock'}))
    b.onResolve({filter: /^@tauri-apps\//}, args => ({path:args.path,namespace:'test-mock'}))
    b.onLoad({filter: /.*/,namespace:'test-mock'}, args => ({contents: args.path==='backend'
      ? 'export const monitoringBackend = globalThis.__runtimeFeedbackBackend; export function readableError(error) { return String(error?.message || error) }'
      : args.path.endsWith('/event') ? 'export async function listen(){return ()=>{}}'
      : 'export async function open(args){return globalThis.__runtimeFeedbackDialog(args)}; export async function save(args){return globalThis.__runtimeFeedbackDialog(args)}',loader:'js'}))
    b.onLoad({filter: /\.vue$/}, args => {
      const {descriptor}=parse(readFileSync(args.path,'utf8'),{filename:args.path})
      return {contents:compileScript(descriptor,{id:args.path,inlineTemplate:true}).content,loader:'ts',resolveDir:dirname(args.path)}
    })
  }}],
})

const node=(tag,text='')=>({tag,text,props:{},children:[],parent:null})
const tree=node('root')
const descendants=(n)=>[n,...n.children.flatMap(descendants)]
const text=(n)=>n.text+n.children.map(text).join('')
const find=(predicate,base=tree)=>descendants(base).find(predicate)
const all=(predicate,base=tree)=>descendants(base).filter(predicate)
const hasClass=(n,name)=>String(n.props.class||'').split(/\s+/).includes(name)
const renderer=createRenderer({
  createElement:tag=>node(tag), createText:value=>node('#text',value), createComment:value=>node('#comment',value),
  setText:(n,value)=>{n.text=value}, setElementText:(n,value)=>{n.text=value;n.children=[]},
  parentNode:n=>n.parent, nextSibling:n=>n.parent?.children[n.parent.children.indexOf(n)+1]||null,
  querySelector:selector=>selector==='body'?tree:find(n=>n.props.id===selector.slice(1)),
  patchProp:(n,key,previous,value)=>{n.props[key]=value},
  insert(n,parent,anchor=null){if(n.parent){n.parent.children.splice(n.parent.children.indexOf(n),1)};n.parent=parent;const i=anchor?parent.children.indexOf(anchor):-1;if(i<0)parent.children.push(n);else parent.children.splice(i,0,n)},
  remove(n){if(n.parent){n.parent.children.splice(n.parent.children.indexOf(n),1);n.parent=null}},
})
globalThis.document={getElementById:id=>find(n=>n.props.id===id)}
globalThis.window={setTimeout,clearTimeout}
globalThis.localStorage={getItem:()=>null,setItem:()=>{}}
const backendCalls=[]
let readMode='success', resolvePending
const group=(id)=>({schema:'mobilee.capture-group/v1',id,serial:'mock-only-no-device',package:'org.example.app',createdUnixMs:1791500000000,state:'partial',cancelRequested:false,unified:false,base:{},budget:{limits:{maxSeconds:900,totalBytes:8589934592},reservations:[],timePlan:{schema:'mobilee.session-time-plan/v4',phases:[{kind:'l0',capMs:25000},{kind:'l1',capMs:105000},{kind:'linker',capMs:25000},{kind:'dump',capMs:245000},{kind:'transfer',capMs:255000},{kind:'archive',capMs:120000},{kind:'import',capMs:120000},{kind:'terminal',capMs:5000}]}},stages:[{id:`stage-${id}`,key:'l1',mode:'tls',durationSeconds:90,launchAfterAttach:false,required:true,attempts:[{relation:{parentId:id,stageId:`stage-${id}`,attemptId:`attempt-${id}`,attempt:1,stageKey:'l1'},state:'partial',startedUnixMs:1791500000000,finishedUnixMs:1791500090000,sessionId:`session-${id}`,error:'real loss preserved'}]}]})
const groups=[group('parent-a'),group('parent-b')]
groups[1].budget.timePlan={schema:'mobilee.session-time-plan/v5',captureMaxMs:400000,l2MaxMs:245000,captureStopAtParentRemainingMs:500000,phases:[{kind:'transfer',capMs:255000,startedUnixMs:1791500100000,finishedUnixMs:1791500112500,elapsedMs:12500,completed:true},{kind:'archive',capMs:120000,completed:false},{kind:'import',capMs:120000,startedUnixMs:1791500112500,completed:false}]}
const report=id=>({sessionId:`session-${id}`,reportSchema:'fixture',report:{session_id:`session-${id}`,execution_complete:true,mode_counts:{observe:5,inspect:2},quality:{lost_records:17},processes:[],limitations:['fixture coverage remains partial']}})
globalThis.__runtimeFeedbackBackend=new Proxy({
  listKernSightGroups:async()=>groups,
  listKernSightGroupTrash:async()=>[],listKernSightGroupPurges:async()=>[],
  kernSightGroupSessionReport:async(id)=>{backendCalls.push(id);if(readMode==='pending')return new Promise(r=>{resolvePending=()=>r(report(id))});if(readMode==='error')throw new Error('fixture report unavailable');return report(id)},
}, {get(target,key){return target[key] || (()=>{throw new Error(`Unexpected backend call: ${String(key)}`)})}})
let dialogError='fixture directory unavailable'
globalThis.__runtimeFeedbackDialog=async()=>{throw new Error(dialogError)}
const {default:RuntimeView}=await import(`data:text/javascript;base64,${Buffer.from(compiled.outputFiles[0].text.replaceAll('from "vue"',`from "${vueUrl}"`)).toString('base64')}`)
const app=renderer.createApp(RuntimeView,{active:false,details:null})
const warnings=[];app.config.warnHandler=m=>warnings.push(m)
app.mount(tree)
async function settle(){for(let i=0;i<5;i++){await Promise.resolve();await nextTick()}}
const click=async(n)=>{assert.ok(n,'expected rendered control');await n.props.onClick?.({preventDefault(){},stopPropagation(){}});await settle()}
const row=id=>find(n=>hasClass(n,'ks-capture-group')&&text(n).includes(id==='parent-a'?'parent-a':'parent-b'))
const summary=id=>row(id).children.find(n=>n.tag==='summary')
const childButton=id=>find(n=>n.tag==='button'&&n.props['aria-controls']===`ks-child-${id}-attempt-${id}`,row(id))
await settle()

test('operation failure stays below its own import button and dismissal does not hide the next failure',async()=>{
  const directory=()=>find(n=>n.tag==='button'&&text(n).includes('导入本地证据'))
  const archive=()=>find(n=>n.tag==='button'&&text(n).includes('打开证据'))
  await click(directory())
  let error=find(n=>hasClass(n,'operation-error'))
  assert.equal(error.parent,directory().parent)
  assert.notEqual(error.parent,archive().parent)
  assert.match(text(error),/fixture directory unavailable/)
  await click(find(n=>n.tag==='button'&&n.props['aria-label']==='关闭本次操作错误',error))
  assert.equal(all(n=>hasClass(n,'operation-error')).length,0)
  dialogError='fixture archive unavailable';await click(archive())
  error=find(n=>hasClass(n,'operation-error'));assert.equal(error.parent,archive().parent);assert.match(text(error),/fixture archive unavailable/)
  await click(find(n=>n.tag==='button'&&n.props['aria-label']==='关闭本次操作错误',error))
})

test('child evidence renders immediately inside its attempt and toggles closed',async()=>{
  await click(summary('parent-a'));await click(childButton('parent-a'))
  const details=find(n=>hasClass(n,'ks-inline-session-detail'))
  assert.equal(details.parent.props.id,'ks-child-parent-a-attempt-parent-a')
  assert.ok(hasClass(details.parent.parent,'ks-stage-attempt'))
  assert.match(text(details),/丢失 17/)
  assert.equal(childButton('parent-a').props['aria-expanded'],true)
  await click(childButton('parent-a'))
  assert.equal(all(n=>hasClass(n,'ks-inline-session-detail')).length,0)
})

test('switching sessions removes old report and nested details; old responses cannot reopen',async()=>{
  await click(childButton('parent-a'));await click(summary('parent-b'))
  assert.equal(all(n=>hasClass(n,'ks-inline-session-detail')).length,0)
  assert.equal(all(n=>hasClass(n,'ks-group-information'),row('parent-a')).length,0)
  readMode='pending'
  const pending=childButton('parent-b').props.onClick({preventDefault(){},stopPropagation(){}})
  await settle();assert.equal(all(n=>hasClass(n,'ks-inline-session-detail')).length,1)
  await click(summary('parent-a'));resolvePending();await pending;await settle()
  assert.equal(all(n=>hasClass(n,'ks-inline-session-detail')).length,0)
  readMode='success'
})

test('stored time plan is shown separately from observed windows and elapsed stage execution',async()=>{
  const ledger=find(n=>hasClass(n,'ks-time-ledger'),row('parent-a'))
  assert.match(text(ledger),/mobilee.session-time-plan\/v4/)
  assert.match(text(ledger),/L2 快照配置上限 245s/)
  assert.match(text(ledger),/保存传输配置上限 255s/)
  assert.match(text(ledger),/L1 90s = 90s/)
  assert.match(text(ledger),/记录时间间隔/);assert.match(text(ledger),/实际耗时见上方阶段计时/);assert.match(find(n=>n.tag==='strong'&&text(n).includes('记录时间间隔'),ledger).props.title,/系统时钟调整会影响/);
  assert.match(text(ledger),/第 1 次90s/)
  assert.match(text(ledger),/实际耗时未知（原记录无字段）/)
})

test('v5 recorded actual timing stays distinct from caps and not-started or running phases',async()=>{
  await click(summary('parent-b'))
  const ledger=find(n=>hasClass(n,'ks-time-ledger'),row('parent-b'))
  assert.match(text(ledger),/总采集上限 400s/)
  assert.match(text(ledger),/保存传输配置上限 255s实际耗时 12.5s/)
  assert.match(text(ledger),/归档配置上限 120s尚未开始/)
  assert.match(text(ledger),/导入配置上限 120s计时中/)
  const technical=find(n=>hasClass(n,'ks-group-technical'),row('parent-b'))
  assert.match(text(technical),/本主会话尚未导入本地技术证据/)
  const idCopy=find(n=>n.tag==='button'&&n.props['aria-label']==='复制完整主会话 ID',row('parent-b'))
  assert.match(idCopy.props.title,/parent-b/)
  assert.equal(text(childButton('parent-b')),'展开子证据')
  await click(summary('parent-a'))
})

test('child read failure remains by its button and preserved loss is never converted to complete coverage',async()=>{
  readMode='error';await click(childButton('parent-a'))
  const error=find(n=>hasClass(n,'operation-error'),row('parent-a'))
  assert.ok(hasClass(error.parent,'ks-stage-attempt'))
  assert.match(text(error),/fixture report unavailable/)
  assert.match(text(row('parent-a')),/real loss preserved/)
  assert.equal(all(n=>hasClass(n,'ks-inline-session-detail')).length,0)
  readMode='success'
  assert.equal(warnings.length,0,warnings.join('\n'))
  assert.deepEqual([...new Set(backendCalls)],['parent-a','parent-b'])
  app.unmount()
})
