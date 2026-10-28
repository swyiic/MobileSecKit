import { launchMe } from './mockedMeHarness.mjs'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
const out = process.env.ME_DELETE_QA_OUTPUT || '/tmp/me-delete-qa'
mkdirSync(out,{recursive:true})
const id='11111111-1111-4111-8111-111111111111', neighbor='22222222-2222-4222-8222-222222222222'
const group=id=>({schema:'mobilee.capture-group/v1',id,serial:'mock-only-no-device',package:'org.example.cleanup',createdUnixMs:1791350000000,cancelRequested:false,state:'failed',unified:false,base:{},stages:[{id:'stage-a',key:'l0',mode:'none',durationSeconds:15,launchAfterAttach:true,required:true,attempts:[]}]})
let trash=[], finish, rejectDelete=false
const groups=[group(id),group(neighbor)]
const h=await launchMe({handler:async(command,args)=>{
 if(command==='list_kernsight_groups')return groups
 if(command==='list_kernsight_group_trash')return trash
 if(command==='list_kernsight_group_purges')return []
 if(command==='delete_kernsight_group'){
  if(rejectDelete)throw new Error('fixture deletion not accepted')
  const entry={schema:'mobilee.capture-group-trash/v1',group:groups.find(g=>g.id===args.parentId),trashedUnixMs:Date.now(),managed:true,trashed:true,retainedSessionIds:[],importedRoots:[],deletion:{localDone:false,deviceDone:false,error:'设备离线，待重试'}}
  return await new Promise(resolve=>{finish=()=>{trash=[entry];resolve(entry)}})
 }
}})
const {page,calls,errors,close}=h
const row=id=>page.locator('.ks-capture-group').filter({has:page.locator(':scope > summary').filter({hasText:id.slice(0,8)})})
try {
 await page.getByRole('button',{name:/KernSight.*采集、会话/}).click()
 await row(id).locator(':scope > summary').click()
 const before=Date.now()
 await row(id).getByRole('button',{name:'删除会话及全部子会话',exact:true}).click()
 await row(id).waitFor({state:'detached',timeout:1000})
 const disappearMs=Date.now()-before
 assert.ok(disappearMs<1000)
 assert.equal(await row(neighbor).count(),1)
 assert.equal(await page.getByRole('dialog').count(),0)
 assert.equal(calls.filter(c=>c.command==='delete_kernsight_group').length,1)
 finish()
 await page.getByText(/手机文件。/).waitFor()
 await page.getByRole('button',{name:'刷新本地记录',exact:true}).click()
 await page.waitForTimeout(200)
 assert.equal(await row(id).count(),0)
 assert.match(await page.locator('.ks-session-panel').innerText(),/手机待清理/)
 await page.screenshot({path:out+'/pending.png'})
 // Persisted deletion survives a complete reload; sibling remains operable.
 await page.reload({waitUntil:'networkidle'})
 if(!await page.locator('.ks-session-panel').isVisible())await page.getByRole('button',{name:/KernSight.*采集、会话/}).click()
 assert.equal(await row(id).count(),0)
 rejectDelete=true
 await row(neighbor).locator(':scope > summary').click()
 await row(neighbor).getByRole('button',{name:'删除会话及全部子会话',exact:true}).click()
 await page.getByText(/删除未受理/).waitFor()
 assert.equal(await row(neighbor).count(),1)
 trash[0].deletion={localDone:true,deviceDone:true,error:null}
 await page.getByText('会话及全部子会话的本地与手机文件已清理完成。',{exact:true}).waitFor()
 assert.equal(errors.length,0,JSON.stringify(errors))
 assert.equal(calls.filter(c=>c.command==='prepare_kernsight_group_purge').length,0)
 writeFileSync(out+'/result.json',JSON.stringify({passed:true,disappearMs,tests:['single click hides family before IPC completion','no preview or second confirmation','durable hidden family after reload','pending physical work shown','failed enqueue restores row','neighbor preserved','completion displayed'],note:'Browser IPC fixture; physical device test recorded separately'},null,2))
 console.log('PASS one-click deletion UI',disappearMs+'ms')
} finally { await close() }
