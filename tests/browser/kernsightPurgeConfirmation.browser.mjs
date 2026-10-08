import { launchMe } from './mockedMeHarness.mjs'
import assert from 'node:assert/strict'
import { mkdirSync, writeFileSync } from 'node:fs'
const output = process.env.ME_PURGE_QA_OUTPUT || '/tmp/me-purge-confirmation'
mkdirSync(output, { recursive: true })
let mode = 'ready', pending = [], count = 0, executions = 0
const makePlan = (args) => {
 const now = Date.now()
 return {id:`fixture-plan-${++count}`,parentId:args.parentId,serial:'fixture-serial',package:'fixture.package',createdUnixMs:now,expiresUnixMs:now+300000,confirmationToken:`nonce-${count}`,localOnly:false,localEntries:[],warnings:[],device:{status:mode === 'offline' ? 'offline' : mode === 'not-required' ? 'not_required' : 'ready',entries:[],warnings:mode === 'offline' ? ['fixture offline reason'] : []},...(mode === 'expired' ? {createdUnixMs:now-300001,expiresUnixMs:now-1} : {}),...(mode === 'empty-token' ? {confirmationToken:''} : {})}
}
const harness = await launchMe({url:'http://127.0.0.1:1420/tests/browser/purgeConfirmationFixture.html',handler:async(command,args)=>{
 if(command === 'prepare_kernsight_group_purge' || command === 'prepare_kernsight_group_purge_retry') {
  if(mode === 'prepare-error') throw new Error('device inspect 超过120秒；未执行删除')
  const p=makePlan({parentId:args.parentId || 'fixture-parent'})
  if(mode === 'pending') return await new Promise(resolve => pending.push(()=>resolve(p)))
  return p
 }
 if(command === 'execute_kernsight_group_purge') { executions++; return {id:args.planId,parentId:'fixture-parent',serial:'fixture-serial',package:'fixture.package',state:mode === 'partial'?'partial':'completed',localState:mode === 'partial'?'pending':'completed',deviceState:mode === 'partial'?'failed':'completed',warnings:[],error:mode === 'partial'?'fixture device failure':null} }
}})
const {page,calls,errors,close}=harness
const yes=()=>page.locator('.danger-button')
const retry=()=>page.getByRole('button',{name:'重新核对并重试',exact:true})
const reason=()=>page.getByTestId('purge-block-reason')
const checks=[]
const record=name=>{checks.push(name);console.log('PASS '+name)}
const waitReady=async()=>{await page.waitForFunction(()=>!document.querySelector('.danger-button').disabled)}
async function setState(value){await page.evaluate(v=>Object.assign(window.__purgeState,v),value)}
async function refresh(nextMode){mode=nextMode;await retry().click();await page.waitForTimeout(100)}
try {
 await waitReady();assert.equal(executions,0);assert.equal(await page.getByRole('checkbox').count(),0);record('ready plan automatically enables one yes without scope input or deletion')
 await refresh('not-required');await waitReady();record('not-required safe device scope enables confirmation')
 await refresh('empty-token');assert.equal(await yes().isDisabled(),true);assert.match(await reason().innerText(),/凭证/);assert.equal(await retry().isEnabled(),true);record('silent false token failure now explains and allows recheck')
 await refresh('expired');assert.equal(await yes().isDisabled(),true);assert.match(await reason().innerText(),/失效/);record('expired refuses deletion with nearby reason')
 await refresh('offline');assert.equal(await yes().isDisabled(),true);assert.match(await reason().innerText(),/fixture offline reason/);assert.equal(executions,0);record('offline reason visible and retry enabled without local-only bypass');await page.screenshot({path:output+'/offline-reason.png'})
 await refresh('prepare-error');assert.equal(await yes().isDisabled(),true);assert.match(await page.getByRole('alert').innerText(),/超过120秒/);assert.equal(await retry().isEnabled(),true);assert.equal(await page.getByRole('button',{name:'正在核对…',exact:true}).count(),0);record('backend timeout stops preparing and retains retry beside exact error')
 mode='ready';await setState({busy:true});assert.equal(await yes().isDisabled(),true);assert.match(await reason().innerText(),/尚未结束/);await setState({busy:false});await waitReady();record('busy transition invalidates scope then automatically prepares after idle')
 mode='pending';await retry().click();await page.waitForTimeout(50);assert.equal(await yes().isDisabled(),true);assert.match(await reason().innerText(),/正在自动核对/);assert.equal(await page.getByRole('button',{name:'正在核对…',exact:true}).isDisabled(),true);await page.screenshot({path:output+'/preparing-reason.png'})
 await setState({active:false});assert.match(await reason().innerText(),/未激活/);mode='ready';await setState({active:true});await waitReady();pending.splice(0).forEach(resolve=>resolve());await page.waitForTimeout(100);assert.equal(await yes().isEnabled(),true);record('inactive-to-active retries automatically and late superseded preview cannot overwrite')
 mode='pending';await retry().click();await page.waitForTimeout(50);await setState({target:{parentId:'other-parent',serial:'fixture-serial',package:'fixture.package',importedRoots:[]}});await page.waitForTimeout(50);assert.equal(pending.length,2);pending[0]();await page.waitForTimeout(50);assert.equal(await yes().isDisabled(),true);pending[1]();pending=[];await waitReady();assert.equal(executions,0);record('target race keeps old async preview from enabling foreign confirmation')
 mode='partial';await setState({target:{parentId:'fixture-parent',serial:'fixture-serial',package:'fixture.package',importedRoots:[]}});await waitReady();await yes().click();await page.getByRole('alert').waitFor();assert.match(await page.getByRole('alert').innerText(),/fixture device failure/);assert.equal(await retry().isEnabled(),true);const first=executions;mode='ready';await retry().click();await waitReady();assert.ok(calls.some(c=>c.command==='prepare_kernsight_group_purge_retry'));assert.equal(executions,first);record('partial keeps local error and explicit retry only re-previews durable remaining plan')
 assert.deepEqual(errors,[]);await page.screenshot({path:output+'/confirmation.png'});writeFileSync(output+'/results.json',JSON.stringify({passed:true,checks,executions,mockedIpc:true,realDeviceCalls:0},null,2))
} catch(error){await page.screenshot({path:output+'/failure.png'});writeFileSync(output+'/failure.json',JSON.stringify({error:String(error),calls,errors},null,2));throw error} finally{await close()}
