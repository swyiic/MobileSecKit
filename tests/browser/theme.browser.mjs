import assert from 'node:assert/strict'
import { writeFileSync, mkdirSync } from 'node:fs'
import { launchMe } from './mockedMeHarness.mjs'
const output=new URL(`file://${process.env.ME_THEME_QA_OUTPUT || '/tmp/me-theme-qa'}/`);mkdirSync(output,{recursive:true})
const results=[]
for(const scenario of [{saved:'light',system:'dark',expected:'light'},{saved:'dark',system:'light',expected:'dark'},{saved:null,system:'light',expected:'light'},{saved:null,system:'dark',expected:'dark'}]){
 const h=await launchMe({handler:async command=>{if(command==='load_app_config'){await new Promise(r=>setTimeout(r,1000));return {}}},setupPage:async page=>{
  await page.emulateMedia({colorScheme:scenario.system})
  await page.addInitScript(saved=>{if(saved)localStorage.setItem('mobilee.theme',saved);else localStorage.removeItem('mobilee.theme');window.__themeFrames=[];let ticks=0;function sample(){window.__themeFrames.push({theme:document.documentElement.dataset.theme,bg:getComputedStyle(document.documentElement).backgroundColor});if(++ticks<40)requestAnimationFrame(sample)};requestAnimationFrame(sample)},scenario.saved)
 }})
 try{
 const {page}=h;await page.waitForSelector('.app-header');await page.waitForTimeout(50)
 const frames=await page.evaluate(()=>window.__themeFrames);assert.ok(frames.length>0)
 assert.ok(frames.every(frame=>frame.theme===scenario.expected),JSON.stringify(frames))
 assert.equal(await page.evaluate(()=>document.documentElement.dataset.theme),scenario.expected)
 for(const title of ['运行时分析 · Frida、DEX 与 Native','KernSight · 采集、会话与 L2 证据','静态分析 · APK / IPA 清单与证据']){
  await page.getByTitle(title,{exact:true}).click();assert.equal(await page.evaluate(()=>document.documentElement.dataset.theme),scenario.expected)
 }
 await page.setViewportSize({width:390,height:850})
 await page.screenshot({path:new URL(`${scenario.saved||'system'}-${scenario.system}-390.png`,output).pathname})
 // Verify existing light overrides using their actual global cascade, not guessed screenshot content.
 const colors=await page.evaluate(()=>{const div=document.createElement('div');div.id='theme-fixture';div.innerHTML='<details class="analyzer-help-popover" open><summary>help</summary><div>help</div></details><details class="analyzer-more-actions" open><summary>more</summary><div>more</div></details><details class="summary-details" open><summary>summary</summary><p>summary</p></details><div class="sensitive-detail"><pre>evidence</pre></div><details class="ks-fact-more" open><summary>fact</summary></details>';document.body.append(div);return [...div.querySelectorAll('.analyzer-help-popover > div,.analyzer-more-actions > div,.summary-details p,.sensitive-detail pre,.ks-fact-more summary')].map(el=>({selector:el.parentElement.className,bg:getComputedStyle(el).backgroundColor}))})
 if(scenario.expected==='light')for(const color of colors){const channels=color.bg.match(/\d+/g).map(Number);assert.ok(channels.slice(0,3).every(n=>n>180),JSON.stringify(color))}
 if(!scenario.saved){await page.emulateMedia({colorScheme:scenario.expected==='light'?'dark':'light'});await page.waitForTimeout(100);assert.equal(await page.evaluate(()=>document.documentElement.dataset.theme),scenario.expected==='light'?'dark':'light')}
 const previous=await page.evaluate(()=>document.documentElement.dataset.theme)
 await page.getByTitle(previous==='dark'?'切换 Codex 浅色':'切换暗色',{exact:true}).click()
 const toggled=previous==='dark'?'light':'dark';await page.waitForTimeout(50)
 assert.equal(await page.evaluate(()=>localStorage.getItem('mobilee.theme')),toggled)
 await page.emulateMedia({colorScheme:toggled==='dark'?'light':'dark'});await page.waitForTimeout(100);assert.equal(await page.evaluate(()=>document.documentElement.dataset.theme),toggled)
 assert.deepEqual(h.errors,[])
 results.push({scenario,frames:frames.length,firstFrame:frames[0],colors,passed:true,native:'mocked command only; actual hidden native window requires built-app validation'})
 }finally{await h.close()}
}
for (const failure of ['configuration-rejected','configuration-hung','native-ipc-rejected']) {
 const h=await launchMe({handler:async command=>{if(command==='load_app_config'){if(failure==='configuration-rejected')throw new Error('fixture rejected');if(failure==='configuration-hung')return new Promise(()=>{});return {}};if(command==='apply_main_window_theme'&&failure==='native-ipc-rejected')throw new Error('fixture IPC refusal')},setupPage:async page=>{
   await page.addInitScript(()=>{localStorage.setItem('mobilee.theme','light');window.__themeRevealCalls=[];const original=window.__meMockInvoke;window.__meMockInvoke=(command,args)=>{if(command==='apply_main_window_theme')window.__themeRevealCalls.push({theme:args.theme,rendered:!!document.querySelector('.app-header'),documentTheme:document.documentElement.dataset.theme});return original(command,args)}})
 }})
 try {await h.page.waitForSelector('.app-header');await h.page.waitForFunction(()=>window.__themeRevealCalls.length>0);const calls=await h.page.evaluate(()=>window.__themeRevealCalls);assert.ok(calls.every(call=>call.rendered&&call.theme==='light'&&call.documentTheme==='light'));assert.deepEqual(h.errors,[]);results.push({failure,passed:true,calls,nativeFallback:'source-reviewed finite3s+200ms once claim; actual native fallback not exercised in Chromium'})}finally{await h.close()}
}
{
 const h=await launchMe({setupPage:async page=>{await page.emulateMedia({colorScheme:'light'});await page.addInitScript(()=>{Object.defineProperty(Storage.prototype,'getItem',{value(){throw new Error('fixture restricted storage')}});Object.defineProperty(Storage.prototype,'setItem',{value(){throw new Error('fixture restricted storage')}})})}})
 try {await h.page.waitForSelector('.app-header');assert.equal(await h.page.evaluate(()=>document.documentElement.dataset.theme),'light');await h.page.getByTitle('切换暗色',{exact:true}).click();assert.equal(await h.page.evaluate(()=>document.documentElement.dataset.theme),'dark');await h.page.emulateMedia({colorScheme:'dark'});await h.page.emulateMedia({colorScheme:'light'});await h.page.waitForTimeout(100);assert.equal(await h.page.evaluate(()=>document.documentElement.dataset.theme),'dark');await h.page.getByTitle('收起菜单',{exact:true}).click();assert.deepEqual(h.errors,[]);results.push({failure:'restricted-storage',passed:true})}finally{await h.close()}
}
for (const theme of ['light','dark']) {
 const device={platform:'android',serial:'mock-theme-only',status:'device',model:'theme fixture',product:'fixture'}
 const h=await launchMe({fixtures:{list_devices:[device],get_device_details:{...device,manufacturer:'fixture',androidVersion:'14',sdkVersion:'34',buildNumber:'fixture',architecture:'arm64',architectureFamily:'arm64',rootStatus:'Root',selinuxStatus:'Enforcing',bootloaderStatus:'Unlocked',ipAddress:'192.0.2.1',securityPatch:'2026-10-01',brand:'fixture',abiList:['arm64-v8a'],kernelVersion:'Linux fixture '+ 'long kernel '.repeat(20)},list_knowledge:[]},setupPage:page=>page.addInitScript(value=>localStorage.setItem('mobilee.theme',value),theme)})
 try {const button=h.page.getByRole('button',{name:'复制完整Kernel',exact:true}).first();await button.waitFor().catch(error=>{console.log('popup fixture errors',h.errors, h.calls.map(c=>c.command));throw error});await h.page.setViewportSize({width:390,height:850});await button.hover();const popup=h.page.locator('.full-value-preview');await popup.waitFor();const actual=await popup.evaluate(el=>({bg:getComputedStyle(el).backgroundColor,fg:getComputedStyle(el).color,rect:{left:el.getBoundingClientRect().left,right:el.getBoundingClientRect().right},width:innerWidth}));assert.equal(actual.bg,theme==='light'?'rgb(255, 255, 255)':'rgb(18, 22, 29)');assert.ok(actual.rect.left>=0&&actual.rect.right<=actual.width);await h.page.screenshot({path:new URL(`popup-${theme}-390.png`,output).pathname});assert.deepEqual(h.errors,[]);results.push({case:'actualFullValuePopup',theme,actual,passed:true})}finally{await h.close()}
}
writeFileSync(new URL('results.json',output),JSON.stringify({passed:true,results,note:'Mocked Tauri IPC, delayed configuration; no installed app restart or device calls. Reference Library screenshot403 not inspected.'},null,2));console.log('PASS10 scenarios:3 configuration/IPC failure protocols, restricted storage,2 actual popup palettes;4 cold persisted/system theme scenarios, page switches, keyboard-compatible toggle, system changes, narrow layout,5 existing CSS surfaces')
