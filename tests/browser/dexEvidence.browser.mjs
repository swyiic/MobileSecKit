import assert from 'node:assert/strict'
import {mkdirSync,writeFileSync} from 'node:fs'
import {pathToFileURL,fileURLToPath} from 'node:url'
import {resolve} from 'node:path'
import {tmpdir} from 'node:os'
import {launchMe} from './mockedMeHarness.mjs'
const root=fileURLToPath(new URL('../../',import.meta.url)),out=resolve(process.env.ME_DEX_QA_OUTPUT||resolve(tmpdir(),'me-dex-consistency-qa'))
mkdirSync(out,{recursive:true})
const {createServer}=await import(pathToFileURL(`${root}/node_modules/vite/dist/node/index.js`).href)
const server=await createServer({root,configFile:`${root}/vite.config.ts`,server:{host:'127.0.0.1',port:1431,strictPort:true},logLevel:'error'})
await server.listen()
const sha=i=>i.toString(16).padStart(64,'0')
const objects=Array.from({length:40},(_,i)=>({sha256:sha(i+1),bytes:100+i,sources:[],classes:i===0?Array.from({length:8201},(_,j)=>`Lexample/Class${j};`):[`Lexample/Other${i};`],indexed_classes:i===0?8201:1,declared_classes:i===0?8201:1,class_index_status:'complete_class_def_index',validation_status:'unknown',ownership:'unknown'}))
const report=(id,list)=>({package:'org.example.dex',dump_id:id,dex_sets:[],content_dex_class_index:{schema:'mobilee.content-dex-class-index/v1',scope:'synthetic regression only',objects:list},local_storage_accounting:{logical_file_bytes:100,allocated_bytes:100,verified_code_duplicate_bytes:0,runtime_observations:[]}})
const bundle=(name,dump)=>({root:`/mock/${name}`,package:dump.package,fileCount:2,totalBytes:100,files:[{relativePath:'readable-dex/classes.dex',bytes:40,category:'readable-dex'},{relativePath:'runtime/bound-elf.code',bytes:60,category:'runtime'}],captureText:'',dumpReport:dump})
const a=bundle('capture-A',report('fixture-A',objects))
const identity={package:a.package,pid:1,birth_ns:2,uid:3,exec_id:4,boot_id:'synthetic-boot'}
const unlinked={sha256:sha(60),bytes:60,sources:[{kind:'runtime',row_index:0,source_report:'runtime/source.json',range_sha256:'e'.repeat(64),source:identity}],class_index_status:'unknown',validation_status:'unknown'}
const b=bundle('capture-B',report('fixture-B',[unlinked,{sha256:sha(61),bytes:61,sources:[],class_index_status:'unknown'}]))
const legacy=bundle('capture-legacy',{package:a.package,dump_id:'legacy',dex_sets:[{sha256:sha(90),bytes:90,canonical_relative_path:'runtime/bound-dex.code',observations:[],sources:[],semantic:{version:'035',declared_file_size:90,class_defs:1,method_ids:1,class_descriptors:['Llegacy/Preserved;'],class_descriptors_truncated:false}}]})
const broken=bundle('capture-malformed',report('malformed',[null,{sha256:sha(99),bytes:1,sources:null,classes:['ok',null]}]))
let nextImport=a,failImport=false
const h=await launchMe({url:'http://127.0.0.1:1431',serve:false,handler:async(command)=>{
 if(command==='list_kernsight_group_purges')return []
 if(command==='plugin:dialog|open'){if(failImport)throw new Error('synthetic DEX import unavailable');return nextImport.root}
 if(command==='import_kernsight_evidence_directory')return nextImport
 if(command==='local_kernsight_evidence_present')return true
}})
const {page,errors,close}=h,checks=[]
const record=name=>{checks.push({name,passed:true});console.log('PASS '+name)}
const index=()=>page.locator('.ks-package-evidence-panel .ks-code-analysis > .ks-dex-index')
async function openIndex(){const details=index();await details.waitFor();if(!await details.evaluate(el=>el.open))await details.locator(':scope > summary').click();return details}
async function importBundle(item){nextImport=item;await page.getByRole('button',{name:/导入本地证据/}).click();await page.locator('.ks-package-list article').filter({hasText:item.package}).first().click();await index().waitFor()}
try{
 await page.getByRole('button',{name:/KernSight.*采集、会话/}).click()
 await importBundle(a);let details=await openIndex()
 assert.match(await details.locator(':scope > summary').innerText(),/40 个可展开结构对象/)
 assert.equal(await details.locator('[data-dex-object]').count(),40)
 assert.equal(await details.locator('[data-dex-group="diagnostic"] [data-dex-object]').count(),40)
 await page.screenshot({path:out+'/forty-objects-visible.png',fullPage:true});record('Synthetic forty-object summary and forty diagnostic rows agree')
 const readableCard=page.locator('.ks-forensic-grid article').filter({hasText:'DEX 文件 / 容器'})
 assert.equal(await readableCard.locator(':scope > b').innerText(),'1')
 await readableCard.click();assert.match(await page.locator('.ks-evidence-browser > header').innerText(),/1 catalogued/)
 assert.equal(await page.locator('.ks-evidence-file-list > button').count(),1)
 assert.match(await page.locator('.ks-evidence-file-list').innerText(),/readable-dex\/classes.dex/)
 assert.doesNotMatch(await page.locator('.ks-evidence-file-list').innerText(),/bound-elf/)
 await page.getByRole('button',{name:'显示全部',exact:true}).click();assert.equal(await page.locator('.ks-evidence-file-list > button').count(),2)
 for(const width of [390,1440]){await page.setViewportSize({width,height:1000});const bounds=await page.locator('.ks-package-evidence-panel').evaluate(el=>({width:el.clientWidth,scroll:el.scrollWidth,page:document.documentElement.clientWidth,pageScroll:document.documentElement.scrollWidth}));assert.ok(bounds.scroll<=bounds.width+1,JSON.stringify(bounds));assert.ok(bounds.pageScroll<=bounds.page+1,JSON.stringify(bounds));await page.screenshot({path:out+`/dex-${width}.png`})}
 record('Physical DEX card and filtered rows agree; show-all and narrow/wide layouts preserve evidence')
 let first=details.locator('[data-dex-object]').first()
 assert.match(await first.locator('[data-dex-index-status="indexed"]').innerText(),/匹配 8201.*当前页 500/)
 await first.getByRole('button',{name:'下一页类名'}).click()
 assert.match(await first.locator(':scope > pre').last().innerText(),/Class500;/)
 await details.locator('input').fill('Class8200;')
 assert.match(await first.locator('[data-dex-index-status="indexed"]').innerText(),/匹配 1.*当前页 1/)
 assert.match(await first.locator(':scope > pre').last().innerText(),/Class8200;/)
 assert.equal(await details.locator('[data-dex-object]').count(),40)
 await details.locator('input').fill('does-not-exist');assert.match(await first.locator('[data-dex-index-status="indexed"]').innerText(),/匹配 0/)
 await details.locator('input').fill('');assert.match(await first.locator(':scope > pre').last().innerText(),/Class0;/)
 record('Class pagination reaches tail; queries reset pages and zero matches preserve all objects')
 await first.locator(':scope > details > summary').click()
 await importBundle(b);details=await openIndex()
 assert.equal(await details.locator('input').inputValue(),'')
 assert.equal(await details.locator('[data-dex-object]').count(),2)
 assert.equal(await details.locator('[data-dex-index-status="unlinked"]').count(),1)
 assert.equal(await details.locator('[data-dex-index-status="unknown"]').count(),1)
 assert.match(await details.innerText(),/匹配数未知/)
 const pick=page.locator('.ks-local-capture-picker select');await pick.selectOption(a.root);details=await openIndex()
 assert.equal(await details.locator('input').inputValue(),'');assert.equal(await details.locator('[data-dex-object]').count(),40)
 assert.equal(await details.locator('[data-dex-object] > details[open]').count(),0)
 record('Same-package capture switches reset queries/pages/details; unlinked indexes differ from measured zero')
 await importBundle(legacy);details=await openIndex()
 assert.equal(await details.locator('[data-dex-object]').count(),1)
 assert.match(await details.innerText(),/producer_class_samples/)
 assert.match(await details.innerText(),/Llegacy\/Preserved;/)
 record('Legacy producer sets render without a local content index and retain unknown verification')
 await importBundle(broken);details=await openIndex()
 assert.equal(await details.locator('[data-dex-object]').count(),1)
 assert.equal(await details.locator('[data-dex-index-status="unknown"]').count(),1)
 assert.match(await details.innerText(),/缺少有效 SHA/)
 failImport=true;await page.getByRole('button',{name:/导入本地证据/}).click()
 await page.getByText(/synthetic DEX import unavailable/).first().waitFor()
 assert.equal(await details.locator('[data-dex-object]').count(),1)
 record('Malformed payload and import errors preserve existing evidence and show unknown states')
 assert.deepEqual(errors,[])
 writeFileSync(out+'/result.json',JSON.stringify({scope:'Synthetic mocked-Tauri frontend regression; not an actual-device 40-object count',checks,pageErrors:errors,passed:true},null,2)+'\n')
}catch(error){await page.screenshot({path:out+'/failure.png',fullPage:true});writeFileSync(out+'/failure.json',JSON.stringify({error:String(error),checks,pageErrors:errors},null,2));throw error}
finally{await close();await server.close()}
