const { chromium } = await import(process.env.ME_PLAYWRIGHT_MODULE || 'playwright');
import { pathToFileURL } from 'node:url';
import { fileURLToPath } from 'node:url';

// Cloud-only UI harness. All Tauri calls are mocked; no device commands execute.
// Vite and Chromium run together. External network requests are blocked.
// Optional ME_PLAYWRIGHT_MODULE and ME_CHROMIUM_PATH select an existing local browser installation.
export async function launchMe({url = 'http://127.0.0.1:1420', fixtures = {}, handler, root = fileURLToPath(new URL('../../', import.meta.url)), serve = true, setupPage} = {}) {
  let server;
  if (serve) {
    const {createServer}=await import(pathToFileURL(`${root}/node_modules/vite/dist/node/index.js`).href);
    server=await createServer({root,configFile:`${root}/vite.config.ts`,server:{host:'127.0.0.1',port:1420},logLevel:'error'});
    await server.listen();
  }
  const browser = await chromium.launch({headless:true, executablePath:process.env.ME_CHROMIUM_PATH || undefined, args:['--no-sandbox','--disable-dev-shm-usage']});
  const page = await browser.newPage({viewport:{width:1440,height:1000},deviceScaleFactor:1});
  const calls = [], errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.route('**/*', route => {
    const hostname = new URL(route.request().url()).hostname;
    return ['localhost','127.0.0.1'].includes(hostname) ? route.continue() : route.abort();
  });
  const defaults = {
    apply_main_window_theme:null, load_app_config:{}, save_app_config:'mock-config', configure_host_environment:'mock-configured',
    list_devices:[], inspect_environment:{hostOs:'linux',hostArch:'x86_64',tools:[],deviceFridaReachable:false,deviceFridaRequiresDeveloperImage:false},
    list_kernsight_groups:[], list_kernsight_group_trash:[], list_ai_task_templates:[],
    list_frida_scripts:[], list_frida_processes:[], list_processes:[], list_installed_apps:[],
    'plugin:event|listen':1, 'plugin:event|unlisten':null,
  };
  await page.exposeFunction('__meMockInvoke', async (command,args) => {
    calls.push({command,args});
    if (handler) {
      const result = await handler(command,args);
      if (result !== undefined) return result;
    }
    if (Object.hasOwn(fixtures,command)) return fixtures[command];
    if (Object.hasOwn(defaults,command)) return defaults[command];
    throw new Error(`Unmocked Tauri command: ${command}`);
  });
  await page.addInitScript(() => {
    let nextCallback=1;
    const callbacks = new Map();
    window.__meMockCallbacks = callbacks;
    window.isTauri = true;
    window.__TAURI_INTERNALS__ = {
      invoke:(command,args={})=>window.__meMockInvoke(command,args),
      transformCallback:(callback,once=false)=>{
        const id=nextCallback++;
        callbacks.set(id,(...args)=>{if(once)callbacks.delete(id);return callback(...args);});
        return id;
      },
      unregisterCallback:id=>callbacks.delete(id),
      convertFileSrc:path=>`http://asset.localhost/${encodeURIComponent(path)}`,
      metadata:{currentWindow:{label:'main'},currentWebview:{label:'main'}},
    };
    window.__TAURI_EVENT_PLUGIN_INTERNALS__={unregisterListener:()=>{}};
  });
  if (setupPage) await setupPage(page);
  await page.goto(url,{waitUntil:'networkidle'});
  const close = async () => {await browser.close(); if(server) await server.close();};
  return {browser,page,calls,errors,close};
}
