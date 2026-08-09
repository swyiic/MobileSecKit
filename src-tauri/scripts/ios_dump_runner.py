import argparse, os, shutil, sys, tempfile, zipfile
import frida
def log(x): print(x,flush=True)
def safe(x): return ''.join(c if c.isalnum() or c in '._-' else '_' for c in x) or 'App'
def pull(e,r,l,n):
 os.makedirs(os.path.dirname(l),exist_ok=True);o=0
 with open(l,'wb') as f:
  while o<n:
   b=e.readfile(r,o,min(262144,n-o))
   if not b: raise RuntimeError(f'read stopped {o}/{n}: {r}')
   f.write(bytes(b));o+=len(b)
def main():
 p=argparse.ArgumentParser();p.add_argument('--serial',required=True);p.add_argument('--bundle',required=True);p.add_argument('--output',required=True);p.add_argument('--agent',required=True);a=p.parse_args()
 log(f'[1/7] Python Frida {frida.__version__}');d=frida.get_device_manager().get_device(a.serial,timeout=8);apps=d.enumerate_applications();app=next((x for x in apps if x.identifier==a.bundle),None)
 if app is None: raise RuntimeError('Bundle ID not installed: '+a.bundle)
 log(f'[2/7] Spawn {app.name} ({app.identifier})');pid=d.spawn([a.bundle]);s=d.attach(pid);j=s.create_script(open(a.agent,encoding='utf-8').read());j.on('message',lambda m,b:log('[agent] '+str(m)));j.load();d.resume(pid);e=j.exports_sync
 try:
  i=e.bundleinfo();root=i['bundlePath'];exe=i['executableName'];remote=f"{i['sandboxPath']}/tmp/me_{safe(exe)}.decrypted";log('[3/7] Dump decrypted Mach-O: '+exe);e.dumpexecutable(remote);items=e.listfiles(root);log(f'[4/7] Pull App Bundle: {len(items)} files')
  with tempfile.TemporaryDirectory(prefix='me-ios-') as t:
   appdir=os.path.join(t,os.path.basename(root));done=0;total=sum(int(x['size']) for x in items)
   for z,x in enumerate(items,1):
    pull(e,root+'/'+x['relative'],os.path.join(appdir,x['relative']),int(x['size']));done+=int(x['size'])
    if z==len(items) or z%25==0: log(f'      bundle {z}/{len(items)} · {done*100//max(total,1)}%')
   tmpdir=os.path.dirname(remote);dumpitem=next((x for x in e.listfiles(tmpdir) if x['relative']==os.path.basename(remote)),None)
   if not dumpitem: raise RuntimeError('decrypted Mach-O missing')
   local=os.path.join(t,exe+'.decrypted');pull(e,remote,local,int(dumpitem['size']));target=os.path.join(appdir,exe);shutil.copy2(local,target);os.chmod(target,0o755);out=os.path.abspath(os.path.expanduser(a.output));os.makedirs(os.path.dirname(out),exist_ok=True);log('[5/7] Replace executable (cryptid=0)');log('[6/7] Build IPA: '+out)
   with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as q:
    for base,_,names in os.walk(appdir):
     for name in names:
      full=os.path.join(base,name);q.write(full,os.path.join('Payload',os.path.basename(appdir),os.path.relpath(full,appdir)))
   log(f'[7/7] SUCCESS {out} ({os.path.getsize(out)} bytes)')
  try:e.removefile(remote)
  except Exception:pass
 finally:s.detach()
if __name__=='__main__':
 try:main()
 except Exception as x:print('[FAILED] '+repr(x),file=sys.stderr,flush=True);raise
