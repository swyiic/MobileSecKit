// @description 内置 Frida 17 App 私有 SO 内存提取；请使用 SO Dump 自动工作流
'use strict';

const TARGET_PACKAGE = '__ME_PACKAGE__';
const OUTPUT_DIR = `/data/user/0/${TARGET_PACKAGE}/files/dump_so_${TARGET_PACKAGE}`;
const dumped = new Set();

function libcFunction(name, returnType, argumentTypes) {
  const libc = Process.getModuleByName('libc.so');
  return new NativeFunction(libc.getExportByName(name), returnType, argumentTypes);
}

function ensureDirectory(path) {
  const mkdir = libcFunction('mkdir', 'int', ['pointer', 'int']);
  mkdir(Memory.allocUtf8String(path), 0x1ff);
}

function safeName(value) {
  return value.replace(/[^a-zA-Z0-9._-]/g, '_');
}

function isAppModule(module) {
  const path = module.path || '';
  return module.name.endsWith('.so') &&
    !path.startsWith('/system/') && !path.startsWith('/apex/') &&
    !path.startsWith('/vendor/') && !path.startsWith('/product/');
}

function dumpModule(module) {
  const key = `${module.base}:${module.size}`;
  if (dumped.has(key) || !isAppModule(module)) return;
  dumped.add(key);
  ensureDirectory(OUTPUT_DIR);
  const prefix = `${OUTPUT_DIR}/${safeName(module.name)}_${module.base}_${module.size}`;
  try {
    const ranges = module.enumerateRanges('r--');
    const manifest = { name: module.name, path: module.path, base: module.base.toString(), size: module.size, ranges: [] };
    ranges.forEach((range, index) => {
      const relativeOffset = range.base.sub(module.base).toString();
      const path = `${prefix}.range${index}.offset_${relativeOffset}.${range.protection}.bin`;
      const file = new File(path, 'wb');
      const chunkSize = 1024 * 1024;
      let written = 0;
      while (written < range.size) {
        const length = Math.min(chunkSize, range.size - written);
        file.write(range.base.add(written).readByteArray(length));
        written += length;
      }
      file.flush();
      file.close();
      manifest.ranges.push({ path, base: range.base.toString(), offset: relativeOffset, size: range.size, protection: range.protection });
      console.log(`[ME_SO_RANGE] ${path} size=${range.size} protection=${range.protection}`);
    });
    const manifestPath = `${prefix}.map.json`;
    const manifestFile = new File(manifestPath, 'w');
    manifestFile.write(JSON.stringify(manifest, null, 2));
    manifestFile.flush();
    manifestFile.close();
    console.log(`[ME_SO_DUMP] ${module.name} ranges=${ranges.length} map=${manifestPath}`);
  } catch (error) {
    console.log(`[ME_SO_ERROR] ${module.name} ${error}`);
  }
}

function dumpCurrentModules() {
  Process.enumerateModules().forEach(dumpModule);
}

function hookLoader(name) {
  const address = Module.findGlobalExportByName(name);
  if (address === null) return;
  Interceptor.attach(address, {
    onEnter(args) {
      this.path = args[0].isNull() ? '' : args[0].readCString();
    },
    onLeave() {
      if (this.path) {
        setTimeout(dumpCurrentModules, 50);
      }
    }
  });
}

console.log('[ME_SO_READY] scanning existing and newly loaded application libraries');
dumpCurrentModules();
hookLoader('dlopen');
hookLoader('android_dlopen_ext');
