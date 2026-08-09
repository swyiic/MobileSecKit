// @description 内置 Frida 17 DEX 运行时提取；请使用 DEX Dump 自动工作流
'use strict';

const TARGET_PACKAGE = '__ME_PACKAGE__';
const OUTPUT_DIR = `/data/user/0/${TARGET_PACKAGE}/files/dump_dex_${TARGET_PACKAGE}`;
const seen = new Set();
let sequence = 1;

function libcFunction(name, returnType, argumentTypes) {
  const libc = Process.getModuleByName('libc.so');
  return new NativeFunction(libc.getExportByName(name), returnType, argumentTypes);
}

function ensureDirectory(path) {
  const mkdir = libcFunction('mkdir', 'int', ['pointer', 'int']);
  mkdir(Memory.allocUtf8String(path), 0x1ff);
}

function validDex(base, size) {
  if (base.isNull() || size < 0x70 || size > 512 * 1024 * 1024) return false;
  try {
    return base.readU8() === 0x64 && base.add(1).readU8() === 0x65 &&
      base.add(2).readU8() === 0x78 && base.add(3).readU8() === 0x0a;
  } catch (_) {
    return false;
  }
}

function writeDex(base, size) {
  const key = `${base}:${size}`;
  if (seen.has(key) || !validDex(base, size)) return;
  seen.add(key);
  ensureDirectory(OUTPUT_DIR);
  const name = sequence === 1 ? 'classes.dex' : `classes${sequence}.dex`;
  sequence += 1;
  const path = `${OUTPUT_DIR}/${name}`;
  try {
    const bytes = base.readByteArray(size);
    const file = new File(path, 'wb');
    file.write(bytes);
    file.flush();
    file.close();
    console.log(`[ME_DEX_DUMP] ${path} base=${base} size=${size}`);
  } catch (error) {
    console.log(`[ME_DEX_ERROR] ${base} size=${size} ${error}`);
  }
}

function installDefineClassHook() {
  const libart = Process.getModuleByName('libart.so');
  const candidates = libart.enumerateSymbols().filter(symbol =>
    symbol.name.includes('ClassLinker') && symbol.name.includes('DefineClass') &&
    symbol.name.includes('DexFile'));
  if (candidates.length === 0) {
    console.log('[ME_DEX_ERROR] ART DefineClass symbol not found');
    return;
  }
  const target = candidates[0];
  console.log(`[ME_DEX_READY] ${target.name} ${target.address}`);
  Interceptor.attach(target.address, {
    onEnter(args) {
      try {
        const dexFile = args[5];
        const base = dexFile.add(Process.pointerSize).readPointer();
        const size = dexFile.add(Process.pointerSize * 2).readU32();
        writeDex(base, size);
      } catch (error) {
        console.log(`[ME_DEX_ERROR] ${error}`);
      }
    }
  });
}

setImmediate(installDefineClassHook);
