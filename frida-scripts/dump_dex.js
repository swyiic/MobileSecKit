// @description 内置 Frida 17 DEX 运行时提取；请使用 DEX Dump 自动工作流
'use strict';

const TARGET_PACKAGE = '__ME_PACKAGE__';
// App-private /data paths can be unreadable even to Magisk root while SELinux
// is enforcing. The app can write its own scoped external files directory and
// adb can recover it without changing SELinux policy.
const OUTPUT_DIR = `/sdcard/Android/data/${TARGET_PACKAGE}/files/dump_dex_${TARGET_PACKAGE}`;
const seen = new Set();
let sequence = 1;

function nextDexPath() {
  const name = sequence === 1 ? 'classes.dex' : `classes${sequence}.dex`;
  sequence += 1;
  return `${OUTPUT_DIR}/${name}`;
}

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
  const path = nextDexPath();
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

function unsignedByte(value) {
  return Number(value) & 0xff;
}

function dexSizeFromHeader(header) {
  if (!header || header.length < 0x70 || unsignedByte(header[0]) !== 0x64 ||
      unsignedByte(header[1]) !== 0x65 || unsignedByte(header[2]) !== 0x78 ||
      unsignedByte(header[3]) !== 0x0a) return 0;
  return unsignedByte(header[0x20]) |
    (unsignedByte(header[0x21]) << 8) |
    (unsignedByte(header[0x22]) << 16) |
    (unsignedByte(header[0x23]) << 24 >>> 0);
}

function javaBytesToArrayBuffer(bytes, length) {
  const output = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) output[index] = unsignedByte(bytes[index]);
  return output.buffer;
}

function writeByteBufferDex(buffer, source) {
  if (!buffer) return false;
  try {
    const duplicate = buffer.duplicate();
    const capacity = Number(duplicate.capacity());
    if (capacity < 0x70 || capacity > 512 * 1024 * 1024) return false;
    const originalPosition = Number(duplicate.position());
    const originalLimit = Number(duplicate.limit());
    let start = originalPosition;
    let declaredSize = 0;
    for (const candidate of [originalPosition, 0]) {
      if (candidate < 0 || candidate + 0x70 > originalLimit) continue;
      duplicate.position(candidate);
      duplicate.limit(originalLimit);
      const header = Java.array('byte', new Array(0x70).fill(0));
      duplicate.get(header);
      const size = dexSizeFromHeader(header);
      if (size >= 0x70 && candidate + size <= originalLimit && size <= 512 * 1024 * 1024) {
        start = candidate;
        declaredSize = size;
        break;
      }
    }
    if (!declaredSize) return false;
    const identity = `${source}:${capacity}:${start}:${declaredSize}`;
    if (seen.has(identity)) return true;
    seen.add(identity);
    ensureDirectory(OUTPUT_DIR);
    const path = nextDexPath();
    duplicate.position(start);
    duplicate.limit(start + declaredSize);
    const file = new File(path, 'wb');
    let remaining = declaredSize;
    while (remaining > 0) {
      const length = Math.min(remaining, 64 * 1024);
      const chunk = Java.array('byte', new Array(length).fill(0));
      duplicate.get(chunk);
      file.write(javaBytesToArrayBuffer(chunk, length));
      remaining -= length;
    }
    file.flush();
    file.close();
    console.log(`[ME_DEX_DUMP] ${path} source=${source} size=${declaredSize}`);
    return true;
  } catch (error) {
    console.log(`[ME_DEX_ERROR] ByteBuffer source=${source} ${error}`);
    return false;
  }
}

function readDexFileObject(dexFile) {
  if (dexFile.isNull()) return false;
  // ART DexFile fields have moved across releases/vendor builds. Probe a
  // bounded set of adjacent pointer/size pairs and validate the DEX header
  // before reading, instead of assuming one Android-version layout.
  const layouts = [0, 1, 2, 3, 4].map(function (slot) {
    return [slot * Process.pointerSize, (slot + 1) * Process.pointerSize];
  });
  for (const layout of layouts) {
    try {
      const base = dexFile.add(layout[0]).readPointer();
      const size = Process.pointerSize === 8
        ? Number(dexFile.add(layout[1]).readU64())
        : dexFile.add(layout[1]).readU32();
      if (validDex(base, size)) {
        writeDex(base, size);
        return true;
      }
    } catch (_) {}
  }
  return false;
}

function scanLoadedDex() {
  const ranges = ['r--', 'rw-', 'r-x'].flatMap(protection => {
    try { return Process.enumerateRanges({ protection, coalesce: true }); }
    catch (_) { return []; }
  });
  let pending = ranges.length;
  let matches = 0;
  if (pending === 0) {
    console.log('[ME_DEX_SCAN] no readable ranges');
    return;
  }
  ranges.forEach(range => {
    try {
      Memory.scan(range.base, range.size, '64 65 78 0a 30 ?? ?? 00', {
        onMatch(address) {
          try {
            const size = address.add(0x20).readU32();
            if (validDex(address, size)) {
              matches += 1;
              writeDex(address, size);
            }
          } catch (_) {}
        },
        onError(reason) {
          console.log(`[ME_DEX_SCAN_ERROR] ${range.base} ${reason}`);
        },
        onComplete() {
          pending -= 1;
          if (pending === 0) console.log(`[ME_DEX_SCAN] complete matches=${matches}`);
        }
      });
    } catch (error) {
      pending -= 1;
      console.log(`[ME_DEX_SCAN_ERROR] ${range.base} ${error}`);
      if (pending === 0) console.log(`[ME_DEX_SCAN] complete matches=${matches}`);
    }
  });
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
        // DefineClass signatures vary. Search likely Handle/DexFile argument
        // positions and accept only a structurally valid DEX object.
        const argumentOrder = [5, 4, 6, 3, 7, 2, 8];
        let found = false;
        for (const index of argumentOrder) {
          if (readDexFileObject(args[index])) { found = true; break; }
        }
        if (!found) {
          console.log('[ME_DEX_ERROR] unsupported DefineClass signature or compact DEX layout');
        }
      } catch (error) {
        console.log(`[ME_DEX_ERROR] ${error}`);
      }
    }
  });
}

function inspectCookie(dexFile, findField, source) {
  for (const fieldName of ['mCookie', 'mInternalCookie']) {
    const cookie = findField(dexFile, fieldName);
    if (!cookie) continue;
    try {
      const length = Number(cookie.length || 0);
      for (let index = 0; index < length; index += 1) {
        try {
          const address = ptr(String(cookie[index]));
          if (!address.isNull()) readDexFileObject(address);
        } catch (_) {}
      }
    } catch (error) {
      console.log(`[ME_DEX_ELEMENT_ERROR] ${source} ${fieldName} ${error}`);
    }
  }
}

function installJavaDexHooks() {
  if (!Java.available) {
    console.log('[ME_DEX_JAVA] Java runtime unavailable');
    return;
  }
  Java.perform(function () {
    function findField(target, name) {
      if (!target) return null;
      let type = null;
      try { type = target.getClass(); } catch (_) { return null; }
      while (type) {
        try {
          const field = type.getDeclaredField(name);
          field.setAccessible(true);
          return field.get(target);
        } catch (_) {}
        try { type = type.getSuperclass(); } catch (_) { type = null; }
      }
      return null;
    }

    function inspectBufferCandidate(value, source) {
      if (!value) return;
      try {
        if (typeof value.duplicate === 'function' && typeof value.capacity === 'function') {
          writeByteBufferDex(value, source);
          return;
        }
      } catch (_) {}
      try {
        const length = Number(value.length || 0);
        if (length > 0 && length < 4096) {
          for (let index = 0; index < length; index += 1) {
            inspectBufferCandidate(value[index], `${source}[${index}]`);
          }
        }
      } catch (_) {}
    }

    function inspectDexElements() {
      let loaders = 0;
      let elementsSeen = 0;
      Java.enumerateClassLoaders({
        onMatch(loader) {
          loaders += 1;
          try {
            const pathList = findField(loader, 'pathList');
            const elements = findField(pathList, 'dexElements');
            if (!elements) return;
            const length = Number(elements.length || 0);
            for (let index = 0; index < length; index += 1) {
              const dexFile = findField(elements[index], 'dexFile');
              if (!dexFile) continue;
              elementsSeen += 1;
              let path = '';
              try { path = String(dexFile.getName()); } catch (_) { path = String(dexFile); }
              console.log(`[ME_DEX_ELEMENT] loader=${loader.$className || loader} index=${index} path=${path}`);
              inspectCookie(dexFile, findField, path || `element-${index}`);
            }
          } catch (error) {
            console.log(`[ME_DEX_ELEMENT_ERROR] ${error}`);
          }
        },
        onComplete() {
          console.log(`[ME_DEX_ELEMENTS] loaders=${loaders} dexFiles=${elementsSeen}`);
        }
      });
    }

    try {
      const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
      InMemoryDexClassLoader.$init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          for (let index = 0; index < arguments.length; index += 1) {
            inspectBufferCandidate(arguments[index], `InMemoryDexClassLoader.$init:${index}`);
          }
          return overload.apply(this, arguments);
        };
      });
      console.log(`[ME_DEX_JAVA] InMemoryDexClassLoader constructors=${InMemoryDexClassLoader.$init.overloads.length}`);
    } catch (error) {
      console.log(`[ME_DEX_JAVA] InMemoryDexClassLoader unavailable: ${error}`);
    }

    try {
      const DexFile = Java.use('dalvik.system.DexFile');
      if (DexFile.openInMemoryDexFile) {
        DexFile.openInMemoryDexFile.overloads.forEach(function (overload) {
          overload.implementation = function () {
            for (let index = 0; index < arguments.length; index += 1) {
              inspectBufferCandidate(arguments[index], `DexFile.openInMemoryDexFile:${index}`);
            }
            return overload.apply(this, arguments);
          };
        });
        console.log(`[ME_DEX_JAVA] openInMemoryDexFile overloads=${DexFile.openInMemoryDexFile.overloads.length}`);
      }
    } catch (error) {
      console.log(`[ME_DEX_JAVA] openInMemoryDexFile unavailable: ${error}`);
    }

    try { inspectDexElements(); }
    catch (error) { console.log(`[ME_DEX_ELEMENT_ERROR] ${error}`); }
  });
}

setImmediate(function () {
  ensureDirectory(OUTPUT_DIR);
  scanLoadedDex();
  installDefineClassHook();
  installJavaDexHooks();
});
