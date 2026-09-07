'use strict';

// Read-only, version-pinned JMProtection observer for authorized iOS testing.
// It deliberately does not replace instructions, return values, signals, or
// trust decisions. Its purpose is to separate "Frida injected" from
// "JMProtection detected/terminated the process" and capture the first
// suspicious call site before attempting any compatibility change.
(function () {
  const CONFIG = {
    moduleName: 'JMProtection',
    expectedUuid: 'c5e5c168-513c-3a0c-960c-1e736e79a86d',
    waitMs: 30000,
    maxDetailedCallsPerSymbol: 3,
    maxCallsPerSymbol: 20,
    offsets: [
      { name: 'jm__denyFishHook', offset: 0x0dcf0, args: 4 },
      { name: 'jm__denyFishHookDylib', offset: 0x0f040, args: 4 },
      { name: 'lookSymbol', offset: 0x0ddb8, args: 4 },
      { name: 'lookExportedSymbol', offset: 0x0e94c, args: 4 },
      { name: 'prepare_fish_hook_check', offset: 0x2b7c0, args: 4 },
      { name: 'fishHooked', offset: 0x2b9f4, args: 4 },
      { name: 'test_fish_hook', offset: 0x2ba98, args: 4 }
    ]
  };

  function emit(type, payload) {
    const timestampMs = Date.now();
    const body = Object.assign({
      type: type,
      pid: Process.id,
      timestamp: new Date(timestampMs).toISOString(),
      timestampMs: timestampMs
    }, payload || {});
    console.log(JSON.stringify(body));
  }

  function safeAddress(value) {
    try { return value ? value.toString() : null; } catch (_) { return null; }
  }

  function moduleFor(address) {
    try { return Process.findModuleByAddress(address); } catch (_) { return null; }
  }

  function describeAddress(address) {
    const text = safeAddress(address);
    if (!text) return null;
    const module = moduleFor(address);
    if (!module) return { address: text };
    return {
      address: text,
      module: module.name,
      modulePath: module.path,
      offset: address.sub(module.base).toString()
    };
  }

  function backtrace(context) {
    try {
      return Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 32).map(describeAddress);
    } catch (_) {
      try { return Thread.backtrace(context, Backtracer.FUZZY).slice(0, 32).map(describeAddress); } catch (_) { return []; }
    }
  }

  function readCString(value) {
    try {
      if (!value || value.isNull()) return null;
      const text = value.readCString();
      if (!text || text.length > 256) return null;
      // These arguments are expected to be symbol/module names. Reject random
      // readable pointers so reports do not fill with binary-looking noise.
      if (!/^[\x20-\x7e]{2,256}$/.test(text)) return null;
      return text;
    } catch (_) { return null; }
  }

  function registerSummary(context) {
    const result = {};
    ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'lr', 'pc'].forEach(function (name) {
      try {
        const value = context[name];
        if (value === undefined) return;
        result[name] = safeAddress(value);
        if (name === 'x0' || name === 'x1' || name === 'x2' || name === 'x3') {
          const text = readCString(value);
          if (text) result[name + 'CString'] = text;
        }
      } catch (_) {}
    });
    return result;
  }

  function uuidForModule(module) {
    try {
      // 64-bit Mach-O header: magic, cputype, cpusubtype, filetype,
      // ncmds at +16, sizeofcmds at +20, commands start at +32.
      const magic = module.base.readU32();
      if (magic !== 0xfeedfacf && magic !== 0xcffaedfe) return null;
      const ncmds = module.base.add(16).readU32();
      let cursor = module.base.add(32);
      for (let i = 0; i < ncmds && i < 4096; i++) {
        const cmd = cursor.readU32();
        const cmdsize = cursor.add(4).readU32();
        if (cmdsize < 8 || cmdsize > 0x100000) return null;
        if (cmd === 0x1b) {
          const bytes = new Uint8Array(cursor.add(8).readByteArray(16));
          const hex = Array.from(bytes).map(function (byte) { return byte.toString(16).padStart(2, '0'); }).join('');
          return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
        }
        cursor = cursor.add(cmdsize);
      }
    } catch (_) {}
    return null;
  }

  function findTargetModule() {
    try {
      const exact = Process.findModuleByName(CONFIG.moduleName);
      if (exact) return exact;
    } catch (_) {}
    try {
      return Process.enumerateModules().find(function (module) {
        return module.name === CONFIG.moduleName || module.path.indexOf('/' + CONFIG.moduleName) !== -1;
      }) || null;
    } catch (_) { return null; }
  }

  const callCounts = Object.create(null);
  let callSequence = 0;

  function install(module) {
    const actualUuid = uuidForModule(module);
    if (CONFIG.expectedUuid && actualUuid && actualUuid.toLowerCase() !== CONFIG.expectedUuid) {
      emit('ME_JM_OBSERVER_UUID_MISMATCH', {
        module: module.name,
        modulePath: module.path,
        expectedUuid: CONFIG.expectedUuid,
        actualUuid: actualUuid,
        installed: []
      });
      return;
    }

    const installed = [];
    CONFIG.offsets.forEach(function (spec) {
      const target = module.base.add(spec.offset);
      try {
        if (!module.base || target.compare(module.base) < 0 || target.compare(module.base.add(module.size)) >= 0) {
          throw new Error('offset outside module');
        }
        Interceptor.attach(target, {
          onEnter(args) {
            const count = (callCounts[spec.name] || 0) + 1;
            callCounts[spec.name] = count;
            this.meSequence = ++callSequence;
            this.meObserved = count <= CONFIG.maxCallsPerSymbol;
            this.meDetailed = count <= CONFIG.maxDetailedCallsPerSymbol;
            if (!this.meObserved) {
              if (count === CONFIG.maxCallsPerSymbol + 1) {
                emit('ME_JM_CALLS_SUPPRESSED', {
                  symbol: spec.name,
                  afterCalls: CONFIG.maxCallsPerSymbol
                });
              }
              return;
            }
            const context = this.context;
            const registers = registerSummary(context);
            const payload = {
              sequence: this.meSequence,
              callCount: count,
              symbol: spec.name,
              module: module.name,
              moduleOffset: '0x' + spec.offset.toString(16),
              threadId: Process.getCurrentThreadId(),
              caller: describeAddress(this.returnAddress),
              x0: registers.x0 || null,
              x0CString: registers.x0CString || null,
              x1: registers.x1 || null,
              x1CString: registers.x1CString || null
            };
            if (this.meDetailed) {
              payload.registers = registers;
              payload.backtrace = backtrace(context);
            }
            emit('ME_JM_CALL', payload);
          },
          onLeave(retval) {
            if (!this.meObserved || !this.meDetailed) return;
            emit('ME_JM_RETURN', {
              sequence: this.meSequence,
              symbol: spec.name,
              module: module.name,
              moduleOffset: '0x' + spec.offset.toString(16),
              threadId: Process.getCurrentThreadId(),
              returnValue: safeAddress(retval)
            });
          }
        });
        installed.push(spec.name + '+0x' + spec.offset.toString(16));
      } catch (error) {
        emit('ME_JM_HOOK_ERROR', {
          symbol: spec.name,
          moduleOffset: '0x' + spec.offset.toString(16),
          error: String(error)
        });
      }
    });

    emit('ME_JM_OBSERVER_READY', {
      module: module.name,
      modulePath: module.path,
      base: module.base.toString(),
      size: module.size,
      uuid: actualUuid,
      expectedUuid: CONFIG.expectedUuid,
      installed: installed,
      note: 'read-only observation; no replacement or anti-debug bypass installed'
    });
  }

  const started = Date.now();
  const timer = setInterval(function () {
    const module = findTargetModule();
    if (module) {
      clearInterval(timer);
      install(module);
    } else if (Date.now() - started >= CONFIG.waitMs) {
      clearInterval(timer);
      emit('ME_JM_OBSERVER_MODULE_TIMEOUT', { moduleName: CONFIG.moduleName, waitedMs: CONFIG.waitMs });
    }
  }, 100);

  emit('ME_JM_OBSERVER_START', {
    moduleName: CONFIG.moduleName,
    expectedUuid: CONFIG.expectedUuid,
    offsets: CONFIG.offsets.map(function (spec) { return spec.name + '+0x' + spec.offset.toString(16); })
  });
})();
