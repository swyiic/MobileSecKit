'use strict';

// Read-only Objective-C runtime inventory for authorized application testing.
// It does not modify trust checks, anti-debugging, or application behavior.
(function () {
  if (!ObjC.available) {
    console.log(JSON.stringify({ type: 'objc-runtime', error: 'Objective-C runtime is unavailable' }));
    return;
  }

  const main = Process.mainModule;
  const appModules = Process.enumerateModules().filter(function (module) {
    return module.name === main.name || module.path.indexOf('.app/') !== -1;
  });
  const appModuleNames = new Set(appModules.map(function (module) { return module.name; }));
  function classBelongsToApp(klass) {
    try {
      const owner = String(klass.$moduleName || '');
      if (owner.indexOf('.app/') !== -1 || appModuleNames.has(owner)) return true;
      const methods = klass.$ownMethods || [];
      return methods.some(function (name) {
        try {
          const method = klass[name];
          const module = method && method.implementation
            ? Process.findModuleByAddress(method.implementation) : null;
          return !!module && (appModuleNames.has(module.name) || module.path.indexOf('.app/') !== -1);
        } catch (_) { return false; }
      });
    } catch (_) { return false; }
  }
  console.log(JSON.stringify({
    type: 'objc-runtime-ready',
    pid: Process.id,
    arch: Process.arch,
    appModules: appModules.map(function (module) { return module.name; })
  }));

  // Yield before touching ObjC.classes. Enumerating every class and method in
  // one script-load callback can block Frida's load RPC long enough for the UI
  // to report an attach timeout even though injection succeeded.
  setTimeout(function () {
    const rows = [];
    let discoveredMethods = 0;
    const maxRows = 400;
    const securityFocus = /(?:url|http|request|session|trust|challenge|cert|webview|script|message|bridge|open|auth|login|token|password|keychain|credential|encrypt|decrypt|crypto|pasteboard|file|path|load|plugin|methodcall|channel|database|sqlite|userdefault|jailbreak|frida|debug|ptrace|sysctl)/i;
    const allClasses = Object.keys(ObjC.classes).sort();
    const classes = [];

  allClasses.forEach(function (className) {
    let klass;
    try {
      klass = ObjC.classes[className];
    } catch (_) {
      return;
    }
    if (!classBelongsToApp(klass)) return;
    classes.push(className);
    let methods = [];
    try {
      methods = klass.$ownMethods || [];
    } catch (_) {
      return;
    }
    methods.forEach(function (methodName) {
      try {
        const method = klass[methodName];
        if (!method || !method.implementation) return;
        const implementation = method.implementation;
        const module = Process.findModuleByAddress(implementation);
        if (!module || !appModuleNames.has(module.name)) return;
        discoveredMethods++;
        if (!securityFocus.test(className + ' ' + methodName) || rows.length >= maxRows) return;
        rows.push({
          className: className,
          method: methodName,
          implementation: implementation.toString(),
          module: module.name,
          modulePath: module.path,
          moduleOffset: implementation.sub(module.base).toString(),
          type: methodName.indexOf('+ ') === 0 ? 'class-method' : 'instance-method'
        });
      } catch (error) {
        rows.push({ className: className, method: methodName, error: String(error) });
      }
    });
  }, 1200);

  console.log(JSON.stringify({
    type: 'objc-runtime-summary',
    pid: Process.id,
    arch: Process.arch,
    mainModule: { name: main.name, base: main.base.toString(), path: main.path },
    appModules: appModules.map(function (module) {
      return { name: module.name, base: module.base.toString(), size: module.size, path: module.path };
    }),
    classCount: classes.length,
    totalRuntimeClassCount: allClasses.length,
    appOwnedMethodCount: discoveredMethods,
    securityFocusedMethodCount: rows.length,
    truncated: rows.length >= maxRows
  }));

  const chunkSize = 50;
  for (let offset = 0; offset < rows.length; offset += chunkSize) {
    console.log(JSON.stringify({
      type: 'objc-runtime-methods',
      offset: offset,
      rows: rows.slice(offset, offset + chunkSize)
    }));
  }
  });
})();
