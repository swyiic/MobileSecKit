'use strict';

// @description Read-only iOS runtime observation for authorized testing: URLSession requests, TLS challenge metadata, trust API calls, and loaded app modules. It never changes requests or trust decisions.
(function () {
  const seen = new Set();
  const counters = { requests: 0, challenges: 0, trustCalls: 0 };
  const maxEvents = 250;

  function emit(type, payload) {
    console.log(JSON.stringify(Object.assign({ type: type }, payload || {})));
  }

  function safeString(value) {
    try { return String(value); } catch (_) { return ''; }
  }

  function redact(value) {
    const text = safeString(value);
    if (!text) return text;
    return /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)$/i.test(text)
      ? '<redacted>'
      : text.length > 512 ? text.slice(0, 512) + '…' : text;
  }

  function objectString(object, selector) {
    try {
      if (!object || !object[selector]) return '';
      return safeString(object[selector]());
    } catch (_) { return ''; }
  }

  function requestDetails(request) {
    try {
      const headers = {};
      const all = request.allHTTPHeaderFields ? request.allHTTPHeaderFields() : null;
      if (all) {
        const keys = Object.keys(all);
        keys.slice(0, 80).forEach(function (key) { headers[key] = redact(all[key]); });
      }
      return {
        url: objectString(request, 'URL'),
        method: objectString(request, 'HTTPMethod') || 'GET',
        headers: headers,
        cachePolicy: safeString(request.cachePolicy ? request.cachePolicy() : '')
      };
    } catch (error) {
      return { error: safeString(error) };
    }
  }

  function hook(selector, handler) {
    if (!ObjC.available) return 0;
    let count = 0;
    try {
      const klass = ObjC.classes.NSURLSession;
      const method = klass[selector];
      if (!method || !method.implementation) return 0;
      const key = selector + ':' + method.implementation.toString();
      if (seen.has(key)) return 0;
      seen.add(key);
      Interceptor.attach(method.implementation, { onEnter: handler });
      emit('hook-installed', { selector: selector, implementation: method.implementation.toString() });
      count++;
    } catch (error) {
      emit('hook-error', { selector: selector, error: safeString(error) });
    }
    return count;
  }

  if (!ObjC.available) {
    emit('ios-runtime-network', { error: 'Objective-C runtime is unavailable' });
    return;
  }

  const appModuleNames = new Set(Process.enumerateModules().filter(function (module) {
    return module.name === Process.mainModule.name || module.path.indexOf('.app/') !== -1;
  }).map(function (module) { return module.name; }));
  function classBelongsToApp(klass) {
    try {
      const owner = String(klass.$moduleName || '');
      if (owner.indexOf('.app/') !== -1 || appModuleNames.has(owner)) return true;
      return (klass.$ownMethods || []).some(function (name) {
        try {
          const method = klass[name];
          const module = method && method.implementation ? Process.findModuleByAddress(method.implementation) : null;
          return !!module && (appModuleNames.has(module.name) || module.path.indexOf('.app/') !== -1);
        } catch (_) { return false; }
      });
    } catch (_) { return false; }
  }
  emit('ios-runtime-network-ready', {
    pid: Process.id,
    arch: Process.arch,
    phase: 'initializing',
    maxEvents: maxEvents
  });

  // Return from script.load() before scanning Objective-C metadata. The heavy
  // work runs asynchronously and only inspects App-owned delegate classes.
  setTimeout(function () {

  hook('- dataTaskWithRequest:completionHandler:', function (args) {
    if (counters.requests >= maxEvents) return;
    counters.requests++;
    emit('urlsession-request', Object.assign({ source: 'NSURLSession dataTaskWithRequest' }, requestDetails(new ObjC.Object(args[2]))));
  });
  hook('- uploadTaskWithRequest:fromData:completionHandler:', function (args) {
    if (counters.requests >= maxEvents) return;
    counters.requests++;
    emit('urlsession-request', Object.assign({ source: 'NSURLSession uploadTaskWithRequest' }, requestDetails(new ObjC.Object(args[2]))));
  });
  hook('- downloadTaskWithRequest:completionHandler:', function (args) {
    if (counters.requests >= maxEvents) return;
    counters.requests++;
    emit('urlsession-request', Object.assign({ source: 'NSURLSession downloadTaskWithRequest' }, requestDetails(new ObjC.Object(args[2]))));
  });

  try {
    const taskClass = ObjC.classes.NSURLSessionTask;
    const resume = taskClass['- resume'];
    if (resume && resume.implementation) {
      Interceptor.attach(resume.implementation, {
        onEnter: function (args) {
          if (counters.requests >= maxEvents) return;
          try {
            const task = new ObjC.Object(args[0]);
            const request = task.currentRequest ? task.currentRequest() : null;
            if (!request) return;
            counters.requests++;
            emit('urlsession-resume', Object.assign({ source: 'NSURLSessionTask resume' }, requestDetails(request)));
          } catch (error) {
            emit('runtime-error', { source: 'NSURLSessionTask resume', error: safeString(error) });
          }
        }
      });
      emit('hook-installed', { selector: 'NSURLSessionTask - resume', implementation: resume.implementation.toString() });
    }
  } catch (error) { emit('hook-error', { selector: 'NSURLSessionTask - resume', error: safeString(error) }); }

  const challengeSelectors = [
    '- URLSession:task:didReceiveChallenge:completionHandler:',
    '- URLSession:didReceiveChallenge:completionHandler:'
  ];
  const hookedChallengeImplementations = new Set();
  Object.keys(ObjC.classes).forEach(function (className) {
    if (counters.challenges >= maxEvents) return;
    try {
      const klass = ObjC.classes[className];
      if (!classBelongsToApp(klass)) return;
      challengeSelectors.forEach(function (selector) {
        const method = klass[selector];
        if (!method || !method.implementation) return;
        const implementation = method.implementation.toString();
        if (hookedChallengeImplementations.has(implementation)) return;
        hookedChallengeImplementations.add(implementation);
        Interceptor.attach(method.implementation, {
          onEnter: function (args) {
            if (counters.challenges >= maxEvents) return;
            counters.challenges++;
            try {
              const challengeIndex = selector.indexOf(':task:') >= 0 ? 4 : 3;
              const challenge = new ObjC.Object(args[challengeIndex]);
              const protection = challenge.protectionSpace();
              emit('tls-challenge', {
                className: className,
                selector: selector,
                host: objectString(protection, 'host'),
                authenticationMethod: objectString(protection, 'authenticationMethod'),
                serverTrustPresent: !!(protection.serverTrust && protection.serverTrust())
              });
            } catch (error) { emit('runtime-error', { source: selector, error: safeString(error) }); }
          }
        });
        emit('hook-installed', { className: className, selector: selector, implementation: implementation });
      });
    } catch (_) {}
  }, 1200);

  ['SecTrustEvaluate', 'SecTrustEvaluateWithError', 'SecItemCopyMatching', 'SecItemAdd', 'SecItemUpdate', 'SecItemDelete'].forEach(function (name) {
    const address = Module.findGlobalExportByName(name);
    if (!address) return;
    Interceptor.attach(address, {
      onEnter: function () {
        if (name.indexOf('SecTrust') === 0) counters.trustCalls++;
        if (counters.trustCalls <= maxEvents) emit('security-api-call', { name: name });
      },
      onLeave: function (retval) {
        if (counters.trustCalls <= maxEvents) emit('security-api-return', { name: name, returnValue: retval.toString() });
      }
    });
    emit('hook-installed', { function: name, address: address.toString() });
  });

  const modules = Process.enumerateModules().filter(function (module) {
    return module.path.indexOf('.app/') !== -1 || /ssl|crypto|boring|nio|afnetwork|alamofire|webkit/i.test(module.name);
  }).map(function (module) {
    return { name: module.name, base: module.base.toString(), size: module.size, path: module.path };
  });
  emit('loaded-network-modules', { modules: modules });
  emit('ios-runtime-network-initialized', {
    pid: Process.id,
    arch: Process.arch,
    appModuleCount: appModuleNames.size,
    installedHooks: seen.size + hookedChallengeImplementations.size
  });
  });
})();
