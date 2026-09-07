'use strict';

// @description Read-only iOS JSBridge observer for authorized testing. It records WebKit/JavaScriptCore bridge registration, messages, origins, navigation, and native JavaScript execution without modifying app behavior.
(function () {
  const VERSION = '1.0.0';
  const MAX_EVENTS = 500;
  const MAX_PREVIEW = 360;
  const MAX_COLLECTION_ITEMS = 30;
  const RESCAN_LIMIT = 8;
  const hookedImplementations = new Set();
  const emittedRisks = new Set();
  const handlers = new Map();
  const origins = new Set();
  const navigationTargets = new Set();
  const counters = {
    emitted: 0,
    registrations: 0,
    messages: 0,
    navigations: 0,
    evaluations: 0,
    legacyCalls: 0,
    risks: 0,
    hookErrors: 0
  };
  let appOwnedClassNames = null;

  function candidateClassNames() {
    if (appOwnedClassNames !== null) return appOwnedClassNames;
    const appModules = Process.enumerateModules().filter(function (module) {
      return module.name === Process.mainModule.name || module.path.indexOf('.app/') !== -1;
    });
    const modules = new Set(appModules.map(function (module) { return module.name; }));
    appOwnedClassNames = Object.keys(ObjC.classes).filter(function (name) {
      try {
        const klass = ObjC.classes[name];
        const owner = String(klass.$moduleName || '');
        if (owner.indexOf('.app/') !== -1 || modules.has(owner)) return true;
        return (klass.$ownMethods || []).some(function (methodName) {
          try {
            const method = klass[methodName];
            const module = method && method.implementation ? Process.findModuleByAddress(method.implementation) : null;
            return !!module && (modules.has(module.name) || module.path.indexOf('.app/') !== -1);
          } catch (_) { return false; }
        });
      }
      catch (_) { return false; }
    });
    emit('jsbridge-app-class-scope', {
      appModuleCount: modules.size,
      candidateClassCount: appOwnedClassNames.length,
      totalRuntimeClassCount: Object.keys(ObjC.classes).length
    }, true);
    return appOwnedClassNames;
  }

  function safeString(value) {
    try { return String(value); } catch (_) { return ''; }
  }

  function bounded(value, limit) {
    const text = safeString(value);
    const cap = limit || MAX_PREVIEW;
    return text.length > cap ? text.slice(0, cap) + '…' : text;
  }

  function redact(value) {
    let text = bounded(value, MAX_PREVIEW * 2);
    if (!text) return text;
    text = text.replace(/((?:authorization|cookie|password|passwd|token|access_token|refresh_token|secret|api[_-]?key|session(?:id)?)\s*["']?\s*[:=]\s*["']?)([^\s,;}&"']+)/ig, '$1<redacted>');
    text = text.replace(/\bBearer\s+[A-Za-z0-9._~+\/-]{8,}/ig, 'Bearer <redacted>');
    text = text.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?/g, '<redacted-jwt>');
    return bounded(text, MAX_PREVIEW);
  }

  function emit(type, payload, force) {
    if (!force && counters.emitted >= MAX_EVENTS) return;
    counters.emitted++;
    try {
      const timestampMs = Date.now();
      console.log(JSON.stringify(Object.assign({
        type: type,
        observer: 'ios-jsbridge',
        version: VERSION,
        timestamp: new Date(timestampMs).toISOString(),
        timestampMs: timestampMs
      }, payload || {})));
    } catch (error) {
      console.log(JSON.stringify({ type: 'jsbridge-observer-error', error: bounded(error, 180) }));
    }
  }

  function obj(object) {
    try {
      if (!object || object.isNull()) return null;
      return new ObjC.Object(object);
    } catch (_) { return null; }
  }

  function call(object, selector) {
    try {
      if (!object || !object[selector]) return null;
      return object[selector]();
    } catch (_) { return null; }
  }

  function objectDescription(object) {
    try {
      if (object === null || object === undefined) return '';
      const value = object.handle ? object : obj(object);
      if (!value) return bounded(object, MAX_PREVIEW);
      return redact(value.toString());
    } catch (_) { return ''; }
  }

  function className(object) {
    try {
      const value = object && object.handle ? object : obj(object);
      return value ? safeString(value.$className || '') : '';
    } catch (_) { return ''; }
  }

  function urlString(value) {
    try {
      const object = value && value.handle ? value : obj(value);
      if (!object) return '';
      const absolute = call(object, 'absoluteString');
      return bounded(absolute || object, MAX_PREVIEW);
    } catch (_) { return ''; }
  }

  function requestUrl(request) {
    try {
      const value = request && request.handle ? request : obj(request);
      return value ? urlString(call(value, 'URL')) : '';
    } catch (_) { return ''; }
  }

  function originFromUrl(url) {
    const text = safeString(url);
    const match = text.match(/^([a-z][a-z0-9+.-]*):\/\/([^\/?#]+)/i);
    return match ? (match[1].toLowerCase() + '://' + match[2].toLowerCase()) : '';
  }

  function isRemoteUrl(url) {
    return /^(?:https?|ws|wss):\/\//i.test(safeString(url));
  }

  function isInsecureRemoteUrl(url) {
    return /^(?:http|ws):\/\//i.test(safeString(url));
  }

  function sensitiveName(value) {
    return /(?:auth|login|token|password|passwd|secret|keychain|credential|sign|encrypt|decrypt|pay|payment|camera|photo|album|contact|location|clipboard|pasteboard|file|download|upload|openurl|deeplink|biometric|faceid|touchid|deviceid|execute|command)/i.test(safeString(value));
  }

  function dynamicDispatch(value) {
    return /(?:selector|classname|class_name|methodname|method_name|invoke|callnative|executenative|dispatch|performselector|nativecommand|action)/i.test(safeString(value));
  }

  function risk(key, severity, title, detail, evidence, confidence) {
    if (emittedRisks.has(key)) return;
    emittedRisks.add(key);
    counters.risks++;
    emit('jsbridge-risk-candidate', {
      severity: severity,
      confidence: confidence || 'runtime-observed',
      title: title,
      detail: detail,
      evidence: evidence || {},
      note: '这是风险候选，不等于漏洞成立；仍需验证不可信来源、可控参数、敏感原生能力及来源/权限校验链。'
    });
  }

  function recordUrl(source, url, extra) {
    if (!url) return;
    counters.navigations++;
    navigationTargets.add(url);
    const origin = originFromUrl(url);
    if (origin) origins.add(origin);
    emit('jsbridge-navigation', Object.assign({ source: source, url: url, origin: origin }, extra || {}));
    if (isInsecureRemoteUrl(url)) {
      risk('insecure-url:' + origin, 'high', 'WebView 加载明文远程内容',
        '观察到 WebView/桥接容器访问 HTTP 或 WS 地址。ATS 例外或 Web 内容任意加载可能扩大中间人注入后调用原生 Bridge 的风险。',
        { source: source, url: url }, 'runtime-observed');
    }
    if (isRemoteUrl(url) && handlers.size > 0) {
      const pageHandlers = [];
      handlers.forEach(function (value, name) {
        if (!value.contentWorld || /page/i.test(value.contentWorld)) pageHandlers.push(name);
      });
      if (pageHandlers.length > 0) {
        risk('remote-page-bridge:' + origin, 'review', '远程页面与 Page World Bridge 同时存在',
          '观察到远程 Web 内容，且至少一个消息处理器位于默认/Page World。需要确认导航白名单、frame/origin 校验以及 handler 的权限边界。',
          { origin: origin, handlers: pageHandlers.slice(0, MAX_COLLECTION_ITEMS) }, 'runtime-observed');
      }
    }
  }

  function contentWorldName(world) {
    try {
      if (!world) return '';
      const name = call(world, 'name');
      if (name) return bounded(name, 120);
      return objectDescription(world);
    } catch (_) { return ''; }
  }

  function hookMethod(classNameValue, selector, callbacks, label) {
    try {
      const klass = ObjC.classes[classNameValue];
      const method = klass && klass[selector];
      if (!method || !method.implementation) return false;
      const implementation = method.implementation.toString();
      const key = selector + '@' + implementation;
      if (hookedImplementations.has(key)) return false;
      hookedImplementations.add(key);
      Interceptor.attach(method.implementation, callbacks);
      emit('jsbridge-hook-installed', {
        className: classNameValue,
        selector: selector,
        implementation: implementation,
        label: label || ''
      });
      return true;
    } catch (error) {
      counters.hookErrors++;
      emit('jsbridge-hook-error', { className: classNameValue, selector: selector, error: bounded(error, 220) });
      return false;
    }
  }

  function hookBridgeRegistration() {
    const classNameValue = 'WKUserContentController';
    hookMethod(classNameValue, '- addScriptMessageHandler:name:', {
      onEnter: function (args) {
        try {
          const handler = obj(args[2]);
          const name = objectDescription(obj(args[3]));
          counters.registrations++;
          handlers.set(name, { handlerClass: className(handler), contentWorld: 'WKContentWorld.page (legacy/default)' });
          emit('jsbridge-handler-registered', {
            api: 'addScriptMessageHandler:name:',
            name: name,
            handlerClass: className(handler),
            contentWorld: 'WKContentWorld.page (legacy/default)',
            pageWorld: true
          });
          if (sensitiveName(name)) {
            risk('sensitive-handler:' + name, 'review', '发现敏感能力命名的 JSBridge Handler',
              'Handler 名称暗示认证、凭据、文件、支付、设备权限或动态命令能力。需确认来源、frame、参数 schema 和业务授权校验。',
              { handler: name, handlerClass: className(handler) }, 'runtime-observed');
          }
          if (dynamicDispatch(name)) {
            risk('dynamic-handler:' + name, 'high', '发现动态分发型 JSBridge Handler',
              'Handler 名称暗示由 JavaScript 指定原生类、方法或命令。若缺少严格 allowlist，可能形成扩大化原生调用面。',
              { handler: name, handlerClass: className(handler) }, 'runtime-observed');
          }
        } catch (error) { emit('jsbridge-runtime-error', { source: 'handler registration', error: bounded(error, 200) }); }
      }
    }, 'bridge-registration');

    [
      '- addScriptMessageHandler:contentWorld:name:',
      '- addScriptMessageHandlerWithReply:contentWorld:name:'
    ].forEach(function (selector) {
      hookMethod(classNameValue, selector, {
        onEnter: function (args) {
          try {
            const handler = obj(args[2]);
            const world = obj(args[3]);
            const name = objectDescription(obj(args[4]));
            const worldName = contentWorldName(world);
            const pageWorld = !worldName || /page/i.test(worldName);
            counters.registrations++;
            handlers.set(name, { handlerClass: className(handler), contentWorld: worldName });
            emit('jsbridge-handler-registered', {
              api: selector.slice(2),
              name: name,
              handlerClass: className(handler),
              contentWorld: worldName,
              pageWorld: pageWorld,
              replyCapable: selector.indexOf('WithReply') !== -1
            });
            if (pageWorld) {
              risk('page-world-handler:' + name, 'review', 'JSBridge Handler 暴露在 Page World',
                'Page World 中页面脚本可见该 Handler。它不是单独的漏洞，但远程内容、XSS 或受污染脚本可因此触达原生能力。',
                { handler: name, contentWorld: worldName || '<unknown>' }, 'runtime-observed');
            }
            if (sensitiveName(name) || dynamicDispatch(name)) {
              risk('sensitive-or-dynamic-handler:' + name, dynamicDispatch(name) ? 'high' : 'review',
                dynamicDispatch(name) ? '发现动态分发型 JSBridge Handler' : '发现敏感能力命名的 JSBridge Handler',
                '需要检查 handler 内部是否使用严格方法 allowlist、参数类型/schema、来源/frame 和业务授权校验。',
                { handler: name, handlerClass: className(handler), contentWorld: worldName }, 'runtime-observed');
            }
          } catch (error) { emit('jsbridge-runtime-error', { source: selector, error: bounded(error, 200) }); }
        }
      }, 'bridge-registration');
    });

    [
      '- removeScriptMessageHandlerForName:',
      '- removeScriptMessageHandlerForName:contentWorld:'
    ].forEach(function (selector) {
      hookMethod(classNameValue, selector, {
        onEnter: function (args) {
          const name = objectDescription(obj(args[2]));
          handlers.delete(name);
          emit('jsbridge-handler-removed', { api: selector.slice(2), name: name });
        }
      }, 'bridge-lifecycle');
    });
  }

  function messageDetails(message) {
    const result = { name: '', bodyType: '', bodyPreview: '', frameUrl: '', origin: '', mainFrame: null };
    try {
      result.name = objectDescription(call(message, 'name'));
      const body = call(message, 'body');
      result.bodyType = className(body);
      result.bodyPreview = objectDescription(body);
      const frameInfo = call(message, 'frameInfo');
      if (frameInfo) {
        const request = call(frameInfo, 'request');
        result.frameUrl = requestUrl(request);
        result.origin = originFromUrl(result.frameUrl);
        try { result.mainFrame = !!call(frameInfo, 'isMainFrame'); } catch (_) {}
        const securityOrigin = call(frameInfo, 'securityOrigin');
        if (securityOrigin) {
          const scheme = objectDescription(call(securityOrigin, 'protocol'));
          const host = objectDescription(call(securityOrigin, 'host'));
          const port = objectDescription(call(securityOrigin, 'port'));
          if (scheme && host) result.securityOrigin = scheme + '://' + host + (port && port !== '0' ? ':' + port : '');
        }
      }
      const webView = call(message, 'webView');
      if (webView) result.webViewClass = className(webView);
    } catch (error) { result.error = bounded(error, 180); }
    return result;
  }

  function hookMessageImplementations() {
    const selectors = [
      '- userContentController:didReceiveScriptMessage:',
      '- userContentController:didReceiveScriptMessage:replyHandler:'
    ];
    candidateClassNames().forEach(function (name) {
      selectors.forEach(function (selector) {
        hookMethod(name, selector, {
          onEnter: function (args) {
            try {
              counters.messages++;
              const message = obj(args[3]);
              const detail = messageDetails(message);
              if (detail.origin) origins.add(detail.origin);
              emit('jsbridge-message-received', Object.assign({
                handlerClass: className(obj(args[0])),
                selector: selector.slice(2),
                replyCapable: selector.indexOf('replyHandler') !== -1
              }, detail));
              if (detail.frameUrl && isRemoteUrl(detail.frameUrl)) {
                risk('remote-message:' + detail.origin + ':' + detail.name, sensitiveName(detail.name) ? 'high' : 'review',
                  '远程来源调用了原生 JSBridge Handler',
                  '已经观察到远程 frame 的消息进入原生 handler。下一步需验证该来源是否受信、参数是否可控、handler 是否执行敏感操作及是否存在显式来源/权限校验。',
                  { handler: detail.name, frameUrl: detail.frameUrl, mainFrame: detail.mainFrame, bodyType: detail.bodyType }, 'runtime-observed');
              }
              if (dynamicDispatch(detail.name + ' ' + detail.bodyPreview)) {
                risk('dynamic-message:' + detail.name, 'high', 'Bridge 消息包含动态原生分发特征',
                  '消息名称或参数中出现 class/method/selector/invoke 等动态分发字段。需确认它们是否被严格 allowlist 约束。',
                  { handler: detail.name, bodyPreview: detail.bodyPreview, origin: detail.origin }, 'runtime-observed');
              }
            } catch (error) { emit('jsbridge-runtime-error', { source: selector, error: bounded(error, 200) }); }
          }
        }, 'incoming-message');
      });
    });
  }

  function hookNavigationDelegates() {
    const selectors = [
      '- webView:decidePolicyForNavigationAction:decisionHandler:',
      '- webView:decidePolicyForNavigationAction:preferences:decisionHandler:'
    ];
    candidateClassNames().forEach(function (name) {
      selectors.forEach(function (selector) {
        hookMethod(name, selector, {
          onEnter: function (args) {
            try {
              const action = obj(args[3]);
              const request = call(action, 'request');
              const url = requestUrl(request);
              const sourceFrame = call(action, 'sourceFrame');
              const targetFrame = call(action, 'targetFrame');
              recordUrl('WKNavigationDelegate ' + selector.slice(2), url, {
                delegateClass: className(obj(args[0])),
                sourceMainFrame: sourceFrame ? !!call(sourceFrame, 'isMainFrame') : null,
                targetMainFrame: targetFrame ? !!call(targetFrame, 'isMainFrame') : null
              });
            } catch (error) { emit('jsbridge-runtime-error', { source: selector, error: bounded(error, 200) }); }
          }
        }, 'navigation-policy');
      });
    });
  }

  function hookWebKitEntryPoints() {
    hookMethod('WKWebView', '- loadRequest:', {
      onEnter: function (args) { recordUrl('WKWebView loadRequest:', requestUrl(obj(args[2]))); }
    }, 'navigation');
    hookMethod('WKWebView', '- loadFileURL:allowingReadAccessToURL:', {
      onEnter: function (args) {
        const fileUrl = urlString(obj(args[2]));
        const readUrl = urlString(obj(args[3]));
        recordUrl('WKWebView loadFileURL:', fileUrl, { allowingReadAccessToURL: readUrl });
        if (readUrl && /file:\/\/\/?$/i.test(readUrl)) {
          risk('wide-file-read:' + readUrl, 'high', 'WKWebView 文件读取范围可能过宽',
            'allowingReadAccessToURL 指向文件系统根或异常宽泛路径时，本地页面漏洞可能扩大为读取其他本地文件。',
            { fileUrl: fileUrl, allowingReadAccessToURL: readUrl }, 'runtime-observed');
        }
      }
    }, 'navigation');
    hookMethod('WKWebView', '- loadHTMLString:baseURL:', {
      onEnter: function (args) {
        const html = objectDescription(obj(args[2]));
        const baseUrl = urlString(obj(args[3]));
        emit('jsbridge-html-load', { baseUrl: baseUrl, htmlPreview: html });
        if (baseUrl) recordUrl('WKWebView loadHTMLString:baseURL:', baseUrl);
      }
    }, 'html-load');
    hookMethod('WKWebView', '- evaluateJavaScript:completionHandler:', {
      onEnter: function (args) {
        counters.evaluations++;
        const script = objectDescription(obj(args[2]));
        emit('jsbridge-javascript-evaluation', { api: 'evaluateJavaScript:completionHandler:', scriptPreview: script });
        if (dynamicDispatch(script) || /(?:location|document\.cookie|innerHTML|postMessage|messageHandlers)/i.test(script)) {
          risk('dynamic-js-eval:' + bounded(script, 80), 'review', '原生侧执行了动态 JavaScript',
            '观察到 evaluateJavaScript 调用包含 Bridge、DOM、Cookie 或动态分发特征。需回溯脚本内容是否拼接了网络、深链或页面可控数据。',
            { scriptPreview: script }, 'runtime-observed');
        }
      }
    }, 'javascript-evaluation');
    hookMethod('WKWebView', '- callAsyncJavaScript:arguments:inFrame:inContentWorld:completionHandler:', {
      onEnter: function (args) {
        counters.evaluations++;
        const script = objectDescription(obj(args[2]));
        const argumentsObject = obj(args[3]);
        const world = obj(args[5]);
        emit('jsbridge-javascript-evaluation', {
          api: 'callAsyncJavaScript:arguments:inFrame:inContentWorld:completionHandler:',
          scriptPreview: script,
          argumentsType: className(argumentsObject),
          argumentsPreview: objectDescription(argumentsObject),
          contentWorld: contentWorldName(world)
        });
      }
    }, 'javascript-evaluation');
  }

  function hookLegacyBridges() {
    hookMethod('UIWebView', '- stringByEvaluatingJavaScriptFromString:', {
      onEnter: function (args) {
        counters.legacyCalls++;
        const script = objectDescription(obj(args[2]));
        emit('jsbridge-legacy-evaluation', { api: 'UIWebView stringByEvaluatingJavaScriptFromString:', scriptPreview: script });
        risk('uiwebview-present', 'review', '观察到已废弃 UIWebView JavaScript Bridge',
          'UIWebView 缺少 WKWebView 的现代隔离和内容世界能力。应重点检查自定义 scheme、导航白名单和脚本注入输入。',
          { scriptPreview: script }, 'runtime-observed');
      }
    }, 'legacy-bridge');
    hookMethod('JSContext', '- evaluateScript:', {
      onEnter: function (args) {
        counters.legacyCalls++;
        emit('jsbridge-jscontext-evaluation', { api: 'JSContext evaluateScript:', scriptPreview: objectDescription(obj(args[2])) });
      }
    }, 'javascriptcore');
    hookMethod('JSContext', '- setObject:forKeyedSubscript:', {
      onEnter: function (args) {
        counters.legacyCalls++;
        const key = objectDescription(obj(args[3]));
        const value = obj(args[2]);
        emit('jsbridge-jscontext-export', { api: 'JSContext setObject:forKeyedSubscript:', key: key, valueClass: className(value) });
        if (sensitiveName(key) || dynamicDispatch(key)) {
          risk('jscontext-export:' + key, 'review', 'JavaScriptCore 导出敏感/动态原生对象',
            '观察到原生对象被注入 JSContext。需审查 JSExport 暴露方法、参数校验和脚本来源。',
            { key: key, valueClass: className(value) }, 'runtime-observed');
        }
      }
    }, 'javascriptcore');
  }

  function summary(reason) {
    const handlerList = [];
    handlers.forEach(function (value, name) {
      if (handlerList.length < MAX_COLLECTION_ITEMS) {
        handlerList.push({ name: name, handlerClass: value.handlerClass, contentWorld: value.contentWorld });
      }
    });
    emit('jsbridge-observer-summary', {
      reason: reason,
      counters: counters,
      handlers: handlerList,
      origins: Array.from(origins).slice(0, MAX_COLLECTION_ITEMS),
      navigationTargets: Array.from(navigationTargets).slice(0, MAX_COLLECTION_ITEMS),
      assessmentRule: 'Attach 无法还原启动期已经完成的 Handler 注册，需用 Spawn 复测注册过程。漏洞确认仍需要：不可信/远程页面 → 可达 Handler → 攻击者可控参数 → 敏感原生操作 → 缺少或可绕过的来源/业务授权校验。'
    }, true);
  }

  function snapshotExistingDelegates() {
    const selectors = [
      '- userContentController:didReceiveScriptMessage:',
      '- userContentController:didReceiveScriptMessage:replyHandler:'
    ];
    const delegates = [];
    candidateClassNames().forEach(function (name) {
      try {
        const klass = ObjC.classes[name];
        const implemented = selectors.filter(function (selector) {
          const method = klass[selector];
          return !!(method && method.implementation);
        });
        if (implemented.length) delegates.push({ className: name, selectors: implemented });
      } catch (_) {}
    });
    emit('jsbridge-existing-delegate-snapshot', {
      delegateCount: delegates.length,
      delegates: delegates.slice(0, MAX_COLLECTION_ITEMS),
      confidence: 'runtime-observed',
      conclusion: delegates.length
        ? '发现已实现 WKScriptMessageHandler delegate 的 App 自有类；Attach 无法证明其 Handler 当前已注册，建议 Spawn 复测启动期注册。'
        : '未发现 App 自有 message handler delegate；这不等于不存在 JSBridge，动态代理、Flutter channel 或启动期卸载仍需按场景复核。'
    }, true);
    if (delegates.length) {
      risk('existing-message-handler-delegates', 'review',
        'Attach 快照发现 ' + delegates.length + ' 个消息 Handler Delegate 候选',
        '这些类实现了 WKScriptMessageHandler 回调，但 Attach 错过了启动期 addScriptMessageHandler 注册。建议用 Spawn 观察真实 Handler 名称、Content World 与消息来源。',
        { delegates: delegates.slice(0, MAX_COLLECTION_ITEMS) }, 'runtime-observed');
    }
  }

  function installStaticHooks() {
    hookBridgeRegistration();
    hookWebKitEntryPoints();
    hookLegacyBridges();
  }

  function start() {
    if (!ObjC.available) {
      emit('jsbridge-observer-unavailable', { error: 'Objective-C runtime is unavailable' }, true);
      return;
    }
    emit('jsbridge-observer-started', {
      mode: 'read-only',
      recommendedFridaMode: 'attach',
      note: '不安装反调试/证书绕过 Hook，不修改请求、导航、Bridge 参数或返回值。'
    }, true);
    snapshotExistingDelegates();
    installStaticHooks();
    let scans = 0;
    function rescan() {
      scans++;
      hookMessageImplementations();
      hookNavigationDelegates();
      if (scans === 1 || scans === 4 || scans === RESCAN_LIMIT) summary('rescan-' + scans);
      if (scans >= RESCAN_LIMIT) clearInterval(timer);
    }
    rescan();
    const timer = setInterval(rescan, 4000);
    setInterval(function () { summary('periodic'); }, 15000);
  }

  emit('jsbridge-observer-ready', { phase: 'waiting-for-app-resume' }, true);
  setTimeout(start, 1200);
}());
