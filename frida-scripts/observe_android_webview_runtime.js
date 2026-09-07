// @description Observe Android WebView navigation, JavaScript evaluation and bridge registration without altering behavior.
Java.perform(function () {
  function emit(type, payload) {
    console.log('ME_ANDROID_WEBVIEW_RUNTIME:' + JSON.stringify(Object.assign({ type: type, pid: Process.id }, payload || {})));
  }
  function bounded(value, limit) {
    var text = String(value == null ? '' : value);
    return text.length > limit ? text.slice(0, limit) + '…' : text;
  }
  function hook(methodName, install) {
    try { install(Java.use('android.webkit.WebView')[methodName]); }
    catch (error) { emit('hook-unavailable', { target: 'WebView.' + methodName, error: bounded(error, 180) }); }
  }

  emit('observer-ready', { arch: Process.arch });

  hook('addJavascriptInterface', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var objectName = arguments.length > 1 ? String(arguments[1]) : '';
        var className = arguments.length && arguments[0] ? String(arguments[0].getClass().getName()) : 'null';
        emit('javascript-interface-registered', { name: objectName, className: className });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('loadUrl', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('webview-navigation', { url: arguments.length ? bounded(arguments[0], 500) : '' });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('postUrl', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('webview-post', { url: arguments.length ? bounded(arguments[0], 500) : '', bodyBytes: arguments.length > 1 && arguments[1] ? arguments[1].length : 0 });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('loadData', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('webview-load-data', { mimeType: arguments.length > 1 ? String(arguments[1]) : '', preview: arguments.length ? bounded(arguments[0], 240) : '' });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('loadDataWithBaseURL', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('webview-load-data', { baseUrl: arguments.length ? bounded(arguments[0], 500) : '', mimeType: arguments.length > 2 ? String(arguments[2]) : '' });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('evaluateJavascript', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('javascript-evaluation', { script: arguments.length ? bounded(arguments[0], 500) : '' });
        return overload.apply(this, arguments);
      };
    });
  });
});
