// @description Observe Android network and TLS API calls without changing arguments or return values.
Java.perform(function () {
  function emit(type, payload) {
    console.log('ME_ANDROID_NETWORK_RUNTIME:' + JSON.stringify(Object.assign({ type: type, pid: Process.id }, payload || {})));
  }
  function hook(className, methodName, install) {
    try { install(Java.use(className)[methodName]); }
    catch (error) { emit('hook-unavailable', { target: className + '.' + methodName, error: String(error).slice(0, 180) }); }
  }

  emit('observer-ready', { arch: Process.arch });

  hook('java.net.URL', 'openConnection', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('url-open-connection', { url: String(this.toString()) });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('okhttp3.Request$Builder', 'url', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('okhttp-request-url', { url: arguments.length ? String(arguments[0]) : '' });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('okhttp3.RealCall', 'execute', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var request = this.request();
        emit('okhttp-call', { mode: 'execute', url: request ? String(request.url()) : '' });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('okhttp3.RealCall', 'enqueue', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var request = this.request();
        emit('okhttp-call', { mode: 'enqueue', url: request ? String(request.url()) : '' });
        return overload.apply(this, arguments);
      };
    });
  });

  ['connect', 'getInputStream', 'getOutputStream'].forEach(function (name) {
    hook('com.android.okhttp.internal.huc.HttpURLConnectionImpl', name, function (method) {
      method.overloads.forEach(function (overload) {
        overload.implementation = function () {
          emit('httpurlconnection-call', { operation: name, url: String(this.getURL()) });
          return overload.apply(this, arguments);
        };
      });
    });
  });

  hook('okhttp3.CertificatePinner', 'check', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('certificate-pinner-check', { host: arguments.length ? String(arguments[0]) : '' });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('javax.net.ssl.SSLContext', 'init', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('sslcontext-init', { protocol: String(this.getProtocol()) });
        return overload.apply(this, arguments);
      };
    });
  });

  hook('javax.net.ssl.HttpsURLConnection', 'setHostnameVerifier', function (method) {
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('hostname-verifier-set', { verifier: arguments.length && arguments[0] ? String(arguments[0].getClass().getName()) : 'null' });
        return overload.apply(this, arguments);
      };
    });
  });
});
