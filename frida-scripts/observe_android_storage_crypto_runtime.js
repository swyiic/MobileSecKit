// @description Observe Android storage and cryptography API metadata without logging stored values, keys or plaintext.
Java.perform(function () {
  function emit(type, payload) {
    console.log('ME_ANDROID_STORAGE_CRYPTO_RUNTIME:' + JSON.stringify(Object.assign({ type: type, pid: Process.id }, payload || {})));
  }
  function install(className, methodName, callback) {
    try {
      var method = Java.use(className)[methodName];
      method.overloads.forEach(function (overload) {
        overload.implementation = function () {
          try { callback.call(this, arguments); } catch (_) {}
          return overload.apply(this, arguments);
        };
      });
    } catch (error) {
      emit('hook-unavailable', { target: className + '.' + methodName, error: String(error).slice(0, 180) });
    }
  }

  emit('observer-ready', { arch: Process.arch, valueCapture: false });
  install('android.app.SharedPreferencesImpl', 'getString', function (args) {
    emit('sharedpreferences-read', { key: args.length ? String(args[0]) : '' });
  });
  ['getInt', 'getLong', 'getFloat', 'getBoolean', 'getStringSet'].forEach(function (name) {
    install('android.app.SharedPreferencesImpl', name, function (args) {
      emit('sharedpreferences-read', { operation: name, key: args.length ? String(args[0]) : '' });
    });
  });
  install('android.app.SharedPreferencesImpl$EditorImpl', 'putString', function (args) {
    emit('sharedpreferences-write', { key: args.length ? String(args[0]) : '' });
  });
  ['putInt', 'putLong', 'putFloat', 'putBoolean', 'putStringSet', 'remove', 'clear'].forEach(function (name) {
    install('android.app.SharedPreferencesImpl$EditorImpl', name, function (args) {
      emit('sharedpreferences-write', { operation: name, key: args.length ? String(args[0]) : '' });
    });
  });
  install('javax.crypto.Cipher', 'getInstance', function (args) {
    emit('cipher-instance', { transformation: args.length ? String(args[0]) : '' });
  });
  install('javax.crypto.Cipher', 'init', function (args) {
    emit('cipher-init', { operationMode: args.length ? Number(args[0]) : null, algorithm: String(this.getAlgorithm()) });
  });
  install('java.security.KeyStore', 'getInstance', function (args) {
    emit('keystore-instance', { type: args.length ? String(args[0]) : '' });
  });
});
