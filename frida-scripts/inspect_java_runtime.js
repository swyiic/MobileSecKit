// @description Read-only Java/ART runtime and ClassLoader summary.
Java.perform(function () {
  var classes = Java.enumerateLoadedClassesSync();
  var loaders = [];
  try {
    Java.enumerateClassLoaders({
      onMatch: function (loader) { if (loaders.length < 80) loaders.push(String(loader)); },
      onComplete: function () {}
    });
  } catch (error) {
    loaders.push('enumerateClassLoaders failed: ' + String(error));
  }
  console.log('ME_ANDROID_JAVA_RUNTIME:' + JSON.stringify({
    pid: Process.id,
    arch: Process.arch,
    java: true,
    loadedClasses: classes.length,
    classLoaders: loaders,
    sample: classes.slice(0, 160)
  }));
});
