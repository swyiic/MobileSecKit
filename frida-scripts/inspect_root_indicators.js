// @description Report common root-indicator paths and properties for a test report; it does not hide or alter them.
Java.perform(function () {
  var paths = [
    '/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su',
    '/system/app/Superuser.apk', '/system/app/Magisk.apk', '/data/adb/magisk',
    '/data/adb/modules', '/data/adb/ksu', '/data/local/tmp/frida-server'
  ];
  var results = paths.map(function (path) {
    var exists = false;
    try { var file = new File(path, 'r'); exists = true; file.close(); } catch (e) {}
    return { path: path, exists: exists };
  });
  var packages = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.koushikdutta.superuser', 'me.weishu.kernelsu', 'me.bmax.apatch'];
  var context = Java.use('android.app.ActivityThread').currentApplication();
  var manager = context ? context.getPackageManager() : null;
  var packageResults = packages.map(function (name) {
    var installed = false;
    try { manager.getPackageInfo(name, 0); installed = true; } catch (_) {}
    return { packageName: name, installed: installed };
  });
  var SystemProperties = Java.use('android.os.SystemProperties');
  var properties = ['ro.debuggable', 'ro.secure', 'ro.build.tags'].map(function (name) {
    var value = '';
    try { value = String(SystemProperties.get(name)); } catch (_) {}
    return { name: name, value: value };
  });
  console.log('ME_ANDROID_ROOT_INDICATORS:' + JSON.stringify({ indicators: results, packages: packageResults, properties: properties }));
});
