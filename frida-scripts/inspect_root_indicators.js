// @description Report common root-indicator paths and properties for a test report; it does not hide or alter them.
Java.perform(function () {
  var paths = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/data/adb/magisk'];
  var results = paths.map(function (path) {
    var exists = false;
    try { var file = new File(path, 'r'); exists = true; file.close(); } catch (e) {}
    return { path: path, exists: exists };
  });
  console.log(JSON.stringify({ indicators: results }, null, 2));
});
