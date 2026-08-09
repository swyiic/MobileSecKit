// @description Read-only Java runtime availability and class-loader summary.
Java.perform(function () {
  var classes = Java.enumerateLoadedClassesSync();
  console.log(JSON.stringify({ java: true, loadedClasses: classes.length, sample: classes.slice(0, 120) }, null, 2));
});
