// @description 只读枚举 Android ClassLoader 委派链、dexElements 与类名样本。
'use strict';

const RESULT_PREFIX = 'ME_CLASSLOADER_RESULT:';
const MAX_LOADERS = 96;
const MAX_HIERARCHY_DEPTH = 16;
const MAX_CLASSES_PER_DEX = 200;
const MAX_CLASS_COUNT = 50000;

function asString(value) {
  try { return value === null || value === undefined ? '' : String(value); }
  catch (_) { return '<unprintable>'; }
}

Java.perform(function () {
  const DexFile = Java.use('dalvik.system.DexFile');

  function findField(target, name) {
    if (!target) return null;
    let type = null;
    try { type = target.getClass(); } catch (_) { return null; }
    while (type) {
      try {
        const field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
      } catch (_) {}
      try { type = type.getSuperclass(); } catch (_) { type = null; }
    }
    return null;
  }

  function classNameOf(target) {
    try { return asString(target.getClass().getName()); }
    catch (_) { return target && target.$className ? target.$className : '<unknown>'; }
  }

  function hierarchyOf(loader) {
    const hierarchy = [];
    const seen = new Set();
    let current = loader;
    while (current && hierarchy.length < MAX_HIERARCHY_DEPTH) {
      const identity = classNameOf(current) + ':' + asString(current);
      if (seen.has(identity)) break;
      seen.add(identity);
      hierarchy.push({ type: classNameOf(current), value: asString(current) });
      try { current = current.getParent(); } catch (_) { current = null; }
    }
    return hierarchy;
  }

  function classNamesFromEntries(dexFile) {
    const classes = [];
    let classCount = 0;
    let truncated = false;
    try {
      const entries = dexFile.entries();
      while (entries.hasMoreElements()) {
        const name = asString(entries.nextElement());
        classCount += 1;
        if (classes.length < MAX_CLASSES_PER_DEX) classes.push(name);
        if (classCount >= MAX_CLASS_COUNT) {
          truncated = entries.hasMoreElements();
          break;
        }
      }
    } catch (_) {}
    return { classCount, classes, truncated: truncated || classCount > classes.length };
  }

  function classNamesFromCookie(dexFile) {
    const cookies = [findField(dexFile, 'mCookie'), findField(dexFile, 'mInternalCookie')];
    for (const cookie of cookies) {
      if (!cookie) continue;
      try {
        if (!DexFile.getClassNameList) continue;
        const names = DexFile.getClassNameList(cookie);
        if (!names) continue;
        const classes = [];
        const classCount = Number(names.length || 0);
        for (let index = 0; index < Math.min(classCount, MAX_CLASSES_PER_DEX); index += 1) {
          classes.push(asString(names[index]));
        }
        return { classCount, classes, truncated: classCount > classes.length };
      } catch (_) {}
    }
    return null;
  }

  function inspectDexFile(dexFile, elementIndex) {
    let path = '';
    try { path = asString(dexFile.getName()); } catch (_) {}
    if (!path) path = asString(dexFile);
    const names = classNamesFromCookie(dexFile) || classNamesFromEntries(dexFile);
    return {
      elementIndex,
      path,
      classCount: names.classCount,
      classes: names.classes,
      truncated: names.truncated
    };
  }

  function inspectLoader(loader) {
    const dexFiles = [];
    const errors = [];
    const pathList = findField(loader, 'pathList');
    if (pathList) {
      const elements = findField(pathList, 'dexElements');
      if (elements) {
        const length = Number(elements.length || 0);
        for (let index = 0; index < length; index += 1) {
          try {
            const element = elements[index];
            const dexFile = findField(element, 'dexFile');
            if (dexFile) dexFiles.push(inspectDexFile(dexFile, index));
          } catch (error) {
            errors.push(`dexElements[${index}]: ${asString(error)}`);
          }
        }
      }
    }
    return {
      type: classNameOf(loader),
      value: asString(loader),
      hierarchy: hierarchyOf(loader),
      dexFiles,
      errors
    };
  }

  const classLoaders = [];
  const topLevelErrors = [];
  try {
    Java.enumerateClassLoaders({
      onMatch(loader) {
        if (classLoaders.length >= MAX_LOADERS) return;
        try { classLoaders.push(inspectLoader(loader)); }
        catch (error) { topLevelErrors.push(asString(error)); }
      },
      onComplete() {
        console.log(RESULT_PREFIX + JSON.stringify({
          pid: Process.id,
          arch: Process.arch,
          classLoaders,
          truncated: classLoaders.length >= MAX_LOADERS,
          errors: topLevelErrors
        }));
      }
    });
  } catch (error) {
    console.log(RESULT_PREFIX + JSON.stringify({
      pid: Process.id,
      arch: Process.arch,
      classLoaders: [],
      truncated: false,
      errors: [asString(error)]
    }));
  }
});
