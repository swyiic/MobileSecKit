// @description Read-only process identity and loaded module inventory.
console.log(JSON.stringify({
  pid: Process.id,
  arch: Process.arch,
  platform: Process.platform,
  modules: Process.enumerateModules().slice(0, 80).map(function (module) {
    return { name: module.name, base: module.base.toString(), size: module.size };
  })
}, null, 2));
