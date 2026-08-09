// @description Inventory loaded networking modules and exported symbols without changing behavior.
var names = Process.enumerateModules().filter(function (module) {
  return /ssl|crypto|boring|conscrypt|okhttp|network/i.test(module.name);
}).map(function (module) {
  return { name: module.name, base: module.base.toString(), exports: module.enumerateExports().slice(0, 40).map(function (item) { return item.name; }) };
});
console.log(JSON.stringify({ candidates: names }, null, 2));
