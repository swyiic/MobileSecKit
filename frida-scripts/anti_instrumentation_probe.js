// @description 零 Hook、只读地采集 Android 进程中的反插桩运行时证据。
(async function () {
  const result = {
    pid: Process.id,
    platform: Process.platform,
    arch: Process.arch,
    maps: [],
    tracerPid: null,
    threads: [],
    modules: [],
    ports: [],
    errors: []
  };

  function readText(path) {
    try {
      return File.readAllText(path);
    } catch (error) {
      result.errors.push(path + ': ' + String(error));
      return '';
    }
  }

  try {
    const maps = readText('/proc/self/maps');
    result.maps = maps.split('\n').filter(function (line) {
      const lower = line.toLowerCase();
      return ['frida', 'gadget', 'gum', 'dobby', 'substrate', 'xposed', 'libhooker']
        .some(function (signal) { return lower.indexOf(signal) !== -1; });
    }).slice(0, 100);

    const status = readText('/proc/self/status');
    const tracer = status.match(/^TracerPid:\s*(\d+)/m);
    result.tracerPid = tracer ? Number(tracer[1]) : null;

    result.threads = Process.enumerateThreads().map(function (thread) {
      const name = readText('/proc/self/task/' + thread.id + '/comm').trim();
      return { id: thread.id, name: name, state: thread.state };
    }).filter(function (thread) {
      const lower = thread.name.toLowerCase();
      return ['gum-js-loop', 'gmain', 'linjector', 'gdbus', 'frida', 'gum-js']
        .some(function (signal) { return lower.indexOf(signal) !== -1; });
    }).slice(0, 100);

    result.modules = Process.enumerateModules().filter(function (module) {
      const lower = (module.name + ' ' + module.path).toLowerCase();
      return ['frida', 'gadget', 'gum', 'dobby', 'substrate', 'xposed', 'libhooker']
        .some(function (signal) { return lower.indexOf(signal) !== -1; });
    }).map(function (module) {
      return { name: module.name, path: module.path, base: module.base.toString(), size: module.size };
    }).slice(0, 100);

    // Read actual listening sockets. Hardened deployments use random ports,
    // making a fixed 27042/27043 probe misleading.
    ['/proc/net/tcp', '/proc/net/tcp6'].forEach(function (path) {
      readText(path).split('\n').slice(1).forEach(function (line) {
        const fields = line.trim().split(/\s+/);
        if (fields.length < 4 || fields[3] !== '0A') return;
        const local = fields[1] || '';
        const separator = local.lastIndexOf(':');
        if (separator < 0) return;
        const port = parseInt(local.slice(separator + 1), 16);
        if (!Number.isFinite(port)) return;
        if (!result.ports.some(function (item) { return item.port === port; })) {
          result.ports.push({ port: port, state: 'listen', source: path });
        }
      });
    });
  } catch (error) {
    result.errors.push(String(error));
  }

  console.log('ME_ANTI_INSTRUMENTATION_RESULT:' + JSON.stringify(result));
})();
