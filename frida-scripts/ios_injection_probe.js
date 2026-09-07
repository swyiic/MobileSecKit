'use strict';

// Deliberately contains no ObjC access and no Interceptor hooks. If this script
// cannot print ME_IOS_INJECTION_OK, the failure happened before user JavaScript
// started and cannot be repaired by an anti-detection hook inside the script.
(function () {
  const main = Process.mainModule;
  console.log(JSON.stringify({
    type: 'ME_IOS_INJECTION_OK',
    pid: Process.id,
    arch: Process.arch,
    mainModule: {
      name: main.name,
      base: main.base.toString(),
      size: main.size,
      path: main.path
    }
  }));
})();
