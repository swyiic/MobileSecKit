'use strict';

// Scoped iOS compatibility hooks for authorized testing. The bootstrap only
// changes calls originating from modules inside the target .app bundle, so
// Frida's own agent/runtime calls are not modified.
(function () {
  const profile = String(globalThis.__ME_IOS_COMPATIBILITY_PROFILE || 'compat').toLowerCase();
  if (profile === 'minimal' || profile === 'none') {
    console.log('[MobileE] iOS compatibility profile=minimal (no hooks)');
    return;
  }

  const installed = [];
  function exp(name) {
    try { return Module.getGlobalExportByName(name); } catch (_) { return null; }
  }
  function isAppCaller(address) {
    try {
      const module = Process.findModuleByAddress(address);
      return !!module && module.path.indexOf('.app/') !== -1;
    } catch (_) {
      return false;
    }
  }
  function appCall(context) {
    return isAppCaller(context.returnAddress);
  }

  // PT_DENY_ATTACH is safe to neutralize when the request came from App code.
  const ptrace = exp('ptrace');
  if (ptrace) {
    Interceptor.attach(ptrace, {
      onEnter(args) {
        this.block = appCall(this) && args[0].toInt32() === 31;
        if (this.block) args[0] = ptr(-1);
      },
      onLeave(retval) {
        if (this.block) retval.replace(0);
      }
    });
    installed.push('ptrace(PT_DENY_ATTACH)');
  }

  const jailbreakMarkers = [
    '/Applications/Cydia.app', '/Applications/Sileo.app', '/Applications/Zebra.app',
    '/var/jb/', '/usr/sbin/frida-server', '/usr/bin/frida-server',
    '/usr/lib/frida', '/usr/lib/libfrida-agent', '/Library/MobileSubstrate',
    '/usr/lib/TweakInject', '/bin/bash', '/bin/su', '/usr/bin/ssh',
    '/private/var/lib/cydia', '/var/lib/cydia'
  ];
  function isJailbreakPath(path) {
    if (!path) return false;
    return jailbreakMarkers.some(function (marker) { return path.indexOf(marker) !== -1; });
  }

  if (typeof ObjC !== 'undefined' && ObjC.available) {
    try {
      const manager = ObjC.classes.NSFileManager;
      ['- fileExistsAtPath:', '- fileExistsAtPath:isDirectory:'].forEach(function (selector) {
        const method = manager[selector];
        if (!method) return;
        Interceptor.attach(method.implementation, {
          onEnter(args) {
            this.block = appCall(this);
            if (this.block) {
              try { this.block = isJailbreakPath(ObjC.Object(args[2]).toString()); } catch (_) { this.block = false; }
            }
          },
          onLeave(retval) {
            if (this.block) retval.replace(0);
          }
        });
        installed.push('NSFileManager ' + selector);
      });
    } catch (error) {
      console.log('[MobileE] NSFileManager compatibility hook skipped: ' + error);
    }
  }

  ['stat', 'stat64', 'lstat', 'lstat64', 'access'].forEach(function (name) {
    const target = exp(name);
    if (!target) return;
    Interceptor.attach(target, {
      onEnter(args) {
        this.block = appCall(this);
        if (this.block) {
          try { this.block = isJailbreakPath(args[0].readCString()); } catch (_) { this.block = false; }
        }
      },
      onLeave(retval) {
        if (this.block) {
          retval.replace(-1);
          this.errno = 2;
        }
      }
    });
    installed.push(name + '(jb-path-only)');
  });

  if (profile === 'aggressive') {
    const taskGetExceptionPorts = exp('task_get_exception_ports');
    if (taskGetExceptionPorts) {
      Interceptor.attach(taskGetExceptionPorts, {
        onEnter() { this.block = appCall(this); },
        onLeave(retval) { if (this.block) retval.replace(5); }
      });
      installed.push('task_get_exception_ports');
    }

    const taskInfo = exp('task_info');
    if (taskInfo) {
      Interceptor.attach(taskInfo, {
        onEnter(args) {
          this.block = appCall(this) && args[2].toInt32() === 13;
        },
        onLeave(retval) { if (this.block) retval.replace(5); }
      });
      installed.push('task_info(TASK_DYLD_INFO)');
    }

    const dlsym = exp('dlsym');
    if (dlsym) {
      Interceptor.attach(dlsym, {
        onEnter(args) {
          if (!appCall(this)) return;
          try {
            const symbol = args[1].readCString();
            if (symbol && /frida|gum/i.test(symbol)) args[1] = Memory.allocUtf8String('_dyld_private');
          } catch (_) {}
        }
      });
      installed.push('dlsym(frida/gum)');
    }

    const kill = exp('kill');
    if (kill) {
      Interceptor.attach(kill, {
        onEnter(args) {
          if (!appCall(this)) return;
          const signal = args[1].toInt32();
          const pid = args[0].toInt32();
          if ((pid === Process.id || pid <= 0) && (signal === 9 || signal === 15)) args[1] = 0;
        }
      });
      installed.push('kill(self)');
    }

    ['pthread_kill', '__pthread_kill'].forEach(function (name) {
      const target = exp(name);
      if (!target) return;
      Interceptor.attach(target, {
        onEnter(args) {
          if (!appCall(this)) return;
          const signal = args[1].toInt32();
          if (signal === 3 || signal === 6 || signal === 9 || signal === 15) args[1] = 0;
        }
      });
      installed.push(name);
    });

    const raise = exp('raise');
    if (raise) {
      Interceptor.attach(raise, {
        onEnter(args) {
          if (!appCall(this)) return;
          const signal = args[0].toInt32();
          if (signal === 3 || signal === 6 || signal === 9 || signal === 15) args[0] = 0;
        }
      });
      installed.push('raise');
    }
  }

  console.log('[MobileE] iOS compatibility profile=' + profile + ' · scoped hooks: ' + installed.join(', '));
})();
