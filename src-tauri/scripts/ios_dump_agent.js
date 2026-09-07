'use strict';
/* =============================================================
 * Me iOS Mach-O runtime recovery agent (Frida 17) v5
 *
 * - minimal is the default and installs no anti-detection hooks.
 * - compat only scopes PT_DENY_ATTACH and jailbreak-path checks to calls
 *   originating from modules inside the target .app bundle.
 * - aggressive adds higher-risk task/dlsym/signal hooks and remains opt-in.
 * - module readiness uses Process.mainModule and always performs at least one
 *   probe, fixing the previous waitReady(0) false-negative.
 * ============================================================= */

function exp(n) {
    try { return Module.getGlobalExportByName(n); } catch (e) { return null; }
}
function native(n, r, a) {
    const p = exp(n);
    return p ? new NativeFunction(p, r, a) : null;
}
function str(v) { const p = Memory.allocUtf8String(v); return p; }

var JB_PATHS = [
    '/Applications/Cydia.app', '/Applications/blackra1n.app',
    '/usr/sbin/frida-server', '/usr/bin/frida-server',
    '/usr/lib/libfrida-agent', '/usr/lib/frida',
    '/var/lib/apt', '/etc/apt', '/var/cache/apt',
    '/bin/bash', '/bin/sh', '/bin/su',
    '/usr/bin/ssh', '/usr/bin/sshd', '/usr/sbin/sshd',
    '/etc/ssh/sshd_config', '/usr/libexec/sftp-server',
    '/usr/libexec/ssh-keysign',
    '/Library/MobileSubstrate', '/usr/lib/substrate',
    '/usr/lib/libsubstrate.dylib', '/usr/lib/TweakInject',
    '/usr/lib/Cephei', '/usr/lib/libcycript',
    '/private/var/lib/cydia', '/var/lib/cydia',
    '/var/tmp/cydia.log', '/private/var/tmp/cydia.log',
    '/private/var/stash', '/var/mobile/Library/SBSettings',
    '/usr/bin/cycript', '/usr/bin/cycript',
    '/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
    '/var/mobile/Media/.evasi0n7_installed',
    '/var/mobile/Library/Preferences/cydia.plist'
];

function isJbPath(p) {
    if (!p) return false;
    for (var i = 0; i < JB_PATHS.length; i++) {
        if (p.indexOf(JB_PATHS[i]) !== -1) return true;
    }
    return false;
}

/* ---------------- 1. 可选、按调用来源限定的兼容钩子 ---------------- */
var compatibilityConfigured = false;
var compatibilityProfile = 'minimal';
var compatibilityHooks = [];

function isAppCaller(address) {
    try {
        const module = Process.findModuleByAddress(address);
        return !!module && module.path.indexOf('.app/') !== -1;
    } catch (e) {
        return false;
    }
}

function appCall(context) {
    return isAppCaller(context.returnAddress);
}

function installFrozenClock() {
    const cfa = exp('CFAbsoluteTimeGetCurrent') || exp('_CFAbsoluteTimeGetCurrent');
    if (!cfa) {
        console.log('[MobileE] CFAbsoluteTimeGetCurrent not found; timestamp hook skipped');
        return false;
    }
    try {
        const original = new NativeFunction(cfa, 'double', []);
        const t0 = original();
        Interceptor.replace(cfa, new NativeCallback(function () {
            // Keep Frida/Gum's own timing intact; only app-originated checks see
            // the frozen startup timestamp. This avoids destabilizing the agent.
            return appCall(this) ? t0 : original();
        }, 'double', []));
        compatibilityHooks.push('CFAbsoluteTimeGetCurrent(frozen)');
        console.log('[MobileE] frozen CFAbsoluteTimeGetCurrent');
        return true;
    } catch (e) {
        console.log('[MobileE] CFAbsoluteTimeGetCurrent hook skipped: ' + e);
        return false;
    }
}

function installDyldImageHiding() {
    const countTarget = exp('_dyld_image_count') || exp('dyld_image_count');
    const headerTarget = exp('_dyld_get_image_header') || exp('dyld_get_image_header');
    const nameTarget = exp('_dyld_get_image_name') || exp('dyld_get_image_name');
    if (!countTarget || !headerTarget || !nameTarget) {
        console.log('[MobileE] dyld image hiding skipped: dyld exports unavailable');
        return false;
    }

    try {
        const originalCount = new NativeFunction(countTarget, 'uint', []);
        const originalHeader = new NativeFunction(headerTarget, 'pointer', ['uint']);
        const originalName = new NativeFunction(nameTarget, 'pointer', ['uint']);
        const rawCount = Math.min(Number(originalCount()), 8192);
        const visibleIndices = [];
        const hiddenIndices = {};

        for (let index = 0; index < rawCount; index++) {
            let imageName = '';
            try {
                const name = originalName(index);
                if (name && !name.isNull()) imageName = name.readCString() || '';
            } catch (e) {}
            if (/frida|gadget|gum/i.test(imageName)) hiddenIndices[index] = true;
            else visibleIndices.push(index);
        }

        function rawIndex(index) {
            const numeric = Number(index);
            if (!Number.isInteger(numeric) || numeric < 0 || numeric >= visibleIndices.length) return -1;
            return visibleIndices[numeric];
        }

        Interceptor.replace(countTarget, new NativeCallback(function () {
            return appCall(this) ? visibleIndices.length : originalCount();
        }, 'uint', []));
        Interceptor.replace(nameTarget, new NativeCallback(function (index) {
            if (!appCall(this)) return originalName(index);
            const mapped = rawIndex(index);
            return mapped < 0 ? ptr(0) : originalName(mapped);
        }, 'pointer', ['uint']));
        Interceptor.replace(headerTarget, new NativeCallback(function (index) {
            if (!appCall(this)) return originalHeader(index);
            const mapped = rawIndex(index);
            return mapped < 0 ? ptr(0) : originalHeader(mapped);
        }, 'pointer', ['uint']));

        const hiddenCount = Object.keys(hiddenIndices).length;
        compatibilityHooks.push('dyld image hiding');
        console.log('[MobileE] dyld image hiding: hidden=' + hiddenCount + ' visible=' + visibleIndices.length);
        return true;
    } catch (e) {
        console.log('[MobileE] dyld image hiding skipped: ' + e);
        return false;
    }
}

function installCompatibility(profile) {
    profile = String(profile || 'minimal').toLowerCase();
    if (['minimal', 'compat', 'aggressive'].indexOf(profile) === -1) {
        throw new Error('compatibility profile must be minimal, compat, or aggressive');
    }
    if (compatibilityConfigured) {
        return { profile: compatibilityProfile, hooks: compatibilityHooks.slice(), alreadyConfigured: true };
    }
    compatibilityConfigured = true;
    compatibilityProfile = profile;
    if (profile === 'minimal') {
        console.log('[MobileE] iOS compatibility profile=minimal (no anti-detection hooks)');
        return { profile: profile, hooks: [] };
    }

    // These two hooks are shared by compat and aggressive profiles. They are
    // scoped to app-originated calls where possible so the Frida runtime keeps
    // its own clock and dyld view.
    installFrozenClock();
    installDyldImageHiding();

    // PT_DENY_ATTACH: only modify calls originating from the target .app.
    const ptraceTarget = exp('ptrace');
    if (ptraceTarget) {
        Interceptor.attach(ptraceTarget, {
            onEnter(args) {
                this.block = appCall(this) && args[0].toInt32() === 31;
                if (this.block) args[0] = ptr(-1);
            },
            onLeave(retval) {
                if (this.block) retval.replace(0);
            }
        });
        compatibilityHooks.push('ptrace(PT_DENY_ATTACH)');
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
                            try { this.block = isJbPath(ObjC.Object(args[2]).toString()); }
                            catch (e) { this.block = false; }
                        }
                    },
                    onLeave(retval) {
                        if (this.block) retval.replace(0);
                    }
                });
                compatibilityHooks.push('NSFileManager ' + selector);
            });
        } catch (e) {
            console.log('[MobileE] NSFileManager compatibility hook skipped: ' + e);
        }
    }

    // Do not hook open() globally: only existence checks for explicit jailbreak markers.
    ['stat', 'stat64', 'lstat', 'lstat64', 'access'].forEach(function (name) {
        const target = exp(name);
        if (!target) return;
        Interceptor.attach(target, {
            onEnter(args) {
                this.block = appCall(this);
                if (this.block) {
                    try { this.block = isJbPath(args[0].readCString()); }
                    catch (e) { this.block = false; }
                }
            },
            onLeave(retval) {
                if (this.block) {
                    retval.replace(-1);
                    this.errno = 2;
                }
            }
        });
        compatibilityHooks.push(name + '(jb-path-only)');
    });

    if (profile === 'aggressive') {
        // These hooks can change legitimate App behavior, so they are opt-in and
        // still exclude all calls originating from Frida/Gum itself.
        const tgp = exp('task_get_exception_ports');
        if (tgp) {
            Interceptor.attach(tgp, {
                onEnter() { this.block = appCall(this); },
                onLeave(retval) { if (this.block) retval.replace(5); }
            });
            compatibilityHooks.push('task_get_exception_ports');
        }

        const taskInfo = exp('task_info');
        if (taskInfo) {
            Interceptor.attach(taskInfo, {
                onEnter(args) { this.block = appCall(this) && args[2].toInt32() === 13; },
                onLeave(retval) { if (this.block) retval.replace(5); }
            });
            compatibilityHooks.push('task_info(TASK_DYLD_INFO)');
        }

        const dlsym = exp('dlsym');
        if (dlsym) {
            Interceptor.attach(dlsym, {
                onEnter(args) {
                    if (!appCall(this)) return;
                    try {
                        const symbol = args[1].readCString();
                        if (symbol && /frida|gum/i.test(symbol)) {
                            args[1] = Memory.allocUtf8String('_dyld_private');
                        }
                    } catch (e) {}
                }
            });
            compatibilityHooks.push('dlsym(frida/gum)');
        }

        const killTarget = exp('kill');
        if (killTarget) {
            Interceptor.attach(killTarget, {
                onEnter(args) {
                    if (!appCall(this)) return;
                    const signal = args[1].toInt32();
                    const pid = args[0].toInt32();
                    if ((pid === Process.id || pid <= 0) && (signal === 9 || signal === 15)) args[1] = 0;
                }
            });
            compatibilityHooks.push('kill(self)');
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
            compatibilityHooks.push(name);
        });

        const raiseTarget = exp('raise');
        if (raiseTarget) {
            Interceptor.attach(raiseTarget, {
                onEnter(args) {
                    if (!appCall(this)) return;
                    const signal = args[0].toInt32();
                    if (signal === 3 || signal === 6 || signal === 9 || signal === 15) args[0] = 0;
                }
            });
            compatibilityHooks.push('raise');
        }
    }

    console.log('[MobileE] iOS compatibility profile=' + profile + ' · scoped hooks: ' + compatibilityHooks.join(', '));
    return { profile: profile, hooks: compatibilityHooks.slice() };
}

/* ---------------- 2. 基础信息（Process.mainModule 优先，ObjC 补充） ---------------- */
function processHome() {
    try {
        const getenv = native('getenv', 'pointer', ['pointer']);
        if (getenv) {
            const value = getenv(str('HOME'));
            if (value && !value.isNull()) return value.readUtf8String();
        }
    } catch (e) {}
    return '/tmp';
}

function moduleCandidates() {
    const rows = [];
    try {
        const main = Process.mainModule;
        if (main) rows.push(main);
    } catch (e) {}
    try {
        Process.enumerateModules().forEach(function (module) {
            if (!rows.some(function (item) { return item.base.equals(module.base); })) rows.push(module);
        });
    } catch (e) {}
    return rows;
}

function appMainModule(expectedName) {
    const modules = moduleCandidates();
    if (modules.length === 0) return null;
    const direct = modules[0];
    if (direct && direct.path.indexOf('.app/') !== -1 && direct.path.indexOf('.appex/') === -1) return direct;
    if (expectedName) {
        const exact = modules.find(function (module) {
            return module.name === expectedName || module.path.endsWith('/' + expectedName);
        });
        if (exact) return exact;
    }
    return modules.find(function (module) {
        if (module.path.indexOf('.app/') === -1 || module.path.indexOf('.framework/') !== -1) return false;
        const suffix = module.path.substring(module.path.indexOf('.app/') + 5);
        return suffix.indexOf('/') === -1;
    }) || null;
}

function fallbackInfo() {
    const appMod = appMainModule(null);
    const root = appMod ? appMod.path.substring(0, appMod.path.lastIndexOf('/')) : null;
    return {
        appName: root ? root.substring(root.lastIndexOf('/') + 1).replace(/\.app$/, '') : null,
        bundleId: null,
        bundlePath: root,
        executableName: appMod ? appMod.name : null,
        sandboxPath: processHome()
    };
}

function info() {
    const fallback = fallbackInfo();
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        try {
            const bundle = ObjC.classes.NSBundle.mainBundle();
            const executablePath = bundle.executablePath();
            const path = executablePath ? executablePath.toString() : (fallback.bundlePath + '/' + fallback.executableName);
            const dictionary = bundle.infoDictionary();
            const displayName = dictionary.objectForKey_('CFBundleDisplayName') || dictionary.objectForKey_('CFBundleName');
            const identifier = bundle.bundleIdentifier();
            return {
                appName: displayName ? displayName.toString() : (fallback.appName || path.split('/').pop()),
                bundleId: identifier ? identifier.toString() : null,
                bundlePath: bundle.bundlePath().toString(),
                executableName: fallback.executableName || path.split('/').pop(),
                sandboxPath: processHome()
            };
        } catch (e) {
            if (fallback.executableName) return fallback;
            throw new Error('info() ObjC 不可用: ' + e);
        }
    }
    if (!fallback.executableName) throw new Error('无法定位 App 主模块');
    return fallback;
}

function findModule(name) {
    return appMainModule(name);
}

/* ---------------- 3. 加载命令解析 ---------------- */
function segname(p) {
    const a = new Uint8Array(p.readByteArray(16));
    let s = '';
    for (let i = 0; i < a.length && a[i]; i++) s += String.fromCharCode(a[i]);
    return s;
}

function macho(base) {
    const m = base.readU32();
    const x = m === 0xfeedfacf || m === 0xcffaedfe;
    if (!x && m !== 0xfeedface && m !== 0xcefaedfe) throw new Error('Unsupported Mach-O');
    let c = x ? 32 : 28, b = null, k = null, a = [];
    const n = base.add(16).readU32();
    for (let i = 0; i < n; i++) {
        const q = base.add(c).readU32();
        const z = base.add(c + 4).readU32();
        if (z < 8) throw new Error('Invalid load command');
        if (q === 1 || q === 0x19) {
            const name = segname(base.add(c + 8));
            const v = x ? base.add(c + 24).readU64().toNumber() : base.add(c + 24).readU32();
            const vs = x ? base.add(c + 32).readU64().toNumber() : base.add(c + 28).readU32();
            const o = x ? base.add(c + 40).readU64().toNumber() : base.add(c + 32).readU32();
            const fs = x ? base.add(c + 48).readU64().toNumber() : base.add(c + 36).readU32();
            if (name === '__TEXT' || (b === null && o === 0)) b = v;
            a.push({ v, vs, o, fs });
        }
        if (q === 0x21 || q === 0x2c) k = c + 16;
        c += z;
    }
    return { a, b, k };
}

/* ---------------- 4. 等待 App 就绪 ---------------- */
function probeReady() {
    try {
        const i = info();
        const mod = findModule(i.executableName);
        if (mod && mod.size > 0) {
            return {
                ok: true,
                module: mod.name,
                modulePath: mod.path,
                base: mod.base.toString(),
                size: mod.size,
                executableName: i.executableName
            };
        }
        return {
            ok: false,
            error: 'module not loaded',
            executableName: i.executableName,
            candidates: moduleCandidates().slice(0, 12).map(function (item) { return item.name + ' @ ' + item.path; })
        };
    } catch (e) {
        return {
            ok: false,
            error: String(e),
            candidates: moduleCandidates().slice(0, 12).map(function (item) { return item.name + ' @ ' + item.path; })
        };
    }
}

function waitReady(ms) {
    const deadline = Date.now() + Math.max(0, Number(ms) || 0);
    let result;
    do {
        result = probeReady();
        if (result.ok) return result;
        if (Date.now() < deadline) Thread.sleep(0.2);
    } while (Date.now() < deadline);
    return result || { ok: false, error: 'module probe did not run' };
}

/* ---------------- 5. dump 主逻辑 ---------------- */
function dump(path, waitMs) {
    waitMs = waitMs || 8000;
    const deadline = Date.now() + waitMs;
    let mod = null;
    let lastErr = null;
    while (Date.now() < deadline) {
        try {
            const i = info();
            mod = findModule(i.executableName);
            if (mod && mod.size > 0) break;
        } catch (e) { lastErr = e; }
        Thread.sleep(0.2);
    }
    if (!mod) throw new Error('等待 App 主模块超时: ' + (lastErr ? String(lastErr) : 'not found'));
    const p = macho(mod.base);
    if (p.b === null) throw new Error('No base segment');
    const f = new File(path, 'wb');
    let written = 0;
    p.a.forEach(s => {
        if (!s.fs) return;
        const n = Math.min(s.fs, s.vs || s.fs);
        f.seek(s.o, File.SEEK_SET);
        f.write(mod.base.add(s.v - p.b).readByteArray(n));
        if (n < s.fs) {
            f.seek(s.o + s.fs - 1, File.SEEK_SET);
            f.write(new Uint8Array([0]).buffer);
        }
        written += s.fs;
    });
    if (p.k !== null) {
        f.seek(p.k, File.SEEK_SET);
        f.write(new Uint8Array([0, 0, 0, 0]).buffer);
    }
    f.flush();
    f.close();
    const i = info();
    return { path, executableName: i.executableName, bundlePath: i.bundlePath, written };
}

function files(root) {
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        const fm = ObjC.classes.NSFileManager.defaultManager();
        const e = fm.enumeratorAtPath_(root);
        const r = [];
        let o;
        while ((o = e.nextObject()) !== null) {
            const rel = o.toString();
            const full = root + '/' + rel;
            const d = Memory.alloc(1);
            d.writeU8(0);
            if (fm.fileExistsAtPath_isDirectory_(full, d) && d.readU8() === 0) {
                const a = fm.attributesOfItemAtPath_error_(full, NULL);
                const s = a ? Number(a.objectForKey_('NSFileSize').toString()) : 0;
                r.push({ relative: rel, size: s });
            }
        }
        return r;
    }
    const od = native('opendir', 'pointer', ['pointer']);
    const rd = native('readdir', 'pointer', ['pointer']);
    const cd = native('closedir', 'int', ['pointer']);
    const r = [];
    const off = Process.pointerSize === 8 ? { type: 20, name: 21 } : { type: 12, name: 13 };
    function walk(dir, rel) {
        const d = od(str(dir));
        if (d.isNull()) return;
        while (true) {
            const e = rd(d);
            if (e.isNull()) break;
            const n = e.add(off.name).readUtf8String();
            if (!n || n === '.' || n === '..') continue;
            const full = dir + '/' + n;
            const q = rel ? rel + '/' + n : n;
            const t = e.add(off.type).readU8();
            if (t === 4) walk(full, q);
            else {
                try {
                    const f = new File(full, 'rb');
                    f.seek(0, File.SEEK_END);
                    const size = Number(f.tell());
                    f.close();
                    r.push({ relative: q, size });
                } catch (x) {}
            }
        }
        cd(d);
    }
    walk(root, '');
    return r;
}

function read(path, offset, size) {
    const f = new File(path, 'rb');
    f.seek(offset, File.SEEK_SET);
    const b = f.readBytes(size);
    f.close();
    return b;
}

function remove(path) {
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        ObjC.classes.NSFileManager.defaultManager().removeItemAtPath_error_(path, NULL);
        return true;
    }
    const u = native('unlink', 'int', ['pointer']);
    return u ? u(str(path)) === 0 : false;
}

rpc.exports = {
    bundleinfo: info,
    configure: installCompatibility,
    ready: probeReady,
    dumpexecutable: dump,
    listfiles: files,
    readfile: read,
    removefile: remove
};
