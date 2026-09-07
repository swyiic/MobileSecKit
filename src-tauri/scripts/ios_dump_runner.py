import argparse, os, shutil, sys, tempfile, time, zipfile
import frida

# 大文件分块大小：旧版 256KB，拉包太慢容易被壳的周期检测杀掉；提高到 1MB
CHUNK = 1024 * 1024
MAX_ATTEMPTS = 6
CURRENT_MODE = 'unknown'
EXPECTED_RUN_TOKEN = '__ME_RUN_TOKEN__'
# Keep the template sentinel split so Rust's global token substitution only
# binds EXPECTED_RUN_TOKEN.  Using the literal marker in this comparison made
# the post-substitution condition `EXPECTED_RUN_TOKEN == '<actual token>'`,
# which rejected every legitimate launch from MobileE.
TEMPLATE_RUN_TOKEN = '__ME_' + 'RUN_TOKEN__'


def require_embedded_launch():
    token = os.environ.pop('ME_EMBEDDED_RUN_TOKEN', '')
    if not token or token != EXPECTED_RUN_TOKEN or EXPECTED_RUN_TOKEN == TEMPLATE_RUN_TOKEN:
        raise RuntimeError('runner must be launched by the application')


class SessionDestroyed(RuntimeError):
    pass


def log(x):
    print(x, flush=True)


def safe(x):
    return ''.join(c if c.isalnum() or c in '._-' else '_' for c in x) or 'App'


def is_destroyed(e):
    msg = str(e).lower()
    return (
        'script has been destroyed' in msg
        or 'no longer exists' in msg
        or 'process is not alive' in msg
        or 'process has exited' in msg
        or 'device is lost' in msg
    )


def classify(e):
    if is_destroyed(e):
        return 'destroyed'
    msg = str(e).lower()
    if 'unable to find application' in msg or 'not installed' in msg:
        return 'not_installed'
    if 'unable to find device' in msg or 'no such device' in msg:
        return 'no_device'
    if 'refused to load frida-agent' in msg or 'terminated during injection' in msg:
        return 'injection_refused'
    if 'probing dyld' in msg:
        return 'dyld_probe'
    if '(os/kern) failure' in msg:
        return 'kern_failure'
    if 'denied' in msg or 'permission' in msg:
        return 'permission'
    if 'timed out' in msg or 'timeout' in msg:
        return 'timeout'
    return 'generic'


def human_error(kind, detail, mode):
    if kind == 'destroyed':
        return (
            'App 进程在砸壳/拉包过程中被加固壳终止（JMCodeProtectKit 双进程保护常见），'
            'Frida 会话被销毁。\n'
            '本工具已自动重试并断点续拉（最多 %d 次），若仍失败请按顺序尝试：\n'
            '  1. 改用 Attach 模式：先在手机上手动打开 App，再点“砸壳”；\n'
            '  2. 在设备上停掉壳的看护进程后重试（Filza/终端 kill 掉与 App 同名或带 Watchdog 的进程）；\n'
            '  3. 换用 CrackerXI / flexdecrypt 在设备端脱壳，把 IPA 拖回 App Analyzer 分析。\n'
            '[原始错误] %s' % (MAX_ATTEMPTS, detail)
        )
    if kind == 'not_installed':
        return '目标 App 未安装或 Bundle ID 不匹配：' + detail
    if kind == 'no_device':
        return '未找到设备（检查 USB/网络连接与 usbmuxd）：' + detail
    if kind == 'injection_refused':
        return (
            '目标进程拒绝装载 frida-agent，或在注入完成前被保护逻辑终止。'
            '这一步发生在用户 JavaScript 开始执行之前，单纯修改 Hook 脚本无法修复。\n'
            '先用“iOS 注入通道探针（零 Hook）”验证；若普通 App 成功、只有目标失败，'
            '优先 Spawn + compat，或手动打开后 Attach + compat；仍失败时需要授权 Gadget/未加固构建。\n'
            '[原始错误] ' + detail
        )
    if kind == 'dyld_probe':
        return 'Frida 无法读取目标 dyld；先检查设备端 frida-server 的 root/task_for_pid 状态：' + detail
    if kind == 'kern_failure':
        return (
            'iOS 内核在 frida-agent 注入/恢复阶段拒绝了目标进程；用户脚本尚未执行，'
            '这不是 Mach-O dump 脚本可修复的问题。请先对 Reqable 等普通 App 运行'
            '“iOS 注入通道探针（零 Hook）”：若能输出 ME_IOS_INJECTION_OK，说明设备与 Frida '
            '基线正常，当前 App 存在目标级注入限制或代码签名保护；若普通 App 也失败，再检查'
            '越狱激活、root frida-server 与版本一致性。\n[原始错误] ' + detail
        )
    if kind == 'permission':
        return '权限不足（确认越狱已激活、frida-server 以 root 运行并与主机同版本）：' + detail
    if kind == 'timeout':
        return '操作超时：' + detail
    return '砸壳失败：' + detail


def pull_file(e, remote, local, n):
    os.makedirs(os.path.dirname(local), exist_ok=True)
    o = 0
    with open(local, 'wb') as f:
        while o < n:
            b = e.readfile(remote, o, min(CHUNK, n - o))
            if not b:
                raise RuntimeError(f'read stopped {o}/{n}: {remote}')
            f.write(bytes(b))
            o += len(b)


def main():
    global CURRENT_MODE
    require_embedded_launch()
    p = argparse.ArgumentParser()
    p.add_argument('--serial', required=True)
    p.add_argument('--bundle', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--agent', required=True)
    p.add_argument('--mode', default='spawn', choices=['spawn', 'attach'])
    p.add_argument('--wait', type=int, default=30)
    p.add_argument('--dump-wait', type=int, default=8000)
    p.add_argument('--profile', default='minimal', choices=['minimal', 'compat', 'aggressive'])
    a = p.parse_args()
    CURRENT_MODE = a.mode

    log(f'[1/7] Python Frida {frida.__version__} · mode={a.mode}')
    d = frida.get_device_manager().get_device(a.serial, timeout=8)
    apps = d.enumerate_applications()
    app = next((x for x in apps if x.identifier == a.bundle), None)
    if app is None:
        raise RuntimeError('Bundle ID not installed: ' + a.bundle)

    # 跨轮次共享状态（断点续拉）
    state = {
        'root': None,
        'exe': None,
        'remote_exe': None,
        'appdir': None,
        'pulled': {},      # relpath -> size
        'dump_written': 0,
    }

    with tempfile.TemporaryDirectory(prefix='me-ios-') as t:
        attempt = 0
        finished = False
        while attempt < MAX_ATTEMPTS:
            attempt += 1
            log(f'      --- 第 {attempt}/{MAX_ATTEMPTS} 轮（已拉 {len(state["pulled"])} 个文件） ---')
            try:
                finished = run_round(d, app, a, state, t)
                if finished:
                    break
            except SessionDestroyed:
                if a.mode == 'attach' or attempt >= MAX_ATTEMPTS:
                    raise RuntimeError(human_error('destroyed', '会话被销毁', a.mode))
                log('      [重试] 会话被壳销毁，重新拉起 App 继续拉取剩余文件…')
                time.sleep(2)
                continue
            except frida.InvalidOperationError as x:
                if is_destroyed(x):
                    if a.mode == 'attach' or attempt >= MAX_ATTEMPTS:
                        raise RuntimeError(human_error('destroyed', str(x), a.mode))
                    log('      [重试] 会话被壳销毁，重新拉起 App 继续拉取剩余文件…')
                    time.sleep(2)
                    continue
                raise
        if not finished:
            raise RuntimeError(human_error('destroyed', '超过重试上限', a.mode))

        # 最终组装 IPA
        log('[5/7] Replace executable (cryptid=0)')
        target = os.path.join(state['appdir'], state['exe'])
        shutil.copy2(state['remote_exe'], target)
        os.chmod(target, 0o755)
        out = os.path.abspath(os.path.expanduser(a.output))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        log('[6/7] Build IPA: ' + out)
        with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as q:
            for base, _, names in os.walk(state['appdir']):
                for name in names:
                    full = os.path.join(base, name)
                    q.write(full, os.path.join('Payload', os.path.basename(state['appdir']), os.path.relpath(full, state['appdir'])))
        log(f'[7/7] SUCCESS {out} ({os.path.getsize(out)} bytes)')


def run_round(d, app, a, state, tmp):
    """一轮完整会话：spawn/attach -> dump -> 拉取剩余文件。返回 True 表示本轮全部拉完。"""
    mode = a.mode
    if mode == 'spawn':
        pid = d.spawn([a.bundle])
    else:
        # Application.pid is the most reliable mapping from Bundle ID to the
        # current process. Process names may be the executable, display name,
        # or truncated Unicode text and must only be used as a fallback.
        pid = int(getattr(app, 'pid', 0) or 0)
        if pid <= 0:
            refreshed = next(
                (item for item in d.enumerate_applications() if item.identifier == a.bundle), None)
            pid = int(getattr(refreshed, 'pid', 0) or 0) if refreshed else 0
        if pid <= 0:
            expected = {app.name, a.bundle.split('.')[-1]}
            normalized = {value.lower().replace(' ', '') for value in expected if value}
            running = next(
                (process for process in d.enumerate_processes()
                 if process.name in expected or process.name.lower().replace(' ', '') in normalized), None)
            pid = running.pid if running else 0
        if pid <= 0:
            raise RuntimeError('attach 模式要求 App 已运行；请先在手机上手动打开并保持前台：' + a.bundle)
    log(f'[2/7] Attach pid={pid} · profile={a.profile}')
    s = d.attach(pid)
    try:
        j = s.create_script(open(a.agent, encoding='utf-8').read())
        j.on('message', lambda m, b: log('[agent] ' + str(m)))
        j.load()
        e = j.exports_sync
        configured = e.configure(a.profile)
        log('      agent profile: ' + str(configured))
        if mode == 'spawn':
            d.resume(pid)

        # 等 App 主模块就绪（覆盖启动 + 壳解密窗口）
        deadline = time.time() + a.wait
        ready = None
        while time.time() < deadline:
            try:
                ready = e.ready()
                if ready and ready.get('ok'):
                    break
            except frida.InvalidOperationError as x:
                raise SessionDestroyed(str(x))
            except Exception as x:
                ready = {'error': str(x)}
            time.sleep(0.5)
        if not (ready and ready.get('ok')):
            diagnostic = ready or {}
            raise RuntimeError(
                f'App 主模块未在 {a.wait}s 内就绪：{diagnostic.get("error")}; '
                f'executable={diagnostic.get("executableName")}; '
                f'candidates={diagnostic.get("candidates")}')
        log('      main module: ' + str(ready))

        i = e.bundleinfo()
        root = i['bundlePath']
        exe = i['executableName']
        remote = f"{i['sandboxPath']}/tmp/me_{safe(exe)}.decrypted"

        log('[3/7] Dump decrypted Mach-O: ' + exe)
        e.dumpexecutable(remote, a.dump_wait)

        items = e.listfiles(root)
        log(f'[4/7] Pull App Bundle: {len(items)} files')

        if state['root'] is None:
            state['root'] = root
            state['exe'] = exe
            state['remote_exe'] = os.path.join(tmp, exe + '.decrypted')
            state['appdir'] = os.path.join(tmp, os.path.basename(root))

        # 拉取全部 bundle 文件（跳过已拉且大小一致的）
        done = 0
        total = sum(int(x['size']) for x in items)
        remaining = 0
        for x in items:
            rel = x['relative']
            size = int(x['size'])
            local = os.path.join(state['appdir'], rel)
            if state['pulled'].get(rel) == size and os.path.exists(local):
                done += size
                continue
            remaining += 1
            pull_file(e, root + '/' + rel, local, size)
            state['pulled'][rel] = size
            done += size
            if remaining % 25 == 0 or done >= total:
                log(f'      bundle {remaining} 剩余 · {done * 100 // max(total, 1)}%')
        log(f'      bundle 拉取完成 {len(state["pulled"])}/{len(items)}')

        # 拉取解密后的主程序（若本轮已把 exe 当作普通文件拉过，会覆盖）
        tmpdir = os.path.dirname(remote)
        dumpitem = next(
            (x for x in e.listfiles(tmpdir) if x['relative'] == os.path.basename(remote)), None)
        if not dumpitem:
            raise RuntimeError('decrypted Mach-O missing')
        pull_file(e, remote, state['remote_exe'], int(dumpitem['size']))
        state['dump_written'] = int(dumpitem['size'])

        try:
            e.removefile(remote)
        except Exception:
            pass
        return True
    except frida.InvalidOperationError as x:
        if is_destroyed(x):
            raise SessionDestroyed(str(x))
        raise
    finally:
        try:
            s.detach()
        except Exception:
            pass


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception as x:
        kind = classify(x)
        print('[FAILED] ' + human_error(kind, str(x), CURRENT_MODE), file=sys.stderr, flush=True)
        sys.exit(1)
