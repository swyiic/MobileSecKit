<template>
  <div class="runtime-monitor-layout">
    <section class="runtime-hero panel">
      <div class="runtime-hero-copy">
        <div class="eyebrow">ANDROID · L0 OBSERVE · L1 INSPECT · L2 DUMP</div>
        <h2>KernSight 证据链</h2>
        <p>按进程实例把内核事实、用户态 Inspect 和显式 dump 串成一条可核验的链：进程身份 → DNS / Handshake SNI → Binder token → TLS / Parcel → DEX / SO / CE·DE。这不是整机仪表盘；confirmed、correlated、inferred 不会被界面升级。</p>
        <div class="runtime-hero-actions">
          <button v-if="!androidReady" class="primary-button" @click="$emit('open-devices')"><span class="material-symbols-outlined">devices</span>选择 Android 设备</button>
          <button v-else class="primary-button" :disabled="probing" @click="runCapabilityProbe"><span class="material-symbols-outlined" :class="{ spinning: probing }">{{ probing ? 'sync' : 'fact_check' }}</span>{{ probing ? '正在探测…' : capabilityProbe ? '重新探测能力' : '检测设备能力' }}</button>
          <button v-if="androidReady" class="ghost-button" :disabled="provisioning" title="从 swyiic/KernSight 的最新 GitHub Release 下载、校验并安装" @click="provisionKernSight"><span class="material-symbols-outlined" :class="{ spinning: provisioning }">{{ provisioning ? 'sync' : 'system_update_alt' }}</span>{{ provisioning ? '正在下载并安装…' : kernSight ? '从 GitHub 检查更新' : '从 GitHub 安装 Agent' }}</button>
          <button v-if="androidReady" class="ghost-button" :disabled="loadingKernSight" @click="loadKernSight"><span class="material-symbols-outlined" :class="{ spinning: loadingKernSight }">{{ loadingKernSight ? 'sync' : 'hub' }}</span>{{ loadingKernSight ? '正在握手…' : kernSight ? '刷新 KernSight' : '连接 KernSight' }}</button>
        </div>
      </div>
      <div class="runtime-readiness" :class="readinessTone">
        <span class="material-symbols-outlined">{{ readinessIcon }}</span>
        <div><small>当前状态</small><strong>{{ readinessTitle }}</strong><p>{{ readinessDetail }}</p></div>
      </div>
    </section>

    <section class="runtime-device-strip panel">
      <div><span>目标设备</span><strong>{{ device?.model || '未选择' }}</strong><small>{{ device?.serial || '请先连接 Android 设备' }}</small></div>
      <div><span>传输</span><strong>{{ kernSight ? `KernSight ${kernSight.agentVersion}` : androidReady ? 'USB · ADB tunnel' : '未建立' }}</strong><small>{{ kernSight ? `Protocol ${kernSight.protocolMajor}.${kernSight.protocolMinor}` : '控制与数据通道' }}</small></div>
      <div><span>内核</span><strong>{{ capabilityProbe?.kernelVersion || details?.kernelVersion || '待检测' }}</strong><small>{{ capabilityProbe ? `${capabilityProbe.architecture} · BTF ${capabilityProbe.btfStatus}` : details?.architecture || 'BTF / BPF 能力待检测' }}</small></div>
      <div><span>信任等级</span><strong :class="trustTone">{{ trustLabel }}</strong><small>{{ trustHint }}</small></div>
    </section>

    <section class="ks-workspace-switcher panel">
      <button :class="{ active: workspaceMode === 'evidence' }" @click="workspaceMode = 'evidence'"><span class="material-symbols-outlined">account_tree</span><strong>证据链</strong><small>先选包，再看 L0/L1 session 与 L2 dump</small></button>
      <button :class="{ active: workspaceMode === 'capture' }" @click="workspaceMode = 'capture'"><span class="material-symbols-outlined">radio_button_checked</span><strong>新建采集</strong><small>L0 内核事实 · 可选 L1 Inspect</small></button>
      <button class="import-local" :disabled="importingLocal" @click="importLocalEvidence"><span class="material-symbols-outlined">folder_open</span><strong>{{ importingLocal ? '正在索引…' : '导入本地证据' }}</strong><small>选择包含 dump-report.json 的包目录</small></button>
    </section>

    <section v-if="probeError" class="notice error-notice runtime-probe-error" role="alert"><span class="material-symbols-outlined">error</span><span>{{ probeError }}</span><button @click="probeError = ''">关闭</button></section>

    <section v-if="provisionResult" class="panel ks-provision-result">
      <header><div><div class="eyebrow">KERNSIGHT PROVISIONING</div><h2>{{ provisionResult.releaseTag }} 安装完成</h2><p>{{ provisionResult.installedVersion }} · {{ formatBytes(provisionResult.assetBytes) }} · SHA-256 {{ provisionResult.assetSha256 }}</p></div><a :href="provisionResult.releaseUrl" target="_blank" rel="noreferrer">查看 Release</a></header>
      <div class="ks-provision-steps"><article v-for="step in provisionResult.steps" :key="step.key"><span class="material-symbols-outlined">check_circle</span><div><strong>{{ step.label }}</strong><small>{{ step.detail }}</small></div></article></div>
    </section>

    <section v-if="capabilityProbe" class="panel capability-probe-panel">
      <header class="capability-probe-header">
        <div><div class="eyebrow">READ-ONLY DEVICE PROBE</div><h2>设备能力结果</h2><p>{{ capabilityProbe.summary }}</p></div>
        <div class="probe-mode"><small>推荐模式</small><strong>{{ recommendedModeLabel }}</strong><span>{{ capabilityProbe.agentStatus }}</span></div>
      </header>
      <div class="capability-check-grid">
        <article v-for="item in capabilityProbe.checks" :key="item.key" :class="`capability-${item.status}`">
          <span class="material-symbols-outlined">{{ capabilityIcon(item.status) }}</span>
          <p><small>{{ item.label }}</small><strong>{{ item.detail }}</strong></p>
          <b>{{ capabilityStatusLabel(item.status) }}</b>
        </article>
      </div>
      <div class="probe-facts">
        <span><small>Android</small><strong>{{ capabilityProbe.androidVersion }} · SDK {{ capabilityProbe.sdkVersion }}</strong></span>
        <span><small>Boot</small><strong>{{ capabilityProbe.bootloaderStatus }}</strong></span>
        <span><small>SELinux</small><strong>{{ capabilityProbe.selinuxStatus }}</strong></span>
        <span><small>eBPF</small><strong>{{ capabilityProbe.bpfStatus }}</strong></span>
      </div>
      <ul v-if="capabilityProbe.warnings.length" class="probe-warnings"><li v-for="warning in capabilityProbe.warnings" :key="warning"><span class="material-symbols-outlined">warning</span>{{ warning }}</li></ul>
      <p class="probe-footnote">本次探测不会安装 Agent、加载 BPF 或修改系统。Root 检查可能触发手机上的授权提示。</p>
    </section>

    <section v-if="capabilityProbe && !kernSight" class="panel ks-install-gate" :class="{ ready: deploymentReady }">
      <header><span class="material-symbols-outlined">{{ deploymentReady ? 'deployed_code' : 'warning' }}</span><div><div class="eyebrow">KERNSIGHT INSTALLATION GATE</div><h2>{{ deploymentReady ? '环境满足开发 Agent 的硬性要求' : '当前环境不满足可靠植入条件' }}</h2><p>{{ deploymentGateSummary }}</p></div><b>{{ deploymentReady ? 'READY' : `${failedRequirements.length} BLOCKERS` }}</b></header>
      <div class="ks-requirement-grid">
        <article v-for="item in deploymentRequirements" :key="item.key" :class="{ passed: item.passed }"><span class="material-symbols-outlined">{{ item.passed ? 'check_circle' : 'cancel' }}</span><div><strong>{{ item.label }}</strong><small>{{ item.detail }}</small></div></article>
      </div>
      <div class="ks-install-guidance">
        <span class="material-symbols-outlined">info</span>
        <p><strong>检测不等于植入。</strong>Agent 和 BPF 对象真正部署并完成协议握手后，MobileE 才会显示采集、会话、取证和分析功能。环境不符合时强行部署可能出现 BPF verifier、权限、BTF relocation 或 bpffs 固定失败。</p>
        <button class="primary-button" :disabled="provisioning" @click="provisionKernSight">{{ provisioning ? '正在下载、校验并安装…' : deploymentReady ? '从 GitHub 下载并安装' : '仍然尝试安装' }}</button>
        <button class="ghost-button" :disabled="loadingKernSight" @click="loadKernSight">我已部署，重新握手</button>
      </div>
    </section>

    <section v-if="kernSight && workspaceMode === 'capture'" class="panel ks-capture-panel">
      <div class="section-title compact">
        <div><div class="eyebrow">CAPTURE CONTROL</div><h2>按层采集</h2><p>L0 默认采集进程、文件、mmap、socket、DNS、Handshake（ClientHello SNI/ALPN、HTTP/1 Host、QUIC 首段）和 Binder parcel prefix。L1 TLS、JNI 明文与 Binder userspace 可同会话；Linker 仍独占。要拿到 SNI，必须在 connect 首写之前开始；包 PID 出现前不要开 Sched。</p></div>
        <span class="device-chip" :class="{ active: captureRunning }">{{ captureRunning ? `RUNNING ${captureElapsed}s` : 'READY' }}</span>
      </div>
      <div class="ks-presets">
        <button :disabled="captureRunning" @click="applyCapturePreset('observe-pkg')"><span class="material-symbols-outlined">hub</span><strong>单包 L0 主干</strong><small>DNS / SNI / Binder token，无 Inspect</small></button>
        <button :disabled="captureRunning" @click="applyCapturePreset('tls-binder')"><span class="material-symbols-outlined">key</span><strong>单包 L0+L1</strong><small>主干 + TLS + JNI 明文 + Parcel</small></button>
        <button :disabled="captureRunning" @click="applyCapturePreset('binder')"><span class="material-symbols-outlined">device_hub</span><strong>单包 Binder L1</strong><small>Parcel token / scalar · ELF64</small></button>
        <button :disabled="captureRunning" @click="applyCapturePreset('linker')"><span class="material-symbols-outlined">deployed_code</span><strong>单包 Linker</strong><small>独占 SO load；不与 TLS 同会话</small></button>
        <button :disabled="captureRunning" @click="applyCapturePreset('whole')"><span class="material-symbols-outlined">public</span><strong>全设备 L0</strong><small>无包过滤 · 不要开 Inspect/Sched</small></button>
        <button :disabled="captureRunning" @click="applyCapturePreset('dump')"><span class="material-symbols-outlined">folder_zip</span><strong>单包 L2 Dump</strong><small>--launch 拷 DEX/SO/CE·DE</small></button>
        <button :disabled="captureRunning" @click="applyCapturePreset('auto')"><span class="material-symbols-outlined">playlist_play</span><strong>完整自动采集</strong><small>L0 {{ captureForm.autoL0Seconds }}s → L0+L1 {{ captureForm.autoL1Seconds }}s → Linker {{ captureForm.autoLinkerSeconds }}s → Dump</small></button>
      </div>
      <div class="ks-layer-contract"><article v-for="layer in layerContracts" :key="layer.key" :class="`layer-${layer.key}`"><header><b>{{ layer.label }}</b><small>{{ layer.stage }}</small></header><strong>{{ layer.title }}</strong><p>{{ layer.detail }}</p><ul><li v-for="item in layer.items" :key="item">{{ item }}</li></ul></article></div>
      <div class="ks-capture-form">
        <label class="wide"><span>目标包（留空表示全设备 Observe）</span><input v-model.trim="captureForm.package" :disabled="captureRunning" placeholder="例如 us.hsbc.hsbcus" /></label>
        <label v-if="captureForm.plan !== 'auto'"><span>时长（秒）</span><input v-model.number="captureForm.durationSeconds" :disabled="captureRunning" type="number" min="1" max="300" /></label>
        <label><span>采样 1 / N</span><input v-model.number="captureForm.sampleOneIn" :disabled="captureRunning" type="number" min="1" max="10000" /></label>
        <label><span>L1 Inspect 组合</span><select v-model="captureForm.inspectMode" :disabled="captureRunning"><option value="none">关闭（仅 L0）</option><option value="tls">TLS plaintext</option><option value="jni_plaintext">JNI plaintext</option><option value="binder_userspace">Binder userspace</option><option value="tls_jni">TLS + JNI</option><option value="binder_jni">Binder + JNI</option><option value="tls_binder">TLS + Binder</option><option value="tls_binder_jni">TLS + Binder + JNI</option><option value="linker_so_load">Linker SO load（独占）</option></select></label>
        <label><span>明文/命中上限</span><select v-model.number="captureForm.inspectMaxBytes" :disabled="captureRunning"><option :value="256">256 B</option><option :value="1024">1 KiB</option><option :value="4096">4 KiB</option><option :value="16384">16 KiB</option><option :value="65536">64 KiB</option></select></label>
        <label v-if="captureForm.plan === 'auto'"><span>L0 主干（秒）</span><input v-model.number="captureForm.autoL0Seconds" :disabled="captureRunning" type="number" min="1" max="300" /></label>
        <label v-if="captureForm.plan === 'auto'"><span>L0+L1 登录窗（秒）</span><input v-model.number="captureForm.autoL1Seconds" :disabled="captureRunning" type="number" min="1" max="300" /></label>
        <label v-if="captureForm.plan === 'auto'"><span>Linker（秒）</span><input v-model.number="captureForm.autoLinkerSeconds" :disabled="captureRunning" type="number" min="1" max="300" /></label>
      </div>
      <div class="ks-sensor-switches">
        <label><input v-model="captureForm.files" :disabled="captureRunning" type="checkbox" />File open</label>
        <label><input v-model="captureForm.network" :disabled="captureRunning" type="checkbox" />Network lifecycle</label>
        <label><input v-model="captureForm.memory" :disabled="captureRunning" type="checkbox" />Memory executable</label>
        <label><input v-model="captureForm.binder" :disabled="captureRunning" type="checkbox" />Binder</label>
        <label><input v-model="captureForm.hideDebug" :disabled="captureRunning" type="checkbox" />Hide debug lab</label>
      </div>
      <details class="ks-advanced-capture">
        <summary>高级采集参数</summary>
        <div class="ks-sensor-switches">
          <label><input v-model="captureForm.filesFd" :disabled="captureRunning" type="checkbox" />FD dup/close（高流量）</label>
          <label><input v-model="captureForm.networkIo" :disabled="captureRunning" type="checkbox" />Network I/O 计数</label>
          <label><input v-model="captureForm.memoryAll" :disabled="captureRunning" type="checkbox" />Memory all（高流量）</label>
          <label><input v-model="captureForm.sched" :disabled="captureRunning" type="checkbox" />Sched wakeup（PID 未出现前禁止）</label>
          <label><input v-model="captureForm.includeThreads" :disabled="captureRunning" type="checkbox" />线程生命周期</label>
        </div>
      </details>
      <div class="ks-capture-actions">
        <button class="primary-button" :disabled="captureRunning || !captureValid" @click="startCapture"><span class="material-symbols-outlined" :class="{ spinning: captureRunning }">{{ captureRunning ? 'sync' : 'radio_button_checked' }}</span>{{ captureActionLabel }}</button>
        <p>{{ capturePolicyHint }}</p>
      </div>
      <div class="ks-capture-plan">
        <div><small>范围</small><strong>{{ captureScopeLabel }}</strong></div>
        <div><small>模式</small><strong :class="`risk-${captureRisk.tone}`">{{ captureRisk.label }}</strong></div>
        <div><small>传感器</small><strong>{{ enabledSensorLabels.join(' · ') || '未选择' }}</strong></div>
        <details><summary>查看等效命令</summary><code>{{ captureCommandPreview }}</code></details>
      </div>
      <p class="ks-control-boundary"><span class="material-symbols-outlined">info</span>当前按钮使用 MobileE 前台 ADB 执行路径；关闭 MobileE 会中断等待。常驻 daemon 的远程 StartSession / UpdatePolicy 尚未接通，界面不会伪装成后台独立控制。</p>
      <details v-if="captureResult" class="ks-capture-log" open>
        <summary>最近一次采集 · {{ shortSession(captureResult.sessionId) }} · {{ Math.max(0, Math.round((captureResult.finishedUnixMs - captureResult.startedUnixMs) / 1000)) }}s</summary>
        <code>{{ captureResult.commandPreview }}</code>
        <pre>{{ [captureResult.stdout, captureResult.stderr].filter(Boolean).join('\n') }}</pre>
      </details>
    </section>

    <section v-if="kernSight && workspaceMode === 'capture'" class="runtime-workspace-grid">
      <article class="panel runtime-stage-card">
        <header><span class="stage-index">L0</span><div><strong>Observe</strong><small>内核事实层</small></div><b>CONNECTED</b></header>
        <p>进程、openat、mmap、socket、DNS、Handshake SNI、Binder debug_id / parcel prefix。最近会话 {{ shortSession(kernSight.status.session_id) }}。</p>
        <ul><li>Protocol {{ kernSight.protocolMajor }}.{{ kernSight.protocolMinor }}</li><li>Heartbeat {{ kernSight.status.heartbeat_monotonic_ns ? '有效' : '未知' }}</li><li>Drop {{ kernSight.status.dropped_records ?? '未知' }}</li></ul>
      </article>
      <article class="panel runtime-stage-card">
        <header><span class="stage-index">L1</span><div><strong>Inspect</strong><small>默认关闭</small></div><b>{{ kernSight.sessions.length }}</b></header>
        <p>TLS、JNIEnv 明文与 Binder Parcel writers 可同会话；Linker 独占。AArch32 uprobe 在当前 GKI 可能 ENOTSUP。</p>
        <ul><li>{{ completedSessions }} completed</li><li>Last batch {{ kernSight.status.last_batch_sequence }}</li><li>{{ formatBytes(kernSight.status.spool_used_bytes) }} spool</li></ul>
      </article>
      <article class="panel runtime-stage-card">
        <header><span class="stage-index">L2</span><div><strong>Dump</strong><small>显式 pull-package</small></div><b>{{ packageDumps.length }}</b></header>
        <p>APK/DEX/SO、heap DEX、runtime SO、堆明文窗口、CE/DE 四类目录。不是 eBPF 自动拷贝。</p>
        <ul><li>{{ sensitiveFileCount }} 个敏感候选</li><li>{{ formatBytes(kernSight.privatePackageBytes) }} 受保护</li><li>{{ formatBytes(kernSight.publicPackageBytes) }} 发布目录</li></ul>
      </article>
      <article class="panel runtime-stage-card">
        <header><span class="stage-index">GAP</span><div><strong>完整性</strong><small>丢失与环境</small></div><b>{{ latestExecutionComplete ? 'COMPLETE' : 'CHECK' }}</b></header>
        <p>握手成功不等于目标行为完整；丢失、采样、截断和环境变化必须留在链上。</p>
        <ul><li>{{ capabilityProbe?.verifiedBootState || 'boot unknown' }}</li><li>{{ capabilityProbe?.selinuxStatus || 'SELinux unknown' }}</li><li>{{ environmentTransitions }} 次环境变化</li></ul>
      </article>
    </section>

    <section v-if="workspaceMode === 'evidence'" class="panel ks-session-panel">
      <div class="section-title compact"><div><div class="eyebrow">L0 / L1 SESSION</div><h2>{{ sessionMatchedPackage ? `${sessionMatchedPackage} · 会话链` : 'KernSight 会话' }}</h2><p>Session 与 L2 包证据独立加载。每条手机 Session 可单独删除；Mac 本地 Session 属于包证据，只能随整个包目录管理。</p></div><div class="ks-title-actions"><button v-if="selectedSession || selectedReport" class="ghost-button" title="只关闭当前详情，不删除任何数据" @click="clearCurrentSession">关闭详情</button><span class="device-chip">{{ visibleLocalSessionBundles.length + (kernSight?.sessions.length || 0) }} SESSIONS</span></div></div>
      <div class="ks-session-list">
        <article v-for="session in kernSight?.sessions || []" :key="session.session_id" class="ks-session-row" :class="{ active: selectedSession === session.session_id, 'pending-delete': pendingDeleteSession === session.session_id }">
          <button class="ks-session-open" :disabled="loadingReport || deletingSession === session.session_id" @click="loadSessionReport(session.session_id)">
            <span :title="session.session_id"><strong>{{ shortSession(session.session_id) }}</strong><small>{{ formatDate(session.started_unix_ms) }} · 设备会话</small></span>
            <span><strong>{{ Number(session.event_count || 0).toLocaleString() }} 条事件</strong><small>{{ session.batch_count || 0 }} 批次 · {{ formatBytes(session.used_bytes || 0) }}</small></span>
            <span class="ks-session-state"><b>{{ session.state }}</b><small>{{ session.stop_reason || (session.compressed ? 'LZ4 batches' : 'uncompressed') }}</small></span>
          </button>
          <div class="ks-session-delete-slot">
            <template v-if="pendingDeleteSession === session.session_id">
              <button type="button" class="ks-session-delete-cancel" :disabled="Boolean(deletingSession)" @click.stop="pendingDeleteSession = ''">取消</button>
              <button type="button" class="ks-session-delete confirm" :disabled="Boolean(deletingSession)" @click.stop="confirmDeleteDeviceSession(session.session_id)">{{ deletingSession === session.session_id ? '删除中…' : '确认删除' }}</button>
            </template>
            <button v-else type="button" class="ks-session-delete" :aria-label="`删除会话 ${session.session_id}`" :disabled="loadingReport || Boolean(deletingSession)" @click.stop="armDeleteDeviceSession(session.session_id)"><span class="material-symbols-outlined" aria-hidden="true">delete</span>删除</button>
          </div>
        </article>
        <article v-for="bundle in visibleLocalSessionBundles" :key="`${bundle.root}:${bundle.package}`" class="ks-session-row local" :class="{ active: selectedSession === bundleSessionId(bundle) }"><button class="ks-session-open" :disabled="loadingReport" @click="loadLocalBundleSession(bundle)"><span><strong>{{ shortSession(bundleSessionId(bundle)) }}</strong><small>{{ bundle.package }} · Mac 本地</small></span><span><strong>{{ Number(bundle.sessionReport?.total_events || 0).toLocaleString() }} events</strong><small>{{ bundle.fileCount.toLocaleString() }} files · {{ formatBytes(bundle.totalBytes) }}</small></span><span class="ks-session-state"><b>LOCAL</b><small>{{ bundle.sessionReport?.execution_complete ? 'complete' : 'incomplete' }}</small></span></button><span class="ks-session-owned">随整包证据管理</span></article>
        <p v-if="!visibleLocalSessionBundles.length && !kernSight?.sessions.length" class="ks-empty">{{ selectedPackage ? '当前包没有已导入的 Session，设备端也没有可重放会话。L2 文件证据仍可独立分析。' : '尚未导入或采集 Session。连接 KernSight 后，设备会话会直接列在这里。' }}</p>
      </div>
      <div v-if="loadingReport" class="ks-loading"><span class="material-symbols-outlined spinning">sync</span>正在重放会话事件（不合并 dump）…</div>
      <template v-if="sessionReport && !loadingReport">
        <div class="ks-case-head">
          <div>
            <small>{{ shortSession(selectedSession) }} · Observe {{ Number(sessionReport.mode_counts?.observe || 0).toLocaleString() }} · Inspect {{ Number(sessionReport.mode_counts?.inspect || 0).toLocaleString() }} · 丢失 {{ reportLostRecords.toLocaleString() }}</small>
            <strong>{{ sessionReport.execution_complete ? '采集结束' : '不完整，不能当完整行为记录' }}</strong>
          </div>
          <div class="ks-case-actions">
            <button class="ghost-button" type="button" @click="openAiReview">{{ aiCopied ? '已复制链 JSON' : '复制链并打开 AI 复核' }}</button>
          </div>
        </div>
        <div v-if="sessionMatchedPackage" class="ks-session-package-link">
          <div><small>检测到包名</small><strong>{{ sessionMatchedPackage }}</strong><span>{{ sessionPackageLinked ? '已显式接入 L2 包证据；关联强度仍按报告原值展示。' : '尚未加载 L2。当前只展示 Session 本身的数据。' }}</span></div>
          <button v-if="!sessionPackageLinked && hasPackageEvidence(sessionMatchedPackage)" class="ghost-button" @click="linkSessionPackageEvidence">接入同包 L2 证据</button>
          <button v-else-if="sessionPackageLinked" class="ghost-button" @click="unlinkSessionPackageEvidence">断开 L2 关联</button>
          <b v-else>没有可用包证据</b>
        </div>
        <nav class="ks-session-detail-tabs" aria-label="Session 详情分类">
          <button :class="{ active: sessionDetailSection === 'summary' }" @click="sessionDetailSection = 'summary'">摘要与证据链</button>
          <button :class="{ active: sessionDetailSection === 'plaintext' }" @click="sessionDetailSection = 'plaintext'">接口 {{ inspectUrlBoard.length }}</button>
          <button :class="{ active: sessionDetailSection === 'network' }" @click="sessionDetailSection = 'network'">网络 {{ networkBackbone.length }}</button>
          <button :class="{ active: sessionDetailSection === 'binder' }" @click="sessionDetailSection = 'binder'">Binder {{ binderRows.length }}</button>
        </nav>
        <template v-if="sessionDetailSection === 'summary'">
        <section v-if="mirrorDiagnosticRow" class="ks-reassembly-diagnostics">
          <header><div><small>BURP MIRROR · PAYLOAD-FREE DIAGNOSTICS</small><strong>镜像覆盖漏斗</strong></div><b>{{ Number(mirrorMetrics.delivered || 0).toLocaleString() }} 已投递</b></header>
          <div class="ks-reassembly-funnel">
            <span><small>边界片段</small><strong>{{ Number(mirrorMetrics.observed_fragments || 0).toLocaleString() }}</strong></span>
            <span><small>重组消息</small><strong>{{ Number(mirrorMetrics.reconstructed_messages || 0).toLocaleString() }}</strong></span>
            <span><small>请求 / 响应</small><strong>{{ Number(mirrorMetrics.reconstructed_requests || 0) }} / {{ Number(mirrorMetrics.reconstructed_responses || 0) }}</strong></span>
            <span><small>投递失败</small><strong>{{ Number(mirrorMetrics.delivery_failed || 0).toLocaleString() }}</strong></span>
            <span><small>未知方向流</small><strong>{{ Number(mirrorMetrics.unknown_directions || 0).toLocaleString() }}</strong></span>
            <span><small>等待缓冲</small><strong>{{ formatBytes(Number(mirrorMetrics.buffered_bytes || 0)) }}</strong></span>
          </div>
          <p>重复片段 {{ Number(mirrorMetrics.duplicate_fragments || 0) }} · 未形成完整消息 {{ Number(mirrorMetrics.fragment_pushes_without_message || 0) }} · 无 Host {{ Number(mirrorMetrics.hostless_requests || 0) }} · 流淘汰 {{ Number(mirrorMetrics.evicted_streams || 0) }}。这些计数不包含 URL、Header、Body 或凭据。</p>
        </section>
        <details v-if="tlsCoverageRows.length" class="ks-command-card ks-coverage-matrix">
          <summary>TLS / Cronet 动态挂载覆盖（{{ tlsCoverageRows.length }}）</summary>
          <div class="ks-data-table"><article v-for="row in tlsCoverageRows" :key="`${row.adapter}-${row.library}`"><strong>{{ shortLibrary(row.library) }}</strong><small>{{ row.adapter }} · {{ row.attached ? '已挂载' : '未挂载' }}</small><span>{{ Number(row.hits || 0).toLocaleString() }} hits</span><code>{{ row.attached ? (Number(row.hits || 0) ? 'active' : 'attached · no hit') : coverageReason(row) }}</code></article></div>
        </details>
        <p class="ks-path-legend"><span class="prio-focus">重点关注</span>明文、可读/堆 DEX、runtime SO、CE/DE 库和 prefs<span class="prio-watch">可复核</span>有事实但不是主干<span class="prio-background">背景</span>系统 Binder / 安装包 stub<span class="prio-gap">缺口</span>这一跳没有证据。高亮来自路径和来源，不是漏洞结论，也不等 AI。</p>
        <ol class="ks-flow">
          <li v-for="step in analysisFlow" :key="step.n" :class="[`prio-${step.priority}`, `verb-${step.verb}`]">
            <span class="ks-flow-n">{{ step.n }}</span>
            <div class="ks-flow-card">
              <header>
                <b>{{ step.verb }}</b>
                <strong>{{ step.title }}</strong>
                <small>{{ step.layer }} · {{ step.strength }}</small>
              </header>
              <dl>
                <div><dt>依据</dt><dd>{{ step.from }}</dd></div>
                <div><dt>得到</dt><dd>{{ step.got }}</dd></div>
                <div v-if="step.land.length"><dt>落地</dt><dd><code v-for="file in step.land" :key="file">{{ file }}</code></dd></div>
                <div><dt>接着</dt><dd>{{ step.next }}</dd></div>
              </dl>
            </div>
          </li>
        </ol>
        <ol class="ks-path">
          <li v-for="hop in analysisPath" :key="hop.key" :class="[`prio-${hop.priority}`, `strength-${hop.strength}`]">
            <header>
              <b>{{ hop.layer }}</b>
              <strong>{{ hop.title }}</strong>
              <em>{{ hop.badge }}</em>
              <small>{{ hop.strength }}</small>
            </header>
            <p>{{ hop.detail }}</p>
            <code v-for="item in hop.items" :key="item">{{ item }}</code>
          </li>
        </ol>
        </template>

        <section v-if="sessionDetailSection === 'plaintext'" class="ks-path-more">
          <h3>接口 / URL（{{ inspectUrlBoard.length }}）</h3>
          <p class="ks-backbone-note"><b>先看这里</b>从 TLS / JNI / HTTP 目录去重抽出的地址。下面的卡片只留带 URL 或 HTTP/JSON 的缓冲；webpack、hex、路径名折进「其它」。不是 MASVS 结论。</p>
          <div v-if="inspectUrlBoard.length" class="ks-url-board">
            <article v-for="item in inspectUrlBoard" :key="item.key">
              <small>{{ item.source }}</small>
              <code>{{ item.url }}</code>
            </article>
          </div>
          <p v-else class="ks-empty">这一会话没有抽出 http(s) 地址。TLS 可能是 HTTP/2 帧或 gzip 后的 JSON 字段里没有 URL。</p>
          <div v-if="usefulPlaintextRows.length" class="ks-plaintext-list">
            <article v-for="(row, index) in usefulPlaintextRows" :key="plaintextCardKey(row, index)" class="prio-focus">
              <header>
                <div><strong>{{ row.source }}</strong><small>pid={{ row.process_id }} · {{ row.adapter }} · {{ plaintextOriginLabel(row) }}</small></div>
                <div class="ks-plaintext-actions">
                  <b>{{ row.content_class || 'unknown' }}</b>
                  <button type="button" class="ghost-button" :disabled="!row.preview" @click="togglePlaintextDecode(row, index)">{{ plaintextDecoded[plaintextCardKey(row, index)] ? '原文' : '转码' }}</button>
                </div>
              </header>
              <ul v-if="plaintextUrlList(row).length" class="ks-url-list">
                <li v-for="url in plaintextUrlList(row)" :key="url">{{ url }}</li>
              </ul>
              <pre>{{ plaintextDecoded[plaintextCardKey(row, index)] || row.preview || '(本组没有 preview)' }}</pre>
            </article>
          </div>
          <details v-if="otherPlaintextRows.length" class="ks-command-card">
            <summary>其它 Inspect 缓冲 {{ otherPlaintextRows.length }}（无 URL，不作为接口目录）</summary>
            <div class="ks-plaintext-list">
              <article v-for="(row, index) in otherPlaintextRows" :key="plaintextCardKey(row, `other-${index}`)">
                <header>
                  <div><strong>{{ row.source }}</strong><small>pid={{ row.process_id }} · {{ row.adapter }} · {{ plaintextOriginLabel(row) }}</small></div>
                  <b>{{ row.content_class || 'unknown' }}</b>
                </header>
                <pre>{{ row.preview || '(本组没有 preview)' }}</pre>
              </article>
            </div>
          </details>
        </section>

        <section v-if="sessionDetailSection === 'network'" class="ks-path-more">
          <h3>网络明细 {{ networkBackbone.length }}</h3>
          <div class="ks-detail-pane">
          <div class="ks-network-summary"><span><small>DNS 数据报</small><strong>{{ dnsDatagrams.toLocaleString() }}</strong></span><span><small>Handshake</small><strong>{{ handshakeRows.length }}</strong></span><span><small>网络目标</small><strong>{{ networkRows.length }}</strong></span><span><small>Socket I/O</small><strong>{{ formatBytes(socketIoBytes) }}</strong></span></div>
          <p class="ks-backbone-note"><b>L0 网络链</b>UDP/53 → QNAME/A/AAAA 标 correlated resolved_name；connect 后首写解析 ClientHello SNI/ALPN、HTTP/1 Host 或 QUIC 长头。Handshake 不需要 --network-io 或 --inspect-tls。SNI 与 DNS 不一致时保留两者，常见于代理 / CONNECT / ECH 外层。</p>
          <div v-if="networkBackbone.length" class="ks-backbone-list"><article v-for="row in networkBackbone" :key="row.key"><b :class="`strength-${row.strength}`">{{ row.strength }}</b><div><strong>{{ row.name }}</strong><small>{{ row.protocol }} · pid={{ row.pid ?? '?' }} fd={{ row.fd ?? '?' }}</small></div><code>{{ row.endpoint }}</code><span>{{ row.detail }}</span></article></div>
          <details v-if="handshakeRows.length" class="ks-command-card"><summary>展开 ClientHello / HTTP / QUIC 首段（{{ handshakeRows.length }}）</summary><pre>{{ JSON.stringify(handshakeRows.slice(0, 128), null, 2) }}</pre></details>
          <div v-if="dnsRows.length" class="ks-dns-list"><article v-for="row in dnsRows" :key="`${row.process_id}-${row.qname}`"><span class="material-symbols-outlined">dns</span><div><strong>{{ row.qname }}</strong><small>pid={{ row.process_id }}</small></div><code>{{ (row.addresses || []).join(', ') || '没有保留 A / AAAA 回答' }}</code></article></div>
          <div class="ks-data-table">
            <article v-for="(row, index) in networkRows" :key="`${row.source}-${row.peer}-${row.port}-${index}`"><strong>{{ row.resolved_name || row.peer || 'unknown peer' }}</strong><small>{{ row.source }} · {{ row.peer }}{{ row.port != null ? `:${row.port}` : '' }}</small><span>{{ row.attempts || 0 }} connect · ↑{{ formatBytes(Number(row.sent_bytes || 0)) }} ↓{{ formatBytes(Number(row.received_bytes || 0)) }}</span><code>{{ compactJson(row) }}</code></article>
          </div>
          <p v-if="!networkRows.length" class="ks-empty">本会话没有聚合后的网络目标。检查 Network sensor 是否启用。</p>
          </div>
        </section>

        <section v-if="sessionDetailSection === 'binder'" class="ks-path-more">
          <h3>Binder 明细 · 内核 {{ binderRows.length }} · Parcel {{ binderSemanticHitCount }}</h3>
          <div class="ks-token-chips"><span v-for="name in kernelBinderInterfaces" :key="name"><b>L0</b>{{ name }}</span></div>
          <div class="ks-data-table">
            <article v-for="(row, index) in binderRows.slice(0, 40)" :key="`${row.source}-${row.target}-${index}`"><strong>{{ row.source }} → {{ row.target }}</strong><small>pid {{ row.source_process_id }} → {{ row.target_process_id ?? '?' }}</small><span>{{ Number(row.requests || 0).toLocaleString() }} req</span><code>kernel {{ compactJson(row.interfaces) }}</code></article>
          </div>
        </section>
      </template>
    </section>

    <section v-if="workspaceMode === 'evidence'" class="panel ks-package-panel">
      <div class="section-title compact"><div><div class="eyebrow">L2 DUMP LIBRARY</div><h2>包证据</h2><p>独立于 Session。证据文件不提供单项删除；手机端证据只能按整个 com 包删除。</p></div><div class="ks-title-actions"><button v-if="selectedPackage" class="ghost-button" title="关闭当前包工作区，不删除数据" @click="closePackageWorkspace">关闭当前包</button><template v-if="selectedPackage && selectedEvidenceSource === 'device'"><button v-if="pendingDeletePackage" class="ghost-button" :disabled="deletingPackage" @click="pendingDeletePackage = false">取消</button><button v-if="pendingDeletePackage" class="ghost-button danger-button" :disabled="deletingPackage" @click="confirmDeleteCurrentPackageEvidence">{{ deletingPackage ? '删除中…' : '确认删除整个包证据' }}</button><button v-else class="ghost-button danger-button" :disabled="deletingPackage" @click="pendingDeletePackage = true">删除整个包证据</button></template><span class="device-chip">MAC {{ localEvidenceBundles.length }} · DEVICE {{ devicePackageNames.size }}</span></div></div>
      <div class="ks-package-list">
        <article v-for="dump in packageDumps" :key="dump.package" :class="{ selected: selectedPackage === dump.package }" @click="selectPackage(dump.package)">
          <div><strong>{{ dump.package }}</strong><small class="ks-source-badges"><b v-for="source in evidenceSources(dump.package)" :key="source.kind" :class="`source-${source.kind}`">{{ source.label }}</b></small><small>{{ evidenceLocationLabel(dump.package) }} · {{ dump.schema_version || 'legacy schema · 建议 recatalog' }}</small></div>
          <span><b>{{ dump.dex_index?.unique_dex ?? dump.readable_dex ?? 0 }}</b><small>唯一 DEX</small></span>
          <span><b>{{ dump.runtime_libs || 0 }}</b><small>SO</small></span>
          <span><b>{{ dump.native_framework_matches?.length || 0 }}</b><small>框架识别</small></span>
          <span><b>{{ sensitiveCount(dump, 'plaintext_candidate', dump.plaintext_windows) }}</b><small>明文候选文件</small></span>
          <span><b>{{ sensitiveCount(dump, 'key_candidate', dump.key_slots) }}</b><small>Key 候选文件</small></span>
          <span><b>{{ dump.sensitive_files?.length || 0 }}</b><small>已哈希文件</small></span>
          <div class="ks-package-source-actions"><button v-if="hasLocalEvidence(dump.package)" class="ghost-button" :class="{ active: selectedPackage === dump.package && selectedEvidenceSource === 'local' }" @click.stop="selectPackageSource(dump.package, 'local')">打开 Mac</button><button v-if="devicePackageNames.has(dump.package)" class="ghost-button" :class="{ active: selectedPackage === dump.package && selectedEvidenceSource === 'device' }" @click.stop="selectPackageSource(dump.package, 'device')">打开手机</button></div>
        </article>
      </div>
      <p v-if="!packageDumps.length" class="ks-empty">当前没有 package dump。可以连接 KernSight 刷新设备证据，或导入本地包目录。</p>
    </section>

    <section v-if="workspaceMode === 'evidence' && selectedPackageDump" class="panel ks-package-evidence-panel">
      <div class="section-title compact"><div><div class="eyebrow">L2 FORENSIC DUMP</div><h2>{{ selectedPackage }} · 产物与私有文件</h2><p>安装包 DEX 常常只是 stub；可读 DEX、runtime SO、堆明文和 CE/DE 才是取证主干。与上方 session 只通过 overlaps_mmap 等 correlated 边连接，文件存在不证明本会话执行或外发。</p></div><span class="device-chip">{{ evidenceFiles.length.toLocaleString() }} FILES · {{ formatBytes(Number(selectedLocalBundle?.totalBytes ?? selectedPackageDump.total_bytes ?? 0)) }}</span></div>
      <template v-if="selectedPackageDump">
      <div class="ks-selected-package-bar"><button v-if="device && selectedEvidenceSource === 'device'" class="primary-button" :disabled="pullingPackage" @click="pullSelectedPackageEvidence">{{ pullingPackage ? '正在拉取…' : '拉回全部情报到本地' }}</button><b :class="`source-${selectedEvidenceSource}`">{{ selectedEvidenceSource === 'local' ? 'MAC 本地证据' : '手机端证据' }}</b><span>Dump {{ selectedPackageDump.dump_id || 'legacy' }}</span><span>{{ selectedPackageDump.launched ? '已执行 launch harvest' : '未执行 launch harvest' }}</span><span>{{ formatBytes(Number(selectedLocalBundle?.totalBytes ?? selectedPackageDump.total_bytes ?? 0)) }}</span></div>
      <div class="ks-forensic-grid">
        <article v-for="surface in forensicSurfaces" :key="surface.key" :class="{ active: selectedEvidenceCategory === surface.key }" @click="openEvidenceCategory(surface.key)"><span class="material-symbols-outlined">{{ surface.icon }}</span><div><strong>{{ surface.label }}</strong><small>{{ surface.path }}</small><p>{{ surface.detail }}</p></div><b>{{ surface.count }}</b></article>
      </div>
      <section ref="evidenceBrowserRef" class="ks-evidence-browser">
        <header><div><strong>L2 文件证据浏览器{{ selectedEvidenceCategoryLabel ? ` · ${selectedEvidenceCategoryLabel}` : '' }}</strong><small>上方分类只筛选此浏览器。DEX/SO 的语义、映射链也在选中文件后展示；证据文件不能在这里单独删除。</small></div><div><b>{{ evidenceFiles.length }} catalogued</b><button v-if="selectedEvidenceCategory" class="ghost-button" @click="openEvidenceCategory('')">显示全部</button></div></header>
        <div class="ks-evidence-file-list"><button v-for="file in visibleEvidenceFiles" :key="`${file.package}:${file.relative_path}`" :class="{ active: selectedEvidenceKey === `${file.package}:${file.relative_path}`, 'prio-focus': evidencePriority(file) === 'focus' }" :disabled="loadingEvidence" @click="openEvidenceEntry(file)"><span><strong>{{ file.relative_path }}</strong><small>{{ file.package }} · {{ file.content_class }}</small></span><b>{{ formatBytes(file.bytes) }}</b><em>{{ evidenceBadge(file) }}</em></button></div>
        <button v-if="visibleEvidenceFiles.length < evidenceFiles.length" class="ghost-button ks-load-more" @click="evidenceVisibleCount += 100">继续显示 {{ Math.min(100, evidenceFiles.length - visibleEvidenceFiles.length) }} 个文件</button>
        <div v-if="loadingEvidence" class="ks-loading"><span class="material-symbols-outlined spinning">sync</span>正在读取证据文件…</div>
        <article v-else-if="selectedEvidence" class="ks-evidence-preview"><header><div><strong>{{ selectedEvidence.relativePath }}</strong><small>{{ selectedEvidence.package }} · {{ formatBytes(selectedEvidence.bytes) }}{{ selectedEvidence.truncated ? ' · 预览已截断' : '' }} · {{ evidenceOriginLabel(selectedEvidence.relativePath) }}</small></div><div><b>{{ evidencePreviewKind }}</b><button class="icon-button" @click="closeEvidencePreview">×</button></div></header><div v-if="evidenceDecodedPreview" class="ks-binary-preview-grid"><section><h4>HEX</h4><pre>{{ evidencePreview }}</pre></section><section><h4>转码 / 可打印字符串</h4><pre>{{ evidenceDecodedPreview }}</pre></section></div><pre v-else>{{ evidencePreview }}</pre></article>
        <article v-if="selectedArtifact" class="ks-artifact-focus"><header><div><strong>{{ selectedArtifact.path }}</strong><small>{{ selectedArtifact.origin }} · {{ selectedArtifact.detail }}</small></div><button class="icon-button" @click="selectedArtifact = null">×</button></header><dl><div><dt>来源</dt><dd>{{ selectedArtifact.source }}</dd></div><div><dt>PID / VMA</dt><dd>{{ selectedArtifact.pid ?? '-' }} · {{ formatRange(selectedArtifact.vmaStart, selectedArtifact.vmaEnd) }}</dd></div><div><dt>映射路径</dt><dd>{{ selectedArtifact.mapPath || '没有 VMA 路径' }}</dd></div><div><dt>SHA-256</dt><dd>{{ selectedArtifact.sha256 || '未记录' }}</dd></div></dl><details v-if="selectedArtifact.classSamples?.length"><summary>类描述符样本（{{ selectedArtifact.classSamples.length }}）</summary><pre>{{ selectedArtifact.classSamples.join('\n') }}</pre></details><details v-if="selectedArtifact.methodSamples?.length"><summary>方法名样本（{{ selectedArtifact.methodSamples.length }}）</summary><pre>{{ selectedArtifact.methodSamples.join('\n') }}</pre></details><div v-if="selectedArtifactEdges.length" class="ks-artifact-chain"><article v-for="(edge,index) in selectedArtifactEdges" :key="`${edge.from}-${edge.relation}-${edge.to}-${index}`"><b :class="`strength-${edge.strength}`">{{ edge.strength }}</b><code>{{ edge.from }}</code><strong>{{ edge.relation }}</strong><code>{{ edge.to }}</code></article></div><p v-else>当前报告没有把这个文件连接到 session mmap。文件仍可单独分析，但不能声称它在该 session 中执行。</p></article>
      </section>
      <details class="ks-command-catalog">
        <summary>KernSight 完整命令映射与证据边界</summary>
        <div class="ks-command-grid"><article v-for="command in commandCatalog" :key="command.key"><header><b>{{ command.tier }}</b><strong>{{ command.label }}</strong></header><code>{{ command.command }}</code><p>{{ command.detail }}</p></article></div>
      </details>
      <div class="ks-evidence-policy"><article v-for="item in evidencePolicies" :key="item.title"><b :class="`strength-${item.strength}`">{{ item.strength }}</b><div><strong>{{ item.title }}</strong><p>{{ item.detail }}</p></div></article></div>
      </template>
    </section>

  </div>
</template>

<script setup lang="ts">
import { computed, markRaw, nextTick, onErrorCaptured, onBeforeUnmount, reactive, ref, shallowRef, watch } from 'vue'
import { open } from '@tauri-apps/plugin-dialog'
import { monitoringBackend, readableError } from '@/services/backend'
import { useKernSightEvidence } from '@/composables/useKernSightEvidence'
import { buildAnalysisFlow, buildAnalysisPath, classifyDex, classifyPrivate, classifySo } from '@/services/kernsightPath'
import type {
  AndroidMonitorCapabilityProbe,
  DeviceDetails,
  DeviceSummary,
  KernSightOverview,
  KernSightProvisionResult,
  KernSightCaptureRequest,
  KernSightCaptureResult,
  KernSightEvidenceFileContent,
  KernSightLocalEvidenceBundle,
  KernSightPackageDumpReport,
  KernSightSessionReportDocument,
} from '@/types'

const props = defineProps<{ device?: DeviceSummary; details: DeviceDetails | null }>()
const emit = defineEmits<{ 'open-devices': []; 'open-ai': [] }>()

const capabilityProbe = ref<AndroidMonitorCapabilityProbe | null>(null)
const probing = ref(false)
const provisioning = ref(false)
const provisionResult = ref<KernSightProvisionResult | null>(null)
const probeError = ref('')
const kernSight = ref<KernSightOverview | null>(null)
const packageDumps = shallowRef<KernSightPackageDumpReport[]>([])
const devicePackageDumps = shallowRef<KernSightPackageDumpReport[]>([])
const selectedReport = shallowRef<KernSightSessionReportDocument | null>(null)
const selectedSession = ref('')
const sessionMatchedPackage = ref('')
const sessionPackageLinked = ref(false)
const sessionDetailSection = ref<'summary' | 'plaintext' | 'network' | 'binder'>('summary')
const loadingKernSight = ref(false)
const loadingReport = ref(false)
const captureRunning = ref(false)
const captureElapsed = ref(0)
const captureResult = ref<KernSightCaptureResult | null>(null)
const detailTab = ref('chain')
const aiCopied = ref(false)
const workspaceMode = ref<'evidence' | 'capture'>('evidence')
const selectedPackage = ref('')
const selectedEvidenceSource = ref<'local' | 'device'>('local')
const { bundles: localEvidenceBundles, upsertBundle, importDirectory, requestedPackage } = useKernSightEvidence()
const devicePackageNames = ref(new Set<string>())
const importingLocal = ref(false)
const pullingPackage = ref(false)
const deletingSession = ref('')
const pendingDeleteSession = ref('')
const deletingPackage = ref(false)
const pendingDeletePackage = ref(false)
const loadingEvidence = ref(false)
const selectedEvidence = ref<KernSightEvidenceFileContent | null>(null)
const selectedEvidenceKey = ref('')
const evidencePreview = ref('')
const evidenceDecodedPreview = ref('')
const evidencePreviewKind = ref('text')
const plaintextDecoded = ref<Record<string, string>>({})
const selectedArtifact = ref<any | null>(null)
const selectedEvidenceCategory = ref('')
const evidenceVisibleCount = ref(100)
const evidenceBrowserRef = ref<HTMLElement | null>(null)
let captureTimer: ReturnType<typeof setInterval> | undefined

type InspectMode = 'none' | 'tls' | 'jni_plaintext' | 'binder_userspace' | 'tls_jni' | 'binder_jni' | 'tls_binder' | 'tls_binder_jni' | 'linker_so_load'

function inspectModeHasTls(mode: InspectMode) {
  return mode === 'tls' || mode === 'tls_binder' || mode === 'tls_jni' || mode === 'tls_binder_jni'
}
function inspectModeHasBinder(mode: InspectMode) {
  return mode === 'binder_userspace' || mode === 'tls_binder' || mode === 'binder_jni' || mode === 'tls_binder_jni'
}
function inspectModeHasJni(mode: InspectMode) {
  return mode === 'jni_plaintext' || mode === 'tls_jni' || mode === 'binder_jni' || mode === 'tls_binder_jni'
}

const captureForm = reactive({
  package: '',
  durationSeconds: 45,
  files: true,
  filesFd: false,
  network: true,
  networkIo: false,
  memory: true,
  memoryAll: false,
  binder: true,
  sched: false,
  includeThreads: false,
  inspectMode: 'none' as InspectMode,
  hideDebug: false,
  sampleOneIn: 1,
  inspectMaxBytes: 65_536,
  inspectMaxHits: 0,
  plan: 'capture' as 'capture' | 'dump' | 'auto',
  autoL0Seconds: 15,
  autoL1Seconds: 90,
  autoLinkerSeconds: 15,
})
const capturePhase = ref('')
const AUTO_DURATION_KEY = 'mobilee.kernsightAutoDurations'

function clampCaptureSeconds(value: unknown, fallback: number) {
  const n = Number(value)
  if (!Number.isFinite(n)) return fallback
  return Math.min(300, Math.max(1, Math.round(n)))
}

function loadAutoDurations() {
  try {
    const raw = localStorage.getItem(AUTO_DURATION_KEY)
    if (!raw) return
    const parsed = JSON.parse(raw) as Record<string, unknown>
    captureForm.autoL0Seconds = clampCaptureSeconds(parsed.autoL0Seconds, 15)
    captureForm.autoL1Seconds = clampCaptureSeconds(parsed.autoL1Seconds, 90)
    captureForm.autoLinkerSeconds = clampCaptureSeconds(parsed.autoLinkerSeconds, 15)
  } catch { /* keep defaults */ }
}
loadAutoDurations()
watch(
  () => [captureForm.autoL0Seconds, captureForm.autoL1Seconds, captureForm.autoLinkerSeconds],
  ([l0, l1, linker]) => {
    const next = {
      autoL0Seconds: clampCaptureSeconds(l0, 15),
      autoL1Seconds: clampCaptureSeconds(l1, 90),
      autoLinkerSeconds: clampCaptureSeconds(linker, 15),
    }
    if (captureForm.autoL0Seconds !== next.autoL0Seconds) captureForm.autoL0Seconds = next.autoL0Seconds
    if (captureForm.autoL1Seconds !== next.autoL1Seconds) captureForm.autoL1Seconds = next.autoL1Seconds
    if (captureForm.autoLinkerSeconds !== next.autoLinkerSeconds) captureForm.autoLinkerSeconds = next.autoLinkerSeconds
    localStorage.setItem(AUTO_DURATION_KEY, JSON.stringify(next))
  },
)

const androidReady = computed(() => props.device?.platform === 'android' && props.device.status === 'device')
const readinessTitle = computed(() => {
  if (kernSight.value) return `KernSight ${kernSight.value.agentVersion} · 已连接`
  if (probing.value) return '正在检测设备能力'
  if (capabilityProbe.value) return `${recommendedModeLabel.value} · 探测完成`
  if (!props.device) return '等待设备'
  if (props.device.platform !== 'android') return '仅支持 Android'
  if (props.device.status !== 'device') return '设备尚未授权'
  return '设备已连接 · Agent 未接入'
})
const readinessDetail = computed(() => capabilityProbe.value?.summary || (androidReady.value ? '先执行只读能力探测，再决定使用 Standard、Dev Root 或 System 模式。' : '选择一台已通过 USB 调试授权的 Android 设备。'))
const sessionReport = computed<Record<string, any> | null>(() => selectedReport.value?.report as Record<string, any> || null)
const selectedLocalBundle = computed(() => selectedEvidenceSource.value === 'local' ? localEvidenceBundles.value.find(bundle => bundle.package === selectedPackage.value) || null : null)
const selectedPackageDump = computed(() => selectedEvidenceSource.value === 'device'
  ? devicePackageDumps.value.find(dump => dump.package === selectedPackage.value) || null
  : selectedLocalBundle.value?.dumpReport || packageDumps.value.find(dump => dump.package === selectedPackage.value) || null)
const visibleLocalSessionBundles = computed(() => localEvidenceBundles.value.filter(bundle => bundle.sessionReport))
const completedSessions = computed(() => kernSight.value?.sessions.filter(session => session.state === 'completed').length || 0)
const sensitiveFileCount = computed(() => packageDumps.value.reduce((total, dump) => total + (dump.sensitive_files?.length || 0), 0))
const latestExecutionComplete = computed(() => Boolean(sessionReport.value?.execution_complete))
const environmentTransitions = computed(() => Number(sessionReport.value?.environment_transitions || 0))
const reportLostRecords = computed(() => Number((sessionReport.value?.quality as Record<string, unknown> | undefined)?.lost_records || 0))
const processRows = computed<any[]>(() => asArray(sessionReport.value?.processes))
const plaintextRows = computed<any[]>(() => asArray(sessionReport.value?.plaintext))
const networkRows = computed<any[]>(() => asArray(sessionReport.value?.network_peers))
const binderRows = computed<any[]>(() => asArray(sessionReport.value?.binder_relations))
const kernelBinderInterfaceCount = computed(() => binderRows.value.reduce((total, row) => total + binderInterfaceNames(row.interfaces).length, 0))
const kernelBinderInterfaces = computed(() => {
  const names = new Set<string>()
  for (const row of binderRows.value) {
    for (const iface of binderInterfaceNames(row.interfaces)) names.add(iface)
  }
  return [...names]
})
const binderSemanticHitCount = computed(() => binderSemanticRows.value.reduce((sum, row) => sum + Number(row.hits || 0), 0))
const httpLikePlaintext = computed(() => plaintextRows.value.filter(row => isHttpLikePlaintext(row)))
const orderedPlaintextRows = computed(() => [...plaintextRows.value].sort((left, right) => {
  const urlDelta = plaintextUrlList(right).length - plaintextUrlList(left).length
  if (urlDelta) return urlDelta
  return String(right.preview || '').length - String(left.preview || '').length
}))
const usefulPlaintextRows = computed(() => orderedPlaintextRows.value.filter(row => plaintextUrlList(row).length > 0 || plaintextLooksHttpJson(row)))
const otherPlaintextRows = computed(() => orderedPlaintextRows.value.filter(row => !plaintextUrlList(row).length && !plaintextLooksHttpJson(row)))
const inspectUrlBoard = computed(() => {
  const seen = new Set<string>()
  const out: { key: string; url: string; source: string }[] = []
  const add = (raw: string, source: string) => {
    const url = withInspectUrlScheme(String(raw || '').trim())
    if (!url || seen.has(url) || isDroppedInspectUrl(url)) return
    seen.add(url)
    out.push({ key: `${source}:${url}`, url, source })
  }
  for (const row of httpCallRows.value) {
    const host = String(row.host || '').trim()
    const path = String(row.path || '').trim()
    if (host) add(`${host}${path}`, `${row.origin || 'inspect'} · ${row.method || row.kind || 'http'}`)
  }
  for (const row of plaintextRows.value) {
    const source = String(row.adapter || 'inspect')
    for (const url of plaintextUrlList(row)) add(url, source)
  }
  return out
})
const dnsRows = computed<any[]>(() => asArray(sessionReport.value?.dns_names))
const handshakeRows = computed<any[]>(() => asArray(sessionReport.value?.handshake_names))
const dnsDatagrams = computed(() => Number(sessionReport.value?.dns_datagrams || 0))
const inspectRows = computed<any[]>(() => asArray(sessionReport.value?.inspect_hits))
const mirrorDiagnosticRow = computed<any | null>(() => inspectRows.value.find(row => row.adapter === 'burp_mirror_diagnostics') || null)
const mirrorMetrics = computed<Record<string, number>>(() => {
  const structured = mirrorDiagnosticRow.value?.metrics
  if (structured && typeof structured === 'object') return structured
  const metrics: Record<string, number> = {}
  for (const match of String(mirrorDiagnosticRow.value?.last_detail || '').matchAll(/([a-z_]+)=(\d+)/g)) metrics[match[1]] = Number(match[2])
  return metrics
})
const tlsCoverageRows = computed<any[]>(() => inspectRows.value.filter(row => String(row.adapter || '').startsWith('tls_ssl_')).sort((left, right) => Number(right.hits || 0) - Number(left.hits || 0)))
const binderSemanticRows = computed(() => inspectRows.value.filter(row => row.adapter === 'binder_userspace' && Number(row.hits || 0) > 0))
const jniRegistrationRows = computed(() => inspectRows.value.filter(row => row.adapter === 'jni_registration' && Number(row.hits || 0) > 0))
const jniPlaintextRows = computed(() => plaintextRows.value.filter(row => String(row.adapter || '').startsWith('jni_')))
const runtimeInspectRows = computed(() => inspectRows.value.filter(row => row.adapter !== 'binder_userspace'))
const binderLifecycle = computed<Record<string, any>>(() => sessionReport.value?.binder_lifecycle || {})
const binderFdTransfers = computed<any[]>(() => asArray(sessionReport.value?.binder_fd_transfers))
const fdLifecycle = computed<Record<string, any>>(() => sessionReport.value?.fd_lifecycle || {})
const memoryLifecycle = computed<Record<string, any>>(() => sessionReport.value?.memory_lifecycle || {})
const socketLifecycle = computed<Record<string, any>>(() => sessionReport.value?.socket_lifecycle || {})
const socketIoBytes = computed(() => Number(socketLifecycle.value.sent_bytes || 0) + Number(socketLifecycle.value.received_bytes || 0))
const reportLimitations = computed<string[]>(() => asArray(sessionReport.value?.limitations).map(item => String(item)))
const rawGraphEdges = computed<any[]>(() => asArray(sessionReport.value?.graph?.edges).slice(0, 400))
const graphEdges = computed<any[]>(() => {
  const unique = new Map<string, any>()
  for (const edge of rawGraphEdges.value) {
    const normalized = {
      ...edge,
      strength: edge.relation === 'overlaps_mmap' ? 'correlated' : (['confirmed', 'correlated', 'inferred'].includes(edge.strength) ? edge.strength : 'inferred'),
    }
    const key = `${normalized.from}|${normalized.relation}|${normalized.to}|${normalized.sensor || ''}`
    unique.set(key, normalized)
  }
  return [...unique.values()]
})
const networkBackbone = computed(() => networkRows.value.map((peer, index) => {
  const handshake = handshakeRows.value.find(row => {
    if (row.process_id !== peer.source_process_id) return false
    if (row.peer && peer.peer && row.peer === peer.peer && (row.port == null || peer.port == null || row.port === peer.port)) return true
    if (row.sni && [peer.sni, peer.http_host, peer.resolved_name].includes(row.sni)) return true
    if (row.http_host && [peer.http_host, peer.sni, peer.resolved_name].includes(row.http_host)) return true
    return false
  }) || (peer.sni || peer.http_host ? handshakeRows.value.find(row => row.process_id === peer.source_process_id && (row.sni || row.http_host)) : null) || {}
  const dns = dnsRows.value.find(row => (row.addresses || []).some((address: string) => String(peer.peer || '').includes(address)))
    || dnsRows.value.find(row => row.qname && [peer.sni, peer.http_host, peer.resolved_name].includes(row.qname))
  const name = handshake.sni || handshake.http_host || peer.sni || peer.http_host || peer.resolved_name || dns?.qname || peer.peer || 'unknown peer'
  const protocol = handshake.kind || peer.handshake_kind || (String(peer.peer || '').startsWith('/') ? 'unix' : peer.source) || 'socket'
  const details = [handshake.alpn || peer.alpn, dns?.qname ? `DNS ${dns.qname}` : '', handshake.http_method || peer.http_method].filter(Boolean)
  return {
    key: `${peer.source_process_id}-${peer.peer}-${peer.port}-${index}`,
    name,
    protocol,
    pid: peer.source_process_id,
    fd: handshake.fd ?? peer.fd ?? null,
    endpoint: `${peer.peer || 'unknown'}${peer.port != null ? `:${peer.port}` : ''}`,
    detail: details.join(' · ') || '只有 socket 生命周期元数据',
    strength: handshake.sni || handshake.http_host || peer.sni || peer.http_host ? 'confirmed' : (peer.resolved_name || dns ? 'correlated' : 'inferred'),
  }
}).sort((left, right) => {
  const rank: Record<string, number> = { confirmed: 0, correlated: 1, inferred: 2 }
  return (rank[left.strength] ?? 9) - (rank[right.strength] ?? 9)
}))
const dumpSummaries = computed(() => {
  try {
    if (!sessionPackageLinked.value || !sessionMatchedPackage.value || selectedPackage.value !== sessionMatchedPackage.value) return []
    const merged = new Set(asArray(sessionReport.value?.merged_dumps).map((item: any) => item.package))
    return packageDumps.value.filter(dump => dump.package === selectedPackage.value && (merged.size === 0 || merged.has(dump.package))).map(dump => {
      const frameworks = asArray(dump.native_framework_matches)
      const ruleProfile = frameworks.filter(item => item.category === 'packer_shell').map(item => item.name).join(' · ')
      return {
        package: dump.package,
        profile: ruleProfile || (Number(dump.runtime_blob_dex || dump.readable_dex || 0) ? '运行时 DEX / 壳形态候选' : '常规安装包 / 运行时工件'),
        dex: dump.dex_index?.unique_dex ?? dump.readable_dex ?? 0,
        dexObservations: dump.dex_index?.observations ?? 0,
        indexedClasses: dump.dex_index?.indexed_class_samples || 0,
        indexedMethods: dump.dex_index?.indexed_method_name_samples || 0,
        classConflicts: dump.dex_index?.class_conflicts?.length || 0,
        heapDex: dump.runtime_blob_dex || 0,
        so: dump.runtime_libs || 0,
        hashed: dump.sensitive_files?.length || 0,
        privateFiles: dump.private_files || 0,
        plaintextWindows: dump.plaintext_windows || 0,
        overlaps: 0,
        artifacts: asArray(dump.artifacts).slice(0, 80),
        dexSets: [],
        dexIndex: dump.dex_index,
        frameworks,
        nativeRuleVersion: dump.native_rule_version,
        backbone: buildDumpBackbone(dump, {
          sni: [...new Set(handshakeRows.value.map(row => row.sni || row.http_host).filter(Boolean))],
          dns: [...new Set(dnsRows.value.map(row => row.qname).filter(Boolean))],
          sockets: networkRows.value.length,
          kernelTokens: kernelBinderInterfaceCount.value,
          binderHits: binderSemanticHitCount.value,
          httpPlaintext: httpLikePlaintext.value.length,
          tlsPreview: plaintextRows.value.length,
        }),
      }
    })
  } catch {
    return []
  }
})
const privateFocusFiles = computed(() => {
  if (!sessionPackageLinked.value || selectedPackage.value !== sessionMatchedPackage.value) return []
  const dump = selectedPackageDump.value
  const fromDump = asArray(dump?.sensitive_files).map((file: any) => ({ path: String(file.relative_path || ''), contentClass: String(file.content_class || '') }))
  const fromBundle = asArray(selectedLocalBundle.value?.files).map((file: any) => ({ path: String(file.relativePath || ''), contentClass: String(file.category || '') }))
  const fromArtifacts = asArray(dump?.artifacts).filter((file: any) => file.source === 'app-private').map((file: any) => ({ path: String(file.relative_path || ''), contentClass: 'app-private' }))
  return [...fromDump, ...fromBundle, ...fromArtifacts].filter(file => classifyPrivate(file.path, file.contentClass) === 'focus').slice(0, 24)
})
const httpCallRows = computed<any[]>(() => {
  const fromSession = asArray(sessionReport.value?.http_calls)
  if (fromSession.length) return fromSession
  return asArray(selectedPackageDump.value?.http_calls)
})
const analysisPathInput = computed(() => ({
  processes: processRows.value,
  networkBackbone: networkBackbone.value,
  handshake: handshakeRows.value,
  plaintext: plaintextRows.value,
  httpPlaintext: httpLikePlaintext.value,
  httpCalls: httpCallRows.value,
  httpCodeRefs: asArray(sessionReport.value?.http_code_refs).length
    ? asArray(sessionReport.value?.http_code_refs)
    : asArray(selectedPackageDump.value?.http_code_refs),
  jniExports: asArray(selectedPackageDump.value?.jni_exports),
  kernelTokens: kernelBinderInterfaces.value,
  binderSemantic: binderSemanticRows.value,
  dump: dumpSummaries.value[0] || null,
  privateFiles: privateFocusFiles.value,
  gaps: honestGaps.value,
}))
const analysisPath = computed(() => buildAnalysisPath(analysisPathInput.value))
const analysisFlow = computed(() => buildAnalysisFlow(analysisPathInput.value))
const forensicSurfaces = computed(() => {
  const selected = selectedPackageDump.value ? [selectedPackageDump.value] : []
  const sum = (field: keyof KernSightPackageDumpReport) => selected.reduce((total, dump) => total + Number(dump[field] || 0), 0)
  const privatePathCount = (prefix: string) => selected.reduce((total, dump) => total + asArray(dump.artifacts).filter(file => file.source === 'app-private' && String(file.relative_path || '').startsWith(prefix)).length, 0)
  return [
    { key: 'apk', icon: 'android', label: '安装包代码', path: 'apk/ · apk-dex/ · lib/ · oat/', count: sum('apk_files') + sum('apk_dex') + sum('native_libs') + sum('oat_files'), detail: '安装包 DEX/SO/OAT；常见壳场景可能只是 stub。' },
    { key: 'readable', icon: 'data_object', label: '可读 DEX', path: 'readable-dex/ · runtime/mem-* · blob-dex/', count: sum('readable_dex') + sum('runtime_blob_dex'), detail: '按 SHA-256 聚合逻辑 DEX Set，但物理文件与来源仍分别保留。' },
    { key: 'native', icon: 'deployed_code', label: '运行时 SO', path: 'runtime/runtime-so/ · apk-assets/', count: sum('runtime_libs') + sum('asset_files'), detail: '规则库命中只代表壳/加密框架候选，不证明算法已执行。' },
    { key: 'plaintext', icon: 'key', label: '内存明文窗口', path: 'runtime/plaintext/ · packer-keys/ · packer-mem/', count: sum('plaintext_windows') + sum('key_slots') + sum('packer_regions'), detail: `${sum('plaintext_windows')} 个明文窗口 · ${sum('key_slots')} 个 key slot · ${sum('packer_regions')} 个 packer region；来自进程内存，不是从 DEX/SO 静态反编译。` },
    { key: 'ce', icon: 'database', label: 'CE 私有数据', path: 'data-private/ce/{shared_prefs,databases,files,no_backup}', count: privatePathCount('data-private/ce/'), detail: `报告总计 ${sum('private_files')} 个有界私有文件；目录明细最多编目 64 条。不能直接证明曾发往某 socket。` },
    { key: 'de', icon: 'lock_open', label: 'DE 私有数据', path: 'data-private/de/{shared_prefs,databases,files,no_backup}', count: privatePathCount('data-private/de/'), detail: '设备加密区的有界副本；不包含完整 cache/code_cache/app_webview。' },
    { key: 'snapshot', icon: 'memory', label: '快照与映射', path: 'runtime/snapshot-*.json · maps-* · mapped/open/code-loader', count: selected.reduce((total, dump) => total + (dump.snapshots?.length || 0) + (dump.mapped_code?.length || 0), 0), detail: 'SIGSTOP + /proc/pid/mem 元数据属于 L2；与 mmap 重叠永远只标 correlated。' },
    { key: 'fd', icon: 'folder_open', label: 'FD / 取证文件', path: 'runtime/fd/ · forensics/', count: sum('fd_images'), detail: '打开文件与 spooled 会话哈希产物；文件存在不自动升级为运行时因果。' },
  ]
})
const evidenceFiles = computed(() => {
  const matchesCategory = (path: string) => {
    const category = selectedEvidenceCategory.value
    if (!category) return true
    const roots: Record<string, string[]> = {
      apk: ['apk/', 'apk-dex/', 'lib/', 'oat/'],
      readable: ['readable-dex/', 'runtime/mem-', 'runtime/blob-dex/'],
      native: ['runtime/runtime-so/', 'apk-assets/'],
      plaintext: ['runtime/plaintext/', 'runtime/packer-keys/', 'runtime/packer-mem/'],
      ce: ['data-private/ce/'], de: ['data-private/de/'],
      snapshot: ['runtime/snapshot-', 'runtime/maps-', 'mapped/', 'open/', 'code-loader/'],
      fd: ['runtime/fd/', 'forensics/'],
    }
    return (roots[category] || []).some(prefix => path.startsWith(prefix))
  }
  if (selectedLocalBundle.value) {
    return selectedLocalBundle.value.files.filter(file => matchesCategory(file.relativePath)).map(file => ({
      package: selectedLocalBundle.value!.package,
      relative_path: file.relativePath,
      content_class: file.category,
      bytes: file.bytes,
      sha256: '',
      confirmed: false,
    }))
  }
  const dump = selectedPackageDump.value
  if (!dump) return []
  const files = new Map<string, any>()
  for (const file of dump.sensitive_files || []) {
    files.set(file.relative_path, { ...file, package: dump.package })
  }
  for (const artifact of (dump.artifacts || []) as any[]) {
    const path = String(artifact.relative_path || '')
    if (!path || files.has(path)) continue
    files.set(path, {
      package: dump.package,
      relative_path: path,
      content_class: artifact.kind === 'dex' ? 'dex' : artifact.kind === 'elf' ? 'elf' : String(artifact.source || artifact.kind || 'artifact'),
      bytes: Number(artifact.bytes || 0),
      sha256: String(artifact.sha256 || ''),
      confirmed: false,
    })
  }
  for (const dex of dump.dex_sets || []) {
    const path = String(dex.canonical_relative_path || '')
    if (!path || files.has(path)) continue
    files.set(path, {
      package: dump.package,
      relative_path: path,
      content_class: 'dex',
      bytes: Number(dex.bytes || 0),
      sha256: dex.sha256,
      confirmed: false,
    })
  }
  return [...files.values()].filter(file => matchesCategory(file.relative_path)).sort((left, right) => left.relative_path.localeCompare(right.relative_path))
})
const analyzableArtifacts = computed<any[]>(() => {
  const dump = selectedPackageDump.value
  if (!dump) return []
  const result: any[] = []
  const represented = new Set<string>()
  for (const dex of dump.dex_sets || []) {
    const observation = dex.observations?.[0]
    const semantic = dex.semantic
    const path = dex.canonical_relative_path
    represented.add(`${dex.sha256}:${path}`)
    result.push({
      key: `dex:${dex.sha256}:${path}`,
      path,
      origin: artifactOriginLabel(observation?.source || dex.sources?.[0] || '', path),
      source: observation?.source || dex.sources?.join(', ') || 'dex-set',
      ready: Boolean(semantic),
      detail: semantic
        ? `DEX ${semantic.version} · ${semantic.class_defs.toLocaleString()} classes · ${semantic.method_ids.toLocaleString()} methods · ${dex.observations.length} observations`
        : `${dex.observations?.length || 0} observations · semantic parse 未完成`,
      pid: observation?.pid,
      vmaStart: observation?.vma_start,
      vmaEnd: observation?.vma_end,
      mapPath: observation?.map_path,
      sha256: dex.sha256,
      classSamples: semantic?.class_descriptors || [],
      methodSamples: semantic?.method_names || [],
    })
  }
  for (const artifact of (dump.artifacts || []) as any[]) {
    if (!['dex', 'elf'].includes(String(artifact.kind))) continue
    if (artifact.kind === 'dex' && represented.has(`${artifact.sha256}:${artifact.relative_path}`)) continue
    const path = String(artifact.relative_path || '')
    result.push({
      key: `${artifact.kind}:${artifact.sha256 || path}:${artifact.pid || ''}`,
      path,
      origin: artifactOriginLabel(String(artifact.source || ''), path),
      source: String(artifact.source || artifact.kind),
      ready: artifact.kind === 'elf' ? /\.so(?:\.|$)/i.test(path) : /\.dex$/i.test(path),
      detail: artifact.kind === 'elf' ? `ELF/SO · ${formatBytes(Number(artifact.bytes || 0))}` : `DEX · ${formatBytes(Number(artifact.bytes || 0))} · 尚未进入语义索引`,
      pid: artifact.pid,
      vmaStart: artifact.vma_start,
      vmaEnd: artifact.vma_end,
      mapPath: artifact.map_path,
      sha256: artifact.sha256,
    })
  }
  return result.sort((left, right) => Number(right.ready) - Number(left.ready) || left.path.localeCompare(right.path))
})
const visibleEvidenceFiles = computed(() => evidenceFiles.value.slice(0, evidenceVisibleCount.value))
const selectedEvidenceCategoryLabel = computed(() => forensicSurfaces.value.find(surface => surface.key === selectedEvidenceCategory.value)?.label || '')
const selectedArtifactEdges = computed(() => {
  if (!selectedArtifact.value) return []
  const artifact = selectedArtifact.value
  const vma = artifact.pid && artifact.vmaStart != null && artifact.vmaEnd != null
    ? `vma:${artifact.pid}:${Number(artifact.vmaStart).toString(16)}-${Number(artifact.vmaEnd).toString(16)}`
    : ''
  const needles = [artifact.path, artifact.sha256, vma].filter(Boolean)
  return graphEdges.value.filter(edge => needles.some(needle => JSON.stringify(edge).includes(needle))).slice(0, 100)
})
const commandCatalog = computed(() => {
  const serial = props.device?.serial || '<serial>'
  const packageName = captureForm.package || '<package>'
  return [
    { key: 'capture', tier: 'L0/L1/L2', label: '当前点击式采集', command: captureCommandPreview.value, detail: captureForm.plan === 'auto' ? `完整自动采集：L0 ${captureForm.autoL0Seconds}s → L0+L1 ${captureForm.autoL1Seconds}s → live/launch dump → Linker ${captureForm.autoLinkerSeconds}s。` : captureForm.plan === 'dump' ? '单包 L2 dump --launch，与 Inspect 不同时挂。' : '与上方控件完全同步；TLS、JNI 与 binder_userspace 可组合，Linker Inspect 仍独占。' },
    { key: 'all', tier: 'L0', label: '全设备默认传感器', command: `ksightctl device --serial ${serial} capture --all --duration-seconds 30 --spool`, detail: '--all 不包含高流量的 --network-io 与 --memory-all。' },
    { key: 'package', tier: 'L2', label: '完整冷启动取证', command: `ksightctl device --serial ${serial} pull-package --package ${packageName} --launch --dest packages`, detail: '生成 APK/DEX/SO、live memory、CE/DE 有界副本和 dump-report.json。' },
    { key: 'evidence', tier: 'L2', label: '仅证据目录', command: `ksightctl device --serial ${serial} pull-package --package ${packageName} --launch --evidence-only --dest packages`, detail: '跳过安装 APK/lib/oat，但保留 runtime、data-private、readable-dex 与报告。' },
    { key: 'forensics', tier: 'L0→L2', label: '拉取会话取证文件', command: `ksightctl device --serial ${serial} pull-forensics ${selectedSession.value || '<session-uuid>'} --dest forensics`, detail: '拉取 capture 期间哈希保存的 DEX/connlog 等文件。' },
    { key: 'recatalog', tier: 'L2', label: '重新编目', command: `ksightctl device --serial ${serial} recatalog-package --package ${packageName}`, detail: '不重新运行 App；重建 artifacts、规则命中和 correlated VMA/maps 图。' },
    { key: 'snapshot', tier: 'L2', label: '有界内存快照', command: `ksightctl device --serial ${serial} snapshot --package ${packageName} --max-mib 32 --dest snapshots`, detail: '默认 SIGSTOP；高扰动取证操作，不属于 eBPF Observe。' },
    { key: 'hide', tier: 'L2', label: 'ADB 检测窗口', command: `ksightctl device --serial ${serial} pull-package --package ${packageName} --launch --hide-debug`, detail: '只暂时关闭 adb_enabled/developer options，不隐藏 root、解锁状态或 KernSight。' },
    { key: 'denylist', tier: 'L2', label: 'Magisk DenyList 窗口', command: `ksightctl device --serial ${serial} pull-package --package ${packageName} --launch --denylist`, detail: '仅在 Magisk 存在时临时加入 DenyList；不是隐 root 声明。' },
  ]
})
const evidencePolicies = computed(() => [
  { strength: 'confirmed', title: '进程身份', detail: '使用 boot_id:pid:start_time_ns 作为 process_instance_id；不能仅按 PID 合并。' },
  { strength: 'correlated', title: 'DNS → Socket', detail: 'DNS A/AAAA 地址与 peer IP 对齐后标 correlated resolved_name；时间接近本身不是证明。' },
  { strength: 'correlated', title: 'Handshake → Socket', detail: '按同一 (pid, fd) 或 peer 关联 SNI / HTTP Host / ALPN；代理、CONNECT、ECH 外层可能与 DNS 不同。' },
  { strength: 'confirmed', title: 'TLS preview', detail: '只有实际 tls_send/tls_recv Inspect 命中才展示有界明文；ELF32 ENOTSUP 不推断为无明文。' },
  { strength: 'confirmed', title: 'Binder L0', detail: '优先展示内核 interface_token、binder_method 与 debug_id/replies_to；ELF64 Inspect scalar 单独展示。' },
  { strength: 'correlated', title: 'DEX ↔ mmap', detail: 'overlaps_mmap 在界面和 AI JSON 中强制保持 correlated；ART joined_dex 不是 ClassLoader 实例。' },
  { strength: 'inferred', title: '私有文件', detail: 'CE/DE 文件是采集时的 at-rest 数据；没有同会话文件/host 证据时不连接到 socket。' },
  { strength: 'inferred', title: '壳 / 加密框架', detail: 'native rules 基于文件名、路径和哈希候选；不得升级为已执行算法或已确认保护。' },
])
const layerContracts = [
  { key: 'l0', label: 'L0', stage: 'Observe · eBPF', title: '内核事实层', detail: '默认不 MITM；整机或单包范围。文档基线 event schema 1.28 / raw ABI 1。', items: ['进程/线程/UID/包名候选/Zygote', 'openat + ≤1 MiB 代码文件 SHA-256', 'mmap/mprotect + memory-all 大映射', 'socket + DNS + ClientHello/HTTP/QUIC 首段', 'Binder debug_id/reply/FD/parcel prefix', 'scoped sched_wakeup'] },
  { key: 'l1', label: 'L1', stage: 'Inspect · uprobe', title: '用户态语义探针', detail: 'TLS、JNIEnv 明文与 binder_userspace 可组合；linker 独占。AArch32 在当前 GKI 可能 ENOTSUP。', items: ['SSL_read / SSL_write 有界明文', 'JNIEnv GetStringUTFChars / NewStringUTF / byte[]', 'RegisterNatives name/signature/fnPtr', 'Parcel token/string/int/bool/fd/byte array', 'ELF64 dlopen 路径', 'ART DexFile Open path/size（非 ClassLoader 实例）'] },
  { key: 'l2', label: 'L2', stage: 'Forensic · explicit', title: '产物与有界快照', detail: 'pull-package --launch；是显式取证操作，不是 eBPF 自动批量拷贝。', items: ['APK/DEX/SO/OAT/VDEX/ART', 'readable-dex + heap blob DEX', 'runtime SO/plaintext/key/packer memory', 'CE/DE 四类目录有界副本', 'SIGSTOP + /proc/pid/mem snapshot'] },
  { key: 'gap', label: 'GAP', stage: 'Not collected', title: '明确空白', detail: '没有证据必须显示为缺口，不能由 AI 或时间邻近补成 confirmed。', items: ['L4 HWBP / ptrace / TEE', 'MITM、ECH 内层、HTTP/3 正文', 'Java/native call stacks、ART 对象字段', 'Parcel mData / float / double', '完整 cache/WebView/data/data', '隐 root / 隐解锁状态'] },
]
const honestGaps = computed(() => {
  const gaps: string[] = []
  const quality = sessionReport.value?.quality as Record<string, any> | undefined
  const lostBySensor = quality?.lost_by_sensor || {}
  if (!sessionReport.value?.execution_complete) gaps.push('execution_complete=false：不能把本会话当作完整行为记录。')
  if (reportLostRecords.value) {
    const binderLost = Number(lostBySensor.binder || 0)
    gaps.push(`丢失 ${reportLostRecords.value.toLocaleString()} 条${binderLost ? `（Binder ${binderLost.toLocaleString()}）` : ''}。`)
  }
  if (networkRows.value.length && !handshakeRows.value.length) gaps.push('有 socket 但 Handshake 为 0：常见于复用连接、空 sockaddr connect，或窗口没覆盖到 connect 后首写。不要写成“没有 TLS”。')
  if (handshakeRows.value.some(row => row.ech_present)) gaps.push('ClientHello 标记 ECH-present：外层 SNI 可能不是内层名字。')
  if (!plaintextRows.value.length) gaps.push('L1 Inspect 明文为空。TLS 需要 --inspect-tls 且 ELF64 导出 SSL_write/SSL_read；JNI 需要 --inspect-jni（GetFunctionTable + jni.h）。空结果不表示 App 没有明文。')
  else if (!httpLikePlaintext.value.length) gaps.push('Inspect preview 没有 HTTP/文本类内容。tls_record 是密文/告警；JNI 可能是二进制 byte[]。')
  if (inspectRows.value.some(row => String(row.adapter || '').startsWith('jni_')) && !jniPlaintextRows.value.length && !jniRegistrationRows.value.length) gaps.push('JNI Inspect 已尝试但没有 UTF-8/byte[] 或 RegisterNatives 命中：窗口内可能没跨 JNI，或加固换了 JNIEnv 表。')
  if (binderRows.value.length && !kernelBinderInterfaceCount.value) gaps.push('内核 parcel interface token 为空。64-bit submit 仍可能读不到 String16；不要用 L1 IComponent 名称冒充 L0 token。')
  if (inspectRows.value.some(row => row.adapter === 'binder_userspace') && !binderSemanticRows.value.length) gaps.push('Binder userspace 已尝试但 hits=0：AArch32 uprobe 在当前 GKI 为 ENOTSUP，改看 L0 内核 parcel prefix。')
  const dump = dumpSummaries.value[0]
  if (dump && dump.plaintextWindows > 0 && !plaintextRows.value.length) gaps.push(`L2 有 ${dump.plaintextWindows} 个堆明文窗口，属于 at-rest 内存候选，不能当作某条 socket 的发送证明。`)
  const sched = Number(sessionReport.value?.sensor_counts?.sched || 0)
  if (sched > 10_000) gaps.push(`Sched 事件 ${sched.toLocaleString()}：包 PID 出现前开 --sched 会打满 ring。后续不要在 attach-first 前开 sched。`)
  return gaps
})
const enabledSensorLabels = computed(() => [
  captureForm.files && 'File', captureForm.filesFd && 'FD', captureForm.network && 'Network',
  captureForm.networkIo && 'Socket I/O', captureForm.memory && 'Memory', captureForm.memoryAll && 'Memory all',
  captureForm.binder && 'Binder', captureForm.sched && 'Sched', captureForm.includeThreads && 'Threads',
  inspectModeHasTls(captureForm.inspectMode) && 'TLS Inspect', inspectModeHasJni(captureForm.inspectMode) && 'JNI Inspect', inspectModeHasBinder(captureForm.inspectMode) && 'Binder userspace Inspect', captureForm.inspectMode === 'linker_so_load' && 'Linker Inspect',
].filter(Boolean) as string[])
const captureScopeLabel = computed(() => captureForm.package ? `${captureForm.package}（含冒号进程）` : '整台设备')
const captureRisk = computed(() => {
  if (captureForm.hideDebug) return { label: '实验模式 · ADB 将暂时断开', tone: 'high' }
  if (captureForm.plan === 'dump') return { label: 'Forensic · dump --launch SIGSTOP', tone: 'high' }
  if (captureForm.plan === 'auto') return { label: 'Observe + Inspect + Dump · 自动冷启动', tone: 'high' }
  if (captureForm.inspectMode !== 'none') return { label: 'Inspect · 用户态探针可被感知', tone: 'medium' }
  if (captureForm.sched || captureForm.filesFd || captureForm.memoryAll) return { label: 'Observe · 高事件量', tone: 'medium' }
  return { label: 'Observe · 内核元数据', tone: 'low' }
})
function captureKsightctlLine(options: { duration: number; inspectMode: InspectMode; launch?: boolean }) {
  const serial = props.device?.serial || '<serial>'
  const pkg = captureForm.package || '<package>'
  const args = [`ksightctl device --serial ${serial} capture`]
  if (captureForm.package || options.launch) args.push(`--package ${pkg}`)
  const flags: Array<[boolean, string]> = [
    [captureForm.files, '--files'], [captureForm.filesFd, '--files-fd'], [captureForm.network, '--network'],
    [captureForm.networkIo, '--network-io'], [captureForm.memory, '--memory'], [captureForm.memoryAll, '--memory-all'],
    [captureForm.binder, '--binder'], [captureForm.sched, '--sched'], [captureForm.includeThreads, '--include-threads'],
    [inspectModeHasTls(options.inspectMode), '--inspect-tls'],
    [inspectModeHasJni(options.inspectMode), '--inspect-jni'],
    [options.inspectMode === 'linker_so_load', '--inspect-linker'],
  ]
  flags.forEach(([enabled, flag]) => { if (enabled) args.push(flag) })
  if (inspectModeHasBinder(options.inspectMode)) args.push('--inspect-adapter binder_userspace')
  args.push(`--duration-seconds ${options.duration}`, `--sample-one-in ${captureForm.sampleOneIn}`, '--spool')
  if (options.inspectMode !== 'none') args.push(`--inspect-max-bytes ${captureForm.inspectMaxBytes}`)
  if (captureForm.hideDebug) args.push('--hide-debug')
  const line = args.join(' ')
  if (!options.launch) return line
  return `am force-stop ${pkg}; (sleep 2; monkey -p ${pkg} -c android.intent.category.LAUNCHER 1) &\n${line}`
}
const dumpCommandPreview = computed(() => {
  const serial = props.device?.serial || '<serial>'
  const pkg = captureForm.package || '<package>'
  const hide = captureForm.hideDebug ? ' --hide-debug' : ''
  return [
    `ksightctl device --serial ${serial} pull-package --package ${pkg} --launch --dest packages${hide}`,
    `# 设备端等效：ksightd dump-package --package ${pkg} --dest /data/local/tmp/ksight/packages/${pkg} --launch${hide}`,
  ].join('\n')
})
const captureCommandPreview = computed(() => {
  if (captureForm.plan === 'dump') return dumpCommandPreview.value
  if (captureForm.plan === 'auto') {
    const pkg = captureForm.package || '<package>'
    return [
      `# 完整自动采集。三档时长可在表单改，会记在本机。壳闪退把 L0+L1 留短；要登录就把 L0+L1 调到 90–180。`,
      `# 1) 单包 L0 主干 ${captureForm.autoL0Seconds}s（无 Inspect，赶 Handshake/SNI）`,
      captureKsightctlLine({ duration: captureForm.autoL0Seconds, inspectMode: 'none', launch: true }),
      `# 2) 单包 L0+L1 ${captureForm.autoL1Seconds}s（TLS + JNI 明文 + Parcel。App 起来后在这段时间里登录/注册）`,
      captureKsightctlLine({ duration: captureForm.autoL1Seconds, inspectMode: 'tls_binder_jni', launch: true }),
      `# 3) L2 dump：进程还在则 live harvest（保留登录态 CE/DE），已死则 --launch`,
      `ksightctl device --serial ${props.device?.serial || '<serial>'} pull-package --package ${pkg} --dest packages   # live，不要 --launch`,
      `ksightctl device --serial ${props.device?.serial || '<serial>'} pull-package --package ${pkg} --launch --dest packages   # 仅当 pidof 为空`,
      `# 4) 单包 Linker ${captureForm.autoLinkerSeconds}s（独占 SO load；会 force-stop，放在 dump 之后以免清掉登录态）`,
      captureKsightctlLine({ duration: captureForm.autoLinkerSeconds, inspectMode: 'linker_so_load', launch: true }),
      `# 壳几秒就自杀的 App 不必加长 L0+L1。要登录的把「L0+L1 登录窗」调到 90–180。`,
    ].join('\n').split('<package>').join(pkg)
  }
  return captureKsightctlLine({ duration: captureForm.durationSeconds, inspectMode: captureForm.inspectMode })
})
const captureValid = computed(() => {
  const packageValid = !captureForm.package || /^[A-Za-z0-9._]+$/.test(captureForm.package)
  const inspectValid = !(captureForm.inspectMode !== 'none' || captureForm.sched || captureForm.plan !== 'capture') || Boolean(captureForm.package)
  const autoOk = captureForm.plan !== 'auto' || [captureForm.autoL0Seconds, captureForm.autoL1Seconds, captureForm.autoLinkerSeconds].every(n => n >= 1 && n <= 300)
  return packageValid && inspectValid && autoOk && captureForm.durationSeconds >= 1 && captureForm.durationSeconds <= 300 && captureForm.sampleOneIn >= 1
})
const capturePolicyHint = computed(() => {
  if (!captureValid.value) return 'Inspect / Sched / Dump / 自动采集必须填写包名；时长 1–300 秒。'
  if (captureForm.plan === 'dump') return 'L2 dump --launch：force-stop 后由 dump 自己拉起 App，SIGSTOP 拷堆 DEX/SO/CE·DE。不是 eBPF 会话，不要同时挂 Inspect。'
  if (captureForm.plan === 'auto') return `完整自动采集：L0 ${captureForm.autoL0Seconds}s → L0+L1 ${captureForm.autoL1Seconds}s（登录窗口）→ Dump（进程在则 live，已死则 --launch）→ Linker ${captureForm.autoLinkerSeconds}s。三档秒数可改，会记住。要注册/登录把 L0+L1 调到 90–180。不要开 Sched。`
  if (captureForm.hideDebug) return 'Hide debug 会暂时断开 ADB；设备端 watchdog 在会话结束后恢复调试，MobileE 会等待重连。'
  if (captureForm.inspectMode === 'tls') return 'TLS Inspect 保留 bounded 明文 preview 与 SHA-256；AArch32 uprobe 在当前 GKI 可能返回 ENOTSUP。'
  if (captureForm.inspectMode === 'jni_plaintext') return 'JNI Inspect 挂 libart JNINativeInterface：GetStringUTFChars / NewStringUTF / byte[] 与 RegisterNatives。不读 ART 对象字段。'
  if (captureForm.inspectMode === 'binder_userspace') return 'Binder userspace 解析 Parcel token/scalar；ELF32 失败时仍保留 L0 内核 parcel prefix。'
  if (captureForm.inspectMode === 'tls_jni') return '同会话 TLS 与 JNIEnv 明文；Linker 不会加入。'
  if (captureForm.inspectMode === 'binder_jni') return '同会话 Binder Parcel writers 与 JNIEnv 明文。'
  if (captureForm.inspectMode === 'tls_binder') return '组合会话同时采集 ELF64 TLS 明文与 Binder Parcel writers；Linker 不会加入这个会话。'
  if (captureForm.inspectMode === 'tls_binder_jni') return '完整 L1：TLS + JNIEnv 明文 + Binder Parcel。自动采集的登录窗用这一档。'
  if (captureForm.inspectMode === 'linker_so_load') return 'Linker Inspect 记录 SO load boundary；与 mmap / dump 的连接仍按 correlated 展示。'
  if (captureForm.package) return `单包 L0：Handshake 只在 connect 后首写出现。先开始采集再冷启动 App；复用 socket 不会再出 SNI。PID 出现前不要开 Sched。`
  return '全设备 L0：只采内核元数据。Inspect 和 Sched 必须带包名，否则会打满 ring 或无处 attach。'
})
const captureActionLabel = computed(() => {
  if (captureRunning.value) return `采集中 · ${captureElapsed.value}s${capturePhase.value ? ` · ${capturePhase.value}` : ''}`
  if (captureForm.plan === 'dump') return '开始 Dump --launch'
  if (captureForm.plan === 'auto') return '开始完整自动采集'
  return '开始采集并自动解析'
})
const aiContextJson = computed(() => JSON.stringify({
  schemaVersion: 'mobilee.kernsight-ai-context/v1',
  sessionId: selectedSession.value,
  reportSchema: selectedReport.value?.reportSchema,
  task: '复核这条运行时证据链。confirmed/correlated 是接合强度，不是漏洞结论。只解释 hops 里的事实和明文 preview，不要补缺口。',
  hops: analysisPath.value,
  flow: analysisFlow.value,
  evidencePolicy: {
    plaintextPreviewRetained: true,
    correlatedIsNotConfirmed: true,
    overlapsMmapAlwaysCorrelated: true,
    privateFilesAreAtRestEvidence: true,
    nativeRulesAreCandidates: true,
    staticOrDumpEvidenceCannotProveRuntimeCausality: true,
    highlightIsHeuristicNotVulnerability: true,
  },
  integrity: {
    executionComplete: sessionReport.value?.execution_complete,
    completion: sessionReport.value?.completion,
    quality: sessionReport.value?.quality,
    environment: sessionReport.value?.environment,
    environmentTransitions: sessionReport.value?.environment_transitions,
  },
  processes: processRows.value.slice(0, 40),
  plaintext: plaintextRows.value,
  networkPeers: networkRows.value.slice(0, 80),
  dnsNames: dnsRows.value.slice(0, 128),
  handshakes: handshakeRows.value.slice(0, 128),
  networkBackbone: networkBackbone.value.slice(0, 128),
  binderRelations: binderRows.value.slice(0, 80),
  binderSemantics: binderSemanticRows.value.slice(0, 80),
  runtimeInspect: runtimeInspectRows.value.slice(0, 80),
  lifecycles: {
    fd: fdLifecycle.value,
    memory: memoryLifecycle.value,
    socket: socketLifecycle.value,
    binder: binderLifecycle.value,
    binderFdTransfers: binderFdTransfers.value.slice(0, 80),
  },
  dump: dumpSummaries.value.map(item => ({ package: item.package, profile: item.profile, dex: item.dex, so: item.so, privateFiles: item.privateFiles, plaintextWindows: item.plaintextWindows, backbone: item.backbone })),
  honestGaps: honestGaps.value,
  explicitlyUnavailable: [
    'L4 HWBP / ptrace / TEE', 'MITM / certificate unpinning', 'QUIC HTTP/3 body and ECH inner SNI',
    'JNI RegisterNatives and Java/native stacks', 'Parcel mData and float/double', 'full /data/data', 'hidden root/unlock state',
  ],
  limitations: reportLimitations.value,
}, null, 2))
const readinessIcon = computed(() => capabilityProbe.value ? capabilityProbe.value.recommendedMode === 'system' ? 'verified' : capabilityProbe.value.recommendedMode === 'development' ? 'terminal' : 'info' : androidReady.value ? 'developer_board' : props.device?.platform === 'ios' ? 'mobile_off' : 'usb_off')
const readinessTone = computed(() => androidReady.value ? 'ready' : 'idle')

const trustLabel = computed(() => {
  if (capabilityProbe.value) return capabilityProbe.value.trustLevel
  if (!androidReady.value) return 'Unknown'
  const root = props.details?.rootStatus.toLowerCase() || ''
  return root.includes('root') && !root.includes('not') ? 'Dev Root' : 'Unverified'
})
const trustHint = computed(() => capabilityProbe.value ? `${capabilityProbe.value.rootStatus} · ${capabilityProbe.value.bootloaderStatus}` : trustLabel.value === 'Dev Root' ? '可研发部署，不代表硬件可信' : '需 Agent、AVB 与启动状态证据')
const trustTone = computed(() => trustLabel.value === 'Dev Root' ? 'trust-dev' : '')
const recommendedModeLabel = computed(() => {
  if (capabilityProbe.value?.recommendedMode === 'system') return 'System Candidate'
  if (capabilityProbe.value?.recommendedMode === 'development') return 'Dev Root'
  return 'Standard'
})
const deploymentRequirements = computed(() => {
  const checks = new Map((capabilityProbe.value?.checks || []).map(item => [item.key, item]))
  const architecture = capabilityProbe.value?.architecture || 'Unknown'
  return [
    { key: 'architecture', label: 'ARM64 架构', passed: /aarch64|arm64/i.test(architecture), detail: architecture },
    { key: 'root', label: 'Root 授权', passed: checks.get('root')?.status === 'available', detail: checks.get('root')?.detail || 'Unknown' },
    { key: 'btf', label: '内核 BTF', passed: checks.get('btf')?.status === 'available', detail: checks.get('btf')?.detail || 'Unknown' },
    { key: 'bpffs', label: 'bpffs 已挂载', passed: checks.get('bpffs')?.status === 'available', detail: checks.get('bpffs')?.detail || 'Unknown' },
  ]
})
const failedRequirements = computed(() => deploymentRequirements.value.filter(item => !item.passed))
const deploymentReady = computed(() => failedRequirements.value.length === 0)
const deploymentGateSummary = computed(() => deploymentReady.value
  ? '可以进入开发 Agent 部署阶段；成功启动和握手后才能确认实际可用。'
  : `缺少：${failedRequirements.value.map(item => item.label).join('、')}。这不是普通警告，而是当前开发部署路径的运行前提。`)

async function runCapabilityProbe() {
  if (!androidReady.value || !props.device) return
  probing.value = true
  probeError.value = ''
  try {
    capabilityProbe.value = await monitoringBackend.probeCapabilities(props.device.serial)
    if (capabilityProbe.value.agentStatus !== 'Not Installed') await loadKernSight()
  } catch (error) {
    capabilityProbe.value = null
    probeError.value = readableError(error)
  } finally {
    probing.value = false
  }
}

async function provisionKernSight() {
  if (!androidReady.value || !props.device) return
  provisioning.value = true
  provisionResult.value = null
  probeError.value = ''
  try {
    provisionResult.value = await monitoringBackend.provisionLatestAgent(props.device.serial)
    capabilityProbe.value = await monitoringBackend.probeCapabilities(props.device.serial)
    await loadKernSight()
  } catch (error) {
    probeError.value = readableError(error)
  } finally {
    provisioning.value = false
  }
}

async function loadKernSight() {
  if (!androidReady.value || !props.device) return
  loadingKernSight.value = true
  probeError.value = ''
  try {
    const [overview, dumps] = await Promise.all([
      monitoringBackend.kernSightOverview(props.device.serial),
      monitoringBackend.kernSightPackageDumps(props.device.serial),
    ])
    kernSight.value = overview
    devicePackageDumps.value = dumps.map(dump => markRaw(dump))
    devicePackageNames.value = new Set(dumps.map(dump => dump.package))
    const merged = new Map(dumps.map(dump => [dump.package, markRaw(dump)]))
    for (const bundle of localEvidenceBundles.value) merged.set(bundle.package, markRaw(bundle.dumpReport))
    packageDumps.value = [...merged.values()]
  } catch (error) {
    kernSight.value = null
    devicePackageDumps.value = []
    devicePackageNames.value = new Set()
    packageDumps.value = localEvidenceBundles.value.map(bundle => markRaw(bundle.dumpReport))
    probeError.value = readableError(error)
  } finally {
    loadingKernSight.value = false
  }
}

async function importLocalEvidence() {
  importingLocal.value = true
  probeError.value = ''
  try {
    const bundle = await importDirectory()
    if (!bundle) return
    const dumps = new Map(packageDumps.value.map(dump => [dump.package, dump]))
    dumps.set(bundle.package, bundle.dumpReport)
    packageDumps.value = [...dumps.values()]
    workspaceMode.value = 'evidence'
    selectPackage(bundle.package)
  } catch (error) {
    probeError.value = readableError(error)
  } finally {
    importingLocal.value = false
  }
}

async function pullSelectedPackageEvidence() {
  if (!props.device || !selectedPackage.value || pullingPackage.value) return
  const destination = await open({ directory: true, multiple: false, title: '选择 KernSight 情报保存目录' })
  if (!destination || Array.isArray(destination)) return
  if (!window.confirm(`将重新启动 ${selectedPackage.value} 并执行完整 L2 取证，然后拉取到 ${destination}。继续吗？`)) return
  pullingPackage.value = true
  probeError.value = ''
  try {
    const bundle = await monitoringBackend.pullKernSightPackageEvidence(props.device.serial, selectedPackage.value, destination)
    upsertBundle(bundle)
    const dumps = new Map(packageDumps.value.map(dump => [dump.package, dump]))
    dumps.set(bundle.package, bundle.dumpReport)
    packageDumps.value = [...dumps.values()]
    selectPackage(bundle.package)
  } catch (error) {
    probeError.value = readableError(error)
  } finally {
    pullingPackage.value = false
  }
}

function selectPackage(packageName: string) {
  selectedPackage.value = packageName
  selectedEvidenceSource.value = hasLocalEvidence(packageName) ? 'local' : 'device'
  captureForm.package = packageName
  selectedArtifact.value = null
  selectedEvidenceCategory.value = ''
  evidenceVisibleCount.value = 100
  closeEvidencePreview()
}

function selectPackageSource(packageName: string, source: 'local' | 'device') {
  selectedPackage.value = packageName
  selectedEvidenceSource.value = source
  captureForm.package = packageName
  selectedArtifact.value = null
  selectedEvidenceCategory.value = ''
  evidenceVisibleCount.value = 100
  closeEvidencePreview()
}

function hasLocalEvidence(packageName: string) {
  return localEvidenceBundles.value.some(bundle => bundle.package === packageName)
}

function closePackageWorkspace() {
  selectedPackage.value = ''
  selectedEvidenceSource.value = 'local'
  sessionPackageLinked.value = false
  selectedArtifact.value = null
  selectedEvidenceCategory.value = ''
  evidenceVisibleCount.value = 100
  closeEvidencePreview()
}

function clearCurrentSession() {
  selectedReport.value = null
  selectedSession.value = ''
  sessionMatchedPackage.value = ''
  sessionPackageLinked.value = false
  sessionDetailSection.value = 'summary'
  aiCopied.value = false
}

function armDeleteDeviceSession(sessionId: string) {
  pendingDeletePackage.value = false
  pendingDeleteSession.value = sessionId
}

async function confirmDeleteDeviceSession(sessionId: string) {
  if (!props.device || deletingSession.value || pendingDeleteSession.value !== sessionId) return
  pendingDeleteSession.value = ''
  deletingSession.value = sessionId
  probeError.value = ''
  try {
    await monitoringBackend.cleanupKernSightSession(props.device.serial, sessionId)
    if (selectedSession.value === sessionId) clearCurrentSession()
    await loadKernSight()
  } catch (error) {
    probeError.value = `删除 Session 失败：${readableError(error)}`
  } finally {
    deletingSession.value = ''
  }
}

async function confirmDeleteCurrentPackageEvidence() {
  if (!props.device || !selectedPackage.value || selectedEvidenceSource.value !== 'device' || deletingPackage.value || !pendingDeletePackage.value) return
  const packageName = selectedPackage.value
  pendingDeletePackage.value = false
  deletingPackage.value = true
  probeError.value = ''
  try {
    await monitoringBackend.cleanupKernSightPackageDump(props.device.serial, packageName)
    closePackageWorkspace()
    await loadKernSight()
  } catch (error) {
    probeError.value = `删除整个包证据失败：${readableError(error)}`
  } finally {
    deletingPackage.value = false
  }
}

function hasPackageEvidence(packageName: string) {
  return packageDumps.value.some(dump => dump.package === packageName)
}

function linkSessionPackageEvidence() {
  if (!sessionMatchedPackage.value || !hasPackageEvidence(sessionMatchedPackage.value)) return
  selectPackage(sessionMatchedPackage.value)
  sessionPackageLinked.value = true
}

function unlinkSessionPackageEvidence() {
  sessionPackageLinked.value = false
}

function evidenceLocationLabel(packageName: string) {
  const bundle = localEvidenceBundles.value.find(item => item.package === packageName)
  const onDevice = devicePackageNames.value.has(packageName)
  if (bundle && onDevice) return `Mac ${bundle.root} · ${bundle.fileCount.toLocaleString()} files · 手机端也有副本`
  if (bundle) return `Mac ${bundle.root} · ${bundle.fileCount.toLocaleString()} files · ${formatBytes(bundle.totalBytes)}`
  return '手机 /data/local/tmp/ksight/packages 受保护证据'
}

function evidenceSources(packageName: string) {
  const sources: Array<{ kind: string; label: string }> = []
  if (localEvidenceBundles.value.some(item => item.package === packageName)) sources.push({ kind: 'local', label: 'MAC 本地' })
  if (devicePackageNames.value.has(packageName)) sources.push({ kind: 'device', label: '手机端' })
  return sources.length ? sources : [{ kind: 'unknown', label: '来源待确认' }]
}

function bundleSessionId(bundle: KernSightLocalEvidenceBundle) {
  return String(bundle.sessionReport?.session_id || `${bundle.package}-local-session`)
}

function loadLocalBundleSession(bundle: KernSightLocalEvidenceBundle) {
  if (!bundle.sessionReport) return
  const sessionId = bundleSessionId(bundle)
  selectedSession.value = sessionId
  sessionMatchedPackage.value = bundle.package
  sessionPackageLinked.value = false
  sessionDetailSection.value = 'summary'
  selectedReport.value = markRaw({
    sessionId,
    reportSchema: String(bundle.sessionReport.schema_version || 'local-session-report'),
    report: bundle.sessionReport,
  })
  detailTab.value = 'chain'
}

async function loadSessionReport(sessionId: string) {
  if (!props.device) return
  selectedReport.value = null
  selectedSession.value = sessionId
  sessionMatchedPackage.value = ''
  sessionPackageLinked.value = false
  sessionDetailSection.value = 'summary'
  loadingReport.value = true
  probeError.value = ''
  try {
    selectedReport.value = markRaw(await monitoringBackend.kernSightReport(props.device.serial, sessionId))
    const processes = asArray<Record<string, any>>(selectedReport.value.report?.processes)
    const matchedPackage = processes
      .map(process => String(process.package || ''))
      .find(packageName => packageDumps.value.some(dump => dump.package === packageName))
    sessionMatchedPackage.value = matchedPackage || processes.map(process => String(process.package || '')).find(Boolean) || ''
    detailTab.value = 'chain'
  } catch (error) {
    clearCurrentSession()
    probeError.value = readableError(error)
  } finally {
    loadingReport.value = false
  }
}

function applyCapturePreset(preset: 'whole' | 'tls-binder' | 'binder' | 'linker' | 'observe-pkg' | 'dump' | 'auto') {
  captureForm.files = true
  captureForm.network = true
  captureForm.memory = true
  captureForm.binder = true
  captureForm.filesFd = false
  captureForm.networkIo = false
  captureForm.memoryAll = false
  captureForm.sched = false
  captureForm.inspectMode = preset === 'tls-binder' ? 'tls_binder_jni' : preset === 'binder' ? 'binder_userspace' : preset === 'linker' ? 'linker_so_load' : 'none'
  captureForm.hideDebug = false
  captureForm.plan = preset === 'dump' ? 'dump' : preset === 'auto' ? 'auto' : 'capture'
  if (preset !== 'auto') captureForm.durationSeconds = preset === 'whole' ? 30 : preset === 'dump' ? 120 : 45
  else captureForm.durationSeconds = captureForm.autoL1Seconds
  if (preset === 'whole') captureForm.package = ''
  else if (!captureForm.package && selectedPackage.value) captureForm.package = selectedPackage.value
}

function buildDumpBackbone(dump: KernSightPackageDumpReport, facts: {
  sni: string[]
  dns: string[]
  sockets: number
  kernelTokens: number
  binderHits: number
  httpPlaintext: number
  tlsPreview: number
}) {
  const parts: string[] = []
  if (facts.sni.length) parts.push(`DNS/Handshake → ${facts.sni[0]}`)
  else if (facts.dns.length) parts.push(`DNS ${facts.dns[0]}（无 SNI）`)
  else if (facts.sockets) parts.push('仅有 socket 元数据，无 DNS/SNI')
  if (facts.kernelTokens) parts.push('L0 Binder token')
  else if (facts.binderHits) parts.push('仅 L1 Parcel，内核 token 空')
  if (facts.httpPlaintext) parts.push('L1 TLS HTTP 明文')
  else if (facts.tlsPreview) parts.push('L1 preview 但非 HTTP 明文')
  if (Number(dump.plaintext_windows || 0) > 0) parts.push(`L2 堆明文窗口 ${dump.plaintext_windows}`)
  if (Number(dump.private_files || 0) > 0) parts.push(`CE/DE ${dump.private_files} 个有界文件`)
  const packers = (dump.native_framework_matches || []).filter(item => item.category === 'packer_shell').map(item => item.name)
  if (packers.length) parts.push(packers.join(' / '))
  return parts.join(' · ') || '分层关联；没有同会话连接证据时只保留候选关系。'
}

function buildCaptureRequest(inspectMode: typeof captureForm.inspectMode, durationSeconds: number, launchAfterAttach: boolean): KernSightCaptureRequest {
  return {
    serial: props.device!.serial,
    package: captureForm.package || null,
    durationSeconds,
    files: captureForm.files,
    filesFd: captureForm.filesFd,
    network: captureForm.network,
    networkIo: captureForm.networkIo,
    memory: captureForm.memory,
    memoryAll: captureForm.memoryAll,
    binder: captureForm.binder,
    sched: captureForm.sched,
    includeThreads: captureForm.includeThreads,
    inspectTls: inspectModeHasTls(inspectMode),
    inspectJni: inspectModeHasJni(inspectMode),
    inspectLinker: inspectMode === 'linker_so_load',
    inspectAdapter: inspectModeHasBinder(inspectMode) ? 'binder_userspace' : null,
    hideDebug: captureForm.hideDebug,
    sampleOneIn: Number(captureForm.sampleOneIn),
    inspectMaxBytes: Number(captureForm.inspectMaxBytes),
    inspectMaxHits: Number(captureForm.inspectMaxHits),
    launchAfterAttach,
  }
}

function mergeCaptureLogs(parts: KernSightCaptureResult[]): KernSightCaptureResult {
  const last = parts[parts.length - 1]
  return {
    sessionId: [...parts].reverse().find(part => part.sessionId)?.sessionId || last?.sessionId,
    startedUnixMs: parts[0]?.startedUnixMs || Date.now(),
    finishedUnixMs: last?.finishedUnixMs || Date.now(),
    commandPreview: parts.map(part => part.commandPreview).filter(Boolean).join('\n\n'),
    stdout: parts.map(part => part.stdout).filter(Boolean).join('\n\n'),
    stderr: parts.map(part => part.stderr).filter(Boolean).join('\n\n'),
    exitCode: last?.exitCode,
    hideDebug: captureForm.hideDebug,
  }
}

async function startCapture() {
  if (!props.device || !captureValid.value || captureRunning.value) return
  captureRunning.value = true
  captureElapsed.value = 0
  capturePhase.value = ''
  captureResult.value = null
  probeError.value = ''
  captureTimer = setInterval(() => { captureElapsed.value += 1 }, 1000)
  try {
    if (captureForm.plan === 'dump') {
      capturePhase.value = 'L2 dump'
      captureResult.value = await monitoringBackend.dumpKernSightPackage(props.device.serial, captureForm.package, captureForm.hideDebug, false)
    } else if (captureForm.plan === 'auto') {
      const logs: KernSightCaptureResult[] = []
      const l0 = clampCaptureSeconds(captureForm.autoL0Seconds, 15)
      const l1 = clampCaptureSeconds(captureForm.autoL1Seconds, 90)
      const linker = clampCaptureSeconds(captureForm.autoLinkerSeconds, 15)
      capturePhase.value = `L0 主干 ${l0}s`
      logs.push(await monitoringBackend.startKernSightCapture(buildCaptureRequest('none', l0, true)))
      capturePhase.value = `L0+L1 ${l1}s`
      logs.push(await monitoringBackend.startKernSightCapture(buildCaptureRequest('tls_binder_jni', l1, true)))
      capturePhase.value = 'L2 dump'
      logs.push(await monitoringBackend.dumpKernSightPackage(props.device.serial, captureForm.package, captureForm.hideDebug, true))
      capturePhase.value = `Linker ${linker}s`
      logs.push(await monitoringBackend.startKernSightCapture(buildCaptureRequest('linker_so_load', linker, true)))
      captureResult.value = {
        ...mergeCaptureLogs(logs),
        sessionId: logs[1]?.sessionId || logs[0]?.sessionId || logs[3]?.sessionId,
      }
    } else {
      captureResult.value = await monitoringBackend.startKernSightCapture(buildCaptureRequest(captureForm.inspectMode, Number(captureForm.durationSeconds), false))
    }
    await loadKernSight()
    if (captureResult.value?.sessionId) {
      workspaceMode.value = 'evidence'
      await loadSessionReport(captureResult.value.sessionId)
    }
  } catch (error) {
    probeError.value = readableError(error)
  } finally {
    captureRunning.value = false
    capturePhase.value = ''
    if (captureTimer) clearInterval(captureTimer)
    captureTimer = undefined
  }
}

async function copyAiContext() {
  try {
    await navigator.clipboard.writeText(aiContextJson.value)
    aiCopied.value = true
    window.setTimeout(() => { aiCopied.value = false }, 1800)
  } catch (error) {
    probeError.value = `无法复制 AI 上下文：${readableError(error)}`
  }
}

async function openAiReview() {
  await copyAiContext()
  emit('open-ai')
}

async function openEvidenceCategory(category: string) {
  selectedEvidenceCategory.value = selectedEvidenceCategory.value === category ? '' : category
  evidenceVisibleCount.value = 100
  selectedArtifact.value = null
  closeEvidencePreview()
  await nextTick()
  evidenceBrowserRef.value?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function artifactForEvidence(path: string) {
  return analyzableArtifacts.value.find(artifact => artifact.path === path) || null
}

function evidencePriority(file: any) {
  const artifact = artifactForEvidence(file.relative_path)
  if (artifact) return classifyDex(artifact.path, artifact.source) === 'focus' || classifySo(artifact.path, artifact.source) === 'focus' ? 'focus' : 'watch'
  return classifyPrivate(file.relative_path, file.content_class)
}

function evidenceBadge(file: any) {
  const artifact = artifactForEvidence(file.relative_path)
  if (artifact) {
    if (evidencePriority(file) === 'focus') return '重点关注'
    return artifact.ready ? '可直接分析' : '需要转换/复核'
  }
  return evidencePriority(file) === 'focus' ? '重点关注' : (file.confirmed ? 'confirmed' : 'candidate')
}

async function openEvidenceEntry(file: any) {
  selectedArtifact.value = artifactForEvidence(file.relative_path)
  await loadEvidenceFile(file.package, file.relative_path)
}

function hexPreview(bytes: Uint8Array) {
  const rows: string[] = []
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const row = bytes.slice(offset, offset + 16)
    rows.push(`${offset.toString(16).padStart(8, '0')}  ${Array.from(row).map(byte => byte.toString(16).padStart(2, '0')).join(' ')}`)
  }
  return rows.join('\n')
}

function readableBinaryPreview(bytes: Uint8Array) {
  const sanitise = (text: string) => text
    .replace(/\u0000/g, '·')
    .replace(/[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '·')
  const utf8 = sanitise(new TextDecoder('utf-8', { fatal: false }).decode(bytes))
  const utf16 = bytes.length >= 2 ? sanitise(new TextDecoder('utf-16le', { fatal: false }).decode(bytes)) : ''
  const asciiRuns = Array.from(new Set((Array.from(bytes, byte => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '\n').join('').match(/[^\n]{4,}/g) || []).map(value => value.trim()).filter(Boolean)))
  const parts = [`UTF-8（不可打印字节以 · 标记）\n${utf8}`]
  if (asciiRuns.length) parts.push(`可打印字符串\n${asciiRuns.slice(0, 1000).join('\n')}`)
  if (utf16 && utf16 !== utf8 && /[\p{L}\p{N}]{2}/u.test(utf16)) parts.push(`UTF-16LE 候选\n${utf16}`)
  return parts.join('\n\n')
}

async function loadEvidenceFile(packageName: string, relativePath: string) {
  loadingEvidence.value = true
  selectedEvidenceKey.value = `${packageName}:${relativePath}`
  probeError.value = ''
  try {
    const local = selectedLocalBundle.value
    const result = local
      ? await monitoringBackend.localKernSightEvidenceFile(local.root, packageName, relativePath)
      : props.device
        ? await monitoringBackend.kernSightPackageFile(props.device.serial, packageName, relativePath)
        : (() => { throw new Error('没有可读取的设备端或本地证据来源') })()
    selectedEvidence.value = result
    const binary = Uint8Array.from(atob(result.content), character => character.charCodeAt(0))
    const controlBytes = binary.slice(0, Math.min(binary.length, 4096)).filter(byte => byte === 0 || (byte < 9) || (byte > 13 && byte < 32)).length
    if (controlBytes > Math.max(4, Math.min(binary.length, 4096) / 20)) {
      const previewBytes = binary.slice(0, 65_536)
      evidencePreviewKind.value = 'binary · HEX + decoded'
      evidencePreview.value = hexPreview(previewBytes)
      evidenceDecodedPreview.value = readableBinaryPreview(previewBytes)
    } else {
      evidencePreviewKind.value = 'UTF-8 text'
      evidencePreview.value = new TextDecoder('utf-8', { fatal: false }).decode(binary)
      evidenceDecodedPreview.value = ''
    }
  } catch (error) {
    selectedEvidence.value = null
    evidencePreview.value = ''
    evidenceDecodedPreview.value = ''
    probeError.value = readableError(error)
  } finally {
    loadingEvidence.value = false
  }
}

function closeEvidencePreview() {
  selectedEvidence.value = null
  selectedEvidenceKey.value = ''
  evidencePreview.value = ''
  evidenceDecodedPreview.value = ''
  evidencePreviewKind.value = 'text'
}

function evidenceOriginLabel(path: string) {
  if (path.startsWith('runtime/plaintext/')) return '匿名进程内存明文窗口；不是从 DEX/SO 静态解析'
  if (path.startsWith('runtime/packer-keys/')) return '堆或 BSS 的 key 候选'
  if (path.startsWith('runtime/packer-mem/')) return '壳/VMP 相关进程内存区'
  if (path.startsWith('runtime/runtime-so/')) return '进程已加载 SO 的取证副本'
  if (path.startsWith('readable-dex/')) return '已修复/可直接交给 DEX 工具的副本'
  if (path.startsWith('data-private/ce/')) return 'CE 静态文件；不能单独证明网络发送'
  if (path.startsWith('data-private/de/')) return 'DE 静态文件；不能单独证明网络发送'
  if (path.startsWith('apk-dex/') || path.startsWith('apk/')) return '安装包或拆分 APK 来源'
  if (path.startsWith('lib/') || path.startsWith('oat/')) return '安装态原生/编译产物'
  if (path === 'session-report.json') return 'Session 聚合报告'
  if (path === 'dump-report.json') return 'L2 dump 聚合报告'
  return '本地取证文件'
}

function artifactOriginLabel(source: string, path: string) {
  if (['heap-blob', 'memory-dex'].includes(source)) return '进程内存 DEX'
  if (source === 'runtime-so' || path.startsWith('runtime/runtime-so/')) return '运行时已加载 SO'
  if (source === 'app-private') return 'App 私有存储'
  if (path.startsWith('apk-dex/') || source.includes('apk')) return '安装包 DEX'
  if (path.startsWith('lib/')) return '安装包原生库'
  return '取证产物'
}

function isHttpLikePlaintext(row: Record<string, any>) {
  const cls = String(row.content_class || '').toLowerCase()
  return cls && !['tls_record', 'unknown', ''].includes(cls)
}

function plaintextCardKey(row: Record<string, any>, index: number | string) {
  return `${row.process_id || 0}:${row.adapter || ''}:${row.direction || ''}:${index}`
}

function hexStringToBytes(hex: string) {
  const clean = hex.replace(/\s+/g, '')
  if (clean.length < 8 || clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) return null
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

async function inflateGzipBytes(bytes: Uint8Array) {
  if (bytes.length < 3 || bytes[0] !== 0x1f || bytes[1] !== 0x8b || bytes[2] !== 0x08) return null
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))
    return new Uint8Array(await new Response(stream).arrayBuffer())
  } catch {
    return null
  }
}

function extractPreviewUrls(text: string) {
  const found = text.match(/https?:\/\/[^\s"'<>\\)\],}]+/g) || []
  const urls = found.map(withInspectUrlScheme).filter(url => Boolean(url) && !isDroppedInspectUrl(url))
  return [...new Set(urls)].slice(0, 32)
}

function withInspectUrlScheme(url: string) {
  const trimmed = url.trim()
  if (!trimmed) return ''
  if (/^https?:\/\//i.test(trimmed)) return trimmed
  return `https://${trimmed}`
}

function isDroppedInspectUrl(url: string) {
  const lower = url.toLowerCase()
  const path = lower.split(/[?#]/)[0] || lower
  if (/\.(png|jpe?g|gif|webp|ico|bmp|svg)$/.test(path)) return true
  return /(digicert|\/ocsp|\.crl$)/i.test(path)
}

function plaintextUrlList(row: Record<string, any>) {
  const recorded = asArray(row.urls).map(item => String(item || '').trim()).filter(Boolean)
  if (recorded.length) return [...new Set(recorded)].slice(0, 32)
  return extractPreviewUrls(String(row.preview || ''))
}

function plaintextLooksHttpJson(row: Record<string, any>) {
  const preview = String(row.preview || '')
  return /HTTP\/1\.|PRI \* HTTP\/2|:path|:authority|^(GET|POST) |https?:\/\//.test(preview) || /"(url|host|path)"\s*:/.test(preview)
}

async function transcodePlaintextPreview(preview: string) {
  const hexBytes = hexStringToBytes(preview.trim())
  let bytes = hexBytes || new TextEncoder().encode(preview)
  const inflated = await inflateGzipBytes(bytes)
  if (inflated) bytes = inflated
  const decoded = readableBinaryPreview(bytes)
  const utf8 = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  const urls = extractPreviewUrls(utf8)
  const parts: string[] = []
  if (inflated) parts.push('gzip 已解压')
  else if (hexBytes) parts.push('hex → bytes')
  else parts.push('按 UTF-8 / UTF-16 / 可打印串转码；不是 protobuf 解码器')
  if (urls.length) parts.push(`URL\n${urls.join('\n')}`)
  parts.push(decoded)
  return parts.join('\n\n')
}

async function togglePlaintextDecode(row: Record<string, any>, index: number) {
  const key = plaintextCardKey(row, index)
  if (plaintextDecoded.value[key]) {
    const next = { ...plaintextDecoded.value }
    delete next[key]
    plaintextDecoded.value = next
    return
  }
  const preview = String(row.preview || '')
  if (!preview) return
  plaintextDecoded.value = { ...plaintextDecoded.value, [key]: await transcodePlaintextPreview(preview) }
}

function plaintextOriginLabel(row: Record<string, any>) {
  const adapter = String(row.adapter || '')
  if (['tls_ssl_read', 'ssl_read'].includes(adapter)) return 'L1 SSL_read 进程缓冲区'
  if (['tls_ssl_write', 'ssl_write'].includes(adapter)) {
    return row.content_class === 'tls_record' ? 'TLS record 分类；是密文/告警，不标为 HTTP 明文' : 'L1 SSL_write 进程缓冲区'
  }
  if (adapter === 'jni_get_string_utf_chars') return 'L1 JNIEnv GetStringUTFChars（Java → native）'
  if (adapter === 'jni_new_string_utf') return 'L1 JNIEnv NewStringUTF（native → Java）'
  if (adapter === 'jni_get_byte_array_region' || adapter === 'jni_get_byte_array_elements' || adapter === 'jni_get_primitive_array_critical') return 'L1 JNIEnv byte[] → native'
  if (adapter === 'jni_set_byte_array_region') return 'L1 JNIEnv native → Java byte[]'
  if (adapter === 'jni_new_string') return 'L1 JNIEnv NewString（UTF-16 native → Java）'
  if (adapter === 'jni_get_string_chars' || adapter === 'jni_get_string_critical') return 'L1 JNIEnv String → UTF-16 native'
  if (adapter === 'jni_get_string_region') return 'L1 JNIEnv GetStringRegion UTF-16'
  if (adapter === 'jni_get_char_array_elements' || adapter === 'jni_get_char_array_region') return 'L1 JNIEnv char[] → UTF-16'
  if (adapter === 'jni_set_char_array_region') return 'L1 JNIEnv native UTF-16 → char[]'
  if (adapter === 'jni_get_direct_buffer_address') return 'L1 JNIEnv DirectByteBuffer'
  if (adapter.startsWith('jni_')) return `L1 JNIEnv ${adapter}`
  if (String(row.source || '').includes('runtime/plaintext')) return 'L2 匿名内存窗口'
  return 'Session 有界 preview'
}

function asArray<T = any>(value: unknown): T[] {
  return Array.isArray(value) ? value as T[] : []
}

function binderInterfaceNames(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(item => String(item || '').trim()).filter(Boolean)
  if (value && typeof value === 'object') return Object.keys(value as Record<string, unknown>).map(item => item.trim()).filter(Boolean)
  return []
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1 }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`
}

function formatDate(value?: number | null) {
  return value ? new Date(value).toLocaleString() : '时间未知'
}

function shortSession(value?: string | null) {
  return value ? `${value.slice(0, 8)}…` : 'none'
}

function shortLibrary(value?: string | null) {
  const path = String(value || '')
  if (!path) return '未记录库路径'
  const parts = path.split('/').filter(Boolean)
  return parts.slice(-2).join('/') || path
}

function coverageReason(row: Record<string, any>) {
  const detail = String(row.last_detail || '')
  if (/symbol\/offset not found|symbol not found/i.test(detail)) return 'symbol / offset missing'
  if (/not supported|ENOTSUP/i.test(detail)) return 'unsupported ABI'
  if (/attach failed/i.test(detail)) return 'attach failed'
  if (/candidate discovered/i.test(detail)) return 'discovered · unresolved'
  return 'not attached'
}

function formatRange(start?: number | null, end?: number | null) {
  if (start == null || end == null) return 'no VMA'
  return `0x${Number(start).toString(16)}–0x${Number(end).toString(16)}`
}

function compactJson(value: unknown) {
  const text = JSON.stringify(value || {})
  return text.length > 420 ? `${text.slice(0, 420)}…` : text
}

function sensitiveCount(dump: KernSightPackageDumpReport, contentClass: string, legacy?: number) {
  if (!dump.sensitive_files) return legacy || 0
  return dump.sensitive_files.filter(file => file.content_class === contentClass).length
}

function capabilityIcon(status: string) {
  if (status === 'available') return 'check_circle'
  if (status === 'restricted') return 'lock'
  if (status === 'warning') return 'warning'
  if (status === 'missing') return 'cancel'
  return 'help'
}

function capabilityStatusLabel(status: string) {
  if (status === 'available') return 'READY'
  if (status === 'restricted') return 'RESTRICTED'
  if (status === 'warning') return 'CHECK'
  if (status === 'missing') return 'MISSING'
  return 'UNKNOWN'
}

watch(() => props.device?.serial, () => {
  capabilityProbe.value = null
  kernSight.value = null
  devicePackageDumps.value = []
  devicePackageNames.value = new Set()
  packageDumps.value = localEvidenceBundles.value.map(bundle => bundle.dumpReport)
  clearCurrentSession()
  captureResult.value = null
  closeEvidencePreview()
  probeError.value = ''
})

onErrorCaptured((error) => {
  probeError.value = `会话页渲染失败：${error instanceof Error ? error.message : String(error)}`
  return false
})

watch(requestedPackage, packageName => {
  if (!packageName) return
  workspaceMode.value = 'evidence'
  const bundle = localEvidenceBundles.value.find(item => item.package === packageName)
  if (!bundle) return
  selectPackage(packageName)
}, { immediate: true })

onBeforeUnmount(() => {
  if (captureTimer) clearInterval(captureTimer)
})
</script>

<style scoped>
.runtime-monitor-layout,
.runtime-monitor-layout > *,
.ks-session-panel,
.ks-session-panel > *,
.ks-flow,
.ks-path,
.ks-chain-stage,
.ks-detail-pane {
  min-width: 0;
  max-width: 100%;
}
.ks-session-panel { overflow-x: clip; }
.ks-flow-card > header,
.ks-flow-card dl,
.ks-flow-card dl > div,
.ks-path > li,
.ks-path > li > header,
.ks-backbone-list article,
.ks-backbone-list article > *,
.ks-data-table article,
.ks-lifecycle-grid article,
.ks-lifecycle-grid article > div {
  min-width: 0;
}
.ks-flow-card strong,
.ks-flow-card dd,
.ks-flow-card code,
.ks-path > li > header > strong,
.ks-path > li > p,
.ks-path > li > code,
.ks-backbone-list strong,
.ks-backbone-list code,
.ks-backbone-list span,
.ks-data-table strong,
.ks-data-table small,
.ks-data-table code,
.ks-lifecycle-grid strong,
.ks-lifecycle-grid p {
  overflow-wrap: anywhere;
  word-break: break-word;
}
.ks-path > li > header > strong { flex: 1 1 180px; }
.ks-path > li > code,
.ks-backbone-list code,
.ks-data-table code {
  max-width: 100%;
}
.runtime-probe-error { margin: 0; }
.capability-probe-panel { padding: 18px; }
.capability-probe-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
.capability-probe-header h2 { margin: 5px 0 0; font-size: 14px; }
.capability-probe-header p { max-width: 760px; margin: 6px 0 0; color: var(--muted); font-size: 9px; line-height: 1.55; }
.probe-mode { flex: 0 0 auto; min-width: 160px; padding: 10px 12px; border: 1px solid rgba(57, 125, 246, .22); border-radius: 11px; background: rgba(57, 125, 246, .055); }
.probe-mode small, .probe-mode strong, .probe-mode span { display: block; }
.probe-mode small { color: #68768b; font-size: 7px; text-transform: uppercase; }
.probe-mode strong { margin-top: 5px; color: #a9c5fa; font-size: 11px; }
.probe-mode span { margin-top: 4px; color: #6f7f96; font-size: 7px; }
.capability-check-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin-top: 14px; }
.capability-check-grid article { display: grid; grid-template-columns: 25px minmax(0, 1fr); gap: 8px; min-width: 0; padding: 10px; border: 1px solid var(--line); border-radius: 10px; background: rgba(4, 8, 13, .28); }
.capability-check-grid article > .material-symbols-outlined { display: grid; width: 25px; height: 25px; place-items: center; border-radius: 8px; color: #6c7b91; background: rgba(255, 255, 255, .04); font-size: 15px; }
.capability-check-grid p, .capability-check-grid small, .capability-check-grid strong { display: block; min-width: 0; margin: 0; }
.capability-check-grid small { color: #657388; font-size: 7px; }
.capability-check-grid strong { overflow: hidden; margin-top: 4px; font-size: 8px; text-overflow: ellipsis; white-space: nowrap; }
.capability-check-grid b { grid-column: 2; color: #617188; font-size: 6px; }
.capability-check-grid .capability-available { border-color: rgba(52, 211, 153, .18); }
.capability-check-grid .capability-available > .material-symbols-outlined, .capability-check-grid .capability-available b { color: #65d7aa; }
.capability-check-grid .capability-warning > .material-symbols-outlined, .capability-check-grid .capability-warning b { color: #f2be58; }
.capability-check-grid .capability-restricted > .material-symbols-outlined, .capability-check-grid .capability-restricted b { color: #d5a35a; }
.capability-check-grid .capability-missing > .material-symbols-outlined, .capability-check-grid .capability-missing b { color: #ec7f8d; }
.probe-facts { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px; margin-top: 12px; overflow: hidden; border: 1px solid var(--line); border-radius: 10px; background: var(--line); }
.probe-facts > span { min-width: 0; padding: 9px 10px; background: #0d1118; }
.probe-facts small, .probe-facts strong { display: block; }
.probe-facts small { color: #617087; font-size: 7px; }
.probe-facts strong { overflow: hidden; margin-top: 4px; font-size: 8px; text-overflow: ellipsis; white-space: nowrap; }
.probe-warnings { display: grid; gap: 5px; margin: 12px 0 0; padding: 0; list-style: none; }
.probe-warnings li { display: flex; align-items: flex-start; gap: 7px; color: #caa85f; font-size: 8px; line-height: 1.5; }
.probe-warnings .material-symbols-outlined { margin-top: 1px; font-size: 13px; }
.probe-footnote { margin: 12px 0 0; padding-top: 10px; border-top: 1px solid var(--line); color: #637188; font-size: 8px; }
.ks-install-gate{padding:18px;border-color:rgba(245,158,11,.24)}.ks-install-gate.ready{border-color:rgba(52,211,153,.24)}.ks-install-gate>header{display:grid;grid-template-columns:38px minmax(0,1fr) auto;gap:11px;align-items:center}.ks-install-gate>header>.material-symbols-outlined{display:grid;width:38px;height:38px;place-items:center;color:#e2ac50;border-radius:11px;background:rgba(245,158,11,.09)}.ks-install-gate.ready>header>.material-symbols-outlined{color:#62d2a5;background:rgba(52,211,153,.09)}.ks-install-gate h2{margin:4px 0 0;font-size:13px}.ks-install-gate header p{margin:5px 0 0;color:var(--muted);font-size:8px;line-height:1.5}.ks-install-gate header>b{color:#d9aa58;font-size:7px}.ks-install-gate.ready header>b{color:#62cea3}.ks-requirement-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-top:13px}.ks-requirement-grid article{display:flex;align-items:center;gap:8px;padding:9px;border:1px solid rgba(245,158,11,.16);border-radius:9px;background:rgba(245,158,11,.035)}.ks-requirement-grid article.passed{border-color:rgba(52,211,153,.16);background:rgba(52,211,153,.025)}.ks-requirement-grid .material-symbols-outlined{color:#db9260;font-size:15px}.ks-requirement-grid article.passed .material-symbols-outlined{color:#5ecb9f}.ks-requirement-grid strong,.ks-requirement-grid small{display:block}.ks-requirement-grid strong{font-size:8px}.ks-requirement-grid small{margin-top:3px;color:var(--muted);font-size:7px}.ks-install-guidance{display:grid;grid-template-columns:20px minmax(0,1fr) auto auto;gap:9px;align-items:center;margin-top:11px;padding:10px;border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.018)}.ks-install-guidance>.material-symbols-outlined{color:#77a4e8;font-size:16px}.ks-install-guidance p{margin:0;color:var(--muted);font-size:8px;line-height:1.55}.ks-install-guidance p strong{color:var(--text)}
.ks-provision-result{padding:15px;border-color:rgba(52,211,153,.25)}.ks-provision-result>header{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.ks-provision-result h2{margin:4px 0 0;font-size:13px}.ks-provision-result header p{margin:5px 0 0;color:var(--muted);font-size:7px;word-break:break-all}.ks-provision-result header>a{color:var(--primary);font-size:8px}.ks-provision-steps{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-top:12px}.ks-provision-steps article{display:grid;grid-template-columns:22px minmax(0,1fr);gap:7px;align-items:start;padding:9px;border:1px solid rgba(52,211,153,.17);border-radius:8px;background:rgba(52,211,153,.035)}.ks-provision-steps .material-symbols-outlined{color:#62d3a7;font-size:16px}.ks-provision-steps strong,.ks-provision-steps small{display:block}.ks-provision-steps strong{font-size:8px}.ks-provision-steps small{overflow:hidden;margin-top:3px;color:var(--muted);font-size:6px;text-overflow:ellipsis;white-space:nowrap}
.ks-session-panel, .ks-package-panel, .ks-package-evidence-panel { padding: 16px; }
.ks-session-panel{order:10}.ks-package-panel{order:20}.ks-package-evidence-panel{order:30}
.ks-workspace-switcher{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;padding:9px}.ks-workspace-switcher>button{display:grid;grid-template-columns:28px minmax(0,1fr);gap:2px 9px;align-items:center;padding:10px;color:inherit;text-align:left;border:1px solid var(--line);border-radius:10px;background:rgba(4,8,13,.3)}.ks-workspace-switcher>button:hover,.ks-workspace-switcher>button.active{border-color:rgba(57,125,246,.4);background:rgba(57,125,246,.08)}.ks-workspace-switcher .material-symbols-outlined{grid-row:1/3;color:#78a7ed;font-size:19px}.ks-workspace-switcher strong,.ks-workspace-switcher small{display:block}.ks-workspace-switcher strong{font-size:9px}.ks-workspace-switcher small{color:#69788e;font-size:7px}
.ks-session-panel .section-title p, .ks-package-panel .section-title p, .ks-package-evidence-panel .section-title p { margin: 4px 0 0; color: #6d7b90; font-size: 8px; }
.ks-title-actions{display:flex;align-items:center;gap:7px}
.danger-button{color:#d86d78;border-color:rgba(216,109,120,.3)}
.ks-session-package-link{display:flex;align-items:center;gap:12px;margin-top:10px;padding:10px 12px;border:1px solid rgba(57,125,246,.22);border-radius:9px;background:rgba(57,125,246,.045)}
.ks-session-package-link>div{display:grid;grid-template-columns:auto auto;align-items:center;gap:3px 8px;min-width:0;flex:1}.ks-session-package-link small{color:#718199;font-size:7px}.ks-session-package-link strong{font-size:9px}.ks-session-package-link span{grid-column:1/-1;color:#72839b;font-size:7px}.ks-session-package-link>b{color:#8694a8;font-size:7px}
.ks-session-detail-tabs{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px;padding-bottom:9px;border-bottom:1px solid var(--line)}
.ks-session-detail-tabs button{padding:7px 10px;color:#718199;font-size:7px;border:1px solid var(--line);border-radius:7px;background:transparent}.ks-session-detail-tabs button.active{color:#a9c8ff;border-color:rgba(57,125,246,.4);background:rgba(57,125,246,.1)}
.ks-session-list { display: grid; gap: 6px; margin-top: 12px; }
.ks-session-row{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:stretch;overflow:hidden;border:1px solid var(--line);border-radius:10px;background:var(--surface-soft)}
.ks-session-row:hover,.ks-session-row.active{border-color:rgba(57,125,246,.35);background:rgba(57,125,246,.07)}
.ks-session-open{display:grid;grid-template-columns:minmax(150px,.8fr) minmax(180px,1fr) auto;align-items:center;gap:12px;width:100%;padding:10px 12px;border:0;color:inherit;text-align:left;background:transparent}
.ks-session-delete-slot{display:flex;min-width:88px;align-items:stretch}.ks-session-delete,.ks-session-delete-cancel{min-width:72px;padding:8px 10px;border:0;border-left:1px solid var(--line);font-size:8px}.ks-session-delete{color:#e8b4b4;background:rgba(214,74,74,.06)}.ks-session-delete:hover{background:rgba(214,74,74,.14)}.ks-session-delete.confirm{color:#fff;background:#8f2f38;font-weight:600}.ks-session-delete.confirm:hover{background:#a33b45}.ks-session-delete-cancel{color:#9aa8bb;background:rgba(255,255,255,.03)}.ks-session-delete-cancel:hover{background:rgba(255,255,255,.08)}.ks-session-row.pending-delete{border-color:rgba(216,109,120,.45)}
.ks-session-owned{display:grid;min-width:92px;padding:8px 10px;place-items:center;border-left:1px solid var(--line);color:#718096;font-size:6px;text-align:center}
.ks-session-list span, .ks-session-list strong, .ks-session-list small { display: block; min-width: 0; }
.ks-session-list strong { font-size: 8px; }.ks-session-list small { margin-top: 3px; color: #657388; font-size: 7px; }
.ks-session-list b { color: #79a3e7; font-size: 7px; text-transform: uppercase; }
.ks-case-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-top:12px}
.ks-case-head small,.ks-case-head strong{display:block}
.ks-case-head small{color:#6d7c91;font-size:7px}
.ks-case-head strong{margin-top:4px;font-size:12px}
.ks-flow{display:grid;gap:0;margin:14px 0 4px;padding:0 0 0 18px;list-style:none;border-left:1px dashed rgba(245,197,66,.35)}
.ks-flow>li{position:relative;display:grid;grid-template-columns:36px minmax(0,1fr);gap:10px;padding:0 0 14px 12px}
.ks-flow-n{display:grid;width:28px;height:28px;place-items:center;border-radius:50%;color:#1b1403;background:#f5c542;font-size:8px;font-weight:700}
.ks-flow-card{min-width:0;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:rgba(4,8,13,.36)}
.ks-flow-card>header{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.ks-flow-card>header>b{padding:2px 7px;border-radius:999px;font-size:7px;letter-spacing:.04em}
.ks-flow .verb-获取> .ks-flow-card>header>b,.ks-flow .verb-落地> .ks-flow-card>header>b{color:#1b1403;background:#f5c542}
.ks-flow .verb-推出> .ks-flow-card>header>b{color:#9fe7f4;background:rgba(79,184,208,.18)}
.ks-flow .verb-缺口> .ks-flow-card>header>b{color:#f3d19a;background:rgba(209,163,91,.18)}
.ks-flow-card>header>strong{flex:1;font-size:11px}
.ks-flow-card>header>small{color:#6d7c91;font-size:6px;text-transform:uppercase}
.ks-flow-card dl{display:grid;gap:6px;margin:8px 0 0}
.ks-flow-card dt{color:#6d7c91;font-size:6px;text-transform:uppercase;letter-spacing:.06em}
.ks-flow-card dd{margin:3px 0 0;color:#c5d0dc;font-size:8px;line-height:1.55}
.ks-flow-card code{display:block;overflow:hidden;margin-top:3px;color:#f5c542;font-size:7px;text-overflow:ellipsis;white-space:nowrap}
.ks-flow>.prio-gap .ks-flow-card{border-color:rgba(245,158,11,.28);background:rgba(245,158,11,.05)}
.ks-flow>.prio-focus .ks-flow-card{border-color:rgba(251,191,36,.4)}
.ks-path-legend{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:10px 0 0;color:#7a8799;font-size:7px;line-height:1.5}
.ks-path-legend>span{padding:3px 7px;border-radius:999px;font-size:6px;letter-spacing:.04em;text-transform:uppercase}
.ks-path{display:grid;gap:8px;margin:12px 0 0;padding:0;list-style:none}
.ks-path>li{padding:11px 12px;border:1px solid var(--line);border-radius:10px;background:rgba(4,8,13,.34);border-left:3px solid #3d4d63}
.ks-path>li>header{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.ks-path>li>header>b{padding:2px 6px;border-radius:4px;color:#7fb0f0;background:rgba(57,125,246,.12);font-size:6px}
.ks-path>li>header>strong{flex:1;font-size:11px}
.ks-path>li>header>em{font-size:7px;font-style:normal}
.ks-path>li>header>small{color:#6d7c91;font-size:6px;text-transform:uppercase}
.ks-path>li>p{margin:7px 0 0;color:#8493a8;font-size:8px;line-height:1.55}
.ks-path>li>code{display:block;overflow:hidden;margin-top:4px;color:#8bb6ff;font-size:7px;text-overflow:ellipsis;white-space:nowrap}
.ks-path>.prio-focus,.ks-plaintext-list>article.prio-focus,.ks-analyzable-list>button.prio-focus,.ks-evidence-file-list>button.prio-focus{border-color:rgba(251,191,36,.55);background:rgba(251,191,36,.08);box-shadow:inset 3px 0 #f5c542}
.ks-path>.prio-focus>header>em,.ks-analyzable-list>button.prio-focus>b,.ks-evidence-file-list>button.prio-focus>em{color:#f5c542}
.ks-path>.prio-watch{border-left-color:#4fb8d0}
.ks-path>.prio-background{border-left-color:#526176;opacity:.78}
.ks-path>.prio-gap{border-color:rgba(245,158,11,.28);background:rgba(245,158,11,.05);border-left-color:#d1a35b}
.ks-path-legend .prio-focus{color:#1b1403;background:#f5c542}
.ks-path-legend .prio-watch{color:#9fe7f4;background:rgba(79,184,208,.16)}
.ks-path-legend .prio-background{color:#9aa8b8;background:rgba(82,97,118,.2)}
.ks-path-legend .prio-gap{color:#f3d19a;background:rgba(209,163,91,.16)}
.ks-path-more{margin-top:8px;padding:8px 10px;border:1px solid var(--line);border-radius:9px;background:rgba(4,8,13,.28)}
.ks-path-more>summary{color:#8ca9d2;font-size:8px;cursor:pointer}
.ks-path-more>h3{margin:0 0 9px;color:#8ca9d2;font-size:8px}
.ks-load-more{display:block;margin:9px auto 0}
.ks-unassigned-sessions{padding:9px;border:1px dashed var(--line);border-radius:9px}.ks-unassigned-sessions>summary{color:#8292a8;font-size:8px;cursor:pointer}.ks-unassigned-sessions>p{margin:7px 0;color:#6b7a90;font-size:7px}.ks-unassigned-sessions>button{margin-top:5px}
.ks-loading { display: flex; align-items: center; gap: 7px; margin-top: 12px; color: #7f91aa; font-size: 8px; }
.ks-report-summary { display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 1px; margin-top: 12px; overflow: hidden; border: 1px solid var(--line); border-radius: 10px; background: var(--line); }
.ks-report-summary span { padding: 10px; background: #0d1118; }.ks-report-summary small,.ks-report-summary strong { display:block; }.ks-report-summary small { color:#657388;font-size:7px }.ks-report-summary strong { margin-top:4px;font-size:9px }
.ks-package-list { display: grid; gap: 7px; margin-top: 12px; }
.ks-package-list article { display: grid; grid-template-columns: minmax(210px,1.5fr) repeat(6,minmax(65px,.45fr)) auto; align-items: center; gap: 9px; padding: 10px; border: 1px solid var(--line); border-radius: 10px; background: rgba(4,8,13,.32); cursor:pointer; }
.ks-package-list article:hover,.ks-package-list article.selected{border-color:rgba(57,125,246,.4);background:rgba(57,125,246,.07)}
.ks-selected-package-bar{display:flex;flex-wrap:wrap;align-items:center;gap:7px;margin-top:12px;padding:8px;border:1px solid rgba(57,125,246,.2);border-radius:9px;background:rgba(57,125,246,.04)}.ks-selected-package-bar span{padding:5px 7px;color:#8194af;font-size:7px;border-radius:6px;background:rgba(255,255,255,.025)}
.ks-package-list article>div strong,.ks-package-list article>div small,.ks-package-list span b,.ks-package-list span small { display:block; }.ks-package-list article>div strong{font-size:8px}.ks-package-list article>div small{margin-top:3px;color:#657388;font-size:7px}.ks-package-list span{text-align:center}.ks-package-list span b{font-size:9px}.ks-package-list span small{margin-top:3px;color:#657388;font-size:6px}.ks-package-list button{white-space:nowrap;font-size:7px}
.ks-source-badges{display:flex!important;flex-wrap:wrap;gap:4px;margin-top:5px!important}.ks-source-badges b{display:inline-block;padding:3px 5px;border-radius:5px;font-size:6px}.ks-source-badges .source-local{color:#62d3a7;background:rgba(52,211,153,.09)}.ks-source-badges .source-device{color:#79a7ea;background:rgba(57,125,246,.1)}.ks-source-badges .source-unknown{color:#d1a35b;background:rgba(245,158,11,.08)}
.ks-package-source-actions{display:flex;gap:4px}.ks-package-source-actions button.active{color:#b9d2fb;border-color:rgba(57,125,246,.4);background:rgba(57,125,246,.1)}.ks-selected-package-bar>b{padding:4px 6px;border-radius:5px;font-size:6px}.ks-selected-package-bar>.source-local{color:#62d3a7;background:rgba(52,211,153,.09)}.ks-selected-package-bar>.source-device{color:#79a7ea;background:rgba(57,125,246,.1)}
.ks-capture-panel { padding: 17px; border-color: rgba(57,125,246,.22); }
.ks-capture-panel .section-title p { max-width: 760px; margin: 4px 0 0; color: #6f7e94; font-size: 8px; line-height: 1.55; }
.device-chip.active { color: #75d7ad; border-color: rgba(52,211,153,.3); }
.ks-presets { display: grid; grid-template-columns: repeat(5,minmax(0,1fr)); gap: 8px; margin-top: 13px; }
.ks-presets button { display: grid; grid-template-columns: 28px 1fr; gap: 2px 9px; padding: 10px; color: inherit; text-align: left; border: 1px solid var(--line); border-radius: 10px; background: rgba(4,8,13,.34); }
.ks-presets button:hover { border-color: rgba(57,125,246,.35); background: rgba(57,125,246,.065); }
.ks-presets .material-symbols-outlined { grid-row: 1/3; display: grid; width: 28px; height: 28px; place-items: center; color: #79a8f2; font-size: 16px; border-radius: 8px; background: rgba(57,125,246,.09); }
.ks-presets strong { font-size: 9px; }.ks-presets small { color: #68768c; font-size: 7px; }
.ks-layer-contract{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-top:9px}.ks-layer-contract>article{padding:10px;border:1px solid var(--line);border-radius:9px;background:rgba(4,8,13,.3)}.ks-layer-contract header{display:flex;align-items:center;justify-content:space-between;gap:8px}.ks-layer-contract header>b{padding:3px 6px;border-radius:5px;color:#75a5ee;background:rgba(57,125,246,.09);font-size:7px}.ks-layer-contract header>small{color:#637188;font-size:6px}.ks-layer-contract>article>strong{display:block;margin-top:8px;font-size:9px}.ks-layer-contract>article>p{margin:5px 0 0;color:#718096;font-size:6px;line-height:1.5}.ks-layer-contract ul{display:grid;gap:3px;margin:8px 0 0;padding-left:14px;color:#8492a6;font-size:6px;line-height:1.45}.ks-layer-contract .layer-gap{border-color:rgba(245,158,11,.18);background:rgba(245,158,11,.025)}.ks-layer-contract .layer-gap header>b{color:#d1a35b;background:rgba(245,158,11,.08)}
.ks-capture-form { display: grid; grid-template-columns: minmax(260px,2fr) repeat(3,minmax(100px,.55fr)); gap: 8px; margin-top: 12px; }
.ks-capture-form label>span { display: block; margin-bottom: 5px; color: #68778d; font-size: 7px; }
.ks-capture-form input,.ks-capture-form select,.ks-event-toolbar input,.ks-event-toolbar select,.ks-graph-toolbar input,.ks-graph-toolbar select { width: 100%; box-sizing: border-box; padding: 8px 9px; color: #c9d2df; font: inherit; font-size: 8px; border: 1px solid var(--line); border-radius: 8px; outline: none; background: #090d13; }
.ks-sensor-switches { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 11px; }
.ks-sensor-switches label { display: flex; align-items: center; gap: 6px; padding: 7px 9px; color: #8997aa; font-size: 8px; border: 1px solid var(--line); border-radius: 8px; background: rgba(4,8,13,.3); }
.ks-sensor-switches input { accent-color: #397df6; }
.ks-advanced-capture { margin-top: 10px; font-size: 8px; }.ks-advanced-capture>summary { color: #728198; cursor: pointer; }
.ks-capture-actions { display: flex; align-items: center; gap: 12px; margin-top: 12px; }.ks-capture-actions p { margin: 0; color: #78879c; font-size: 8px; line-height: 1.5; }
.ks-capture-plan{display:grid;grid-template-columns:minmax(150px,.8fr) minmax(180px,.9fr) minmax(240px,1.4fr);gap:1px;margin-top:11px;overflow:hidden;border:1px solid var(--line);border-radius:9px;background:var(--line)}.ks-capture-plan>div,.ks-capture-plan>details{min-width:0;padding:9px 10px;background:#0a0f16}.ks-capture-plan small,.ks-capture-plan strong{display:block}.ks-capture-plan small{color:#627188;font-size:6px;text-transform:uppercase}.ks-capture-plan strong{overflow:hidden;margin-top:4px;font-size:8px;text-overflow:ellipsis;white-space:nowrap}.ks-capture-plan details{grid-column:1/4}.ks-capture-plan summary{color:#7692ba;font-size:7px;cursor:pointer}.ks-capture-plan code{display:block;margin-top:7px;color:#69b5ce;font-size:7px;line-height:1.5;word-break:break-all;white-space:pre-wrap}.risk-low{color:#67d3a8}.risk-medium{color:#e1b35e}.risk-high{color:#ec8592}.ks-control-boundary{display:flex;align-items:flex-start;gap:7px;margin:9px 0 0;color:#68778d;font-size:7px;line-height:1.55}.ks-control-boundary .material-symbols-outlined{margin-top:1px;color:#6f9ee4;font-size:13px}
.ks-capture-log { margin-top: 12px; padding: 10px; border: 1px solid var(--line); border-radius: 9px; background: #080c12; }.ks-capture-log summary { color: #8da6ce; font-size: 8px; cursor: pointer; }.ks-capture-log code { display:block; margin-top:8px; color:#72b7d0; font-size:7px; word-break:break-all }.ks-capture-log pre { max-height:180px; margin:8px 0 0; overflow:auto; color:#9aa8ba; font-size:7px; white-space:pre-wrap; }
.ks-detail-tabs { display: flex; gap: 5px; margin-top: 13px; padding-bottom: 8px; overflow-x: auto; border-bottom: 1px solid var(--line); }
.ks-detail-tabs button { display: flex; align-items: center; gap: 5px; flex: 0 0 auto; padding: 7px 8px; color: #738198; font-size: 7px; border: 1px solid transparent; border-radius: 8px; background: transparent; }.ks-detail-tabs button.active { color: #a9c8fb; border-color: rgba(57,125,246,.28); background: rgba(57,125,246,.08); }.ks-detail-tabs .material-symbols-outlined { font-size: 13px; }.ks-detail-tabs b { color:#5f9cff;font-size:6px; }
.ks-detail-pane { margin-top: 12px; }
.ks-chain-rail{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:6px;margin:10px 0 0}
.ks-chain-rail>button{display:grid;gap:3px;padding:9px;color:inherit;text-align:left;border:1px solid var(--line);border-radius:9px;background:rgba(4,8,13,.32)}
.ks-chain-rail>button:hover,.ks-chain-rail>button.active{border-color:rgba(57,125,246,.4);background:rgba(57,125,246,.08)}
.ks-chain-rail>button>b{width:fit-content;padding:2px 5px;border-radius:4px;color:#75a5ee;background:rgba(57,125,246,.09);font-size:6px}
.ks-chain-rail>button>strong{font-size:8px}
.ks-chain-rail>button>small{color:#6d7c91;font-size:6px;line-height:1.45}
.ks-chain-rail>button>em{font-size:6px;font-style:normal;text-transform:uppercase}
.ks-chain-rail .tone-confirmed>em{color:#62d3a7}
.ks-chain-rail .tone-present>em{color:#4fb8d0}
.ks-chain-rail .tone-gap>em{color:#d1a35b}
.ks-chain-rail .tone-empty>em{color:#6d7c91}
.ks-chain-stage{margin-top:12px;padding:10px;border:1px solid var(--line);border-radius:10px;background:rgba(4,8,13,.28)}
.ks-chain-stage>header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.ks-chain-stage>header>b{padding:3px 6px;border-radius:5px;color:#75a5ee;background:rgba(57,125,246,.09);font-size:6px}
.ks-chain-stage>header>strong{flex:1;font-size:9px}
.ks-chain-stage>header>span{color:#6d7c91;font-size:7px}
.ks-chain-stage .ks-backbone-note,.ks-chain-stage .ks-empty,.ks-chain-stage .ks-backbone-list,.ks-chain-stage .ks-data-table,.ks-chain-stage .ks-plaintext-list,.ks-chain-stage .ks-lifecycle-grid{margin-top:0}
.ks-token-chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
.ks-token-chips span{display:inline-flex;align-items:center;gap:5px;padding:4px 7px;border:1px solid var(--line);border-radius:6px;color:#8aa0bb;font-size:7px;background:#080c12}
.ks-token-chips b{color:#4fb8d0;font-size:6px}
.ks-dump-join{display:grid;gap:7px}
.ks-dump-join>article{display:grid;gap:4px;padding:9px;border:1px solid var(--line);border-radius:8px;background:#080c12}
.ks-dump-join strong{font-size:8px}
.ks-dump-join small,.ks-dump-join span{color:#6d7c91;font-size:7px}
.ks-gap-stage{border-color:rgba(245,158,11,.22);background:rgba(245,158,11,.04)}
.ks-gap-stage>header>b{color:#d1a35b;background:rgba(245,158,11,.1)}
.ks-gap-list{display:grid;gap:6px;margin:0;padding-left:16px;color:#c4a36a;font-size:7px;line-height:1.55}
.ks-integrity-strip,.ks-network-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;margin-top:9px;overflow:hidden;border:1px solid var(--line);border-radius:9px;background:var(--line)}.ks-integrity-strip article{display:flex;align-items:center;gap:8px;padding:9px;background:#0a0f16}.ks-integrity-strip article.warning{background:rgba(245,158,11,.055)}.ks-integrity-strip .material-symbols-outlined{color:#66cfa7;font-size:15px}.ks-integrity-strip article.warning .material-symbols-outlined{color:#e3ad53}.ks-integrity-strip small,.ks-integrity-strip strong,.ks-network-summary small,.ks-network-summary strong{display:block}.ks-integrity-strip small,.ks-network-summary small{color:#637188;font-size:6px}.ks-integrity-strip strong,.ks-network-summary strong{margin-top:3px;font-size:8px}.ks-limitations{margin-top:9px;padding:9px 10px;border:1px solid rgba(245,158,11,.16);border-radius:8px;background:rgba(245,158,11,.025)}.ks-limitations summary{color:#c39b58;font-size:7px;cursor:pointer}.ks-limitations ul{display:grid;gap:4px;margin:8px 0 0;padding-left:16px;color:#857962;font-size:7px;line-height:1.5}
.ks-network-summary{margin:0 0 9px}.ks-network-summary span{padding:9px 10px;background:#0a0f16}.ks-network-summary strong{font-size:10px}.ks-dns-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;margin-bottom:9px}.ks-dns-list article{display:grid;grid-template-columns:24px minmax(120px,.8fr) minmax(140px,1fr);gap:8px;align-items:center;padding:8px;border:1px solid var(--line);border-radius:8px;background:#080c12}.ks-dns-list .material-symbols-outlined{color:#58acc4;font-size:15px}.ks-dns-list strong,.ks-dns-list small{display:block}.ks-dns-list strong{font-size:8px}.ks-dns-list small{margin-top:3px;color:#627086;font-size:6px}.ks-dns-list code{overflow:hidden;color:#7890ad;font-size:6px;text-overflow:ellipsis;white-space:nowrap}
.ks-semantic-list,.ks-inspect-list{display:grid;gap:6px;margin-bottom:10px}.ks-semantic-list details,.ks-inspect-list details{border:1px solid rgba(57,125,246,.18);border-radius:9px;background:rgba(4,8,13,.34)}.ks-semantic-list summary,.ks-inspect-list summary{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 10px;cursor:pointer}.ks-semantic-list summary strong,.ks-semantic-list summary small,.ks-inspect-list summary strong,.ks-inspect-list summary small{display:block}.ks-semantic-list summary strong,.ks-inspect-list summary strong{font-size:8px}.ks-semantic-list summary small,.ks-inspect-list summary small{margin-top:3px;color:#69788e;font-size:6px}.ks-semantic-list summary b,.ks-inspect-list summary b{color:#63a0ee;font-size:7px}.ks-semantic-list dl{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;margin:0 9px;background:var(--line)}.ks-semantic-list dl>div{padding:7px;background:#0a0f16}.ks-semantic-list dt{color:#617087;font-size:6px}.ks-semantic-list dd{margin:3px 0 0;font-size:7px}.ks-semantic-list pre,.ks-inspect-list pre{max-height:220px;margin:8px 9px 9px;padding:8px;overflow:auto;color:#9fb0c5;font:7px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-all;border:1px solid var(--line);border-radius:7px;background:#070b10}
.ks-lifecycle-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-bottom:10px}.ks-lifecycle-grid article{display:grid;grid-template-columns:28px 1fr;gap:8px;padding:10px;border:1px solid var(--line);border-radius:9px;background:rgba(4,8,13,.32)}.ks-lifecycle-grid .material-symbols-outlined{display:grid;width:28px;height:28px;place-items:center;color:#6ba4ea;font-size:16px;border-radius:8px;background:rgba(57,125,246,.08)}.ks-lifecycle-grid small,.ks-lifecycle-grid strong{display:block}.ks-lifecycle-grid small{color:#65748a;font-size:6px}.ks-lifecycle-grid strong{margin-top:4px;font-size:8px}.ks-lifecycle-grid p{margin:5px 0 0;color:#718096;font-size:6px;line-height:1.45}
.ks-intelligence-grid { display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px }.ks-intelligence-grid article { padding:10px;border:1px solid var(--line);border-radius:9px;background:rgba(4,8,13,.32) }.ks-intelligence-grid small,.ks-intelligence-grid strong {display:block}.ks-intelligence-grid small{color:#68768c;font-size:7px}.ks-intelligence-grid strong{margin-top:5px;font-size:12px}.ks-intelligence-grid p{margin:5px 0 0;color:#758399;font-size:7px;line-height:1.45}
.ks-dump-summary-list { display:grid;gap:8px;margin-top:10px }.ks-dump-summary-list>article{padding:11px;border:1px solid rgba(57,125,246,.18);border-radius:10px;background:rgba(4,8,13,.34)}.ks-dump-summary-list header,.ks-plaintext-list header,.ks-ai-context-header{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}.ks-dump-summary-list header strong,.ks-dump-summary-list header small,.ks-plaintext-list header strong,.ks-plaintext-list header small{display:block}.ks-dump-summary-list header strong,.ks-plaintext-list header strong{font-size:9px}.ks-dump-summary-list header small,.ks-plaintext-list header small{margin-top:4px;color:#6d7b90;font-size:7px}.ks-dump-summary-list header>b,.ks-plaintext-list header>b{color:#4fb8d0;font-size:7px}.ks-dump-summary-list dl{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;margin:10px 0 0;overflow:hidden;border:1px solid var(--line);border-radius:8px;background:var(--line)}.ks-dump-summary-list dl>div{padding:8px;background:#0b1017}.ks-dump-summary-list dt{color:#68768c;font-size:7px}.ks-dump-summary-list dd{margin:4px 0 0;font-size:10px}.ks-dump-summary-list details{margin-top:10px}.ks-dump-summary-list details>summary{color:#7890b4;font-size:8px;cursor:pointer}
.ks-artifact-table { display:grid;gap:5px;margin-top:8px }.ks-artifact-table>div{display:grid;grid-template-columns:38px minmax(180px,1.4fr) minmax(120px,.7fr);gap:5px 8px;padding:8px;border:1px solid var(--line);border-radius:8px;background:#080c12}.ks-artifact-table b{grid-row:1/3;color:#50b8d1;font-size:7px;text-transform:uppercase}.ks-artifact-table code{overflow:hidden;color:#b4c3d7;font-size:7px;text-overflow:ellipsis;white-space:nowrap}.ks-artifact-table span,.ks-artifact-table small{color:#6f7d91;font-size:7px}.ks-artifact-table em{grid-column:2/4;color:#527691;font-size:6px;font-style:normal;word-break:break-all}
.ks-framework-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-top:10px}.ks-framework-list>article{padding:9px;border:1px solid rgba(52,211,153,.2);border-radius:8px;background:rgba(16,185,129,.04)}.ks-framework-list>article.framework-packer_shell{border-color:rgba(251,191,36,.24);background:rgba(251,191,36,.04)}.ks-framework-list p{margin:5px 0;color:#7d8ca1;font-size:7px;line-height:1.5}.ks-framework-list code{display:block;overflow:hidden;margin-top:3px;color:#91a8c7;font-size:6px;text-overflow:ellipsis;white-space:nowrap}.ks-dex-set-list{display:grid;gap:6px;margin-top:8px}.ks-dex-set-list>article{padding:9px;border:1px solid var(--line);border-radius:8px;background:#080c12}.ks-dex-set-list>article>code{display:block;margin-top:6px;color:#527691;font-size:6px;word-break:break-all}.ks-dex-set-list p{margin:5px 0 0;color:#8493a8;font-size:7px}.ks-dex-set-list details>div{display:grid;gap:3px;margin-top:5px;padding:6px;border-top:1px solid var(--line)}.ks-dex-set-list details code,.ks-dex-set-list details small{font-size:6px}.ks-conflict-list{display:grid;gap:4px;margin-top:7px}.ks-conflict-list>div{display:flex;justify-content:space-between;gap:10px;padding:6px;border:1px solid var(--line);border-radius:6px}.ks-conflict-list code,.ks-conflict-list small{font-size:7px}
.ks-plaintext-list { display:grid;gap:8px }.ks-plaintext-list article{padding:11px;border:1px solid rgba(52,211,153,.18);border-radius:10px;background:rgba(4,12,12,.34)}.ks-plaintext-stats{display:flex;gap:6px;margin-top:8px}.ks-plaintext-stats span{padding:4px 6px;color:#77a794;font-size:7px;border-radius:6px;background:rgba(52,211,153,.07)}.ks-plaintext-list pre{max-height:320px;margin:9px 0 0;padding:10px;overflow:auto;color:#d7e0e8;font:8px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-all;border:1px solid var(--line);border-radius:8px;background:#070b10}.ks-plaintext-list details{margin-top:8px}.ks-plaintext-list details summary{color:#6f829e;font-size:7px;cursor:pointer}.ks-plaintext-list details code{display:block;margin-top:4px;color:#568099;font-size:6px;word-break:break-all}.ks-plaintext-actions{display:flex;align-items:center;gap:8px}.ks-plaintext-actions .ghost-button{padding:3px 8px;font-size:7px}.ks-url-list{display:grid;gap:3px;margin:8px 0 0;padding:8px;list-style:none;border:1px solid rgba(52,211,153,.22);border-radius:8px;background:rgba(16,185,129,.06)}.ks-url-list li{color:#9ee7c7;font:7px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.ks-url-board{display:grid;gap:7px;margin:10px 0 14px}.ks-url-board>article{display:grid;gap:5px;padding:12px 14px;border:1px solid rgba(52,211,153,.32);border-radius:10px;background:#0c1612}.ks-url-board small{color:#7d9b8e;font-size:8px}.ks-url-board code{color:#e7fff4;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.ks-data-table { display:grid;gap:5px }.ks-data-table article{display:grid;grid-template-columns:minmax(160px,1fr) minmax(120px,.8fr) auto;gap:4px 10px;align-items:center;padding:9px;border:1px solid var(--line);border-radius:8px;background:rgba(4,8,13,.3)}.ks-data-table strong{font-size:8px}.ks-data-table small{color:#6d7b90;font-size:7px}.ks-data-table span{color:#87a3ce;font-size:7px;text-align:right}.ks-data-table b{font-size:7px}.ks-data-table code{grid-column:1/4;overflow:hidden;color:#60738d;font-size:6px;text-overflow:ellipsis;white-space:nowrap}
.ks-graph-toolbar,.ks-event-toolbar{display:grid;grid-template-columns:auto minmax(180px,1fr);gap:7px;align-items:center}.ks-event-toolbar{grid-template-columns:150px minmax(240px,1fr) auto}.ks-graph-toolbar span{color:#7b899d;font-size:8px}.ks-edge-list{display:grid;gap:4px;margin-top:9px}.ks-edge-list article{display:grid;grid-template-columns:65px minmax(140px,1fr) auto minmax(140px,1fr) 70px;gap:7px;align-items:center;padding:7px 8px;border:1px solid var(--line);border-radius:7px;background:#080c12}.ks-edge-list b{font-size:6px;text-transform:uppercase}.ks-edge-list strong{color:#79a7ea;font-size:7px}.ks-edge-list code{overflow:hidden;color:#909fb2;font-size:7px;text-overflow:ellipsis;white-space:nowrap}.ks-edge-list small{color:#617086;font-size:6px;text-align:right}.strength-confirmed{color:#62d3a7}.strength-correlated{color:#4fb8d0}.strength-inferred{color:#d1a35b}
.ks-event-type-chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}.ks-event-type-chips span{padding:4px 6px;color:#75859c;font-size:6px;border:1px solid var(--line);border-radius:6px}.ks-event-type-chips b{margin-right:4px;color:#75a5ee}.ks-event-list{display:grid;gap:5px;margin-top:9px}.ks-event-list details{border:1px solid var(--line);border-radius:8px;background:#080c12}.ks-event-list summary{display:grid;grid-template-columns:150px minmax(160px,1fr) auto;gap:8px;padding:8px;cursor:pointer}.ks-event-list summary b{color:#52b7d0;font-size:7px}.ks-event-list summary strong{font-size:7px}.ks-event-list summary span{color:#66758a;font-size:6px}.ks-event-list pre{max-height:420px;margin:0;padding:10px;overflow:auto;color:#aab7c8;font:7px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;border-top:1px solid var(--line)}.ks-pagination{display:flex;justify-content:center;align-items:center;gap:10px;margin-top:10px}.ks-pagination button{padding:5px 8px;color:#8fa7ca;font-size:7px;border:1px solid var(--line);border-radius:6px;background:#090d13}.ks-pagination span{color:#6d7a8e;font-size:7px}
.ks-ai-context-header strong,.ks-ai-context-header small{display:block}.ks-ai-context-header strong{font-size:9px}.ks-ai-context-header small{max-width:720px;margin-top:4px;color:#6d7b90;font-size:7px;line-height:1.5}.ks-ai-context{max-height:600px;margin:10px 0 0;padding:12px;overflow:auto;color:#a8bad2;font:7px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-word;border:1px solid var(--line);border-radius:9px;background:#070b10}.ks-empty{margin:0;padding:14px;color:#718096;font-size:8px;text-align:center;border:1px dashed var(--line);border-radius:9px}
.ks-backbone-list{display:grid;gap:5px;margin-bottom:9px}.ks-backbone-list article{display:grid;grid-template-columns:70px minmax(150px,.8fr) minmax(160px,.8fr) minmax(220px,1.2fr);gap:9px;align-items:center;padding:9px;border:1px solid var(--line);border-radius:8px;background:#080c12}.ks-backbone-list article>b{font-size:6px;text-transform:uppercase}.ks-backbone-list strong,.ks-backbone-list small{display:block}.ks-backbone-list strong{font-size:8px}.ks-backbone-list small{margin-top:3px;color:#66758a;font-size:6px}.ks-backbone-list code{color:#77a8d9;font-size:7px}.ks-backbone-list span{color:#75859b;font-size:7px}.ks-command-card{margin-bottom:9px;padding:9px;border:1px solid var(--line);border-radius:8px;background:#080c12}.ks-command-card summary{color:#7897c3;font-size:7px;cursor:pointer}.ks-command-card pre{max-height:280px;margin:8px 0 0;padding:9px;overflow:auto;color:#9fb0c5;font:7px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.ks-backbone-note{display:flex;align-items:flex-start;gap:8px;margin:9px 0 0;padding:8px 9px;border:1px solid rgba(79,184,208,.2);border-radius:8px;color:#8292a7;background:rgba(79,184,208,.035);font-size:7px;line-height:1.55}.ks-backbone-note>b{flex:0 0 auto;color:#4fb8d0}
.ks-reassembly-diagnostics{margin:10px 0;padding:11px;border:1px solid var(--line-strong);border-radius:10px;background:var(--surface-soft)}.ks-reassembly-diagnostics>header{display:flex;align-items:center;justify-content:space-between;gap:12px}.ks-reassembly-diagnostics>header small,.ks-reassembly-diagnostics>header strong{display:block}.ks-reassembly-diagnostics>header small{color:var(--muted);font-size:6px;letter-spacing:.12em}.ks-reassembly-diagnostics>header strong{margin-top:3px;font-size:10px}.ks-reassembly-diagnostics>header>b{color:var(--primary);font-size:8px}.ks-reassembly-funnel{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:1px;margin-top:9px;overflow:hidden;border:1px solid var(--line);border-radius:8px;background:var(--line)}.ks-reassembly-funnel>span{padding:8px;background:var(--surface)}.ks-reassembly-funnel small,.ks-reassembly-funnel strong{display:block}.ks-reassembly-funnel small{color:var(--muted);font-size:6px}.ks-reassembly-funnel strong{margin-top:4px;font-size:9px}.ks-reassembly-diagnostics>p{margin:8px 0 0;color:var(--muted);font-size:7px;line-height:1.5}.ks-coverage-matrix{background:var(--surface-soft)}
.ks-forensic-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin-top:14px}.ks-forensic-grid>article{display:grid;grid-template-columns:28px minmax(0,1fr) auto;gap:8px;padding:10px;border:1px solid var(--line);border-radius:9px;background:rgba(4,8,13,.32)}.ks-forensic-grid .material-symbols-outlined{color:#6ba4ea;font-size:18px}.ks-forensic-grid strong,.ks-forensic-grid small{display:block}.ks-forensic-grid strong{font-size:8px}.ks-forensic-grid small{margin-top:3px;color:#67809f;font:6px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-word}.ks-forensic-grid p{margin:6px 0 0;color:#748297;font-size:6px;line-height:1.5}.ks-forensic-grid>article>b{color:#79a7ea;font-size:10px}.ks-command-catalog{margin-top:12px;padding:10px;border:1px solid var(--line);border-radius:10px;background:rgba(4,8,13,.28)}.ks-command-catalog>summary{color:#8ca9d2;font-size:8px;cursor:pointer}.ks-command-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:9px}.ks-command-grid>article{padding:9px;border:1px solid var(--line);border-radius:8px;background:#080c12}.ks-command-grid header{display:flex;align-items:center;gap:7px}.ks-command-grid header>b{padding:3px 5px;border-radius:5px;color:#63a0ee;background:rgba(57,125,246,.09);font-size:6px}.ks-command-grid header>strong{font-size:8px}.ks-command-grid code{display:block;margin-top:7px;color:#69b5ce;font:7px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}.ks-command-grid p{margin:6px 0 0;color:#718096;font-size:6px;line-height:1.5}.ks-evidence-policy{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-top:12px}.ks-evidence-policy>article{display:grid;grid-template-columns:70px 1fr;gap:8px;padding:9px;border:1px solid var(--line);border-radius:8px;background:rgba(4,8,13,.28)}.ks-evidence-policy>article>b{font-size:6px;text-transform:uppercase}.ks-evidence-policy strong{font-size:8px}.ks-evidence-policy p{margin:4px 0 0;color:#748297;font-size:7px;line-height:1.5}
.ks-evidence-browser{margin-top:12px;padding:11px;border:1px solid var(--line);border-radius:10px;background:var(--surface-soft);scroll-margin-top:18px}.ks-evidence-browser>header,.ks-evidence-preview>header{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}.ks-evidence-browser>header strong,.ks-evidence-browser>header small,.ks-evidence-preview>header strong,.ks-evidence-preview>header small{display:block}.ks-evidence-browser>header strong,.ks-evidence-preview>header strong{font-size:9px}.ks-evidence-browser>header small,.ks-evidence-preview>header small{margin-top:4px;color:var(--muted);font-size:7px}.ks-evidence-browser>header>b,.ks-evidence-preview>header>b{color:#67a0ec;font-size:7px}.ks-evidence-file-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;max-height:300px;margin-top:9px;overflow:auto}.ks-evidence-file-list button{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:8px;align-items:center;padding:8px;border:1px solid var(--line);border-radius:8px;color:inherit;background:var(--surface);text-align:left}.ks-evidence-file-list button:hover,.ks-evidence-file-list button.active{border-color:rgba(57,125,246,.35);background:var(--primary-soft)}.ks-evidence-file-list strong,.ks-evidence-file-list small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ks-evidence-file-list strong{font:7px ui-monospace,SFMono-Regular,Menlo,monospace}.ks-evidence-file-list small{margin-top:3px;color:var(--muted);font-size:6px}.ks-evidence-file-list button>b{color:#517dbd;font-size:7px}.ks-evidence-file-list em{color:var(--amber);font-size:6px;font-style:normal}.ks-evidence-preview{margin-top:9px;padding:10px;border:1px solid var(--line);border-radius:9px;background:var(--surface)}.ks-evidence-preview pre{max-height:520px;margin:9px 0 0;padding:10px;overflow:auto;color:var(--text);background:var(--surface-soft);font:8px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-word}.ks-binary-preview-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:9px}.ks-binary-preview-grid section{min-width:0;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--surface-soft)}.ks-binary-preview-grid h4{margin:0;color:var(--primary);font-size:7px;letter-spacing:.08em}.ks-binary-preview-grid pre{height:520px;margin:7px 0 0;padding:8px;background:var(--surface);white-space:pre-wrap;overflow-wrap:anywhere}
.ks-forensic-grid>article{cursor:pointer}.ks-forensic-grid>article:hover,.ks-forensic-grid>article.active{border-color:rgba(57,125,246,.4);background:rgba(57,125,246,.075)}
.ks-code-evidence{margin-top:12px;padding:11px;border:1px solid var(--line);border-radius:10px;background:rgba(4,8,13,.28)}.ks-code-evidence>header,.ks-artifact-focus>header{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}.ks-code-evidence header strong,.ks-code-evidence header small{display:block}.ks-code-evidence header strong{font-size:9px}.ks-code-evidence header small{max-width:780px;margin-top:4px;color:#6e7e94;font-size:7px;line-height:1.5}.ks-code-evidence header>b{color:#67a0ec;font-size:7px}.ks-analyzable-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;max-height:340px;margin-top:9px;overflow:auto}.ks-analyzable-list>button{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 8px;padding:8px;color:inherit;text-align:left;border:1px solid var(--line);border-radius:8px;background:#080c12}.ks-analyzable-list>button:hover,.ks-analyzable-list>button.active{border-color:rgba(57,125,246,.4);background:rgba(57,125,246,.07)}.ks-analyzable-list span strong,.ks-analyzable-list span small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ks-analyzable-list span strong{font:7px ui-monospace,SFMono-Regular,Menlo,monospace}.ks-analyzable-list span small,.ks-analyzable-list em{color:#68778d;font-size:6px;font-style:normal}.ks-analyzable-list em{grid-column:1/3}.ks-analyzable-list b{font-size:6px}.ks-analyzable-list b.ready{color:#62d3a7}.ks-analyzable-list b.candidate{color:#d1a35b}.ks-artifact-focus{margin-top:8px;padding:10px;border:1px solid rgba(57,125,246,.24);border-radius:9px;background:#080c12}.ks-artifact-focus dl{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;margin:9px 0;background:var(--line)}.ks-artifact-focus dl>div{min-width:0;padding:8px;background:#0a0f16}.ks-artifact-focus dt{color:#68778d;font-size:6px}.ks-artifact-focus dd{overflow:hidden;margin:4px 0 0;font-size:7px;text-overflow:ellipsis;white-space:nowrap}.ks-artifact-focus>p{color:#7e8ca0;font-size:7px}.ks-artifact-chain{display:grid;gap:4px}.ks-artifact-chain article{display:grid;grid-template-columns:70px minmax(120px,1fr) auto minmax(120px,1fr);gap:7px;padding:7px;border:1px solid var(--line);border-radius:7px}.ks-artifact-chain b,.ks-artifact-chain strong,.ks-artifact-chain code{font-size:6px}.ks-artifact-chain code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ks-evidence-browser>header>div:last-child{display:flex;align-items:center;gap:7px}.ks-evidence-browser>header>div:last-child>b{color:#67a0ec;font-size:7px}.ks-evidence-preview>header>div:last-child{display:flex;align-items:center;gap:7px}
.ks-artifact-focus>details{margin:7px 0;padding:7px;border:1px solid var(--line);border-radius:7px}.ks-artifact-focus>details summary{color:#7897c3;font-size:7px;cursor:pointer}.ks-artifact-focus>details pre{max-height:240px;margin:7px 0 0;padding:8px;overflow:auto;color:#9fb0c5;background:#070b10;font:7px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}
.ks-evidence-browser .ks-artifact-focus,.ks-evidence-browser .ks-artifact-focus dl>div,.ks-evidence-browser .ks-artifact-focus details pre{color:var(--text);background:var(--surface)}
.runtime-monitor-layout .ks-flow-card code,
.runtime-monitor-layout .ks-path>li>code,
.runtime-monitor-layout .ks-backbone-list code,
.runtime-monitor-layout .ks-backbone-list span,
.runtime-monitor-layout .ks-data-table code {
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.runtime-monitor-layout .ks-path>li>header>* { min-width: 0; }
.runtime-monitor-layout .ks-path>li>header>strong,
.runtime-monitor-layout .ks-path>li>p { overflow-wrap: anywhere; word-break: break-word; }
@media (max-width: 960px) { .capability-check-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 1100px) { .ks-package-list article { grid-template-columns: minmax(200px,1fr) repeat(3,minmax(65px,.4fr)); }.ks-package-list article>span:nth-of-type(n+4){display:none}.ks-capture-form{grid-template-columns:repeat(3,1fr)}.ks-capture-form .wide{grid-column:1/4}.ks-intelligence-grid,.ks-lifecycle-grid,.ks-forensic-grid,.ks-layer-contract,.ks-chain-rail{grid-template-columns:repeat(2,1fr)}.ks-presets{grid-template-columns:repeat(2,1fr)}.ks-backbone-list article{grid-template-columns:70px minmax(150px,1fr) minmax(150px,1fr)}.ks-backbone-list article>span{grid-column:2/4}.ks-reassembly-funnel{grid-template-columns:repeat(3,minmax(0,1fr))} }
@media (max-width: 850px) { .ks-requirement-grid,.ks-provision-steps{grid-template-columns:repeat(2,1fr)} }
@media (max-width: 900px){.ks-binary-preview-grid{grid-template-columns:1fr}.ks-binary-preview-grid pre{height:360px}}
@media (max-width: 650px) { .capability-probe-header { flex-direction: column; }.probe-mode { width: 100%; }.capability-check-grid, .probe-facts, .ks-report-summary,.ks-presets,.ks-capture-form,.ks-intelligence-grid,.ks-integrity-strip,.ks-network-summary,.ks-dns-list,.ks-lifecycle-grid,.ks-capture-plan,.ks-requirement-grid,.ks-provision-steps,.ks-forensic-grid,.ks-command-grid,.ks-evidence-policy,.ks-evidence-file-list,.ks-layer-contract,.ks-chain-rail,.ks-reassembly-funnel { grid-template-columns: 1fr; }.ks-install-gate>header,.ks-install-guidance{grid-template-columns:1fr}.ks-capture-plan details{grid-column:auto}.ks-capture-form .wide{grid-column:auto}.ks-session-row{grid-template-columns:1fr}.ks-session-open,.ks-package-list article{grid-template-columns:1fr}.ks-session-delete,.ks-session-owned{border-top:1px solid var(--line);border-left:0}.ks-package-list article>span{text-align:left}.ks-package-list article>span:nth-of-type(n){display:block}.ks-edge-list article,.ks-event-list summary,.ks-data-table article,.ks-backbone-list article{grid-template-columns:1fr}.ks-backbone-list article>span{grid-column:auto}.ks-edge-list small,.ks-data-table span{text-align:left}.ks-data-table code{grid-column:1}.ks-event-toolbar,.ks-graph-toolbar{grid-template-columns:1fr}.ks-dns-list article{grid-template-columns:24px 1fr}.ks-dns-list code{grid-column:2}.ks-semantic-list dl{grid-template-columns:1fr 1fr} }
@media (max-width:650px){.ks-workspace-switcher,.ks-analyzable-list,.ks-artifact-focus dl{grid-template-columns:1fr}.ks-analyzable-list em{grid-column:auto}.ks-artifact-chain article{grid-template-columns:1fr}}
/* Compact session actions and restrained secondary controls in both themes. */
.runtime-monitor-layout .ghost-button,
.runtime-hero-actions .primary-button,
.ks-review-actions .primary-button {
  color: var(--text); background: var(--surface); border: 1px solid var(--line-strong);
  box-shadow: none; letter-spacing: normal; text-transform: none;
}
.runtime-monitor-layout .ghost-button:hover { background: var(--surface-soft); }
.runtime-monitor-layout .ks-session-list { gap: 0; border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.runtime-monitor-layout .ks-session-row { border: 0; border-bottom: 1px solid var(--line); border-radius: 0; background: var(--surface); align-items: center; }
.runtime-monitor-layout .ks-session-row:last-of-type { border-bottom: 0; }
.runtime-monitor-layout .ks-session-row:hover { background: var(--surface-soft); }
.runtime-monitor-layout .ks-session-row.active { background: var(--primary-soft); box-shadow: inset 3px 0 var(--primary); }
.runtime-monitor-layout .ks-session-open { grid-template-columns: minmax(0,1.3fr) minmax(0,.8fr) minmax(0,.65fr); padding: 12px 14px; gap: 14px; min-width: 0; }
.runtime-monitor-layout .ks-session-open small { color: var(--muted); overflow-wrap: anywhere; }
.runtime-monitor-layout .ks-session-state { text-align: right; }
.runtime-monitor-layout .ks-session-state b { color: var(--muted); font-size: 7px; }
.runtime-monitor-layout .ks-session-delete-slot { min-width: 0; gap: 4px; padding: 0 10px; align-items: center; }
.runtime-monitor-layout .ks-session-delete,
.runtime-monitor-layout .ks-session-delete-cancel { display: inline-flex; align-items: center; justify-content: center; gap: 3px; min-width: 0; min-height: 28px; padding: 5px 7px; border: 1px solid transparent; border-radius: 6px; color: var(--muted); background: transparent; }
.runtime-monitor-layout .ks-session-delete .material-symbols-outlined { font-size: 13px; }
.runtime-monitor-layout .ks-session-delete:hover { color: var(--red); border-color: var(--red); background: transparent; }
.runtime-monitor-layout .ks-session-delete.confirm { color: var(--red); border-color: var(--red); background: transparent; }
.runtime-monitor-layout .ks-session-owned { min-width: 0; border: 0; color: var(--muted); }
.runtime-monitor-layout .ks-session-open:focus-visible,
.runtime-monitor-layout .ks-session-delete:focus-visible { outline: 2px solid var(--primary); outline-offset: -2px; }
@media (max-width: 650px) {
  .runtime-monitor-layout .ks-session-row { grid-template-columns: minmax(0,1fr) auto; }
  .runtime-monitor-layout .ks-session-open { grid-template-columns: minmax(0,1fr); gap: 6px; }
  .runtime-monitor-layout .ks-session-state { text-align: left; }
  .runtime-monitor-layout .ks-session-delete-slot { flex-direction: column; }
}
</style>
