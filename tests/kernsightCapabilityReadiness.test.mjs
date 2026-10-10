import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'

const source = readFileSync(new URL('../src/services/kernsightCapabilityReadiness.ts', import.meta.url), 'utf8')
let compiled
try {
  const { default: ts } = await import('typescript')
  compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
} catch (error) {
  if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error
  // Source-only review environments can use Node 24; CI uses the project's TS.
  const { stripTypeScriptTypes } = await import('node:module')
  compiled = stripTypeScriptTypes(source)
}
const { deploymentAssessment, capabilityIconPath, capabilityStatusLabel } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
const view = readFileSync(new URL('../src/views/AndroidRuntimeMonitorView.vue', import.meta.url), 'utf8')
const fixture = (root = 'available', btf = 'missing', bpffs = 'unknown', architecture = 'aarch64') => ({
  architecture, checks: [{ key: 'root', status: root, detail: 'fixture root' }, { key: 'btf', status: btf, detail: 'fixture BTF' }, { key: 'bpffs', status: bpffs, detail: 'fixture bpffs' }],
})

test('root + ARM64 is a deployment candidate, never proof of BPF or BTF readiness', () => {
  for (const status of ['missing', 'restricted', 'unknown', 'warning']) {
    const result = deploymentAssessment(fixture('available', status, status))
    assert.equal(result.state, 'candidate')
    assert.equal(result.blockers.length, 0)
    assert.match(result.summary, /不代表 BPF 可加载/)
    assert.equal(result.requirements.find(item => item.key === 'btf').status, status)
    assert.equal(result.requirements.find(item => item.key === 'btf').required, false)
    assert.equal(result.requirements.find(item => item.key === 'bpffs').required, false)
  }
})
test('unknown and denied root stay distinct; root does not upgrade other capabilities', () => {
  assert.equal(deploymentAssessment(null).state, 'unknown')
  assert.equal(deploymentAssessment(fixture('unknown')).state, 'unknown')
  assert.equal(deploymentAssessment(fixture('restricted')).state, 'blocked')
  assert.equal(deploymentAssessment(fixture('missing')).state, 'blocked')
  assert.equal(deploymentAssessment(fixture('available', 'available', 'available', 'x86_64')).state, 'blocked')
  assert.equal(deploymentAssessment(fixture('available', 'available', 'available', 'permission denied')).state, 'unknown')
})
test('all status glyphs are local SVG paths with independent visible status labels', () => {
  for (const status of ['available', 'restricted', 'warning', 'missing', 'unknown', 'unavailable', 'limited']) {
    assert.match(capabilityIconPath(status), /^M/)
    assert.doesNotMatch(capabilityIconPath(status), /check_circle|cancel|https?:/)
    assert.notEqual(capabilityStatusLabel(status), status)
  }
  const cards = view.slice(view.indexOf('<section v-if="provisionResult'), view.indexOf('<section v-if="kernSight && workspaceMode'))
  assert.doesNotMatch(cards, /material-symbols|check_circle|cancel/)
  assert.match(cards, /aria-hidden="true" focusable="false"/)
  assert.match(cards, /capabilityStatusLabel\(item.status\)/)
  assert.match(cards, /读取上下文/)
})

// Execute the production async handlers with controlled promises. No device,
// network, update installation, or filesystem mutation is performed.
const handlers = view.slice(view.indexOf('async function runCapabilityProbe()'), view.indexOf('\nasync function loadKernSight()'))
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b }); return { promise, resolve, reject } }
const latest = () => { let current = 0; return { begin: () => ++current, invalidate: () => ++current, isCurrent: token => token === current } }
function harness() {
  const state = {
    androidReady: { value: true }, props: { device: { serial: 'A' } },
    probeRequests: latest(), provisionRequests: latest(), probing: { value: false }, provisioning: { value: false },
    capabilityProbe: { value: null }, provisionResult: { value: null }, agentBadge: { value: { fresh: false, version: '' } }, probeError: { value: '' },
  }
  const calls = [], errors = [], pendingProbes = [], pendingUpdates = []
  const dependencies = { ...state,
    monitoringBackend: {
      probeCapabilities: serial => { calls.push(['probe', serial]); const d = deferred(); pendingProbes.push(d); return d.promise },
      provisionLatestAgent: serial => { calls.push(['provision', serial]); const d = deferred(); pendingUpdates.push(d); return d.promise },
    }, beginOperation: () => 1, failOperation: (...args) => errors.push(args), loadKernSight: async () => { calls.push(['overview', state.props.device.serial]) },
  }
  const functions = new Function(...Object.keys(dependencies), `${handlers}; return {runCapabilityProbe, provisionKernSight}`)(...Object.values(dependencies))
  const switchDevice = serial => {
    state.props.device = { serial }; state.probeRequests.invalidate(); state.provisionRequests.invalidate()
    state.probing.value = false; state.provisioning.value = false; state.capabilityProbe.value = null
    state.provisionResult.value = null; state.agentBadge.value = { fresh: false, version: '' }
  }
  return { ...state, ...functions, switchDevice, calls, errors, pendingProbes, pendingUpdates }
}
test('late probe A cannot replace B or clear B busy state', async () => {
  const h = harness(); const a = h.runCapabilityProbe(); h.switchDevice('B'); const b = h.runCapabilityProbe()
  h.pendingProbes[0].resolve({ serial: 'A', agentStatus: 'Installed' }); await a
  assert.equal(h.capabilityProbe.value, null); assert.equal(h.probing.value, true)
  assert.deepEqual(h.calls, [['probe', 'A'], ['probe', 'B']])
  h.pendingProbes[1].resolve({ serial: 'B', agentStatus: 'Not Installed' }); await b
  assert.equal(h.capabilityProbe.value.serial, 'B'); assert.equal(h.probing.value, false)
})
test('late updater A cannot badge B, probe B, handshake B or clear B busy state', async () => {
  const h = harness(); const a = h.provisionKernSight(); h.switchDevice('B'); const b = h.provisionKernSight()
  h.pendingUpdates[0].resolve({ installedVersion: 'A-version', alreadyCurrent: false }); await a
  assert.equal(h.agentBadge.value.fresh, false); assert.equal(h.provisionResult.value, null); assert.equal(h.provisioning.value, true)
  assert.deepEqual(h.calls, [['provision', 'A'], ['provision', 'B']])
  h.pendingUpdates[1].resolve({ installedVersion: 'B-version', alreadyCurrent: true }); await b
  assert.equal(h.agentBadge.value.version, 'B-version'); assert.equal(h.provisioning.value, false)
  assert.deepEqual(h.calls.at(-1), ['overview', 'B'])
})
test('A-to-B-to-A navigation and stale rejection cannot revive old results', async () => {
  const h = harness(); const a = h.runCapabilityProbe(); const update = h.provisionKernSight()
  h.switchDevice('B'); h.switchDevice('A')
  h.pendingProbes[0].resolve({ serial: 'A', agentStatus: 'Installed' }); h.pendingUpdates[0].reject(new Error('old update error'))
  await Promise.all([a, update]); assert.equal(h.capabilityProbe.value, null); assert.deepEqual(h.errors, [])
  assert.deepEqual(h.calls, [['probe', 'A'], ['provision', 'A']])
})
test('device watcher synchronously resets scoped badges and invalidates requests', () => {
  const watcher = view.slice(view.indexOf('watch(() => props.device?.serial, () => {'), view.indexOf('\nonErrorCaptured'))
  for (const expected of ['probeRequests.invalidate()', 'provisionRequests.invalidate()', "agentBadge.value = { fresh: false, version: '' }", 'provisionResult.value = null', 'capabilityProbe.value = null', "flush: 'sync'"]) assert.ok(watcher.includes(expected), expected)
})
