import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const code = ts.transpileModule(readFileSync(new URL('../src/services/kernsightWorkspaceState.ts', import.meta.url), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
}).outputText
const { selectedImportedBundle, packageEvidenceReports, importedSessionId, bundleForSession, linkedEvidenceMatches, createLatestRequest, createKeyedRequests, evidenceCountLabel, executionStatusLabel } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
const bundle = (root, parent, count) => ({
  root, package: 'org.example.app', fileCount: count, files: [{ relativePath: `${root}/classes.dex` }],
  dumpReport: { package: 'org.example.app', dump_id: `dump-${root}`, readable_dex: count },
  sessionReport: parent ? { mobilee_capture_group: { id: parent } } : {},
})

test('two captures of one package default to the latest import without merging identities', () => {
  const old = bundle('old', 'parent-old', 1), current = bundle('new', 'parent-new', 7)
  const bundles = [old, current]
  assert.equal(selectedImportedBundle(bundles, old.package), current)
  assert.equal(packageEvidenceReports([], bundles, {})[0], current.dumpReport)
  assert.equal(bundles.length, 2)
})

test('explicit capture selection keeps list counts and opened file/report identity aligned', () => {
  const old = bundle('old', 'parent-old', 1), current = bundle('new', 'parent-new', 7)
  const bundles = [old, current]
  for (const selected of bundles) {
    const roots = { [selected.package]: selected.root }
    const card = packageEvidenceReports([], bundles, roots)[0]
    const opened = selectedImportedBundle(bundles, selected.package, roots[selected.package])
    assert.equal(card, opened.dumpReport)
    assert.equal(card.readable_dex, opened.fileCount)
    assert.equal(opened.files[0].relativePath, `${selected.root}/classes.dex`)
    assert.equal(importedSessionId(opened), selected.sessionReport.mobilee_capture_group.id)
  }
})

test('missing or wrong-package explicit roots never silently select another capture', () => {
  const a = bundle('a', 'parent-a', 1)
  assert.equal(selectedImportedBundle([a], a.package, 'missing'), null)
  assert.equal(selectedImportedBundle([a], 'other.package', 'a'), null)
})

test('choosing the device uses device counts instead of a same-package local report', () => {
  const local = bundle('local', 'parent-local', 1)
  const device = { ...local.dumpReport, dump_id: 'device-dump', readable_dex: 9 }
  assert.equal(packageEvidenceReports([device], [local], {})[0], local.dumpReport)
  assert.equal(packageEvidenceReports([device], [local], {}, local.package)[0], device)
})

test('legacy reports without a session ID have distinct root identities', () => {
  assert.notEqual(importedSessionId(bundle('one', null, 0)), importedSessionId(bundle('two', null, 0)))
  const legacy = bundle('one', null, 0)
  legacy.sessionReport.session_id = 'session-1'
  assert.equal(importedSessionId(legacy), 'session-1')
})

test('session evidence remains unlinked until requested and cannot cross capture roots', () => {
  assert.equal(linkedEvidenceMatches(false, 'app', 'app', 'root-a', 'root-a'), false)
  assert.equal(linkedEvidenceMatches(true, 'app', 'other', 'root-a', 'root-a'), false)
  assert.equal(linkedEvidenceMatches(true, 'app', 'app', 'root-a', 'root-b'), false)
  assert.equal(linkedEvidenceMatches(true, 'app', 'app', 'root-a', ''), false)
  assert.equal(linkedEvidenceMatches(true, 'app', 'app', 'root-a', 'root-a'), true)
  assert.equal(linkedEvidenceMatches(true, 'app', 'app', '', 'root-b'), true)
})

test('a device child cannot link the newest same-package dump from a different parent', () => {
  const a = bundle('a', 'parent-a', 1), b = bundle('b', 'parent-b', 9)
  assert.equal(bundleForSession([a, b], a.package, '', 'parent-a', b.root), a)
  assert.equal(bundleForSession([b], a.package, '', 'parent-a', b.root), null)
  assert.equal(bundleForSession([a, b], a.package, b.root, 'parent-a'), null)
})

test('late successes/errors/finalizers cannot overwrite newer requests or reopen closed views', async () => {
  const requests = createLatestRequest()
  const first = requests.begin(), next = requests.begin()
  await Promise.resolve()
  assert.equal(requests.isCurrent(first), false)
  assert.equal(requests.isCurrent(next), true)
  requests.invalidate()
  assert.equal(requests.isCurrent(next), false)
  assert.equal(requests.isCurrent(requests.begin()), true)
})

test('missing counters and execution statuses stay unknown, distinct from measured zero/false', () => {
  for (const value of [null, undefined, '', '0', -1, NaN, Infinity]) assert.equal(evidenceCountLabel(value), '未知')
  assert.equal(evidenceCountLabel(0), '0')
  assert.match(executionStatusLabel(undefined), /未知/)
  assert.match(executionStatusLabel(false), /不完整/)
  assert.match(executionStatusLabel(true), /覆盖另核对/)
})

test('plaintext navigation/close invalidates every pending decode, even for reused row keys', () => {
  const requests = createKeyedRequests()
  const old = requests.begin('same-pid-adapter-direction-index')
  requests.invalidate()
  const current = requests.begin('same-pid-adapter-direction-index')
  assert.equal(requests.isCurrent('same-pid-adapter-direction-index', old), false)
  assert.equal(requests.isCurrent('same-pid-adapter-direction-index', current), true)
})

test('cancel/restart ignores late decoding and does not cancel independent rows', () => {
  const requests = createKeyedRequests()
  const a = requests.begin('a'), b = requests.begin('b')
  requests.cancel('a')
  const restarted = requests.begin('a')
  assert.equal(requests.isCurrent('a', a), false)
  assert.equal(requests.isCurrent('a', restarted), true)
  assert.equal(requests.isCurrent('b', b), true)
  requests.invalidate()
  assert.equal(requests.isCurrent('a', restarted), false)
  assert.equal(requests.isCurrent('b', b), false)
})
