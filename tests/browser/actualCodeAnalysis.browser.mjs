import assert from 'node:assert/strict'
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { tmpdir } from 'node:os'
import ts from 'typescript'
import { launchMe } from './mockedMeHarness.mjs'

const projectRoot = fileURLToPath(new URL('../../', import.meta.url))
const inputPath = process.env.ME_ACTUAL_EVIDENCE_FIXTURE
assert.ok(inputPath, 'Set ME_ACTUAL_EVIDENCE_FIXTURE to a read-only serialized KernSightLocalEvidenceBundle snapshot')
const fixtureKind = process.env.ME_EVIDENCE_FIXTURE_KIND || 'actual_import_snapshot'
const sourceLabel = fixtureKind === 'actual_import_snapshot' ? 'Actual' : 'Synthetic script-smoke'
const raw = readFileSync(inputPath)
const actual = JSON.parse(raw)
assert.ok(actual.root && actual.package && actual.dumpReport && Array.isArray(actual.files), 'The fixture must retain the actual bundle shape and file inventory')
const dump = actual.dumpReport
const array = value => Array.isArray(value) ? value : []
const validObject = value => value && /^[a-f0-9]{64}$/i.test(value.sha256 || '') && Number.isSafeInteger(value.bytes) && value.bytes >= 0
const keys = [...new Set([...array(dump.content_dex_class_index?.objects), ...array(dump.dex_sets)].filter(validObject).map(value => `${value.sha256.toLowerCase()}:${value.bytes}`))]
assert.ok(keys.length, 'This actual-object regression requires at least one source-recorded object; it does not invent an inventory for missing reports')
const dexPaths = new Set([
  ...array(dump.artifacts).filter(value => value?.kind === 'dex').map(value => value.relative_path),
  ...array(dump.dex_sets).filter(validObject).map(value => value.canonical_relative_path),
  ...array(dump.content_dex_class_index?.objects).filter(validObject).flatMap(value => array(value.sources).map(source => source?.relative_path)),
].filter(value => typeof value === 'string'))
const readable = actual.files.filter(file => dexPaths.has(file.relativePath) || /^(?:readable-dex\/|(?:runtime\/)?blob-dex\/|runtime\/mem-).*\.dex$/i.test(file.relativePath) || array(file.codeEvidence).some(note => note?.relative_path === file.relativePath && note.local_content_status === 'complete_range_hash_verified' && array(note.object_inspection?.derived_objects).some(object => object?.kind === 'dex' && /^[a-f0-9]{64}$/i.test(object.sha256 || '') && Number.isSafeInteger(object.length) && object.length >= 0)))
const eligibleNoiseFiles = actual.files.filter(file => array(file.codeEvidence).length || ['dex', 'elf'].includes(file.category)).length
const ownershipCount = array(dump.dex_ownership?.entries).length
const out = resolve(process.env.ME_ACTUAL_CODE_QA_OUTPUT || resolve(tmpdir(), 'me-actual-code-analysis-qa'))
mkdirSync(out, { recursive: true })
const service = ts.transpileModule(readFileSync(new URL('../../src/services/kernsightCodeEvidence.ts', import.meta.url), 'utf8'), { compilerOptions: { module: ts.ModuleKind.ESNext } }).outputText
const { projectDexEvidence, runtimeDexClassMatches } = await import(`data:text/javascript;base64,${Buffer.from(service).toString('base64')}`)
const projected = projectDexEvidence(dump)
assert.equal(projected.objects.length, keys.length)
let nextImport = actual
// An alias of the same snapshot tests local-root selection state only. It is not a second capture.
const alias = { ...actual, root: `${actual.root}-browser-layout-alias` }
const h = await launchMe({ root: projectRoot, fixtures: { list_kernsight_group_purges: [] }, handler: async command => {
  if (command === 'plugin:dialog|open') return nextImport.root
  if (command === 'import_kernsight_evidence_directory') return nextImport
  if (command === 'local_kernsight_evidence_present') return true
} })
const { page, calls, errors, close } = h
const checks = []
const record = name => { checks.push(name); console.log('PASS ' + name) }
const panel = page.locator('.ks-package-evidence-panel')
const analysis = panel.locator('.ks-code-analysis')
const index = analysis.locator(':scope > .ks-dex-index')
const noise = analysis.locator(':scope > .ks-code-noise')
const ownership = analysis.locator(':scope > .ks-code-ownership')
const browser = panel.locator('.ks-evidence-browser')
const fileRows = browser.locator('.ks-evidence-file-list > button')
const card = panel.locator('.ks-forensic-grid > article').filter({ has: page.locator('strong').filter({ hasText: 'DEX 文件 / 容器' }) })
async function importBundle(bundle) {
  nextImport = bundle
  await page.getByRole('button', { name: /导入本地证据/ }).click()
  await page.locator('.ks-package-list article').filter({ hasText: bundle.package }).first().click()
  await panel.waitFor()
}
try {
  await page.getByRole('button', { name: /KernSight.*采集、会话/ }).click()
  await importBundle(actual)
  assert.match(await analysis.locator(':scope > header').innerText(), /仅使用此采集记录/)
  assert.equal(await analysis.getByRole('button', { name: '复制完整当前代码分析来源目录' }).textContent(), actual.root)
  assert.equal(await analysis.locator(':scope > details[open]').count(), 0)
  const coverage = panel.locator('.ks-source-diagnostics .ks-runtime-coverage')
  const ledger = dump.local_storage_accounting
  if (Array.isArray(ledger?.runtime_range_inventory)) {
    assert.match(await coverage.textContent(), new RegExp(`范围清单 ${(ledger.runtime_range_inventory_records ?? ledger.runtime_range_inventory.length).toLocaleString('en-US')} 条`))
    if (ledger.runtime_inspection_unique_contents != null) assert.match(await coverage.textContent(), new RegExp(`唯一内容检查 ${ledger.runtime_inspection_unique_contents.toLocaleString('en-US')} 份`))
  } else {
  if (ledger?.runtime_observation_limit != null) assert.match(await coverage.textContent(), new RegExp(`范围上限 ${ledger.runtime_observation_limit} 条`))
  if (ledger?.omitted_observations != null) assert.match(await coverage.textContent(), new RegExp(`另省略 ${ledger.omitted_observations} 条`))
  if (ledger?.runtime_sources_omitted != null) assert.match(await coverage.textContent(), new RegExp(`另省略 ${ledger.runtime_sources_omitted} 份`))
  }
  if (ledger?.runtime_source_ledger_complete === false) assert.match(await coverage.textContent(), /来源账本不完整/)
  if (ledger?.runtime_analysis_complete === false) assert.match(await coverage.textContent(), /代码分析不完整/)
  await analysis.screenshot({ path: out + '/actual-analysis-collapsed.png' })
  await index.locator(':scope > summary').click()
  assert.equal(await index.locator('[data-dex-object]').count(), keys.length)
  const verifiedKeys = new Set(array(dump.content_dex_class_index?.objects).filter(object => validObject(object) && object.sha1_signature_verified === true && object.adler32_checksum_verified === true && object.validation_status === 'checksum_and_bounded_structure_verified' && object.layout_diagnostics?.status === 'declared_spans_cover_file').map(object => `${object.sha256.toLowerCase()}:${object.bytes}`))
  assert.equal(await index.locator('[data-dex-group="verified"] [data-dex-object]').count(), verifiedKeys.size)
  assert.equal(await index.locator('[data-dex-group="diagnostic"] [data-dex-object]').count(), keys.length - verifiedKeys.size)
  const displayedKeys = await index.locator('[data-dex-object] > p:first-child').allTextContents()
  for (const key of keys) assert.ok(displayedKeys.some(text => text.toLowerCase().includes(key.split(':')[0])), 'Missing actual object ' + key)
  const last = index.locator('[data-dex-object]').last()
  await last.scrollIntoViewIfNeeded()
  assert.ok(await last.isVisible())
  await index.screenshot({ path: out + '/actual-object-list.png' })
  record(`${sourceLabel} snapshot: ${keys.length} source-recorded distinct structure objects appear in the same-source expandable component`)

  const candidate = projected.objects.find(object => runtimeDexClassMatches(dump.local_storage_accounting, object, '').status === 'indexed')
  if (candidate) {
    const expected = runtimeDexClassMatches(dump.local_storage_accounting, candidate, '')
    const row = index.locator('[data-dex-object]').filter({ has: page.locator(':scope > p:first-child').filter({ hasText: candidate.sha256 }) })
    assert.match(await row.locator('[data-dex-index-status="indexed"]').innerText(), new RegExp(`匹配 ${expected.total} · 当前页 ${expected.classes.length}`))
    if (expected.nextOffset !== null) {
      await row.getByRole('button', { name: '下一页类名', exact: true }).click()
      assert.equal(await row.getByRole('button', { name: '上一页类名', exact: true }).count(), 1)
    }
    const needle = expected.classes.at(-1)
    if (needle) {
      await index.locator('input').fill(needle)
      const searched = runtimeDexClassMatches(dump.local_storage_accounting, candidate, needle)
      assert.match(await row.locator('[data-dex-index-status="indexed"]').innerText(), new RegExp(`匹配 ${searched.total} · 当前页 ${searched.classes.length}`))
      assert.ok((await row.locator(':scope > pre').allTextContents()).some(text => text.includes(needle)))
      await index.locator('input').fill('')
      assert.equal(await row.getByRole('button', { name: '上一页类名', exact: true }).count(), 0)
    }
    record(`${sourceLabel} saved class index retains its measured match count, page navigation and query reset`)
  } else {
    assert.equal(await index.locator('[data-dex-index-status="indexed"]').count(), 0)
    assert.ok(await index.locator('[data-dex-index-status="unknown"], [data-dex-index-status="unlinked"]').count())
    record(`${sourceLabel} snapshot lacks a linked class index; the component keeps match counts unknown`)
  }
  await index.locator(':scope > summary').click()
  assert.equal(await card.locator(':scope > b').innerText(), String(readable.length))
  await card.click()
  assert.match(await browser.locator(':scope > header').innerText(), new RegExp(`${readable.length} catalogued`))
  assert.equal(await fileRows.count(), Math.min(100, readable.length))
  const paths = await fileRows.locator('strong').allTextContents()
  assert.deepEqual(paths, readable.slice(0, 100).map(file => file.relativePath))
  await browser.getByRole('button', { name: '显示全部', exact: true }).click()
  assert.equal(await fileRows.count(), Math.min(100, actual.files.length))
  record(`${sourceLabel} physical DEX/container card ${readable.length} matches its selected file list; all-files reset returns the current inventory`)

  await noise.locator(':scope > summary').click()
  for (const summary of await noise.locator(':scope > details > summary').all()) await summary.click()
  assert.equal(await noise.locator('.ks-noise-body article > div').count(), eligibleNoiseFiles)
  await noise.locator(':scope > summary').click()
  await ownership.locator(':scope > summary').click()
  assert.equal(await ownership.locator('.ks-dex-ownership-list > article').count(), Math.min(30, ownershipCount))
  while (await ownership.getByRole('button', { name: /继续显示 \d+ 个 DEX/ }).count()) await ownership.getByRole('button', { name: /继续显示 \d+ 个 DEX/ }).click()
  assert.equal(await ownership.locator('.ks-dex-ownership-list > article').count(), ownershipCount)
  await ownership.locator(':scope > summary').click()
  assert.equal(await ownership.locator('.ks-dex-ownership-list > article:visible').count(), 0)
  record(`${sourceLabel} file evidence and ownership rows remain complete inside their local collapsed sections`)

  await index.locator(':scope > summary').click()
  await index.locator('input').fill('temporary-browser-state')
  await importBundle(alias)
  assert.equal(await analysis.locator(':scope > details[open]').count(), 0)
  await importBundle(actual)
  assert.equal(await analysis.locator(':scope > details[open]').count(), 0)
  await index.locator(':scope > summary').click()
  assert.equal(await index.locator('input').inputValue(), '')
  await index.locator(':scope > summary').click()
  record(`${sourceLabel} root and its layout-only alias close old analysis and clear its query`)

  for (const width of [1440, 821, 390]) {
    await page.setViewportSize({ width, height: 1000 })
    const bounds = await panel.evaluate(el => ({ client: el.clientWidth, scroll: el.scrollWidth, pageClient: document.documentElement.clientWidth, pageScroll: document.documentElement.scrollWidth }))
    assert.ok(bounds.scroll <= bounds.client + 1 && bounds.pageScroll <= bounds.pageClient + 1, JSON.stringify({ width, bounds }))
    await analysis.screenshot({ path: out + `/actual-analysis-${width}.png` })
    for (const detail of [index, noise, ownership]) {
      await detail.locator(':scope > summary').click()
      const expanded = await analysis.evaluate(el => ({ client: el.clientWidth, scroll: el.scrollWidth, pageClient: document.documentElement.clientWidth, pageScroll: document.documentElement.scrollWidth }))
      assert.ok(expanded.scroll <= expanded.client + 1 && expanded.pageScroll <= expanded.pageClient + 1, JSON.stringify({ width, expanded }))
      const height = await detail.evaluate(el => el.getBoundingClientRect().height)
      assert.ok(height <= 730, `Local expanded analysis must remain scrollable within 70vh: ${height}`)
      if (detail === index) await analysis.screenshot({ path: out + `/actual-object-list-${width}.png` })
      await detail.locator(':scope > summary').click()
    }
  }
  record(`${sourceLabel} source labels and both collapsed and locally scrollable expanded analysis fit wide, medium and narrow Chromium layouts`)
  assert.deepEqual(errors, [])
  assert.deepEqual(calls.filter(call => /^(begin_|provision_|run_kernsight|start_|dump_|execute_|trash_|restore_|cleanup_|cancel_)/.test(call.command)), [])
  writeFileSync(out + '/browser-results.json', JSON.stringify({ passed: true, checks, errors, fixtureKind, inputPath, inputSha256: createHash('sha256').update(raw).digest('hex'), actual: { root: actual.root, package: actual.package, dumpId: dump.dump_id, files: actual.files.length, physicalDexFiles: readable.length, producerDexSets: array(dump.dex_sets).length, localContentObjects: array(dump.content_dex_class_index?.objects).length, distinctObjects: keys.length, runtimeObservations: Array.isArray(dump.local_storage_accounting?.runtime_observations) ? dump.local_storage_accounting.runtime_observations.length : null, runtimeSourceReportsOmitted: dump.local_storage_accounting?.runtime_sources_omitted ?? null, omittedObservations: dump.local_storage_accounting?.omitted_observations ?? null, runtimeObservationLimit: dump.local_storage_accounting?.runtime_observation_limit ?? null, runtimeSourceReportLimit: dump.local_storage_accounting?.runtime_source_limit ?? null, runtimeSourceLedgerComplete: dump.local_storage_accounting?.runtime_source_ledger_complete ?? null, runtimeAnalysisComplete: dump.local_storage_accounting?.runtime_analysis_complete ?? null, verifiedObjects: verifiedKeys.size, diagnosticObjects: keys.length - verifiedKeys.size, storedClassNamesSum: array(dump.content_dex_class_index?.objects).reduce((sum, object) => sum + array(object?.classes).length, 0) }, commands: [...new Set(calls.map(call => call.command))], note: `${fixtureKind === 'actual_import_snapshot' ? 'Read-only actual importer snapshot' : 'SYNTHETIC SCRIPT SMOKE ONLY; not actual capture evidence'} in independent Chromium with mocked IPC. The second root is a layout-only alias of this same snapshot. No capture, deployment, native ME/WebKit verification or source-state upgrade.` }, null, 2))
  console.log(JSON.stringify({ passed: true, checks: checks.length, out }))
} catch (error) {
  await page.screenshot({ path: out + '/failure.png', fullPage: true })
  writeFileSync(out + '/failure.txt', String(error) + '\n' + JSON.stringify({ errors, calls }, null, 2))
  throw error
} finally { await close() }
