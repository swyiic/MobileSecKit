import type { KernSightLocalEvidenceBundle, KernSightPackageDumpReport } from '../types/monitoring'

/** Import order is only a default. An explicit root always identifies one capture. */
export function selectedImportedBundle(
  bundles: KernSightLocalEvidenceBundle[], packageName: string, root?: string,
): KernSightLocalEvidenceBundle | null {
  const candidates = bundles.filter(bundle => bundle.package === packageName)
  if (root) return candidates.find(bundle => bundle.root === root) || null
  return candidates[candidates.length - 1] || null
}

export function packageEvidenceReports(
  device: KernSightPackageDumpReport[], bundles: KernSightLocalEvidenceBundle[], roots: Record<string, string>,
  activeDevicePackage = '',
): KernSightPackageDumpReport[] {
  const reports = new Map(device.map(report => [report.package, report]))
  for (const packageName of new Set(bundles.map(bundle => bundle.package))) {
    if (packageName === activeDevicePackage && device.some(report => report.package === packageName)) continue
    const bundle = selectedImportedBundle(bundles, packageName, roots[packageName])
    if (bundle) reports.set(packageName, bundle.dumpReport)
  }
  return [...reports.values()]
}

export function importedSessionId(bundle: KernSightLocalEvidenceBundle): string {
  const report = bundle.sessionReport
  const parent = report?.mobilee_capture_group as { id?: unknown } | undefined
  if (typeof parent?.id === 'string' && parent.id) return parent.id
  if (typeof report?.session_id === 'string' && report.session_id) return report.session_id
  return `local:${bundle.root}`
}

export function bundleForSession(
  bundles: KernSightLocalEvidenceBundle[], packageName: string, root: string, parentId: string, preferredRoot?: string,
): KernSightLocalEvidenceBundle | null {
  const candidates = bundles.filter(bundle => bundle.package === packageName && (!parentId
    || (bundle.sessionReport?.mobilee_capture_group as { id?: unknown } | undefined)?.id === parentId))
  if (root) return selectedImportedBundle(candidates, packageName, root)
  return candidates.find(bundle => bundle.root === preferredRoot) || selectedImportedBundle(candidates, packageName)
}

export function linkedEvidenceMatches(
  linked: boolean, sessionPackage: string, selectedPackage: string,
  sessionRoot: string, selectedRoot: string,
): boolean {
  return linked && Boolean(sessionPackage) && sessionPackage === selectedPackage
    && (!sessionRoot || sessionRoot === selectedRoot)
}

/** Closing or changing context invalidates pending success, error and finally work. */
export function createLatestRequest() {
  let current = 0
  return {
    begin: () => ++current,
    invalidate: () => { ++current },
    isCurrent: (request: number) => request === current,
  }
}

/** Independent row work can finish in any order, but never after cancel/navigation. */
export function createKeyedRequests() {
  const pending = new Map<string, object>()
  return {
    begin(key: string) { const request = {}; pending.set(key, request); return request },
    isCurrent: (key: string, request: object) => pending.get(key) === request,
    cancel: (key: string) => { pending.delete(key) },
    invalidate: () => { pending.clear() },
  }
}

export function evidenceCountLabel(value: unknown): string {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value.toLocaleString() : '未知'
}

export function executionStatusLabel(value: unknown): string {
  if (value === true) return '采集执行结束（覆盖另核对）'
  if (value === false) return '采集不完整，不能当完整行为记录'
  return '采集执行状态未知'
}
