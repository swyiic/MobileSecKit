import { computed, markRaw, ref, shallowRef, type MaybeRef, unref } from 'vue'
import { open } from '@tauri-apps/plugin-dialog'
import { monitoringBackend } from '@/services/backend'
import { buildKernSightAnalyzerJoin } from '@/services/kernsightJoin'
import type { KernSightAnalyzerJoin, KernSightLocalEvidenceBundle } from '@/types/monitoring'

const bundles = shallowRef<KernSightLocalEvidenceBundle[]>([])
const requestedPackage = ref('')
const PARENT_KEY = 'mobilee.kernsightReportsParent'

function reportsParent() {
  return typeof localStorage === 'undefined' ? '' : localStorage.getItem(PARENT_KEY) || ''
}

function rememberParent(root: string) {
  const trimmed = root.replace(/[\\/]+$/, '')
  const parent = trimmed.replace(/[\\/][^\\/]+$/, '')
  if (parent && typeof localStorage !== 'undefined') localStorage.setItem(PARENT_KEY, parent)
}

export function upsertKernSightBundle(bundle: KernSightLocalEvidenceBundle) {
  bundles.value = [
    ...bundles.value.filter(item => item.root !== bundle.root && item.package !== bundle.package),
    markRaw(bundle),
  ]
  rememberParent(bundle.root)
}

export function bundleForPackage(packageName: string) {
  return bundles.value.find(bundle => bundle.package === packageName) || null
}

export async function importKernSightDirectory(path?: string) {
  const chosen = path || await open({ directory: true, multiple: false, title: '选择包含 dump-report.json 的包目录' })
  if (!chosen || Array.isArray(chosen)) return null
  const bundle = await monitoringBackend.importKernSightEvidenceDirectory(chosen)
  upsertKernSightBundle(bundle)
  requestedPackage.value = bundle.package
  return bundle
}

export async function importKernSightArchive(path?: string) {
  const chosen = path || await open({
    multiple: false,
    title: '打开 MobileE 案例',
    filters: [{ name: 'ME evidence', extensions: ['mee', 'meevidence', 'mobileevidence'] }],
  })
  if (!chosen || Array.isArray(chosen)) return null
  const bundle = await monitoringBackend.importKernSightEvidenceArchive(chosen)
  upsertKernSightBundle(bundle)
  requestedPackage.value = bundle.package
  return bundle
}

export async function importKernSightForPackage(packageName: string) {
  const existing = bundleForPackage(packageName)
  if (existing) return existing
  const parent = reportsParent()
  if (!parent || !packageName) return null
  const separator = parent.includes('\\') ? '\\' : '/'
  try {
    return await importKernSightDirectory(`${parent}${separator}${packageName}`)
  } catch {
    return null
  }
}

export function requestKernSightPackage(packageName: string) {
  requestedPackage.value = packageName
}

export function useKernSightEvidence(packageName?: MaybeRef<string>) {
  const currentPackage = computed(() => unref(packageName) || '')
  const bundle = computed(() => currentPackage.value ? bundleForPackage(currentPackage.value) : null)
  const join = computed<KernSightAnalyzerJoin | null>(() => bundle.value ? buildKernSightAnalyzerJoin(bundle.value) : null)
  return {
    bundles,
    requestedPackage,
    bundle,
    join,
    upsertBundle: upsertKernSightBundle,
    importDirectory: importKernSightDirectory,
    importArchive: importKernSightArchive,
    importForPackage: importKernSightForPackage,
    requestPackage: requestKernSightPackage,
  }
}
