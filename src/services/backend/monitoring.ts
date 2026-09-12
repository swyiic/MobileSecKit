import { invoke } from '@tauri-apps/api/core'
import type {
  AndroidMonitorCapabilityProbe,
  KernSightOverview,
  KernSightProvisionResult,
  KernSightCaptureRequest,
  KernSightCaptureResult,
  KernSightMirrorStatus,
  KernSightEventPage,
  KernSightEvidenceFileContent,
  KernSightLocalEvidenceBundle,
  KernSightPackageDumpReport,
  KernSightSessionReportDocument,
} from '@/types/monitoring'

export const monitoringBackend = {
  probeCapabilities: (serial: string) =>
    invoke<AndroidMonitorCapabilityProbe>('probe_android_monitor_capabilities', { serial }),
  provisionLatestAgent: (serial: string) =>
    invoke<KernSightProvisionResult>('provision_latest_kernsight_agent', { serial }),
  kernSightOverview: (serial: string) =>
    invoke<KernSightOverview>('get_kernsight_overview', { serial }),
  kernSightReport: (serial: string, sessionId: string) =>
    invoke<KernSightSessionReportDocument>('get_kernsight_session_report', { serial, sessionId }),
  cleanupKernSightSession: (serial: string, sessionId: string) =>
    invoke<void>('cleanup_kernsight_session', { serial, sessionId }),
  kernSightEvents: (serial: string, sessionId: string, offset = 0, limit = 50, sensor?: string, query?: string) =>
    invoke<KernSightEventPage>('get_kernsight_session_events', { serial, sessionId, offset, limit, sensor, query }),
  startKernSightCapture: (request: KernSightCaptureRequest) =>
    invoke<KernSightCaptureResult>('start_kernsight_capture', { request }),
  startKernSightMirror: (request: KernSightCaptureRequest) =>
    invoke<KernSightCaptureResult>('start_kernsight_mirror', { request }),
  stopKernSightMirror: (serial?: string, reversePort?: number) => invoke<KernSightMirrorStatus>('stop_kernsight_mirror', { serial, reversePort }),
  kernSightMirrorStatus: (serial?: string) => invoke<KernSightMirrorStatus>('kernsight_mirror_status', { serial }),
  dumpKernSightPackage: (serial: string, packageName: string, hideDebug = false, preferLive = false) =>
    invoke<KernSightCaptureResult>('dump_kernsight_package', { serial, package: packageName, hideDebug, preferLive }),
  kernSightPackageDumps: (serial: string) =>
    invoke<KernSightPackageDumpReport[]>('list_kernsight_package_dumps', { serial }),
  kernSightPackageFile: (serial: string, packageName: string, relativePath: string, maxBytes = 1_048_576) =>
    invoke<KernSightEvidenceFileContent>('read_kernsight_package_file', { serial, package: packageName, relativePath, maxBytes }),
  importKernSightEvidenceDirectory: (path: string) =>
    invoke<KernSightLocalEvidenceBundle>('import_kernsight_evidence_directory', { path }),
  importKernSightEvidenceArchive: (path: string) =>
    invoke<KernSightLocalEvidenceBundle>('import_kernsight_evidence_archive', { path }),
  exportKernSightEvidenceArchive: (root: string, outputPath: string) =>
    invoke<string>('export_kernsight_evidence_archive', { root, outputPath }),
  pullKernSightPackageEvidence: (serial: string, packageName: string, destination: string) =>
    invoke<KernSightLocalEvidenceBundle>('pull_kernsight_package_evidence', { serial, package: packageName, destination }),
  pullKernSightPackageArchive: (serial: string, packageName: string, outputPath: string) =>
    invoke<KernSightLocalEvidenceBundle>('pull_kernsight_package_archive', { serial, package: packageName, outputPath }),
  localKernSightEvidenceFile: (root: string, packageName: string, relativePath: string, maxBytes = 1_048_576) =>
    invoke<KernSightEvidenceFileContent>('read_local_kernsight_evidence_file', { root, package: packageName, relativePath, maxBytes }),
  cleanupKernSightPackageDump: (serial: string, packageName: string) =>
    invoke<void>('cleanup_kernsight_package_dump', { serial, package: packageName }),
}
