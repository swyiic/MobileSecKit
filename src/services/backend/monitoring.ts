import { captureGroupIPC } from '../kernsightCapturePlan'
import { captureIPCCommand } from '../kernsightCapturePlan'
import { invoke } from '@tauri-apps/api/core'
import type {
  AndroidMonitorCapabilityProbe,
  KernSightOverview,
  KernSightCaptureGroup,
  KernSightCaptureGroupTrash,
  KernSightGroupPurgePlan,
  KernSightGroupPurgeReport,
  KernSightGroupStageResult,
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
  localKernSightEvidencePresent: (path: string) => invoke<boolean>('local_kernsight_evidence_present', { path }),
  prepareKernSightGroupPurge: (parentId: string, importedRoots: string[], localOnly: boolean, requestId?: string) => invoke<KernSightGroupPurgePlan>('prepare_kernsight_group_purge', { parentId, importedRoots, localOnly, requestId }),
  executeKernSightGroupPurge: (planId: string, confirmationToken: string) => invoke<KernSightGroupPurgeReport>('execute_kernsight_group_purge', { planId, confirmationToken }),
  cancelKernSightGroupPurgePreparation: (requestId: string) => invoke<void>('cancel_kernsight_group_purge_preparation', { requestId }),
  cancelKernSightGroupPurge: (planId: string) => invoke<KernSightGroupPurgeReport>('cancel_kernsight_group_purge', { planId }),
  kernSightGroupPurgePlan: (planId: string) => invoke<KernSightGroupPurgePlan>('get_kernsight_group_purge_plan', { planId }),
  resumeKernSightGroupPurge: (planId: string) => invoke<KernSightGroupPurgeReport>('resume_kernsight_group_purge', { planId }),
  listKernSightGroupPurges: () => invoke<KernSightGroupPurgeReport[]>('list_kernsight_group_purges'),
  prepareKernSightGroupPurgeRetry: (planId: string, localOnly = false, requestId?: string) => invoke<KernSightGroupPurgePlan>('prepare_kernsight_group_purge_retry', { planId, localOnly, requestId }),
  kernSightGroupSessionReport:(parentId:string,serial:string,packageName:string,sessionId:string)=>invoke<KernSightSessionReportDocument>('get_kernsight_group_session_report',{parentId,serial,package:packageName,sessionId}),
  localKernSightChildReport:(root:string,parentId:string,sessionId:string)=>invoke<KernSightSessionReportDocument>('get_local_kernsight_child_report',{root,parentId,sessionId}),
  beginKernSightGroup:(request:KernSightCaptureRequest,durations:number[],startupReplay:boolean)=>invoke<KernSightCaptureGroup>(captureGroupIPC(request),{request,durations,startupReplay}),
  trashKernSightGroup: (parentId: string, importedRoots: string[]) => invoke<KernSightCaptureGroupTrash>('trash_kernsight_group', { parentId, importedRoots }),
  listKernSightGroupTrash: () => invoke<KernSightCaptureGroupTrash[]>('list_kernsight_group_trash'),
  restoreKernSightGroup: (parentId: string) => invoke<KernSightCaptureGroupTrash>('restore_kernsight_group', { parentId }),
  listKernSightGroups:(serial?:string)=>invoke<KernSightCaptureGroup[]>('list_kernsight_groups',{serial:serial||null}),
  runKernSightUnifiedGroup:(parentId:string)=>invoke<KernSightGroupStageResult>('run_kernsight_unified_group',{parentId}),
  runKernSightGroupStage:(parentId:string,stageKey:string)=>invoke<KernSightGroupStageResult>('run_kernsight_group_stage',{parentId,stageKey}),
  cancelKernSightGroup:(parentId:string)=>invoke<KernSightCaptureGroup>('cancel_kernsight_group',{parentId}),
  probeCapabilities: (serial: string) =>
    invoke<AndroidMonitorCapabilityProbe>('probe_android_monitor_capabilities', { serial }),
  provisionLatestAgent: (serial: string) =>
    invoke<KernSightProvisionResult>('provision_latest_kernsight_agent', { serial }),
  kernSightOverview: (serial: string) =>
    invoke<KernSightOverview>('get_kernsight_overview', { serial }),
  kernSightReport: (serial: string, sessionId: string) =>
    invoke<KernSightSessionReportDocument>('get_kernsight_session_report', { serial, sessionId }),
  kernSightEvents: (serial: string, sessionId: string, offset = 0, limit = 50, sensor?: string, query?: string) =>
    invoke<KernSightEventPage>('get_kernsight_session_events', { serial, sessionId, offset, limit, sensor, query }),
  startKernSightCapture: (request: KernSightCaptureRequest) =>
    invoke<KernSightCaptureResult>(captureIPCCommand(request), { request }),
  startKernSightMirror: (request: KernSightCaptureRequest) =>
    invoke<KernSightCaptureResult>('start_kernsight_mirror', { request }),
  stopKernSightMirror: (serial?: string, reversePort?: number) => invoke<KernSightMirrorStatus>('stop_kernsight_mirror', { serial, reversePort }),
  kernSightMirrorStatus: (serial?: string) => invoke<KernSightMirrorStatus>('kernsight_mirror_status', { serial }),
  dumpKernSightPackage: (serial: string, packageName: string, hideDebug = false, preferLive = false, requireLive = false) =>
    invoke<KernSightCaptureResult>('dump_kernsight_package', { serial, package: packageName, hideDebug, preferLive, requireLive }),
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
  pullKernSightPackageArchive: (serial: string, packageName: string, outputPath: string, parentId?:string) =>
    invoke<KernSightLocalEvidenceBundle>('pull_kernsight_package_archive', { serial, package: packageName, outputPath, parentId:parentId||null }),
  localKernSightEvidenceFile: (root: string, packageName: string, relativePath: string, maxBytes = 1_048_576) =>
    invoke<KernSightEvidenceFileContent>('read_local_kernsight_evidence_file', { root, package: packageName, relativePath, maxBytes }),
}
