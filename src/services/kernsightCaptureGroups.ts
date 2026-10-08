import type { KernSightCaptureGroup, KernSightCaptureGroupTrash, KernSightLocalEvidenceBundle, KernSightCaptureRequest } from '../types/monitoring'
export function mergeCaptureGroups(device:KernSightCaptureGroup[], imported:KernSightCaptureGroup[]):KernSightCaptureGroup[] {
  const groups=new Map(device.map(group=>[group.id,group]))
  for(const group of imported)if(!groups.has(group.id))groups.set(group.id,group)
  return [...groups.values()].sort((a,b)=>b.createdUnixMs-a.createdUnixMs)
}
export function groupSessionIds(groups:KernSightCaptureGroup[]):Set<string> {
  return new Set(groups.flatMap(group=>group.stages.flatMap(stage=>stage.attempts.flatMap(attempt=>attempt.sessionId?[attempt.sessionId]:[]))))
}
export function sameImportedCapture(a:KernSightLocalEvidenceBundle,b:KernSightLocalEvidenceBundle):boolean {
  if(a.root===b.root)return true
  const pa=(a.sessionReport?.mobilee_capture_group as {id?:unknown}|undefined)?.id
  const pb=(b.sessionReport?.mobilee_capture_group as {id?:unknown}|undefined)?.id
  return typeof pa==='string' && pa===pb && typeof a.dumpReport.dump_id==='string' && a.dumpReport.dump_id===b.dumpReport.dump_id
}

export function captureGroupEdges(group:KernSightCaptureGroup):Array<{from:string;relation:string;to:string}> {
  return group.stages.flatMap(stage=>[
    {from:group.id,relation:'contains_stage',to:stage.id},
    ...stage.attempts.flatMap(attempt=>[
      {from:stage.id,relation:'has_attempt',to:attempt.relation.attemptId},
      ...(attempt.sessionId?[{from:attempt.relation.attemptId,relation:'captured_session',to:attempt.sessionId}]:[]),
      ...(attempt.remoteArtifactRoot?[{from:attempt.relation.attemptId,relation:'artifact_source',to:attempt.remoteArtifactRoot}]:[]),
    ]),
  ])
}

/** A trash marker applies to one parent and only the explicitly included import roots. */
export function captureGroupImportIsTrashed(group: KernSightCaptureGroup, root: string, trash: KernSightCaptureGroupTrash[]): boolean {
  return trash.some(entry => entry.trashed !== false && entry.group.id === group.id && entry.group.serial === group.serial
    && entry.group.package === group.package && entry.importedRoots.includes(root))
}

export function captureGroupCanTrash(group: KernSightCaptureGroup, runningParent = '', busy = false): boolean {
  return !busy && group.id !== runningParent && group.state !== 'running'
    && !group.stages.some(stage => stage.attempts.some(attempt => attempt.state === 'running'))
}


/** Only configuration is copied. The backend allocates fresh parent/stages/attempts/deadline. */
export function newCaptureFromGroup(group: KernSightCaptureGroup) {
  const base = structuredClone(group.base) as unknown as KernSightCaptureRequest
  delete base.captureRelation
  delete base.captureRelations
  delete base.outputBudgetBytes
  delete base.outputBudgetMs
  base.serial = group.serial
  base.package = group.package
  const durations = ['l0', 'l1', 'linker'].map(key => group.stages.find(stage => stage.key === key)?.durationSeconds)
  if (durations.some(value => !Number.isFinite(value) || Number(value) <= 0)) throw new Error('旧主会话缺少有效阶段窗口；请在新建采集中重新配置。')
  return { base, durations: durations as number[], separate: group.unified !== true }
}
