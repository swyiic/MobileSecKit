import type { KernSightCaptureGroup, KernSightLocalEvidenceBundle } from '../types/monitoring'
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
