import type { AndroidMonitorCapabilityProbe, MonitorCapabilityStatus } from '../types/monitoring'

export function capabilityStatusLabel(status: MonitorCapabilityStatus): string {
  if (status === 'available') return '已确认'
  if (status === 'restricted') return '权限受限'
  if (status === 'warning' || status === 'limited') return '待验证 / 受限'
  if (status === 'missing') return '确认缺失'
  if (status === 'unavailable') return '不可用'
  return '未知'
}

// Local SVG geometry: status cards must remain legible with web fonts blocked.
export function capabilityIconPath(status: MonitorCapabilityStatus): string {
  const circle = 'M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0Z '
  if (status === 'available') return circle + 'm-16 0 4 4 8-8'
  if (status === 'missing' || status === 'unavailable') return circle + 'm-14-4 8 8m0-8-8 8'
  if (status === 'restricted') return 'M6 10h12v11H6Zm2 0V6a4 4 0 0 1 8 0v4m-4 5v2'
  if (status === 'warning' || status === 'limited') return 'M12 2 1 22h22ZM12 9v5m0 3v1'
  return circle + 'M9 8a3 3 0 0 1 6 0c0 2-3 2-3 5m0 3v1'
}

interface DeploymentRequirement {
  key: string
  label: string
  required: boolean
  status: MonitorCapabilityStatus
  detail: string
}

export function deploymentAssessment(probe: AndroidMonitorCapabilityProbe | null) {
  const checks = new Map((probe?.checks || []).map(item => [item.key, item]))
  const architecture = probe?.architecture?.trim() || 'Unknown'
  const architectureStatus: MonitorCapabilityStatus = /^(aarch64|arm64(?:-v8a)?)$/i.test(architecture) ? 'available'
    : /^(?:x86_64|x86|i[3-6]86|armv[5-8]l|armeabi(?:-v7a)?|riscv64)$/i.test(architecture) ? 'missing' : 'unknown'
  const check = (key: string, label: string, required: boolean): DeploymentRequirement => ({
    key, label, required, status: checks.get(key)?.status || 'unknown',
    detail: checks.get(key)?.detail || '尚未获得可核验的探测结果',
  })
  const requirements: DeploymentRequirement[] = [
    { key: 'architecture', label: 'ARM64 架构', required: true, status: architectureStatus, detail: architecture },
    check('root', 'Root 授权', true),
    check('btf', '内核 BTF · 按对象需要', false),
    check('bpffs', 'bpffs · 固定对象需要', false),
  ]
  const blockers = requirements.filter(item => item.required && ['missing', 'restricted', 'unavailable'].includes(item.status))
  const unresolved = requirements.filter(item => item.required && item.status !== 'available' && !blockers.includes(item))
  const state = blockers.length ? 'blocked' : unresolved.length ? 'unknown' : 'candidate'
  const title = state === 'candidate' ? '可尝试开发 Agent 部署，采集能力仍待验证'
    : state === 'blocked' ? '当前开发部署路径存在限制' : '部署条件尚未确认'
  const label = state === 'candidate' ? '部署候选' : state === 'blocked' ? '受限' : '待确认'
  const summary = state === 'candidate'
    ? '已确认 ARM64 与 Root 授权；这不代表 BPF 可加载或全部采集能力可用。需实际加载、挂载与协议握手验证。'
    : state === 'blocked'
      ? `当前限制：${blockers.map(item => item.label).join('、')}。其他未知项不能据此判为缺失。`
      : `待确认：${unresolved.map(item => item.label).join('、')}。读取失败或权限不足不等于能力缺失。`
  return { requirements, blockers, unresolved, state, title, label, summary }
}
