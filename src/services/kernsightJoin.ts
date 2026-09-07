import type {
  KernSightAnalyzerFact,
  KernSightAnalyzerJoin,
  KernSightEvidenceStrength,
  KernSightLocalEvidenceBundle,
} from '@/types/monitoring'

const DISCLAIMER = 'KernSight 的 confirmed / correlated / inferred 只描述证据怎么连上，不是 MASVS 漏洞结论。静态命中仍须人工判定。'

function record(value: unknown): Record<string, any> {
  return value && typeof value === 'object' ? value as Record<string, any> : {}
}

function list(value: unknown): any[] {
  return Array.isArray(value) ? value : []
}

function unique(values: Array<string | null | undefined>): string[] {
  return [...new Set(values.map(value => String(value || '').trim()).filter(Boolean))]
}

function fact(
  key: string,
  layer: KernSightAnalyzerFact['layer'],
  title: string,
  strength: KernSightEvidenceStrength,
  summary: string,
  items: string[],
): KernSightAnalyzerFact {
  return { key, layer, title, strength, summary, items: items.slice(0, 8) }
}

export function buildKernSightAnalyzerJoin(bundle: KernSightLocalEvidenceBundle): KernSightAnalyzerJoin {
  const session = record(bundle.sessionReport)
  const dump = bundle.dumpReport
  const handshake = list(session.handshake_names)
  const dns = list(session.dns_names)
  const peers = list(session.network_peers)
  const plaintext = list(session.plaintext)
  const inspect = list(session.inspect_hits)
  const binder = list(session.binder_relations)
  const sni = unique(handshake.map(row => row.sni || row.http_host).concat(peers.map(row => row.sni || row.http_host)))
  const qnames = unique(dns.map(row => row.qname).concat(peers.map(row => row.resolved_name)))
  const httpPlaintext = plaintext.filter(row => {
    const cls = String(row.content_class || '').toLowerCase()
    return cls && !['tls_record', 'unknown', ''].includes(cls)
  })
  const kernelTokens = unique(binder.flatMap(row => list(row.interfaces)))
  const parcel = inspect.filter(row => row.adapter === 'binder_userspace' && Number(row.hits || 0) > 0)
  const files = bundle.files || []
  const privateFiles = files.filter(file => file.relativePath.startsWith('data-private/'))
  const privateDbs = unique(privateFiles.map(file => file.relativePath).filter(path => /\.db(?:-wal|-shm|-journal)?$/i.test(path)))
  const heapWindows = files.filter(file => file.relativePath.startsWith('runtime/plaintext/'))
  const readableDex = files.filter(file => file.relativePath.startsWith('readable-dex/') || file.relativePath.includes('blob-dex/'))
  const facts: KernSightAnalyzerFact[] = [
    fact(
      'sni',
      'L0',
      'DNS / Handshake SNI',
      sni.length ? 'confirmed' : (qnames.length ? 'correlated' : (peers.length ? 'inferred' : 'absent')),
      sni.length
        ? `ClientHello / HTTP Host：${sni.slice(0, 3).join(', ')}`
        : (qnames.length
          ? `有 DNS ${qnames.slice(0, 3).join(', ')}，本会话没有 Handshake SNI`
          : (peers.length ? `${peers.length} 个 socket，无 DNS/SNI` : '没有网络聚合')),
      sni.length ? sni : qnames,
    ),
    fact(
      'tls',
      'L1',
      'TLS 明文',
      httpPlaintext.length ? 'confirmed' : (plaintext.length ? 'inferred' : 'absent'),
      httpPlaintext.length
        ? `${httpPlaintext.length} 组 HTTP 类 Inspect preview`
        : (plaintext.length ? `${plaintext.length} 组 preview，content_class 不是 HTTP 明文（常见 tls_record）` : '没有 L1 TLS 明文；ELF32 ENOTSUP 或未挂 --inspect-tls'),
      httpPlaintext.map(row => `${row.adapter || 'tls'} ${row.direction || ''} ${row.content_class || ''}`.trim()),
    ),
    fact(
      'jni',
      'L1',
      'JNI 明文',
      plaintext.filter(row => String(row.adapter || '').startsWith('jni_')).length ? 'confirmed' : 'absent',
      plaintext.filter(row => String(row.adapter || '').startsWith('jni_')).length
        ? `${plaintext.filter(row => String(row.adapter || '').startsWith('jni_')).length} 组 JNIEnv UTF-8/byte[]`
        : '没有 JNI Inspect 命中；需要 --inspect-jni',
      plaintext.filter(row => String(row.adapter || '').startsWith('jni_')).map(row => `${row.adapter || 'jni'} ${row.direction || ''}`.trim()),
    ),
    fact(
      'binder',
      'L0',
      'Binder token',
      kernelTokens.length ? 'confirmed' : (parcel.length ? 'correlated' : (binder.length ? 'inferred' : 'absent')),
      kernelTokens.length
        ? `内核 interface token ${kernelTokens.length} 个`
        : (parcel.length ? `L1 Parcel ${parcel.length} hits，内核 token 空；不回填 IComponent` : (binder.length ? `${binder.length} 条 Binder 关系，token 未解析` : '没有 Binder 关系')),
      kernelTokens.length ? kernelTokens : parcel.map(row => `${row.binder_interface || '未解析'}${row.binder_method ? `.${row.binder_method}` : ''}`),
    ),
    fact(
      'dex',
      'L2',
      'Dump DEX',
      (dump.dex_index?.unique_dex || dump.readable_dex || readableDex.length) ? 'inferred' : 'absent',
      `${dump.dex_index?.unique_dex ?? dump.readable_dex ?? readableDex.length} 个唯一/可读 DEX · heap/memory ${dump.runtime_blob_dex || 0}；DEX↔mmap 只标 correlated`,
      unique(readableDex.map(file => file.relativePath)).slice(0, 8),
    ),
    fact(
      'private',
      'L2',
      'data-private',
      privateFiles.length || dump.private_files ? 'inferred' : 'absent',
      `CE/DE 有界文件 ${privateFiles.length || dump.private_files || 0} 个；at-rest，不能单独证明发到某条 socket`,
      privateDbs.length ? privateDbs : unique(privateFiles.map(file => file.relativePath)).slice(0, 8),
    ),
    fact(
      'heap',
      'L2',
      '堆明文窗口',
      (dump.plaintext_windows || heapWindows.length) ? 'inferred' : 'absent',
      `${dump.plaintext_windows || heapWindows.length} 个匿名内存窗口；不是 TLS Inspect，也不是静态反编译`,
      unique(heapWindows.map(file => file.relativePath)),
    ),
  ]
  return {
    package: bundle.package,
    root: bundle.root,
    sessionId: String(session.session_id || ''),
    fileCount: bundle.fileCount,
    facts,
    disclaimer: DISCLAIMER,
  }
}
