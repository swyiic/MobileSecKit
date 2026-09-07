import { computed, ref, watch, type ComputedRef, type Ref } from 'vue'
import { environmentBackend, fridaBackend, readableError } from '@/services/backend'
import { appConfig } from '@/services/config'
import { runtimeOutputCompletesStep, runtimeStepForScript } from '@/services/runtimeCoverage'
import type { AdvancedCommandResult, RuntimeEvidenceStepKey, TerminalEntry } from '@/types/common'
import type { DeviceSummary } from '@/types/device'
import type { EnvironmentReport } from '@/types/environment'
import type { AppAnalysis } from '@/types/analysis'
import type {
  DexDumpRequest,
  FridaProcess,
  FridaScriptEntry,
  FridaServerRequest,
  IosDumpRequest,
  RunFridaRequest,
  RuntimeWorkflowRequest,
  SoDumpRequest,
} from '@/types/frida'

interface FridaToolboxContext {
  selectedSerial: Ref<string>
  selectedDevice: ComputedRef<DeviceSummary | undefined>
  environment: Ref<EnvironmentReport | null>
  toolDirectory: Ref<string>
  terminalHistory: Ref<TerminalEntry[]>
  error: Ref<string>
  commandRunning: Ref<boolean>
  analysis: Ref<AppAnalysis | null>
}

function recordResult(
  history: Ref<TerminalEntry[]>,
  result: AdvancedCommandResult,
  scope?: Pick<TerminalEntry, 'appId' | 'deviceId' | 'platform' | 'source' | 'runtimeStep'>,
) {
  history.value.unshift({
    time: Date.now(),
    command: result.command,
    output: result.output,
    success: result.success,
    ...scope,
  })
}

function recordFailure(
  history: Ref<TerminalEntry[]>,
  command: string,
  cause: unknown,
  scope: Pick<TerminalEntry, 'appId' | 'deviceId' | 'platform' | 'source' | 'runtimeStep'>,
) {
  history.value.unshift({
    time: Date.now(),
    command,
    output: readableError(cause),
    success: false,
    ...scope,
  })
}

export function useFridaToolbox(context: FridaToolboxContext) {
  const fridaScriptDirectory = computed(() => appConfig.fridaScriptDirectory)
  const fridaProcesses = ref<FridaProcess[]>([])
  const fridaScripts = ref<FridaScriptEntry[]>([])

  watch(context.selectedSerial, () => {
    fridaProcesses.value = []
  })

  watch(fridaScriptDirectory, async () => {
    try {
      fridaScripts.value = await fridaBackend.listScripts(fridaScriptDirectory.value || undefined)
    } catch (cause) {
      context.error.value = readableError(cause)
    }
  }, { immediate: true })

  function inspectSelectedEnvironment() {
    return environmentBackend.inspect({
      serial: context.selectedSerial.value || undefined,
      platform: context.selectedDevice.value?.platform,
      toolDirectory: context.toolDirectory.value || undefined,
    })
  }

  async function refreshFridaProcesses(surfaceError = true) {
    try {
      fridaProcesses.value = await fridaBackend.listProcesses(
        context.selectedSerial.value || undefined,
      )
    } catch (cause) {
      // A transient device/Frida error must not erase the last usable app
      // inventory. In particular, an injected target may exit while the list
      // is refreshing; installed-but-stopped apps remain selectable for Spawn.
      if (surfaceError) context.error.value = readableError(cause)
    }
  }

  async function refreshFrida() {
    try {
      fridaScripts.value = await fridaBackend.listScripts(fridaScriptDirectory.value || undefined)
      await refreshFridaProcesses()
    } catch (cause) {
      context.error.value = readableError(cause)
    }
  }

  async function runFrida(request: RunFridaRequest, runtimeStep?: RuntimeEvidenceStepKey): Promise<boolean> {
    const scopedRuntimeStep = runtimeStep || runtimeStepForScript(request.scriptPath)
    context.commandRunning.value = true
    try {
      const result = await fridaBackend.runScript({
        serial: context.selectedSerial.value || undefined,
        ...request,
      })
      const stepCompleted = !scopedRuntimeStep || (result.success && runtimeOutputCompletesStep(scopedRuntimeStep, result.output))
      const recordedResult = scopedRuntimeStep && !stepCompleted
        ? { ...result, success: false, output: `${result.output}\n\n[MobileE] ${scopedRuntimeStep} 未产生完成标记，已标记为 BLOCKED；不会自动继续后续运行时步骤。`.trim() }
        : result
      recordResult(context.terminalHistory, recordedResult, {
        appId: request.process,
        deviceId: context.selectedSerial.value || undefined,
        platform: context.selectedDevice.value?.platform || 'unknown',
        source: 'frida',
        runtimeStep: scopedRuntimeStep,
      })
      const current = context.analysis.value
      const sameApp = current?.packageId?.trim().toLowerCase() === request.process.trim().toLowerCase()
      const confirmationScript = /(?:anti_instrumentation_probe|ios_injection_probe)\.js$/i.test(request.scriptPath || '')
      // Only the dedicated zero-Hook confirmation may mutate the Anti-
      // Instrumentation state. A later ObjC/network attach timeout is useful
      // session evidence, but must not overwrite an already-passed baseline.
      if (current && sameApp && confirmationScript) {
        try {
          const antiInstrumentation = await fridaBackend.confirmAntiInstrumentation({
            assessment: current.antiInstrumentation || { status: 'not-detected', candidates: [], indicators: [] },
            runtimeOutput: result.output,
            exitCode: result.exitCode,
            appId: current.packageId,
          })
          const runtimeEvidence = antiInstrumentation.candidates.flatMap((candidate) => candidate.evidence.slice(-1))
          const dataBoundaries = current.dataBoundaries.map((boundary) => boundary.boundary === 'anti-instrumentation'
            ? {
                ...boundary,
                sourceType: antiInstrumentation.status === 'pending' ? boundary.sourceType : 'runtime-observed',
                severity: antiInstrumentation.status === 'blocked' ? 'high' : boundary.severity,
                confidence: antiInstrumentation.status === 'pending' ? boundary.confidence : 'high',
                summary: `${boundary.summary.replace(/运行时确认状态为 [^。]+。?/, '')} 运行时确认状态：${antiInstrumentation.status}。`,
                evidence: [...new Set([...boundary.evidence, ...runtimeEvidence])],
              }
            : boundary)
          context.analysis.value = { ...current, antiInstrumentation, dataBoundaries }
          const latest = context.terminalHistory.value[0]
          if (latest?.appId?.trim().toLowerCase() === request.process.trim().toLowerCase()) {
            const correlation = antiInstrumentation.status === 'pending'
              ? runtimeOutputCompletesStep('injection', result.output)
                ? '[MobileE] iOS 零 Hook 注入基线已通过；这只证明 agent 与脚本能够进入进程，静态 Anti-Instrumentation 候选仍需专项运行证据确认。'
                : '[MobileE] 已保存运行日志，但未出现零 Hook 成功标记或明确终止事件；Anti-Instrumentation 仍待确认。'
              : `[MobileE] Anti-Instrumentation 已自动回填为 ${antiInstrumentation.status.toUpperCase()}；返回 App Analyzer 即可进入整体分析。`
            latest.output = `${latest.output}\n\n${correlation}`.trim()
          }
        } catch (cause) {
          context.error.value = `Frida 已执行，但 Anti-Instrumentation 状态回填失败：${readableError(cause)}`
        }
      }
      // Injection can terminate or restart the target between process refresh
      // and Attach. Refresh immediately so a dead PID is cleared and the same
      // installed app remains available as STOPPED for a Spawn retry.
      if (!result.success
        || (scopedRuntimeStep && !stepCompleted)
        || /Process terminated|unable to find process|early end-of-stream/i.test(result.output)) {
        await refreshFridaProcesses(false)
      }
      return stepCompleted
    } catch (cause) {
      recordFailure(context.terminalHistory, `frida ${request.mode} ${request.process}`, cause, {
        appId: request.process,
        deviceId: context.selectedSerial.value || undefined,
        platform: context.selectedDevice.value?.platform || 'unknown',
        source: 'frida',
        runtimeStep: scopedRuntimeStep,
      })
      context.error.value = readableError(cause)
      await refreshFridaProcesses(false)
      return false
    } finally {
      context.commandRunning.value = false
    }
  }

  async function runRuntimeWorkflow(request: RuntimeWorkflowRequest) {
    if (!context.selectedDevice.value || !request.process || !request.steps.length) return
    for (const [index, step] of request.steps.entries()) {
      const completed = await runFrida({
        process: request.process,
        pid: index === 0 ? request.pid : undefined,
        // A cold-start workflow spawns only once. Later steps attach to the
        // process created by the baseline instead of trying to spawn it again.
        mode: index === 0 ? request.mode : 'attach',
        script: '',
        scriptPath: step.scriptPath,
        durationSeconds: request.durationSeconds,
        compatibilityProfile: request.compatibilityProfile,
      }, step.key)
      if (!completed) {
        context.terminalHistory.value.unshift({
          time: Date.now(),
          command: `runtime workflow stopped at ${step.key}`,
          output: `运行时步骤 ${step.key} 被拦截或未完成，自动流程已停止；已保存此前证据，不影响 App Analyzer 的静态分析及其他独立分析。`,
          success: false,
          appId: request.process,
          deviceId: context.selectedSerial.value || undefined,
          platform: context.selectedDevice.value.platform,
          source: 'system',
          runtimeStep: step.key,
        })
        break
      }
    }
  }

  async function runAndroidDump(
    kind: 'DEX' | 'SO',
    request: DexDumpRequest | SoDumpRequest,
  ) {
    if (!context.selectedSerial.value || context.selectedDevice.value?.platform !== 'android') {
      context.error.value = `${kind} Dump 需要选择已 Root 的 Android 设备`
      return
    }
    context.commandRunning.value = true
    try {
      const payload = { serial: context.selectedSerial.value, ...request }
      const result =
        kind === 'DEX' ? await fridaBackend.dumpDex(payload) : await fridaBackend.dumpSo(payload)
      recordResult(context.terminalHistory, result, {
        appId: request.package,
        deviceId: context.selectedSerial.value,
        platform: 'android',
        source: 'frida',
        runtimeStep: kind === 'DEX' ? 'dex-artifact' : 'so-artifact',
      })
    } catch (cause) {
      recordFailure(context.terminalHistory, `frida collect ${kind} ${request.package}`, cause, {
        appId: request.package,
        deviceId: context.selectedSerial.value,
        platform: 'android',
        source: 'frida',
        runtimeStep: kind === 'DEX' ? 'dex-artifact' : 'so-artifact',
      })
      context.error.value = readableError(cause)
    } finally {
      context.commandRunning.value = false
    }
  }

  const runDexDump = (request: DexDumpRequest) => runAndroidDump('DEX', request)
  const runSoDump = (request: SoDumpRequest) => runAndroidDump('SO', request)

  async function runIosDump(request: IosDumpRequest) {
    if (!context.selectedSerial.value || context.selectedDevice.value?.platform !== 'ios') {
      context.error.value = '请先选择 Frida 可访问的越狱 iOS 设备'
      return
    }
    context.commandRunning.value = true
    try {
      const result = await fridaBackend.dumpIos({
        serial: context.selectedSerial.value,
        ...request,
      })
      recordResult(context.terminalHistory, result, {
        appId: request.bundleId,
        deviceId: context.selectedSerial.value,
        platform: 'ios',
        source: 'frida',
        runtimeStep: 'app-artifact',
      })
    } catch (cause) {
      recordFailure(context.terminalHistory, `frida iOS dump ${request.bundleId}`, cause, {
        appId: request.bundleId,
        deviceId: context.selectedSerial.value,
        platform: 'ios',
        source: 'frida',
        runtimeStep: 'app-artifact',
      })
      context.error.value = readableError(cause)
    } finally {
      context.commandRunning.value = false
    }
  }

  async function manageFridaServer(request: FridaServerRequest) {
    if (!context.selectedSerial.value || context.selectedDevice.value?.platform !== 'android') {
      context.error.value = '请先连接 Android 设备'
      return
    }
    try {
      const result = await fridaBackend.manageServer({
        serial: context.selectedSerial.value,
        ...request,
      })
      recordResult(context.terminalHistory, result)
      if (request.action === 'start' && result.success && appConfig.hardenFridaByDefault) {
        const hardened = await fridaBackend.manageServer({
          serial: context.selectedSerial.value,
          action: 'harden',
        })
        recordResult(context.terminalHistory, hardened)
      }
      context.environment.value = await inspectSelectedEnvironment()
    } catch (cause) {
      context.error.value = readableError(cause)
    }
  }

  async function downloadFridaServer(destinationDirectory?: string) {
    if (!context.selectedSerial.value || context.selectedDevice.value?.platform !== 'android') {
      context.error.value = '请先连接 Android 设备'
      return
    }
    try {
      const result = await fridaBackend.downloadServer({
        serial: context.selectedSerial.value,
        destinationDirectory,
      })
      recordResult(context.terminalHistory, result)
      if (result.success) {
        const deploy = await fridaBackend.manageServer({
          serial: context.selectedSerial.value,
          action: 'start',
          path: result.output.trim(),
        })
        recordResult(context.terminalHistory, deploy)
        if (deploy.success && appConfig.hardenFridaByDefault) {
          const hardened = await fridaBackend.manageServer({
            serial: context.selectedSerial.value,
            action: 'harden',
          })
          recordResult(context.terminalHistory, hardened)
        }
        context.environment.value = await inspectSelectedEnvironment()
      }
    } catch (cause) {
      context.error.value = readableError(cause)
    }
  }

  async function installFridaTools() {
    try {
      const result = await environmentBackend.installFridaTools()
      recordResult(context.terminalHistory, result)
      context.environment.value = await inspectSelectedEnvironment()
    } catch (cause) {
      context.error.value = readableError(cause)
    }
  }

  async function openEnvironmentTerminal() {
    try {
      const message = await environmentBackend.openTerminal()
      context.terminalHistory.value.unshift({
        time: Date.now(),
        command: 'open environment terminal',
        output: message,
        success: true,
      })
    } catch (cause) {
      context.error.value = readableError(cause)
    }
  }

  async function mountIosDeveloperImage(directory: string) {
    if (!context.selectedSerial.value || context.selectedDevice.value?.platform !== 'ios') return
    try {
      const result = await environmentBackend.mountIosDeveloperImage({
        serial: context.selectedSerial.value,
        directory,
      })
      recordResult(context.terminalHistory, result)
      context.environment.value = await inspectSelectedEnvironment()
    } catch (cause) {
      context.error.value = readableError(cause)
    }
  }

  return {
    fridaProcesses,
    fridaScripts,
    refreshFrida,
    runFrida,
    runRuntimeWorkflow,
    runDexDump,
    runSoDump,
    runIosDump,
    manageFridaServer,
    downloadFridaServer,
    installFridaTools,
    openEnvironmentTerminal,
    mountIosDeveloperImage,
  }
}
