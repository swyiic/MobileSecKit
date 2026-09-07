import { aiBackend } from './ai'
import { adbBackend } from './adb'
import { analysisBackend } from './analysis'
import { deviceBackend } from './device'
import { environmentBackend } from './environment'
import { fridaBackend } from './frida'
import { monitoringBackend } from './monitoring'

export { adbBackend, aiBackend, analysisBackend, deviceBackend, environmentBackend, fridaBackend, monitoringBackend }
export { readableError } from './shared'

// Compatibility facade for existing views. New modules should depend on a domain backend directly.
export const backend = {
  configureHostEnvironment: environmentBackend.configure,
  listDevices: deviceBackend.list,
  getDeviceDetails: deviceBackend.details,
  getIosDeviceDetails: deviceBackend.iosDetails,
  listProcesses: deviceBackend.processes,
  runAction: adbBackend.runAction,
  inspectEnvironment: environmentBackend.inspect,
  runShell: adbBackend.runShell,
  runProxy: adbBackend.runProxy,
  certificateInfo: adbBackend.certificateInfo,
  installCertificate: adbBackend.installCertificate,
  listFridaProcesses: fridaBackend.listProcesses,
  listFridaScripts: fridaBackend.listScripts,
  runFridaScript: fridaBackend.runScript,
  runDexDump: fridaBackend.dumpDex,
  runSoDump: fridaBackend.dumpSo,
  runIosDump: fridaBackend.dumpIos,
  manageFridaServer: fridaBackend.manageServer,
  downloadFridaServer: fridaBackend.downloadServer,
  installFridaTools: environmentBackend.installFridaTools,
  openEnvironmentTerminal: environmentBackend.openTerminal,
  mountIosDeveloperImage: environmentBackend.mountIosDeveloperImage,
  analyzeApp: analysisBackend.analyze,
  listAiTaskTemplates: aiBackend.listTaskTemplates,
  buildAiContextPack: aiBackend.buildContextPack,
  exportAiContextPack: aiBackend.exportContextPack,
  validateAiAnalysisResult: aiBackend.validateResult,
  testAiProvider: aiBackend.testProvider,
  runAiSecurityReview: aiBackend.runSecurityReview,
  exportAnalysisHtml: analysisBackend.exportHtml,
  exportSensitiveValue: analysisBackend.exportSensitiveValue,
  saveAnalysisCase: analysisBackend.saveCase,
  loadAnalysisCase: analysisBackend.loadCase,
  compareAnalysisCase: analysisBackend.compareCase,
  pullFiles: adbBackend.pullFiles,
  pushFile: adbBackend.pushFile,
  probeAndroidMonitorCapabilities: monitoringBackend.probeCapabilities,
}
