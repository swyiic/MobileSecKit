import { createApp } from 'vue'
import './assets/global.css'
import './assets/analyzer.css'
import App from './App.vue'
import './assets/light-theme.css'
import { loadAppConfig } from '@/services/config'
import { applyDocumentTheme, applyNativeTheme, resolvedTheme } from '@/services/theme'

async function bootstrap() {
  applyDocumentTheme(resolvedTheme())
  let configurationTimer: ReturnType<typeof setTimeout> | undefined
  try { await Promise.race([loadAppConfig(), new Promise<never>((_, reject) => { configurationTimer = setTimeout(() => reject(new Error('App configuration timed out')), 1500) })]) } catch (error) { console.warn('App configuration could not be loaded', error) } finally { clearTimeout(configurationTimer) }
  createApp(App).mount('#app')
  await new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve())))
  await applyNativeTheme(resolvedTheme()).catch(error => console.warn('Window theme could not be applied', error))
}

void bootstrap().catch(async error => {
  console.error('App bootstrap failed', error)
  await applyNativeTheme(resolvedTheme()).catch(revealError => console.warn('Window reveal failed', revealError))
})
