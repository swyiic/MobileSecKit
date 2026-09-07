import { createApp } from 'vue'
import './assets/global.css'
import './assets/analyzer.css'
import App from './App.vue'
import './assets/light-theme.css'
import { loadAppConfig } from '@/services/config'

async function bootstrap() {
  await loadAppConfig()
  createApp(App).mount('#app')
}

void bootstrap()
