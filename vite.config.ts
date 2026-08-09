// vite.config.js
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

const host = process.env.TAURI_DEV_HOST

export default defineConfig(async () => {
  // 在 async function 裡動態載入
  const tailwindcss = (await import('@tailwindcss/vite')).default

  return {
    plugins: [
      vue(),
      tailwindcss(),           // ← 這裡呼叫它
    ],

    resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    }
  },

    clearScreen: false,

    server: {
      port: 1420,
      strictPort: true,
      host: host || false,
      hmr: host
        ? {
            protocol: 'ws',
            host,
            port: 1421,
          }
        : undefined,
      watch: {
        ignored: ['**/src-tauri/**'],
      },
    },
  }
})