import { invoke, isTauri } from '@tauri-apps/api/core'
export type AppTheme = 'light' | 'dark'
export function storedTheme(): AppTheme | null {
  try { const value = localStorage.getItem('mobilee.theme'); return value === 'light' || value === 'dark' ? value : null } catch { return null }
}
export function resolvedTheme(): AppTheme {
  return storedTheme() ?? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
}
export function applyDocumentTheme(theme: AppTheme) {
  document.documentElement.dataset.theme = theme
  document.documentElement.style.colorScheme = theme
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#090b0f' : '#f5f7fa')
}
export async function applyNativeTheme(theme: AppTheme) {
  if (isTauri()) await invoke('apply_main_window_theme', { theme })
}
