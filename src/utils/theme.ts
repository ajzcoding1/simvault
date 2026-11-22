export type ThemeMode = 'system' | 'light' | 'dark';

export const THEME_STORAGE_KEY = 'simvault_theme';

export function normalizeThemeMode(raw: string | null | undefined): ThemeMode {
  if (raw === 'light' || raw === 'dark' || raw === 'system') {
    return raw;
  }
  return 'system';
}

export function resolveIsDark(mode: ThemeMode, systemPrefersDark: boolean): boolean {
  if (mode === 'dark') return true;
  if (mode === 'light') return false;
  return systemPrefersDark;
}

export function getNextThemeMode(current: ThemeMode): ThemeMode {
  if (current === 'system') return 'dark';
  if (current === 'dark') return 'light';
  return 'system';
}

export function getThemeLabel(mode: ThemeMode): string {
  if (mode === 'dark') return 'Dark';
  if (mode === 'light') return 'Light';
  return 'Auto';
}
