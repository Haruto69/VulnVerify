/**
 * Theme (light/dark) resolution and persistence.
 *
 * Entirely frontend-only presentation state -- no backend involved.
 * Preference order on first load: explicit saved choice in
 * localStorage, then the OS-level `prefers-color-scheme`, then
 * "light" as the final fallback.
 */

const STORAGE_KEY = "vulnverify.theme";

export function getStoredTheme() {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

export function getSystemTheme() {
  if (typeof window === "undefined" || !window.matchMedia) return "light";

  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

export function getInitialTheme() {
  return getStoredTheme() || getSystemTheme();
}

export function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
}

export function storeTheme(theme) {
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // localStorage unavailable (private browsing, etc.) -- the
    // theme still applies for this session, it just won't persist.
  }
}
