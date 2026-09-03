// Resolve the saved or system theme before the first stylesheet can paint.
(() => {
  let theme = 'dark';
  try {
    const saved = localStorage.getItem('keys-keeper-theme');
    theme = saved === 'light' || saved === 'dark'
      ? saved
      : (window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  } catch {}
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute(
    'content', theme === 'light' ? '#f4f3f1' : '#0a0b0c');
})();
