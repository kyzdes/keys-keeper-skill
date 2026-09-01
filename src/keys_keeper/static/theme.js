// Apply the saved or system theme before CSS paints the page.
(() => {
  let theme = 'dark';
  try {
    const saved = localStorage.getItem('keys-keeper-theme');
    theme = saved === 'light' || saved === 'dark'
      ? saved
      : (window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  } catch {}
  document.documentElement.dataset.theme = theme;
})();
