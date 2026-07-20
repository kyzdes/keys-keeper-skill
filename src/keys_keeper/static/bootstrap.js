// The server has already exchanged ?t=... for a port-scoped HttpOnly cookie.
// Strip the one-time capability from browser history without copying it into
// any JavaScript-readable storage.
(() => {
  const params = new URLSearchParams(location.search);
  if (params.has('t')) history.replaceState({}, '', location.pathname);
})();
