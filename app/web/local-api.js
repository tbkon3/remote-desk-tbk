"use strict";

(() => {
  const originalFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    if (url.origin !== location.origin || !url.pathname.startsWith("/api/")) {
      return originalFetch(input, init);
    }
    const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
    const local = localStorage.getItem("rd.local");
    const login = localStorage.getItem("rd.login");
    if (local) headers.set("X-RD-Local", local);
    if (login) headers.set("X-RD-Login", login);
    const response = await originalFetch(input, {...init, headers, redirect: "error", credentials: "omit"});
    if (response.ok && response.headers.has("X-RD-Login")) {
      const next = response.headers.get("X-RD-Login");
      if (next) localStorage.setItem("rd.login", next);
      else localStorage.removeItem("rd.login");
    }
    return response;
  };
})();
