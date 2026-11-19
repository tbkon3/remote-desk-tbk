"use strict";

(async () => {
  const fragment = location.hash.slice(1);
  history.replaceState(null, "", "/local/start");
  try {
    const ticket = JSON.parse(decodeURIComponent(fragment));
    const response = await fetch("/api/local/claim", {
      method: "POST",
      credentials: "omit",
      redirect: "error",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(ticket),
    });
    if (!response.ok) throw new Error();
    const {path, token} = await response.json();
    if ((path !== "/" && path !== "/chat") || typeof token !== "string" || !token) throw new Error();
    localStorage.setItem("rd.local", token);
    location.replace(path);
  } catch {
    document.getElementById("status").textContent =
      "Collegamento scaduto o non valido. Riapri RemoteDesk dall’icona nell’area di notifica.";
  }
})();
