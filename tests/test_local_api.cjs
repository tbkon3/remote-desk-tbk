"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

const scripts = path.join(__dirname, "../app/web");
const origin = "http://127.0.0.1:47800";

function storage(initial = {}) {
  const record = new Map(Object.entries(initial));
  return {
    getItem: key => record.get(key) ?? null,
    setItem: (key, value) => record.set(key, value),
    removeItem: key => record.delete(key),
  };
}

test("browser sends credentials only to same-origin API and consumes login/logout headers", async () => {
  const localStorage = storage({"rd.local": "local", "rd.login": "login"});
  const requests = [];
  let nextLogin = "";
  const window = {fetch: async (input, init) => {
    requests.push({input, init});
    return {ok: true, headers: new Headers({"X-RD-Login": nextLogin})};
  }};
  vm.runInNewContext(fs.readFileSync(path.join(scripts, "local-api.js"), "utf8"), {
    window, localStorage, URL, Request, Headers, location: {origin, href: origin + "/"},
  });
  for (const route of ["/web/icon.png", "http://127.0.0.1:47801/api/login", "https://example.test/api/"]) {
    await window.fetch(route);
    assert.equal(requests.at(-1).init.headers, undefined);
    assert.equal(localStorage.getItem("rd.login"), "login");
  }
  nextLogin = "new";
  await window.fetch("/api/login", {method: "POST", headers: {"Content-Type": "application/json"}});
  const {init} = requests.at(-1);
  assert.equal(init.headers.get("X-RD-Local"), "local");
  assert.equal(init.headers.get("X-RD-Login"), "login");
  assert.equal(init.headers.get("Content-Type"), "application/json");
  assert.equal(init.redirect, "error");
  assert.equal(init.credentials, "omit");
  assert.equal(localStorage.getItem("rd.login"), "new");
  nextLogin = "";
  await window.fetch("/api/logout");
  assert.equal(localStorage.getItem("rd.login"), null);
});

test("bootstrap erases fragment before claim and only opens allowed paths", async () => {
  for (const pathValue of ["/chat", "//untrusted.test"]) {
    const localStorage = storage();
    const events = [];
    const status = {};
    const location = {hash: "#" + encodeURIComponent('{"sig":"test"}'), replace: target => events.push(target)};
    const history = {replaceState: (_a, _b, dest) => events.push(dest)};
    const fetch = async (url, init) => {
      assert.equal(url, "/api/local/claim");
      assert.equal(init.redirect, "error");
      assert.equal(events[0], "/local/start");
      return {ok: true, json: async () => ({token: "browser", path: pathValue})};
    };
    await vm.runInNewContext(fs.readFileSync(path.join(scripts, "bootstrap.js"), "utf8"), {
      location, history, fetch, localStorage, document: {getElementById: () => status},
    });
    if (pathValue === "/chat") {
      assert.deepEqual(events, ["/local/start", "/chat"]);
      assert.equal(localStorage.getItem("rd.local"), "browser");
    } else {
      assert.deepEqual(events, ["/local/start"]);
      assert.equal(localStorage.getItem("rd.local"), null);
      assert.ok(status.textContent);
    }
  }
});
