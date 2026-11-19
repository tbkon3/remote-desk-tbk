const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = ['session_ice.js','manage.js'].map(name => fs.readFileSync(path.join(__dirname, '../app/web', name), 'utf8')).join('\n');
const settle = () => new Promise(resolve => setImmediate(resolve));

// Exercise the actual page script with an isolated browser/peer pair.
const renewal = {t:'renew', protocol:2, net:'n', to:'m', mode:'manage', sid:'a'.repeat(32), iat:1, usig:'fixture', msig:'fixture'};
function browser(proof=renewal) {
  class Element {
    constructor() { this.children = []; this.dataset = {}; this.textContent = ''; this.hidden = false }
    append(child) { this.children.push(child) }
    setAttribute(name, value) { this[name] = value }
    replaceChildren() { this.children = [] }
  }
  const elements = new Map(), channels = [], requests = [], posts = [], timers = new Map();
  const tabs = ['shares','drives','services','apps'].map(section => {
    const e = new Element();
    e.dataset.section = section; e.textContent = section;
    return e;
  });
  let valid = true, closed = false, next = 0;
  const id = key => {
    if (!elements.has(key)) elements.set(key, new Element());
    return elements.get(key);
  };
  const context = {
    URLSearchParams, TextEncoder, AbortController, location:{search:'?net=n&id=m'},
    document:{getElementById:id, createElement:() => new Element(),
      createDocumentFragment:() => new Element(), querySelectorAll:() => tabs},
    window:{addEventListener() {}},
    setTimeout:(fn, delay) => { timers.set(++next, {fn,delay}); return next },
    clearTimeout:key => timers.delete(key),
    fetch:async (url, args) => {
      posts.push([url, JSON.parse(args.body)]);
      const responses = {'/api/session/ice':{ice:[]}, '/api/connect':{lease:'session-token', sdp:'answer'},
        '/api/session/lease':{ok:valid, proof}};
      return {ok:true, json:async () => responses[url]};
    },
    RTCPeerConnection:class {
      constructor() { this.iceGatheringState = 'complete' }
      createDataChannel(label, options) {
        const channel = {label, ordered:options.ordered, readyState:'connecting', send:raw => requests.push(JSON.parse(raw))};
        channels.push(channel);
        return channel;
      }
      async createOffer() { return {sdp:'a=candidate:fixture'} }
      async setLocalDescription(sdp) { this.localDescription = sdp }
      async setRemoteDescription() { channels[0].readyState = 'open'; channels[0].onopen() }
      close() { closed = true }
    }
  };
  vm.runInNewContext(source, context);
  return {id, tabs, channels, requests, posts, closed:() => closed, revoke:() => { valid = false },
    tick:delay => [...timers.values()].find(t => t.delay === delay).fn(),
    frame:fields => channels[0].onmessage({data:JSON.stringify({...requests.at(-1), ...fields})})};
}

test('inventory is data-only, requires a lease and renders ordered chunks as text', async () => {
  const ui = browser();
  await settle();
  assert.deepEqual(ui.channels.map(c => [c.label, c.ordered]), [['inventory',true]]);
  assert.deepEqual(ui.posts.map(p => p[0]), ['/api/session/ice','/api/connect','/api/session/lease']);
  assert.deepEqual(ui.posts[1][1], {nid:'n', to:'m', mode:'manage', sdp:'a=candidate:fixture'});
  assert.deepEqual(ui.requests, [renewal, {t:'inventory', section:'shares', id:1}]);
  const rawName = '<b>Share</b>';
  ui.frame({more:true, result:{rows:[{name:rawName,type:'Disk',description:''}], partial:false, note:''}});
  assert.equal(ui.id('results').hidden, true);
  ui.frame({more:false, result:{rows:[], partial:true, note:'Accesso limitato'}});
  assert.equal(ui.id('results').hidden, false);
  assert.equal(ui.id('rows').children[0].children[0].children[0].textContent, rawName);
  assert.match(ui.id('status').textContent, /parziale.*1 voce.*Accesso limitato/);
  for (const [index, section] of ['drives','services','apps'].entries()) {
    ui.tabs[index + 1].onclick();
    assert.deepEqual(ui.requests.at(-1), {t:'inventory', section, id:index + 2});
    ui.frame({more:false, result:{rows:[], partial:false, note:''}});
    assert.match(ui.id('status').textContent, /Nessuna voce/);
  }
  ui.revoke();
  await ui.tick(5000);
  assert.equal(ui.closed(), true);
  assert.equal(ui.id('results').hidden, true);
  assert.ok(ui.tabs.every(t => t.disabled));
});

test('unexpected or oversized inventory responses close the session', async () => {
  for (const invalid of [{id:17}, {error:'x'.repeat(17000)}, {more:false, result:{rows:new Array(1501), partial:false, note:''}}]) {
    const ui = browser();
    await settle();
    ui.frame(invalid);
    assert.equal(ui.closed(), true);
    assert.equal(ui.id('rows').children.length, 0);
  }
});

test('an agent without a signed renewal cannot start an inventory query', async () => {
  const s = browser(null); await settle();
  assert.equal(s.closed(), true);
  assert.deepEqual(s.requests, []);
});
