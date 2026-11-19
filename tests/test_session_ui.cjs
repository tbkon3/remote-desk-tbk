const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const web = path.join(__dirname, '../app/web');
const script = fs.readFileSync(path.join(web, 'session_ice.js'), 'utf8') + '\n' +
  fs.readFileSync(path.join(web, 'session.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const settle = () => new Promise(resolve => setImmediate(resolve));

const renewal = mode => ({t:'renew', protocol:2, net:'net', to:'555', mode, sid:'a'.repeat(32), iat:1, msig:'fixture', usig:'fixture'});
const peer = {peer_presence:123456, peer_pub:'A'.repeat(43) + '=', peer_version:'2.4.0'};
function session(mode, proof=renewal(mode)) {
  class Element {
    constructor(){
      this.options = []; this.style = {}; this.dataset = {}; this.value = ''; this.textContent = '';
      const classes = new Set();
      this.classList = {toggle:(c,on) => { if (on) classes.add(c); else classes.delete(c) },
        contains:c => classes.has(c), add:c => classes.add(c), remove:c => classes.delete(c)};
    }
    addEventListener() {} replaceChildren() {} append() {} focus() {} remove() {}
    querySelector(){ return new Element() }
  }
  const elements = new Map(), timers = new Map(), posts = [], channels = [], media = [], sent = [];
  const replies = new Map();
  let next = 0, valid = true, closed = false, now = 0;
  function id(key){
    if (!elements.has(key)) elements.set(key, new Element());
    return elements.get(key);
  }
  id('quality').value = '1,15';
  const timer = (fn, delay) => { timers.set(++next, {fn,delay}); return next };
  const context = {URLSearchParams, TextEncoder, AbortController, Uint32Array, crypto:webcrypto, Event,
    location:{search:'?net=net&id=555&mode=' + mode}, window:{addEventListener() {}, close(){}}, performance:{now:()=>now},
    document:{getElementById:id, querySelectorAll:() => [], body:new Element(), createElement:() => new Element(), addEventListener() {}},
    clearTimeout:n => timers.delete(n), clearInterval:n => timers.delete(n), setTimeout:timer, setInterval:timer,
    fetch:async (url, args) => {
      const body = JSON.parse(args.body); posts.push([url, body]);
      const override = replies.get(url);
      if (override) return {ok:override.status < 400, status:override.status, json:async()=>({...override.data})};
      const result = {'/api/session/ice':{ice:[],...peer}, '/api/connect':{sdp:'answer',lease:'proof'},
        '/api/session/lease':{ok:valid, proof}, '/api/clip/read':{text:'local fixture'}, '/api/clip':{ok:true}};
      if (!Object.hasOwn(result,url)) throw Error('unexpected endpoint');
      return {ok:true, json:async () => result[url]};
    },
    RTCPeerConnection:class {
      constructor(){ this.iceGatheringState = 'complete'; this.localChannels = [] }
      addTransceiver(kind){ media.push(kind); return {receiver:{}} }
      createDataChannel(label){
        const ch = {label, readyState:'connecting', dispatchEvent() {}, send(raw){ sent.push([label,JSON.parse(raw)]) }};
        channels.push(ch); this.localChannels.push(ch); return ch;
      }
      async createOffer(){ return {sdp:'a=candidate:fixture'} }
      async setLocalDescription(d){ this.localDescription = d }
      async setRemoteDescription(){
        for (const ch of this.localChannels) { ch.readyState = 'open'; ch.onopen?.() }
        this.localChannels[0].onmessage({data:JSON.stringify({t:'info', lease_active:true, name:'peer', current:0, monitors:[], audio:false,
          perms:{control:mode === 'control', clipboard:mode === 'control', files:mode === 'files'}})});
        this.connectionState = 'connected'; this.onconnectionstatechange();
      }
      close(){ closed = true; this.connectionState = 'closed' }
    }
  };
  vm.runInNewContext(script, context);
  return {id, posts, channels, media, sent, revoked:() => closed,
    reply:(url,status,data)=>replies.set(url,{status,data}),
    async nextRetry() {
      const entry = [...timers].find(([,t]) => [2000,5000,10000,20000].includes(t.delay) || t.delay === 180000-now);
      if (!entry) return 0;
      timers.delete(entry[0]); now += entry[1].delay; await entry[1].fn(); await settle(); return entry[1].delay;
    },
    pendingTimers:()=>timers.size,
    revoke:async () => { valid = false; await [...timers.values()].find(t => t.delay === 5000).fn() },
    frame:msg => channels[0].onmessage({data:JSON.stringify(msg)})};
}

test('desktop, view and files negotiate only their respective media and data channels', async () => {
  for (const [mode, channels, media] of [['control',['ctl','mm'],['video','audio']], ['view',['ctl'],['video']], ['files',['ctl','files'],[]]]) {
    const s = session(mode); await settle();
    assert.deepEqual(s.channels.map(c => c.label), channels);
    assert.deepEqual(s.media, media);
    assert.deepEqual(s.posts.map(p => p[0]), ['/api/session/ice','/api/connect','/api/session/lease']);
    assert.deepEqual(s.sent[0], ['ctl', renewal(mode)]);
    if (mode === 'files') {
      assert.equal(s.id('fUpl').disabled, true);
      assert.equal(s.sent.filter(([channel,m]) => channel === 'files' && m.op === 'roots').length, 1);
      const info = {t:'info', lease_active:true, current:0, monitors:[], perms:{files:true, files_write:true, files_delete:false}};
      s.frame(info); assert.equal(s.id('fUpl').disabled, false);
      assert.equal(s.sent.filter(([channel,m]) => channel === 'files' && m.op === 'roots').length, 1);
    }
    assert.equal(s.id('ovTxt').textContent, mode === 'files' ? '' : "In attesa dell'immagine...");
    s.frame({t:'clip', text:'unexpected', id:1});
    assert.equal(s.posts.length, 3);
    await s.revoke();
    assert.equal(s.revoked(), true);
    assert.match(s.id('ovTxt').textContent, /Autorizzazione scaduta/);
  }
});

test('clipboard operates only on explicit gestures, current lease and matching single-use request', async () => {
  const s = session('control'); await settle();
  await s.id('clipPush').onclick();
  assert.deepEqual(s.posts.at(-1), ['/api/clip/read', {lease:'proof'}]);
  assert.deepEqual(s.sent.at(-1), ['ctl', {t:'clip', text:'local fixture'}]);
  s.id('clipPull').onclick();
  const rid = s.sent.at(-1)[1].id;
  assert.equal(s.sent.at(-1)[1].t, 'clipread');
  assert.ok(Number.isInteger(rid) && rid >= 0 && rid <= 2 ** 31 - 1);
  s.frame({t:'clip', id:rid + 1, text:'unexpected'});
  assert.equal(s.posts.length, 4);
  s.frame({t:'clip', id:rid, text:'remote fixture'}); await settle();
  assert.deepEqual(s.posts.at(-1), ['/api/clip', {lease:'proof', text:'remote fixture'}]);
  s.frame({t:'clip', id:rid, text:'replay'});
  s.id('clipPull').onclick();
  s.frame({t:'clip', id:s.sent.at(-1)[1].id, text:'à'.repeat(31000)});
  assert.equal(s.posts.length, 5);
  await s.revoke();
  await s.id('clipPush').onclick();
  assert.equal(s.posts.at(-1)[0], '/api/session/lease');
});

test('a missing renewal closes a desktop connection before any data channel opens', async () => {
  const s = session('control', null); await settle();
  assert.equal(s.revoked(), true);
  assert.deepEqual(s.sent, []);
});

test('update waits through offline probes and reopens with the same peer and a fresh lease', async () => {
  const s = session('control'); await settle();
  s.frame({t:'bye', reason:'update'});
  s.reply('/api/session/ice',409,{code:'peer_offline',error:'offline'});
  assert.equal(await s.nextRetry(),2000);
  assert.equal(await s.nextRetry(),5000);
  assert.equal(s.posts.filter(([p])=>p==='/api/connect').length,1);
  s.reply('/api/session/ice',200,{ice:[],...peer});
  assert.equal(await s.nextRetry(),10000);
  const offers = s.posts.filter(([p])=>p==='/api/connect');
  assert.equal(offers.length,2);
  assert.equal(offers[1][1].expected_pub,peer.peer_pub);
  assert.equal(s.posts.filter(([p])=>p==='/api/session/lease').length,2);
});

test('update notice survives channel close and ignores stale online presence', async () => {
  const s=session('view'); await settle();
  s.frame({t:'notice',reason:'update',text:'Aggiornamento'});
  s.channels[0].onclose();
  await s.nextRetry();
  await s.nextRetry();
  assert.equal(s.posts.filter(([p])=>p==='/api/connect').length,1);
  s.reply('/api/session/ice',200,{ice:[],...peer,peer_version:'2.4.1'});
  await s.nextRetry();
  assert.equal(s.posts.filter(([p])=>p==='/api/connect').length,2);
});

test('maintenance halts on revocation, changed identity, incompatible version or rejected offer', async () => {
  for (const [status,result] of [[401,{code:'peer_offline',error:'login richiesto'}],
    [403,{error:'revocata'}],[409,{error:'Aggiorna RemoteDesk'}],
    [200,{ice:[],...peer,peer_pub:'B'.repeat(43)+'='}],[200,{ice:[],...peer,peer_version:'2.3.2'}]]) {
    const s=session('view'); await settle(); s.frame({t:'bye',reason:'update'});
    s.reply('/api/session/ice',status,result); await s.nextRetry();
    assert.equal(s.posts.filter(([p])=>p==='/api/connect').length,1);
    assert.equal(s.pendingTimers(),0);
  }
  for (const error of ['Accesso rifiutato', 'Firma non valida', 'Nessuna risposta']) {
    const s=session('view'); await settle(); s.frame({t:'bye',reason:'update'});
    s.reply('/api/session/ice',200,{ice:[],...peer,peer_version:'2.4.1'});
    s.reply('/api/connect',200,{error});
    await s.nextRetry();
    assert.equal(s.posts.filter(([p])=>p==='/api/connect').length,2);
    assert.equal(s.id('ovTxt').textContent,error);
    assert.equal(s.pendingTimers(),0);
  }
});

test('maintenance stops after three minutes or an explicit disconnect', async () => {
  const s=session('files'); await settle(); s.frame({t:'bye',reason:'update'});
  s.reply('/api/session/ice',409,{code:'peer_offline',error:'offline'});
  let elapsed=0;
  for (let i=0;i<20 && s.pendingTimers();i++) elapsed+=await s.nextRetry();
  assert.equal(elapsed,180000); assert.equal(s.pendingTimers(),0);
  assert.equal(s.posts.filter(([p])=>p==='/api/connect').length,1);
  const other=session('view'); await settle(); other.frame({t:'bye',reason:'update'});
  other.id('bBye').onclick(); assert.equal(other.pendingTimers(),0);
});
