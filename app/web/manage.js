"use strict";

const byId = id => document.getElementById(id);
const params = new URLSearchParams(location.search);
const target = {nid:params.get('net'), to:params.get('id'), mode:'manage'};
const tabs = [...document.querySelectorAll('[data-section]')];
const columns = {
  shares: {name:'Nome', type:'Tipo', description:'Descrizione'},
  drives: {drive:'Unità', remote:'Percorso di rete'},
  services: {display:'Nome visualizzato', name:'Nome servizio', status:'Stato', start:'Avvio'},
  apps: {name:'Nome', version:'Versione', publisher:'Editore', scope:'Ambito'}
};
const utf8 = new TextEncoder();
let section = 'shares', requestId = 0, session = null, query = null;

async function post(url, body, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body), signal:controller.signal});
    const result = await response.json();
    if (!response.ok || result.error) throw Error(result.error || 'Richiesta rifiutata');
    return result;
  } finally { clearTimeout(timer) }
}

function status(message) { byId('status').textContent = message }

function controls(ready) {
  for (const tab of tabs) {
    tab.disabled = !ready;
    tab.setAttribute('aria-pressed', String(tab.dataset.section === section));
  }
  byId('refresh').disabled = !ready;
  byId('retry').hidden = !!session;
  byId('disconnect').hidden = !session;
}

function clearResults() {
  byId('results').hidden = true;
  byId('rows').replaceChildren();
  byId('columns').replaceChildren();
}

function closeSession(message) {
  byId('intuneCatalog').hidden = true;
  const old = session;
  session = null;
  if (old) {
    clearTimeout(old.deadline);
    clearTimeout(old.heartbeat);
    clearTimeout(old.pathTimer);
    if (old.pc) old.pc.close();
  }
  clearTimeout(query?.timer);
  query = null;
  clearResults();
  byId('path').hidden = true;
  controls(false);
  status(message);
}

function requestSection(key) {
  if (!session || session.channel?.readyState !== 'open' || query || !Object.hasOwn(columns, key)) return;
  section = key;
  byId('intuneCatalog').hidden = key !== 'apps';
  const selected = tabs.find(tab => tab.dataset.section === key);
  byId('sectionTitle').textContent = selected.textContent;
  controls(false);
  clearResults();
  status('Lettura in corso…');
  const heading = document.createElement('tr');
  for (const title of Object.values(columns[key])) {
    const cell = document.createElement('th');
    cell.scope = 'col';
    cell.textContent = title;
    heading.append(cell);
  }
  byId('columns').append(heading);
  query = {id:++requestId, count:0, bytes:0, chunks:0, partial:false, note:'',
    timer:setTimeout(() => closeSession('Il PC remoto non ha completato la lettura.'), 30000)};
  try { session.channel.send(JSON.stringify({t:'inventory', section, id:query.id})) }
  catch { closeSession('Canale inventario interrotto.') }
}

function onFrame(data) {
  if (!query || typeof data !== 'string' || data.length > 16384) throw Error('Formato inatteso');
  const bytes = utf8.encode(data).length;
  query.bytes += bytes;
  if (bytes > 16384 || query.bytes > 1024 * 1024 || ++query.chunks > 1600) throw Error('Limite superato');
  const frame = JSON.parse(data);
  if (frame.t !== 'inventory' || frame.id !== query.id || frame.section !== section) throw Error('Risposta inattesa');
  if (typeof frame.error === 'string') {
    clearTimeout(query.timer);
    query = null;
    clearResults();
    controls(true);
    status(frame.error.slice(0, 500) || 'Lettura non riuscita.');
    return;
  }
  const result = frame.result;
  if (typeof frame.more !== 'boolean' || !Array.isArray(result?.rows) ||
      typeof result.partial !== 'boolean' || typeof result.note !== 'string' ||
      result.rows.length > 1500 - query.count) throw Error('Risposta incompleta');
  const fragment = document.createDocumentFragment();
  const keys = Object.keys(columns[section]);
  for (const row of result.rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw Error('Riga non valida');
    const tr = document.createElement('tr');
    for (const key of keys) {
      const td = document.createElement('td');
      const value = row[key];
      td.textContent = typeof value === 'string' || typeof value === 'number' ? String(value) : '';
      tr.append(td);
    }
    fragment.append(tr);
  }
  byId('rows').append(fragment);
  query.count += result.rows.length;
  if (result.partial) query.partial = true;
  if (result.note) query.note = result.note.slice(0, 500);
  if (frame.more) return;
  clearTimeout(query.timer);
  const {count, partial, note} = query;
  query = null;
  byId('results').hidden = count === 0;
  status([partial ? 'Elenco parziale.' : '', count ? count + (count === 1 ? ' voce.' : ' voci.') : 'Nessuna voce disponibile.', note].filter(Boolean).join(' '));
  controls(true);
}

async function checkLease(current) {
  const r = await post('/api/session/lease', {lease:current.lease}, 4500);
  if (r.ok !== true || !renewalMatches(r.proof, target.nid, target.to, target.mode) ||
      (current.proof && current.proof.sid !== r.proof.sid)) throw Error('Autorizzazione scaduta. Accedi di nuovo dalla console.');
  if (session !== current) return;
  current.proof = r.proof;
  if (current.channel.readyState === 'open') current.channel.send(JSON.stringify(current.proof));
}

async function heartbeat(current) {
  if (session !== current) return;
  try { await checkLease(current) }
  catch { if (session === current) closeSession('Autorizzazione scaduta o console non disponibile.'); return }
  if (session === current) current.heartbeat = setTimeout(() => heartbeat(current), 5000);
}

async function showPath(current) {
  let label = 'Non determinato';
  try { label = remoteDeskPath(await current.pc.getStats()).label } catch {}
  if (session !== current) return;
  byId('path').textContent = label;
  byId('path').hidden = false;
  current.pathTimer = setTimeout(() => showPath(current), 5000);
}

async function connect() {
  if (session) return;
  if (!target.nid || !target.to) { closeSession('Apri Gestisci PC dalla rubrica.'); return }
  const current = {};
  session = current;
  controls(false);
  status('Collegamento al PC remoto…');
  current.deadline = setTimeout(() => closeSession('Il PC remoto non risponde.'), 75000);
  try {
    const {ice} = await post('/api/session/ice', target, 10000);
    if (current !== session) return;
    const pc = new RTCPeerConnection({iceServers:ice});
    current.pc = pc;
    const channel = pc.createDataChannel('inventory', {ordered:true});
    current.channel = channel;
    channel.onopen = () => {
      if (current !== session) return;
      if (!current.proof) { closeSession('Autorizzazione della sessione mancante.'); return }
      try { channel.send(JSON.stringify(current.proof)) } catch { closeSession('Canale inventario interrotto.'); return }
      clearTimeout(current.deadline);
      showPath(current);
      requestSection(section);
    };
    channel.onmessage = event => {
      if (current !== session) return;
      try { onFrame(event.data) } catch { closeSession('Risposta inventario non valida.') }
    };
    channel.onclose = channel.onerror = () => { if (current === session) closeSession('Canale inventario chiuso.') };
    pc.onconnectionstatechange = () => {
      if (current === session && ['disconnected','closed','failed'].includes(pc.connectionState)) closeSession(
        pc.connectionState === 'failed' ? 'Percorso WebRTC non disponibile. Per Internet verifica il server TURN su entrambi i PC.' : 'PC remoto disconnesso.');
    };
    pc.ondatachannel = event => event.channel.close();
    await pc.setLocalDescription(await pc.createOffer());
    const offer = await gatherRemoteDeskIce(pc);
    if (current !== session) return;
    const r = await post('/api/connect', {...target, sdp:offer}, 60000);
    if (current !== session) return;
    if (typeof r.lease !== 'string' || !r.lease) throw Error('Autorizzazione della sessione mancante.');
    current.lease = r.lease;
    await checkLease(current);
    if (current !== session) return;
    current.heartbeat = setTimeout(() => heartbeat(current), 5000);
    await pc.setRemoteDescription({type:'answer', sdp:r.sdp});
  } catch (e) {
    if (current === session) closeSession(e.name === 'AbortError' ? 'Il PC remoto non risponde.' : e.message);
  }
}

byId('target').textContent = [params.get('name'), target.to].filter(Boolean).join(' · ');
for (const tab of tabs) tab.onclick = () => requestSection(tab.dataset.section);
byId('refresh').onclick = () => requestSection(section);
byId('disconnect').onclick = () => closeSession('Disconnesso.');
byId('retry').onclick = connect;
window.addEventListener('pagehide', () => closeSession('Disconnesso.'));
connect();
