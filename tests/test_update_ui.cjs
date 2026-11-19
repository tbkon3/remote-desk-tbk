const test = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {join} = require('node:path');
const vm = require('node:vm');
const source = readFileSync(join(__dirname,'../app/web/console.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const settle = () => new Promise(resolve => setImmediate(resolve));

function consolePage(){
  class Element {
    constructor(){
      this.children = []; this.style = {}; this.dataset = {}; this.textContent = ''; this.value = '';
      const classes = new Set();
      this.classList = {add:c => classes.add(c), remove:c => classes.delete(c), contains:c => classes.has(c),
        toggle:(c,on) => on ? classes.add(c) : classes.delete(c)};
    }
    append(...children){ this.children.push(...children) }
    replaceChildren(){ this.children = []; this.textContent = '' }
    contains(){return false} addEventListener() {}
  }
  const elements = new Map(), calls = [], dialogs = [], controls = {};
  let now = 1000000;
  function id(key){
    if (!elements.has(key)) elements.set(key,new Element());
    return elements.get(key);
  }
  const data = {update_target:{mode:'portable',path:'C:\\test\\<operator>'},
    local_update:{current:'2.4.0',latest:'2.4.1', auto:true, supported:true, available:true, state:'idle'}};
  const pub = {can_add_network:true, configured:false, logged:false, admin_any:false, networks:[], service:{installed:false}, me:{name:'unit',id:'1'}};
  const context = vm.createContext({
    AbortController, queueMicrotask, setInterval(){}, setTimeout(){}, clearTimeout(){},
    Date:class extends Date { static now(){return now} },
    document:{body:new Element(), getElementById:id, createElement:() => new Element(),
      querySelectorAll:() => [], querySelector:id, addEventListener() {}},
    confirm:m => { dialogs.push(m);return true },
    fetch:async (url,init={}) => {
      calls.push([url,init.body ? JSON.parse(init.body) : null]);
      if (controls.offline) throw Error('offline');
      return {ok:true, json:async () => url === '/api/public' ? pub : url === '/api/update/local' ? data : {ok:true}};
    }
  });
  vm.runInContext(source,context);
  return {id,calls,dialogs,data,pub,controls,advance:n => { now += n },
    refresh:() => vm.runInContext('refresh()',context)};
}

test('first-run owner sees the exact target before confirming and auto-update changes only on a gesture', async () => {
  const ui = consolePage(); await settle();
  assert.deepEqual(ui.calls.map(([url]) => url), ['/api/public','/api/update/local']);
  assert.equal(ui.id('welcomeAuto').checked, true);
  assert.match(ui.id('welcomeTarget').textContent, /Copia portabile/);
  assert.ok(ui.id('welcomeTarget').textContent.includes(ui.data.update_target.path));
  const button = ui.id('updBanner').children.at(-1);
  await button.onclick(); await settle();
  assert.ok(ui.dialogs[0].includes(ui.data.update_target.path));
  assert.deepEqual(ui.calls.find(([url]) => url === '/api/update/install')[1], {expected_target:ui.data.update_target});
  ui.id('welcomeAuto').checked = false; await ui.id('welcomeAuto').onchange(); await settle();
  assert.deepEqual(ui.calls.find(([url]) => url === '/api/settings')[1], {auto_update:false});
  ui.pub.can_add_network = false;
  await ui.refresh();
  assert.equal(ui.id('welcomeTarget').textContent,'');
  assert.ok(ui.id('updBanner').classList.contains('hide'));
});

test('unchanged progress reports its age and the disconnected banner forgets the local path', async () => {
  const ui = consolePage(); await settle();
  Object.assign(ui.data.local_update, {state:'downloading',progress:100});
  await ui.refresh();
  assert.match(ui.id('updBanner').children[0].textContent, /Preparazione/);
  ui.advance(36000); await ui.refresh();
  assert.match(ui.id('updBanner').children[0].textContent, /36 s/);
  ui.controls.offline = true;
  for (let i=0; i<2; i++) {
    await ui.refresh();
    assert.match(ui.id('updBanner').textContent, /Contatto.*interrotto/);
    assert.equal(ui.id('welcomeTarget').textContent, '');
    assert.equal(ui.id('updBanner').children.length, 0);
  }
  ui.controls.offline = false;
  Object.assign(ui.data.local_update, {available:false,current:'2.4.1',state:'idle'});
  await ui.refresh();
  assert.ok(ui.id('updBanner').classList.contains('hide'));
  assert.match(ui.id('welcomeUpdateStatus').textContent, /2\.4\.1/);
});

test('first-run service setup requires a prepared copy and a new local confirmation', async () => {
  const ui = consolePage(); await settle();
  const button = ui.id('welcomeSvcBtn');
  const guide = ui.id('welcomeSvcGuide');
  const route = '/api/service';
  const path = 'C:\\Program Files\\RemoteDesk';
  ui.data.service_setup = {path, registered:false, ready:false};
  await ui.refresh();
  assert.ok(!ui.id('welcomeService').classList.contains('hide'));
  assert.ok(button.classList.contains('hide'));
  assert.ok(!guide.classList.contains('hide'));
  await button.onclick();
  assert.ok(!ui.calls.some(([url]) => url === route));
  ui.data.service_setup.ready = true;
  await ui.refresh();
  assert.ok(!button.classList.contains('hide'));
  assert.ok(guide.classList.contains('hide'));
  await button.onclick(); await settle();
  assert.ok(ui.dialogs[0].includes(path));
  assert.deepEqual(ui.calls.filter(([url]) => url === route), [[route, {action:'install'}]]);
  ui.data.service_setup.registered = true;
  await ui.refresh();
  assert.ok(button.classList.contains('hide'));
  assert.match(ui.id('welcomeSvcTxt').textContent, /già registrato/);
});
