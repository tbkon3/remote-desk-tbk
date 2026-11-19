const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ice = vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../app/web/session_ice.js'), 'utf8') + '\nremoteDeskPath');

test('report the active ICE route, excluding unused, failed and incomplete pairs', () => {
  const stats = new Map([
    ['s',{type:'transport', selectedCandidatePairId:'p'}],
    ['p',{type:'candidate-pair', state:'succeeded', localCandidateId:'l', remoteCandidateId:'r', currentRoundTripTime:0.025}],
    ['l',{candidateType:'host'}], ['r',{candidateType:'srflx'}],
    ['spare',{candidateType:'relay'}]
  ]);
  assert.equal(ice(stats).label, 'Diretto');
  assert.equal(ice(stats).rtt, 25);
  stats.get('r').candidateType = 'relay';
  assert.equal(ice(stats).label, 'Via TURN');
  stats.get('p').state = 'failed';
  assert.equal(ice(stats).label, 'Non determinato');
  stats.delete('s'); stats.get('p').state = 'succeeded';
  assert.equal(ice(stats).label, 'Non determinato');
  stats.get('p').nominated = true;
  assert.equal(ice(stats).label, 'Via TURN');
  stats.delete('r');
  assert.equal(ice(stats).label, 'Non determinato');
});
