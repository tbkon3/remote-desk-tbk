"use strict";

function renewalMatches(proof, net, target, mode) {
  return proof?.t === 'renew' && proof.protocol === 2 && proof.net === net && proof.to === target &&
    proof.mode === mode && typeof proof.sid === 'string' && /^[a-f0-9]{32}$/.test(proof.sid) &&
    Number.isSafeInteger(proof.iat) && typeof proof.usig === 'string' && proof.usig.length > 0 &&
    typeof proof.msig === 'string' && proof.msig.length > 0;
}

function remoteDeskPath(report) {
  let selected = null, nominated = null;
  report.forEach(row => {
    if (row.type === 'transport' && row.selectedCandidatePairId) {
      const pair = report.get(row.selectedCandidatePairId);
      if (pair?.type === 'candidate-pair' && pair.state === 'succeeded') selected = pair;
    }
    if (row.type === 'candidate-pair' && row.nominated && row.state === 'succeeded') nominated = row;
  });
  const pair = selected || nominated;
  if (!pair) return {label:'Non determinato', rtt:null};
  const local = report.get(pair.localCandidateId)?.candidateType;
  const remote = report.get(pair.remoteCandidateId)?.candidateType;
  const direct = ['host','srflx','prflx'];
  let label = 'Non determinato';
  if (local === 'relay' || remote === 'relay') label = 'Via TURN';
  else if (direct.includes(local) && direct.includes(remote)) label = 'Diretto';
  return {label, rtt:Number.isFinite(pair.currentRoundTripTime) ? Math.round(pair.currentRoundTripTime * 1000) : null};
}

async function gatherRemoteDeskIce(peer) {
  await new Promise(resolve => {
    if (peer.iceGatheringState === 'complete') { resolve(); return }
    const timer = setTimeout(done, 8000);
    function done() {
      clearTimeout(timer);
      peer.removeEventListener('icegatheringstatechange', changed);
      resolve();
    }
    function changed() { if (peer.iceGatheringState === 'complete') done() }
    peer.addEventListener('icegatheringstatechange', changed);
  });
  const sdp = peer.localDescription?.sdp || '';
  if (!/^a=candidate:/m.test(sdp)) throw Error('Nessun percorso ICE disponibile. Verifica rete, firewall e server TURN.');
  return sdp;
}
