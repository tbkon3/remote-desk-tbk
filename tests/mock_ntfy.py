# Server ntfy minimo per i test in locale (solo pubblicazione/sottoscrizione JSON, senza allegati).
# Uso: python3 tests/mock_ntfy.py   poi in RemoteDesk: Impostazioni > Server di segnalazione = http://127.0.0.1:8099
import asyncio, json, time, itertools
from aiohttp import web
subs, hist = {}, {}
state = {'used': 0, 'limit': 100000}   # simulazione del limite giornaliero (GET /_limit?n=N per cambiarlo)
cnt = itertools.count(1)
CORS = {'Access-Control-Allow-Origin': '*'}
async def pub(req):
    t = req.match_info['t']; body = await req.text()
    if state['used'] >= state['limit']:
        return web.json_response({'code': 42908, 'error': 'limit reached: daily message quota'}, status=429, headers=CORS)
    state['used'] += 1
    ev = {'id': f'm{next(cnt)}', 'time': int(time.time()), 'event': 'message', 'topic': t, 'message': body}
    hist.setdefault(t, []).append(ev)
    for q in subs.get(t, []): q.put_nowait(ev)
    return web.json_response(ev, headers=CORS)
async def stream(req):
    t = req.match_info['t']; q = asyncio.Queue(); subs.setdefault(t, []).append(q)
    since = req.query.get('since', '')
    r = web.StreamResponse(headers={'Content-Type': 'application/x-ndjson'}); await r.prepare(req)
    await r.write((json.dumps({'event': 'open'}) + '\n').encode())
    back = hist.get(t, [])
    if since.endswith('s'): back = [e for e in back if e['time'] >= time.time() - int(since[:-1])]
    elif since:
        ids = [e['id'] for e in back]; back = back[ids.index(since)+1:] if since in ids else []
    else: back = []
    for e in back: await r.write((json.dumps(e) + '\n').encode())
    try:
        while True:
            try: ev = await asyncio.wait_for(q.get(), 30)
            except asyncio.TimeoutError: ev = {'event': 'keepalive'}
            await r.write((json.dumps(ev) + '\n').encode())
    finally: subs[t].remove(q)
async def account(req):
    return web.json_response({'limits': {'messages': state['limit']}, 'stats': {'messages': state['used']}})
async def set_limit(req):
    state['limit'] = int(req.query.get('n', 100000)); return web.json_response(state)
app = web.Application()
app.router.add_get('/v1/account', account)
app.router.add_get('/_limit', set_limit)
app.router.add_post('/{t}', pub)
app.router.add_get('/{t}/json', stream)
web.run_app(app, host='127.0.0.1', port=8099, print=None)
