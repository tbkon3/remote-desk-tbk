# Server ntfy minimo per i test in locale (solo pubblicazione/sottoscrizione JSON, senza allegati).
# Uso: python3 tests/mock_ntfy.py   poi in RemoteDesk: Impostazioni > Server di segnalazione = http://127.0.0.1:8099
import asyncio, json, time, itertools
from aiohttp import web
subs, hist = {}, {}
cnt = itertools.count(1)
CORS = {'Access-Control-Allow-Origin': '*'}
async def pub(req):
    t = req.match_info['t']; body = await req.text()
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
app = web.Application()
app.router.add_post('/{t}', pub)
app.router.add_get('/{t}/json', stream)
web.run_app(app, host='127.0.0.1', port=8099, print=None)
