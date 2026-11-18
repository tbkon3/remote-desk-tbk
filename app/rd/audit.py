"""Registro accessi locale (data/audit.jsonl), conservato 90 giorni.

Ogni macchina registra cio' che succede SU di lei; gli amministratori lo consultano da
qualsiasi console con una richiesta firmata. La risposta e' cifrata con una chiave
effimera (X25519) che solo la console richiedente possiede."""
import json
import logging
import os
import threading
import time
import zlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .auth import b64, unb64

log = logging.getLogger("rd.audit")
RETENTION_DAYS = 90
CLIP_MAX = 300   # caratteri del testo degli appunti salvati nel registro

KINDS = {
    "session_start": "Sessione iniziata",
    "session_end": "Sessione terminata",
    "file_in": "File ricevuto",
    "file_out": "File inviato",
    "file_del": "File eliminato",
    "file_ren": "File rinominato",
    "file_mkdir": "Cartella creata",
    "login_fail": "Login fallito",
    "auth_fail": "Accesso negato",
    "clip_in": "Appunti ricevuti",
    "clip_out": "Appunti inviati",
}


class Audit:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "audit.jsonl")
        self.lock = threading.Lock()
        self.prune()

    def add(self, kind, **f):
        e = {"t": int(time.time()), "k": kind}
        e.update({k: v for k, v in f.items() if v not in (None, "")})
        if "text" in e:
            txt = str(e["text"])
            e["len"] = len(txt)
            e["text"] = txt[:CLIP_MAX]
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")

    def _read(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        yield json.loads(line)
                    except ValueError:
                        continue
        except FileNotFoundError:
            return

    def prune(self):
        cutoff = time.time() - RETENTION_DAYS * 86400
        with self.lock:
            keep = [e for e in self._read() if e.get("t", 0) >= cutoff]
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                for e in keep:
                    fh.write(json.dumps(e, ensure_ascii=False) + "\n")
            os.replace(tmp, self.path)

    def query(self, since=0, until=None, limit=5000, net=None):
        until = until or time.time() + 60
        with self.lock:
            out = [e for e in self._read() if since <= e.get("t", 0) <= until and (net is None or e.get("net") == net)]
        return out[-limit:]


# =========================================================================== cifratura risposta
def _key(shared):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"rd-audit").derive(shared)


def new_ephemeral():
    k = X25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return k, b64(pub)


def seal_for(epub_b64, obj):
    mine = X25519PrivateKey.generate()
    shared = mine.exchange(X25519PublicKey.from_public_bytes(unb64(epub_b64)))
    nonce = os.urandom(12)
    ct = AESGCM(_key(shared)).encrypt(nonce, zlib.compress(json.dumps(obj).encode(), 9), None)
    epk = mine.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"epk": b64(epk), "n": b64(nonce), "c": b64(ct)}


def open_with(priv, box):
    shared = priv.exchange(X25519PublicKey.from_public_bytes(unb64(box["epk"])))
    data = AESGCM(_key(shared)).decrypt(unb64(box["n"]), unb64(box["c"]), None)
    return json.loads(zlib.decompress(data))
