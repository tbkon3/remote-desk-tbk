"""Sicurezza: utenti, permessi e firme.

Modello (nessun server):
- La CHIAVE DI RETE (casuale) cifra i messaggi di segnalazione: senza, non si vede nulla.
- Ogni UTENTE ha una coppia di chiavi Ed25519 derivata (scrypt) da rete+utente+password.
  La password non lascia mai il PC su cui viene digitata.
- Ogni MACCHINA ha una coppia di chiavi Ed25519 casuale, generata al primo avvio.
- Il REGISTRO (utenti, permessi, macchine) e' un documento firmato da un amministratore,
  replicato su tutte le macchine. Una nuova versione e' accettata solo se firmata da un
  amministratore della versione corrente.
- Ogni richiesta di connessione e' firmata dall'utente (e include l'hash dell'offerta WebRTC,
  quindi l'impronta DTLS): la macchina verifica firma e permessi prima di rispondere.
  La risposta e' firmata dalla macchina: niente man-in-the-middle anche se la chiave di
  rete venisse scoperta.
"""
import base64
import hashlib
import json
import os
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

RIGHTS = ("view", "control", "files")


def b64(b):
    return base64.b64encode(b).decode()


def unb64(s):
    return base64.b64decode(s)


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def norm_user(u):
    return u.strip().lower()


def derive_user_key(network, username, password):
    salt = ("rd-user:" + network.strip().lower() + ":" + norm_user(username)).encode()
    seed = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    return Ed25519PrivateKey.from_private_bytes(seed)


def pub_of(priv):
    return b64(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def sign(priv, obj):
    return b64(priv.sign(canon(obj)))


def verify(pub_b64, obj, sig_b64):
    try:
        Ed25519PublicKey.from_public_bytes(unb64(pub_b64)).verify(unb64(sig_b64), canon(obj))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def doc_hash(doc):
    return hashlib.sha256(canon(doc)).hexdigest() if doc else None


def sdp_hash(sdp):
    return hashlib.sha256(sdp.encode()).hexdigest()


def new_network_key():
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alpha) for _ in range(24))
    return "-".join(raw[i:i + 6] for i in range(0, 24, 6))


def load_machine_key(data_dir):
    from .common import write_private
    path = os.path.join(data_dir, "machine.key")
    try:
        with open(path, "rb") as f:
            raw = unb64(f.read().decode().strip())
        if len(raw) != 32:
            raise ValueError("lunghezza errata")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except FileNotFoundError:
        pass
    except ValueError:
        os.replace(path, f"{path}.corrupt-{int(time.time())}")
    k = Ed25519PrivateKey.generate()
    raw = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    write_private(path, b64(raw))
    return k


# =========================================================================== registro firmato
class Registry:
    def __init__(self, doc=None):
        self.doc = doc

    @property
    def version(self):
        return self.doc["v"] if self.doc else 0

    def users(self):
        return (self.doc or {}).get("users", {})

    def machines(self):
        return (self.doc or {}).get("machines", {})

    def user(self, name):
        return self.users().get(norm_user(name or ""))

    def is_admin(self, name):
        u = self.user(name)
        return bool(u and u.get("admin"))

    def rights(self, username, machine_id):
        u = self.user(username)
        if not u:
            return set()
        if u.get("admin"):
            return set(RIGHTS)
        p = u.get("perms", {})
        r = set(p.get("*", [])) | set(p.get(str(machine_id), []))
        if "control" in r:
            r.add("view")
        return r & set(RIGHTS)

    @staticmethod
    def body(doc):
        return {k: v for k, v in doc.items() if k != "sig"}

    def check_new(self, doc, pinned_admin_pub=None):
        """Verifica un registro ricevuto. pinned_admin_pub: usato solo all'ingresso in rete."""
        try:
            signer = norm_user(doc["signer"])
            body = self.body(doc)
            if pinned_admin_pub:
                su = doc["users"].get(signer)
                return bool(su and su.get("admin") and su["pub"] == pinned_admin_pub and
                            verify(pinned_admin_pub, body, doc["sig"]))
            # catena: solo la versione successiva, collegata a quella che conosco gia'
            if not self.doc or doc["v"] != self.doc["v"] + 1 or doc.get("prev") != doc_hash(self.doc):
                return False
            cur = self.user(signer)  # deve essere admin nella versione CHE GIA' CONOSCO
            return bool(cur and cur.get("admin") and verify(cur["pub"], body, doc["sig"]))
        except (KeyError, TypeError):
            return False

    def signed_update(self, admin_name, admin_priv, mutate):
        """Crea una nuova versione firmata applicando mutate(doc)."""
        doc = json.loads(json.dumps(self.body(self.doc))) if self.doc else {"users": {}, "machines": {}}
        mutate(doc)
        doc["v"] = self.version + 1
        doc["prev"] = doc_hash(self.doc)
        doc["signer"] = norm_user(admin_name)
        doc["ts"] = int(time.time())
        doc["sig"] = sign(admin_priv, doc)
        return doc


def trust_chain(docs, pinned_pub):
    """Ingresso in rete: parte dalla versione piu' recente firmata dall'amministratore di cui
    conosco la password (ancora di fiducia) e applica in ordine solo le versioni successive
    collegate e firmate da un admin della versione precedente. Ritorna il Registry o None."""
    by_v = {}
    for d in docs:
        if isinstance(d, dict) and isinstance(d.get("v"), int):
            by_v.setdefault(d["v"], []).append(d)
    anchor = None
    for v in sorted(by_v, reverse=True):
        for d in by_v[v]:
            if Registry().check_new(d, pinned_admin_pub=pinned_pub):
                anchor = d
                break
        if anchor:
            break
    if not anchor:
        return None
    reg = Registry(anchor)
    while True:
        nxt = next((d for d in by_v.get(reg.version + 1, []) if reg.check_new(d)), None)
        if not nxt:
            return reg
        reg = Registry(nxt)
