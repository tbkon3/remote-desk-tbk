"""Sicurezza: utenti, permessi e firme.

Modello (nessun server):
- La CHIAVE DI RETE (casuale) cifra i messaggi di segnalazione: senza, non si vede nulla.
- Ogni UTENTE ha una coppia di chiavi Ed25519 derivata (scrypt) da rete+utente+password.
  La password non lascia mai il PC su cui viene digitata.
- Ogni MACCHINA ha una coppia di chiavi Ed25519 casuale, generata al primo avvio.
- Il REGISTRO (utenti, permessi, macchine) e' un documento firmato da un amministratore,
  replicato su tutte le macchine. Una nuova versione e' accettata solo se firmata da un
  amministratore della versione corrente.
- Ogni richiesta di connessione e' firmata dall'utente e dalla macchina (e include l'hash dell'offerta WebRTC,
  quindi l'impronta DTLS): la macchina verifica firma e permessi prima di rispondere.
  La risposta e' firmata dalla macchina: niente man-in-the-middle anche se la chiave di
  rete venisse scoperta.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SESSION_PROTOCOL = 2
LEGACY_RIGHTS = ("view", "control", "files")
RIGHTS = (*LEGACY_RIGHTS, "files_write", "files_delete", "inventory", "power", "block_input", "secure_desktop")
MODE_RIGHTS = {"view": "view", "control": "control", "files": "files", "manage": "inventory"}


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


def offer_body(nid, m):
    """Canonical message signed by both credentials. Version 1 cannot authorize a session."""
    return {"kind": "offer", "protocol": SESSION_PROTOCOL, "net": nid, "frm": m["frm"], "to": m["to"],
            "sid": m["sid"], "mode": m["mode"], "user": m["user"], "ts": m["uts"], "h": sdp_hash(m["sdp"])}


def answer_body(nid, m):
    body = {"kind": "answer", "protocol": SESSION_PROTOCOL, "net": nid, "frm": m["frm"], "to": m["to"],
            "sid": m["sid"], "mode": m["mode"]}
    if "error" in m:
        body["error"] = m["error"]
    else:
        body["h"] = sdp_hash(m["sdp"])
    return body


def renewal_body(nid, frm, to, sid, mode, user, issued):
    return {"t": "renew", "protocol": SESSION_PROTOCOL, "net": nid, "frm": frm, "to": to, "sid": sid,
            "mode": mode, "user": user, "iat": issued}


def audit_reply_body(nid, frm, to, rid, box):
    return {"type": "auditrep", "protocol": SESSION_PROTOCOL, "net": nid,
            "frm": frm, "to": to, "rid": rid, "digest": doc_hash(box)}


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
def _plain_text(value, limit):
    return isinstance(value, str) and len(value) <= limit and all(c.isprintable() for c in value)


def _encoded(value, size):
    if not isinstance(value, str) or len(value) != 4 * ((size + 2) // 3):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == size and b64(raw) == value
    except ValueError:
        return False


def _machine_id(value):
    return isinstance(value, str) and re.fullmatch("[0-9]{9}", value) is not None


def _username(value):
    # Historical bootstrap administrators may use spaces and non-ASCII names.
    return bool(value) and _plain_text(value, 500) and norm_user(value) == value


def _registry_shape(doc):
    if not isinstance(doc, dict) or doc.keys() - {"users", "machines", "v", "prev", "signer", "ts", "network", "sig"}:
        return False
    version = doc.get("v")
    if (type(version) is not int or not 1 <= version < 2**53
            or type(doc.get("ts")) is not int or not 0 <= doc["ts"] < 2**53
            or not _username(doc.get("signer")) or not _encoded(doc.get("sig"), 64)
            or not _plain_text(doc.get("network", ""), 1024) or "prev" not in doc):
        return False
    if version == 1:
        if doc["prev"] is not None:
            return False
    elif not isinstance(doc["prev"], str) or not re.fullmatch("[a-f0-9]{64}", doc["prev"]):
        return False
    machines, users = doc.get("machines"), doc.get("users")
    if not isinstance(machines, dict) or not isinstance(users, dict) or max(len(machines), len(users)) > 10000:
        return False
    for mid, machine in machines.items():
        if (not _machine_id(mid) or not isinstance(machine, dict) or machine.keys() - {"name", "pub"}
                or not _plain_text(machine.get("name", ""), 1024) or not _encoded(machine.get("pub"), 32)):
            return False
    grants = 0
    for name, user in users.items():
        if (not _username(name) or not isinstance(user, dict) or user.keys() - {"name", "pub", "perms", "admin"}
                or type(user.get("admin", False)) is not bool or not _plain_text(user.get("name", ""), 1024)
                or not _encoded(user.get("pub"), 32)):
            return False
        perms = user.get("perms", {})
        if not isinstance(perms, dict) or len(perms) > 10001:
            return False
        grants += len(perms)
        if grants > 100000:
            return False
        for mid, rights in perms.items():
            if ((mid != "*" and not _machine_id(mid)) or not isinstance(rights, list)
                    or len(rights) > 32 or not all(_plain_text(right, 48) and right for right in rights)):
                return False
    return len(canon(doc)) <= 2 * 1024 * 1024


class Registry:
    def __init__(self, doc=None):
        self.doc = doc
        self.trusted_history = []

    @classmethod
    def from_cache(cls, doc):
        # The trust anchor is already stored locally. The previous signer may have
        # rotated its key or lost its role in this snapshot.
        return cls(doc if _registry_shape(doc) else None)

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
        p = u.get("perms", {})
        r = set(p.get("*", [])) | set(p.get(str(machine_id), []))
        if u.get("admin"):
            r.update(LEGACY_RIGHTS)
        if "control" in r:
            r.add("view")
        return r & set(RIGHTS)

    @staticmethod
    def body(doc):
        return {k: v for k, v in doc.items() if k != "sig"}

    def check_new(self, doc, pinned_admin_pub=None):
        """Verifica un registro ricevuto. pinned_admin_pub: usato solo all'ingresso in rete."""
        try:
            if not _registry_shape(doc):
                return False
            signer = norm_user(doc["signer"])
            body = self.body(doc)
            if pinned_admin_pub:
                su = doc["users"].get(signer)
                return bool(su and su.get("admin") and su["pub"] == pinned_admin_pub and
                            verify(pinned_admin_pub, body, doc["sig"]))
            # catena: solo la versione successiva, collegata a quella che conosco gia'
            if (not self.doc or doc["v"] != self.doc["v"] + 1 or doc.get("prev") != doc_hash(self.doc)
                    or doc.get("network") != self.doc.get("network")):
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
        if not _registry_shape(doc):
            raise ValueError("Struttura o dimensione del registro non valida")
        return doc


def trust_chain(docs, pinned_pub):
    """Join from the pinned administrator, rejecting contradictory authenticated histories."""
    by_v = {}
    for index, doc in enumerate(docs):
        if index >= 2048:
            return None
        if _registry_shape(doc):
            by_v.setdefault(doc["v"], {})[doc_hash(doc)] = doc
    current = None
    history = []
    for version, candidates in sorted(by_v.items()):
        linked = current is not None and version == current.version + 1
        next_doc = None
        for doc in candidates.values():
            anchored = Registry().check_new(doc, pinned_admin_pub=pinned_pub)
            trusted = current.check_new(doc) if linked else False
            if anchored and current is not None and not trusted:
                return None  # Conflicting predecessor or an unverifiable gap after a known anchor.
            if trusted or anchored:
                if next_doc is not None:
                    return None
                next_doc = doc
        if next_doc is not None:
            current = Registry(next_doc)
            history.append(next_doc)
    if current is not None:
        current.trusted_history = history[-100:]
    return current
