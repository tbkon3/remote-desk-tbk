"""Configurazione ICE condivisa dai due peer. Nessuna risoluzione DNS durante la validazione."""
import base64
import hmac
import ipaddress
import re
import secrets
import time


TURN_LIFETIME = 3600
MAX_STUN = 8
_URI = re.compile(r"(stun|turn|turns):([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?(?:\?transport=(tcp|udp))?")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _validated_url(value, schemes):
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("Indirizzo ICE non valido")
    match = _URI.fullmatch(value)
    if not match or match[1] not in schemes:
        raise ValueError("Indirizzo ICE non valido. Usare un nome DNS o IPv4 e una porta facoltativa")
    scheme, host, port, transport = match.groups()
    host = host.lower()
    if len(host) > 253 or not all(_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError("Nome host ICE non valido")
    if re.fullmatch(r"[0-9.]+", host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            raise ValueError("Indirizzo IPv4 ICE non valido") from None
    if port and not 0 < int(port) <= 65535:
        raise ValueError("Porta ICE non valida")
    if scheme == "stun" and transport:
        raise ValueError("STUN non accetta il parametro transport")
    if scheme == "turns" and transport not in (None, "tcp"):
        raise ValueError("TURN via TLS richiede TCP")
    canonical = f"{scheme}:{host}" + (f":{int(port)}" if port else "")
    return canonical + (f"?transport={transport}" if transport else "")


def validate_turn_url(value):
    return "" if value == "" else _validated_url(value, ("turn", "turns"))


def validate_stun(values):
    if not isinstance(values, list) or len(values) > MAX_STUN:
        raise ValueError(f"Specificare al massimo {MAX_STUN} server STUN")
    return list(dict.fromkeys(_validated_url(value, ("stun",)) for value in values))


def _credential(value, label):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"Valore {label} TURN non valido")
    return value


def servers(cfg):
    result = [{"urls": url} for url in validate_stun(cfg.get("stun", []))]
    url = validate_turn_url(cfg.get("turn_url", ""))
    if not url:
        return result
    shared = _credential(cfg.get("turn_secret", ""), "segreto")
    if shared:
        if len(shared.encode("utf-8")) < 32:
            raise ValueError("Il segreto condiviso TURN deve essere di almeno 32 byte")
        # Formato TURN REST di coturn. L'identificativo casuale non rivela utente o macchina.
        username = f"{int(time.time()) + TURN_LIFETIME}:{secrets.token_hex(12)}"
        password = base64.b64encode(hmac.digest(shared.encode(), username.encode("ascii"), "sha1")).decode("ascii")
    else:
        username = _credential(cfg.get("turn_user", ""), "utente")
        password = _credential(cfg.get("turn_pass", ""), "password")
        if not username or not password:
            raise ValueError("Configurare il segreto condiviso o le credenziali statiche TURN")
    result.append({"urls": url, "username": username, "credential": password})
    return result
