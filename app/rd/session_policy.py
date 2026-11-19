"""Session authorization, shared between admission and the live channel handlers."""
import re
from . import auth


def capabilities(cfg, reg, user, mode, windows):
    rights = reg.rights(user, cfg["id"])
    if not cfg["accept_incoming"] or auth.MODE_RIGHTS.get(mode) not in rights:
        return set()
    if mode == "manage":
        return {"inventory"} if windows and cfg.get("allow_inventory") else set()
    if mode == "files":
        return rights.intersection({"files", "files_write", "files_delete"}) if cfg.get("allow_files") else set()
    if mode == "view":
        return {"view"}
    if mode != "control" or not cfg["allow_control"]:
        return set()
    granted = {"view", "control", "audio"}
    if cfg.get("allow_clipboard"):
        granted.add("clipboard")
    if windows and not cfg.get("on_air"):
        for right, setting in (("power", "allow_power"), ("block_input", "allow_local_block"),
                               ("secure_desktop", "allow_sas")):
            if right in rights and cfg.get(setting):
                granted.add(right)
    return granted


def permitted_channels(mode):
    return {"view": ("ctl",), "control": ("ctl", "mm"), "files": ("ctl", "files"),
            "manage": ("inventory",)}.get(mode, ())


def validate_sdp(sdp, mode):
    """Validate the same SDP representation that the DTLS implementation consumes."""
    from aiortc.sdp import SessionDescription
    kinds = {"manage": {"application"}, "files": {"application"}, "view": {"application", "video"},
             "control": {"application", "video", "audio"}}
    if mode not in kinds or not isinstance(sdp, str) or len(sdp) > 256 * 1024:
        raise ValueError("Descrizione di sessione non valida")
    try:
        media = SessionDescription.parse(sdp).media
    except Exception as exc:
        raise ValueError("Descrizione di sessione non valida") from exc
    offered = [item.kind for item in media]
    if ("application" not in offered or len(offered) != len(set(offered))
            or not set(offered).issubset(kinds[mode])):
        raise ValueError("I canali audio, video o dati richiesti non corrispondono alla modalità")
    for item in media:
        if not item.dtls or not any(
                fp.algorithm.lower() in ("sha-256", "sha-384", "sha-512")
                and len(fp.value.split(":")) == int(fp.algorithm[4:]) // 8
                and re.fullmatch(r"(?:[0-9A-Fa-f]{2}:)*[0-9A-Fa-f]{2}", fp.value)
                for fp in item.dtls.fingerprints):
            raise ValueError("Impronta DTLS assente o non valida")


def prompt_capabilities(scope):
    labels = (("view", "vedere lo schermo"), ("control", "usare tastiera e mouse"),
              ("files", "leggere i file consentiti"), ("files_write", "creare file e cartelle"),
              ("files_delete", "eliminare file e cartelle"), ("inventory", "consultare l'inventario di condivisioni, unità, servizi e applicazioni Windows"),
              ("audio", "ascoltare l'audio di sistema"), ("clipboard", "scambiare appunti se attivati"),
              ("power", "bloccare, riavviare o spegnere il PC"), ("block_input", "bloccare l'input locale"),
              ("secure_desktop", "inviare Ctrl+Alt+Canc"))
    return ", ".join(label for right, label in labels if right in scope)
