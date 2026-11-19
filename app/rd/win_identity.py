"""Bind an interactive service session to its Windows logon AuthenticationId."""
import ctypes


def logon_id(token):
    from . import winapi as W
    # TOKEN_STATISTICS begins with TokenId and AuthenticationId, both LUIDs.
    stats = ctypes.create_string_buffer(256)
    size = ctypes.c_uint32()
    if not W.advapi32.GetTokenInformation(token, 10, stats, len(stats), ctypes.byref(size)) or size.value < 16:
        raise PermissionError("Identità della sessione Windows non disponibile")
    return bytes(stats[8:16])


def interactive_logon():
    from . import winapi as W
    from ctypes import wintypes
    sid = W.process_session()
    token = wintypes.HANDLE()
    if not sid or not W.wtsapi32 or not W.wtsapi32.WTSQueryUserToken(sid, ctypes.byref(token)):
        raise PermissionError("Nessuna sessione Windows interattiva")
    try:
        return sid, logon_id(token)
    finally:
        W.kernel32.CloseHandle(token)


def effective_logon():
    """Inside file workers, query the already impersonated token without switching identities."""
    from . import winapi as W
    from ctypes import wintypes
    token = wintypes.HANDLE()
    current = wintypes.HANDLE(W.kernel32.GetCurrentThread())
    if W.advapi32.OpenThreadToken(current, 0x0008, True, ctypes.byref(token)):
        try:
            return W.process_session(), logon_id(token)
        finally:
            W.kernel32.CloseHandle(token)
    if ctypes.get_last_error() != 1008:  # ERROR_NO_TOKEN
        raise PermissionError("Token del thread non disponibile")
    return interactive_logon()
