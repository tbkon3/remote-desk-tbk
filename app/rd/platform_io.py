"""Cattura schermo, iniezione input e appunti: un'unica interfaccia per Windows e
(per test/uso secondario) Linux X11 / macOS."""
import logging
import os
from collections import deque
from contextlib import contextmanager, nullcontext
import shutil
import subprocess
import threading
import time

import av
import mss

from .common import WIN

log = logging.getLogger("rd.io")

if WIN:
    from . import winapi as W


def _new_mss():
    return mss.MSS() if hasattr(mss, "MSS") else mss.mss()


ALL = -1  # indice speciale: tutti gli schermi in un'unica immagine


def _desktop_ok(service):
    try:
        return not WIN or W.default_desktop_active(service)
    except OSError:
        return False


class _OtherLogon(PermissionError):
    pass


@contextmanager
def _user_context(service, expected=None):
    if WIN and service:
        from .win_identity import logon_id
        session = W.process_session()
        with W.as_session_user(session) as user:
            if not expected or (session, logon_id(user.tok)) != expected:
                raise _OtherLogon("Sessione Windows cambiata o non verificata")
            yield
    else:
        yield


def layout(sct):
    """Monitor del PC: lista di dict left/top/width/height (+ primary).
    RD_FAKE_MONITORS="x,y,w,h;x,y,w,h" simula piu' monitor (solo per i test)."""
    fake = os.environ.get("RD_FAKE_MONITORS")
    if fake:
        mons = [dict(zip(("left", "top", "width", "height"), map(int, r.split(",")))) for r in fake.split(";")]
    else:
        mons = [{k: m[k] for k in ("left", "top", "width", "height")} for m in (sct.monitors[1:] or sct.monitors[:1])]
    prim = next((i for i, m in enumerate(mons) if m["left"] == 0 and m["top"] == 0), 0)
    for i, m in enumerate(mons):
        m["primary"] = i == prim
    return mons


def bounding(mons):
    left = min(m["left"] for m in mons)
    top = min(m["top"] for m in mons)
    right = max(m["left"] + m["width"] for m in mons)
    bottom = max(m["top"] + m["height"] for m in mons)
    return {"left": left, "top": top, "width": right - left, "height": bottom - top}


def pick(mons, idx):
    if idx == ALL and len(mons) > 1:
        return bounding(mons)
    return mons[min(max(idx, 0), len(mons) - 1)]


def primary_index(mons):
    return next((i for i, m in enumerate(mons) if m.get("primary")), 0)


# =========================================================================== cattura
class Capturer:
    """Da usare sempre dallo stesso thread (mss e i desktop Windows sono legati al thread)."""

    def __init__(self, service_mode=False, expected_logon=None):
        self.sct = None
        self.born = 0
        self.service_mode = service_mode
        self.expected_logon = expected_logon
        self.last = None   # ultimo array catturato

    def _reset(self):
        try:
            if self.sct:
                self.sct.close()
        except Exception:
            pass
        self.sct = None
        self.last = None

    def monitors(self):
        if self.sct is None or time.time() - self.born > 10:
            self._reset()
            self.sct = _new_mss()
            self.born = time.time()
        return layout(self.sct)

    def grab(self, mon_index):
        """Return (None, True) to immediately replace an inaccessible desktop with black."""
        try:
            with _user_context(self.service_mode, self.expected_logon):
                if not _desktop_ok(self.service_mode):
                    self._reset()
                    return None, True
                mon = pick(self.monitors(), mon_index)
                img = self.sct.grab({k: mon[k] for k in ("left", "top", "width", "height")})
                raw = img.bgra
                if not _desktop_ok(self.service_mode):
                    self._reset()
                    return None, True
        except Exception as e:
            log.debug("grab fallita: %s", e)
            self._reset()
            return None, True
        arr = (raw, img.width, img.height)
        changed = self.last is None or self.last[1:] != arr[1:] or self.last[0] != raw
        self.last = arr
        return arr, changed


def to_frame(arr, scale):
    """arr = (bytes BGRA, larghezza, altezza)"""
    raw, w, h = arr
    frame = av.VideoFrame(w, h, "bgra")
    plane = frame.planes[0]
    stride = w * 4
    if plane.line_size == stride:
        plane.update(raw)
    else:  # righe con padding
        pad = b"\0" * (plane.line_size - stride)
        plane.update(b"".join(raw[y * stride:(y + 1) * stride] + pad for y in range(h)))
    tw = max(int(w * scale) // 2 * 2, 16)
    th = max(int(h * scale) // 2 * 2, 16)
    return frame.reformat(width=tw, height=th, format="yuv420p")


def black_frame(w=1280, h=720):
    return to_frame((bytes(w * h * 4), w, h), 1.0)


def list_monitors():
    if not _desktop_ok(False):
        return []
    with _new_mss() as s:
        return layout(s)


# =========================================================================== input
class Injector:
    """Dispatch on one thread. Consent barriers invalidate pending input before showing a dialog."""

    def __init__(self, service_mode=False):
        self.service_mode = service_mode
        self.q = deque()
        self._work = threading.Condition()
        self._pauses = 0
        self._epoch = 0
        self._barriers = []
        self._reset_requested = False
        self._release_pending = False
        self._held_logon = None
        self._stopping = False
        self.mods = set()
        self.buttons = set()
        self.blocked = False
        self._mons = []
        self._mons_t = 0
        self._thread = threading.Thread(target=self._run, daemon=True, name="injector")
        self._thread.start()

    def put(self, m, expected_logon=None, authorized=None):
        with self._work:
            if self._stopping or self._pauses or not _desktop_ok(self.service_mode):
                self._epoch += 1
                self.q.clear()
                return
            if len(self.q) >= 256:
                self.q.clear()
                self._epoch += 1
                self._reset_requested = True
            self.q.append((m, expected_logon, authorized))
            self._work.notify()

    def pause_and_drain(self):
        completed = threading.Event()
        result = []
        with self._work:
            self._pauses += 1
            self._epoch += 1
            self.q.clear()
            self._barriers.append((completed, result))
            self._work.notify()
        if not completed.wait(2) or result != [True]:
            raise PermissionError("Impossibile sospendere in sicurezza il controllo remoto")

    def resume(self):
        with self._work:
            self._pauses = max(0, self._pauses - 1)

    def close(self):
        with self._work:
            self._stopping = True
            self._epoch += 1
            self.q.clear()
            self._work.notify()
        self._thread.join(2)

    def _clear_input(self, allowed):
        # Windows only lets the blocking thread unblock input. Never synthesize key-ups
        # on an inaccessible desktop or while the interactive user token is unavailable.
        if WIN and self.blocked:
            if not W.block_input(False):
                raise OSError("Impossibile sbloccare l'input locale")
            self.blocked = False
        self._release_pending = bool(self.mods or self.buttons)
        if allowed and self._release_pending:
            guard = W.input_guard(lambda: _desktop_ok(self.service_mode)) if WIN else nullcontext()
            try:
                with _user_context(self.service_mode, self._held_logon), guard:
                    self._release_all(strict=True)
            except _OtherLogon:
                self.buttons.clear()
                self.mods.clear()
            self._release_pending = False

    def _monitors(self):
        if time.time() - self._mons_t > 5:
            try:
                self._mons = list_monitors()
            except Exception:
                pass
            self._mons_t = time.time()
        return self._mons

    def _run(self):
        if not WIN:
            self._init_pynput()
        while True:
            with self._work:
                self._work.wait_for(lambda: self._barriers or self.q or self._stopping or self._reset_requested, timeout=0.1)
                barriers, self._barriers = self._barriers, []
                reset, self._reset_requested = self._reset_requested, False
                m, expected, authorized = self.q.popleft() if self.q and not self._pauses and not reset else (None, None, None)
                epoch = self._epoch
                stopping = self._stopping
            if stopping:
                try:
                    self._clear_input(_desktop_ok(self.service_mode))
                except OSError:
                    log.debug("Chiudo il thread di input senza inviare comandi al desktop")
                finally:
                    for completed, _ in barriers:
                        completed.set()
                return
            if not barriers and not reset and m is None and not (self.blocked or self.mods or self.buttons):
                continue
            try:
                allowed = _desktop_ok(self.service_mode)
                if barriers or reset or not allowed or self._release_pending:
                    with self._work:
                        self._epoch += 1
                        self.q.clear()
                    self._clear_input(allowed)
                elif m is not None:
                    def can_send():
                        return (self._epoch == epoch and not self._pauses and (authorized is None or authorized())
                                and _desktop_ok(self.service_mode))
                    with _user_context(self.service_mode, expected), (W.input_guard(can_send) if WIN else nullcontext()):
                        if not can_send():
                            raise PermissionError("Desktop interattivo non disponibile")
                        self._held_logon = expected
                        self._handle(m)
                for _, result in barriers:
                    result.append(allowed)
            except Exception as e:
                with self._work:
                    self.q.clear()
                try:
                    self._clear_input(_desktop_ok(self.service_mode))
                except OSError:
                    pass
                log.debug("input sospeso: %s", e)
            finally:
                for completed, _ in barriers:
                    completed.set()

    # ------------------------------------------------------------------ helpers
    def _abs(self, m):
        mon = pick(self._monitors(), int(m.get("mon", 0)))
        x = min(max(float(m["x"]), 0.0), 0.9999)
        y = min(max(float(m["y"]), 0.0), 0.9999)
        return mon["left"] + int(x * mon["width"]), mon["top"] + int(y * mon["height"])

    def _handle(self, m):
        t = m.get("t")
        if t == "mm":
            self.move(*self._abs(m))
        elif t in ("md", "mu"):
            self.move(*self._abs(m))
            b = int(m.get("b", 0))
            self.button(b, t == "md")
            (self.buttons.add if t == "md" else self.buttons.discard)(b)
        elif t == "w":
            self.wheel(float(m.get("dx", 0)), float(m.get("dy", 0)))
        elif t == "mod":
            k = m.get("k")
            if k in ("ctrl", "alt", "shift", "meta"):
                if m.get("d") and k not in self.mods:
                    self.mods.add(k)
                    self.mod_key(k, True)
                elif not m.get("d") and k in self.mods:
                    self.mods.discard(k)
                    self.mod_key(k, False)
        elif t in ("ch", "txt"):
            text = str(m.get("c") if t == "ch" else m.get("text", ""))[:100_000]
            held = list(self.mods)
            for k in held:
                self.mod_key(k, False)
            self.type_text(text)
            for k in held:
                self.mod_key(k, True)
        elif t == "k":
            want = {x for x in ("ctrl", "alt", "shift", "meta") if x[0] in m.get("mods", "")}
            extra = [k for k in want if k not in self.mods]
            for k in extra:
                self.mod_key(k, True)
                self.mods.add(k)
            self.tap(m.get("key", ""))
            for k in reversed(extra):
                self.mod_key(k, False)
                self.mods.discard(k)
        elif t == "combo":
            self.combo([str(x) for x in m.get("keys", [])])
        elif t == "rel":
            self._release_all()
        elif t == "_block" and WIN:
            on = bool(m.get("on"))
            if W.block_input(on):
                self.blocked = on

    def release_all(self):
        with self._work:
            self.q.clear()
            self._epoch += 1
            self._reset_requested = True
            self._work.notify()

    def _release_all(self, strict=False):
        failed = False
        for b in list(self.buttons):
            try:
                self.button(b, False)
                self.buttons.discard(b)
            except Exception:
                failed = True
        for k in list(self.mods):
            try:
                self.mod_key(k, False)
                self.mods.discard(k)
            except Exception:
                failed = True
        if failed and strict:
            raise PermissionError("Impossibile rilasciare i comandi di input")

    # ------------------------------------------------------------------ backend Windows
    if WIN:
        def move(self, x, y):
            W.mouse_move_abs(x, y)

        def button(self, b, down):
            W.mouse_button(b, down)

        def wheel(self, dx, dy):
            W.mouse_wheel(int(dx * 1.2), int(dy * 1.2))

        def mod_key(self, k, down):
            W.key_vk(W.MOD_VK[k], down)

        def type_text(self, text):
            W.type_text(text)

        def _vk(self, key):
            if key in W.VK_NAMES:
                return W.VK_NAMES[key]
            if len(key) == 1:
                if key.isascii() and key.isalnum():
                    return ord(key.upper())
                return W.vk_for_char(key)
            return None

        def tap(self, key):
            vk = self._vk(key)
            if vk is None:
                if len(key) == 1:
                    W.type_text(key)
                return
            W.key_combo([vk])

        def combo(self, keys):
            vks = [v for v in (self._vk(k) for k in keys) if v]
            W.key_combo(vks)

        def set_block(self, on, expected_logon=None, authorized=None):
            if on:
                self.put({"t": "_block", "on": True}, expected_logon, authorized)
            else:
                self.release_all()

    # ------------------------------------------------------------------ backend pynput (Linux/mac)
    else:
        def _init_pynput(self):
            from pynput.keyboard import Controller as KC, Key, KeyCode
            from pynput.mouse import Button, Controller as MC
            self._Key, self._KeyCode, self._Button = Key, KeyCode, Button
            self._kb, self._mouse = KC(), MC()
            g = lambda n: getattr(Key, n, None)  # noqa: E731
            self._names = {
                "Enter": g("enter"), "Backspace": g("backspace"), "Tab": g("tab"), "Escape": g("esc"),
                "Delete": g("delete"), "Insert": g("insert"), "Home": g("home"), "End": g("end"),
                "PageUp": g("page_up"), "PageDown": g("page_down"), "ArrowUp": g("up"),
                "ArrowDown": g("down"), "ArrowLeft": g("left"), "ArrowRight": g("right"), " ": g("space"),
                "CapsLock": g("caps_lock"), "ContextMenu": g("menu"), "PrintScreen": g("print_screen"),
                "ctrl": g("ctrl"), "alt": g("alt"), "shift": g("shift"), "win": g("cmd"), "meta": g("cmd"),
                "tab": g("tab"), "esc": g("esc"), "del": g("delete"), "enter": g("enter"),
                "print_screen": g("print_screen"), "space": g("space"),
            }
            for i in range(1, 21):
                self._names[f"F{i}"] = self._names[f"f{i}"] = g(f"f{i}")

        def move(self, x, y):
            self._mouse.position = (x, y)

        def button(self, b, down):
            btn = {0: self._Button.left, 1: self._Button.middle, 2: self._Button.right}.get(b, self._Button.left)
            (self._mouse.press if down else self._mouse.release)(btn)

        def wheel(self, dx, dy):
            sx = 0 if not dx else (1 if dx > 0 else -1) * max(1, round(abs(dx) / 100))
            sy = 0 if not dy else (-1 if dy > 0 else 1) * max(1, round(abs(dy) / 100))
            self._mouse.scroll(sx, sy)

        def mod_key(self, k, down):
            key = self._names["win" if k == "meta" else k]
            (self._kb.press if down else self._kb.release)(key)

        def type_text(self, text):
            self._kb.type(text)

        def _key(self, key):
            if key in self._names:
                return self._names[key]
            if len(key) == 1:
                return self._KeyCode.from_char(key.lower())
            return None

        def tap(self, key):
            k = self._key(key)
            if k is not None:
                self._kb.press(k)
                self._kb.release(k)

        def combo(self, keys):
            ks = [k for k in (self._key(x) for x in keys) if k is not None]
            for k in ks:
                self._kb.press(k)
            for k in reversed(ks):
                self._kb.release(k)

        def set_block(self, on, expected_logon=None, authorized=None):
            pass


# =========================================================================== appunti
class Clipboard:
    """Testo negli appunti. Windows: API native. Linux: xclip/xsel se presenti. mac: pbcopy."""

    def __init__(self):
        self.mem = ""
        self.tool = None
        if not WIN:
            if shutil.which("pbcopy"):
                self.tool = ("pbpaste", ["pbcopy"])
            elif shutil.which("xclip"):
                self.tool = (["xclip", "-selection", "clipboard", "-o"], ["xclip", "-selection", "clipboard"])
            elif shutil.which("xsel"):
                self.tool = (["xsel", "-b", "-o"], ["xsel", "-b", "-i"])

    def get(self):
        if WIN:
            return W.clip_get()
        if self.tool:
            try:
                r = subprocess.run(self.tool[0], capture_output=True, timeout=2)
                return r.stdout.decode("utf-8", "replace")
            except Exception:
                return None
        return self.mem

    def set(self, text):
        if WIN:
            return W.clip_set(text)
        if self.tool:
            try:
                subprocess.run(self.tool[1], input=text.encode(), timeout=2)
                return True
            except Exception:
                return False
        self.mem = text
        return True
