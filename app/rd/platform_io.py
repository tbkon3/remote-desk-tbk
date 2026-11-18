"""Cattura schermo, iniezione input e appunti: un'unica interfaccia per Windows e
(per test/uso secondario) Linux X11 / macOS."""
import logging
import os
import queue
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

    def __init__(self):
        self.sct = None
        self.born = 0
        self.desk = W.DesktopFollower() if WIN else None
        self.last = None   # ultimo array catturato

    def _reset(self):
        try:
            if self.sct:
                self.sct.close()
        except Exception:
            pass
        self.sct = None

    def monitors(self):
        if self.sct is None or time.time() - self.born > 10:
            self._reset()
            self.sct = _new_mss()
            self.born = time.time()
        return layout(self.sct)

    def grab(self, mon_index):
        """Ritorna (array BGRA, changed) oppure (None, False) se il desktop non e' leggibile."""
        if self.desk and self.desk.sync():
            self._reset()
        try:
            mon = pick(self.monitors(), mon_index)
            img = self.sct.grab({k: mon[k] for k in ("left", "top", "width", "height")})
        except Exception as e:
            log.debug("grab fallita: %s", e)
            self._reset()
            return None, False
        raw = img.bgra
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
    with _new_mss() as s:
        return layout(s)


# =========================================================================== input
class Injector:
    """Thread dedicato: riceve eventi (dict) e li inietta. Su Windows segue il desktop attivo,
    cosi' funziona anche su UAC e schermata di accesso (in modalita' servizio)."""

    def __init__(self):
        self.q = queue.Queue()
        self.mods = set()
        self.buttons = set()
        self.blocked = False
        self._mons = []
        self._mons_t = 0
        threading.Thread(target=self._run, daemon=True, name="injector").start()

    def put(self, m):
        self.q.put(m)

    def _monitors(self):
        if time.time() - self._mons_t > 5:
            try:
                self._mons = list_monitors()
            except Exception:
                pass
            self._mons_t = time.time()
        return self._mons

    def _run(self):
        desk = W.DesktopFollower() if WIN else None
        if not WIN:
            self._init_pynput()
        last_sync = 0
        while True:
            m = self.q.get()
            if desk and time.time() - last_sync > 0.25:
                desk.sync()
                last_sync = time.time()
            try:
                self._handle(m)
            except Exception as e:
                log.debug("input %s: %s", m.get("t"), e)

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
            self.tap(m.get("key", ""))
            for k in reversed(extra):
                self.mod_key(k, False)
        elif t == "combo":
            self.combo([str(x) for x in m.get("keys", [])])
        elif t == "rel":
            self._release_all()
        elif t == "_block" and WIN:
            self.blocked = bool(m.get("on"))
            W.block_input(self.blocked)

    def release_all(self):
        self.q.put({"t": "rel"})

    def _release_all(self):
        for b in list(self.buttons):
            try:
                self.button(b, False)
            except Exception:
                pass
        self.buttons.clear()
        for k in list(self.mods):
            try:
                self.mod_key(k, False)
            except Exception:
                pass
        self.mods.clear()

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
            W.key_vk(vk, True)
            W.key_vk(vk, False)

        def combo(self, keys):
            vks = [v for v in (self._vk(k) for k in keys) if v]
            for v in vks:
                W.key_vk(v, True)
            for v in reversed(vks):
                W.key_vk(v, False)

        def set_block(self, on):
            self.q.put({"t": "_block", "on": on})

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

        def set_block(self, on):
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
