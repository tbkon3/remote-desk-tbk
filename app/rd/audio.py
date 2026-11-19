"""Audio del PC (cio' che esce dalle casse), inviato al tecnico su richiesta.

Windows: cattura "loopback" WASAPI con PyAudioWPatch. La sorgente e' condivisa tra le
sessioni e si accende solo quando almeno una sessione ha l'audio attivo."""
import asyncio
import logging
import math
import os
import struct
import threading
import time
from collections import deque
from fractions import Fraction

import av
from aiortc.mediastreams import MediaStreamTrack

from .common import WIN

log = logging.getLogger("rd.audio")
RATE, CH, SAMPLES = 48000, 2, 960          # 20 ms a 48 kHz stereo
FRAME_BYTES = SAMPLES * CH * 2
MAX_BUFFER = FRAME_BYTES * 8               # oltre 160 ms di ritardo scarto: latenza bassa
SILENCE = bytes(FRAME_BYTES)
LAYOUTS = {1: "mono", 2: "stereo", 4: "quad", 6: "5.1", 8: "7.1"}


class AudioSource:
    def __init__(self):
        self.users = 0
        self.lock = threading.Lock()
        self.chunks = deque()
        self.bufs = {}             # lettore -> buffer: ogni sessione riceve tutto l'audio
        self.stream = self.pa = None
        self.resampler = None
        self.in_fmt = None
        self.error = None

    # ------------------------------------------------------------------ apertura/chiusura
    def acquire(self, reader):
        with self.lock:
            self.bufs[reader] = bytearray()
            self.users = len(self.bufs)
            if self.users == 1:
                self._open()
        return self.error

    def release(self, reader):
        with self.lock:
            self.bufs.pop(reader, None)
            self.users = len(self.bufs)
            if self.users == 0:
                self._close()

    def _open(self):
        self.error = None
        self.chunks.clear()
        if os.environ.get("RD_FAKE_AUDIO"):
            self.in_fmt = (RATE, 2)
            threading.Thread(target=self._fake, daemon=True).start()
            return
        if not WIN:
            self.error = "Audio disponibile solo su Windows"
            return
        try:
            import pyaudiowpatch as pyaudio
            self.pa = pa = pyaudio.PyAudio()
            wasapi = pa.get_host_api_info_by_type(pyaudio.paWASAPI)
            spk = pa.get_device_info_by_index(wasapi["defaultOutputDevice"])
            if not spk.get("isLoopbackDevice"):
                for lb in pa.get_loopback_device_info_generator():
                    if spk["name"] in lb["name"]:
                        spk = lb
                        break
                else:
                    raise RuntimeError("dispositivo loopback non trovato")
            ch = int(spk["maxInputChannels"]) or 2
            rate = int(spk["defaultSampleRate"])
            self.in_fmt = (rate, ch)

            def cb(data, frames, info, status):
                self.chunks.append(data)
                return (None, pyaudio.paContinue)
            self.stream = pa.open(format=pyaudio.paInt16, channels=ch, rate=rate, input=True,
                                  input_device_index=spk["index"], frames_per_buffer=rate // 100,
                                  stream_callback=cb)
            log.info("audio: cattura da '%s' %s Hz %s canali", spk["name"], rate, ch)
        except Exception as e:
            self.error = f"Audio non disponibile: {e}"
            log.warning(self.error)
            self._close()

    def _close(self):
        try:
            if self.stream:
                self.stream.stop_stream()
                self.stream.close()
            if self.pa:
                self.pa.terminate()
        except Exception:
            pass
        self.stream = self.pa = None
        self.resampler = None
        self.in_fmt = None

    def _fake(self):  # tono di prova (test)
        n = 0
        while self.users > 0 and os.environ.get("RD_FAKE_AUDIO"):
            vals = []
            for i in range(SAMPLES):
                v = int(8000 * math.sin(2 * math.pi * 440 * (n + i) / RATE))
                vals += [v, v]
            n += SAMPLES
            self.chunks.append(struct.pack(f"<{len(vals)}h", *vals))
            time.sleep(SAMPLES / RATE)

    # ------------------------------------------------------------------ lettura 20 ms
    def _push(self, data):
        for b in list(self.bufs.values()):
            b += data
            if len(b) > MAX_BUFFER:    # lettore in ritardo: scarto il vecchio, latenza bassa
                del b[:len(b) - FRAME_BYTES * 2]

    def read(self, reader):
        fmt = self.in_fmt
        while self.chunks and fmt:
            data = self.chunks.popleft()
            rate, ch = fmt
            if (rate, ch) == (RATE, CH):
                self._push(data)
                continue
            n = len(data) // (2 * ch)
            if not n:
                continue
            f = av.AudioFrame(format="s16", layout=LAYOUTS.get(ch, "stereo"), samples=n)
            f.planes[0].update(data[:n * 2 * ch])
            f.sample_rate = rate
            if self.resampler is None:
                self.resampler = av.AudioResampler(format="s16", layout="stereo", rate=RATE)
            for out in self.resampler.resample(f):
                self._push(bytes(out.planes[0])[:out.samples * CH * 2])
        buf = self.bufs.get(reader)
        if buf is not None and len(buf) >= FRAME_BYTES:
            out = bytes(buf[:FRAME_BYTES])
            del buf[:FRAME_BYTES]
            return out
        return None


SOURCE = AudioSource()


class SystemAudioTrack(MediaStreamTrack):
    kind = "audio"

    def __init__(self, session):
        super().__init__()
        self.s = session
        self.start = None
        self.pts = 0
        self.active = False

    def set_active(self, on):
        if on and not self.active:
            self.active = True
            return SOURCE.acquire(self)
        if not on and self.active:
            self.active = False
            SOURCE.release(self)
        return None

    async def recv(self):
        if self.start is None:
            self.start = time.time()
        else:
            self.pts += SAMPLES
            wait = self.start + self.pts / RATE - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
            elif wait < -1:
                self.start = time.time() - self.pts / RATE
        data = (SOURCE.read(self) if self.active and self.s.can_view() and "audio" in self.s.rights else None) or SILENCE
        f = av.AudioFrame(format="s16", layout="stereo", samples=SAMPLES)
        f.planes[0].update(data)
        f.sample_rate = RATE
        f.pts = self.pts
        f.time_base = Fraction(1, RATE)
        return f

    def stop(self):
        self.set_active(False)
        super().stop()
