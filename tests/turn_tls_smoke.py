"""Prova WebRTC con coturn locale. Avviare con run_turn_tls_smoke.sh su Linux."""
import asyncio
import os
import secrets
import socket
import ssl
import sys
from pathlib import Path
from unittest.mock import patch

from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from rd.ice import servers


HOST = "127.0.0.1"
PORT = 15349
URI = f"turns:{HOST}:{PORT}?transport=tcp"


def peer(secret):
    config = {"stun": [], "turn_url": URI, "turn_secret": secret}
    ice = [RTCIceServer(**entry) for entry in servers(config)]
    return RTCPeerConnection(RTCConfiguration(iceServers=ice))


def relay_candidates(description):
    result = []
    for line in description.sdp.splitlines():
        if not line.startswith("a=candidate:"):
            continue
        parts = line.split()
        if len(parts) < 8 or parts[6:8] != ["typ", "relay"] or parts[4] != HOST:
            raise AssertionError("La sessione ha proposto un percorso diverso dal relay di prova")
        result.append((parts[4], int(parts[5])))
    return result


async def wait_server():
    context = ssl.create_default_context()
    for _ in range(60):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(HOST, PORT, ssl=context, server_hostname=HOST), 2)
        except ConnectionRefusedError:
            await asyncio.sleep(0.1)
            continue
        try:
            tls = writer.get_extra_info("ssl_object")
            if tls is None or tls.version() not in {"TLSv1.2", "TLSv1.3"}:
                raise AssertionError("Connessione TLS verificata non disponibile")
        finally:
            writer.close()
            await writer.wait_closed()
        return
    raise RuntimeError("coturn non si è avviato sul loopback")


async def roundtrip(secret):
    sender, receiver = peer(secret), peer(secret)
    received = asyncio.get_running_loop().create_future()
    payload, reply = secrets.token_bytes(48), secrets.token_bytes(48)
    channel = sender.createDataChannel("turn-smoke", ordered=True)

    @receiver.on("datachannel")
    def connected(remote):
        if remote.label != "turn-smoke":
            return

        @remote.on("message")
        def echo(message):
            if message == payload:
                remote.send(reply)

    @channel.on("open")
    def send():
        channel.send(payload)

    @channel.on("message")
    def check(message):
        if not received.done():
            received.set_result(message)

    try:
        await sender.setLocalDescription(await sender.createOffer())
        first = relay_candidates(sender.localDescription)
        if not first:
            raise AssertionError("Allocazione del primo peer via TURN/TLS fallita")
        await receiver.setRemoteDescription(sender.localDescription)
        await receiver.setLocalDescription(await receiver.createAnswer())
        second = relay_candidates(receiver.localDescription)
        if not second or set(first).intersection(second):
            raise AssertionError("Il secondo peer richiede una propria allocazione TURN/TLS")
        await sender.setRemoteDescription(receiver.localDescription)
        if await asyncio.wait_for(received, 15) != reply:
            raise AssertionError("La risposta sul canale dati non corrisponde al messaggio atteso")
        print("OK: due allocazioni relay distinte, scambio DTLS/SCTP bidirezionale su TURN/TLS.")
    finally:
        await asyncio.gather(sender.close(), receiver.close())


async def expect_no_allocation(secret, label):
    pc = peer(secret)
    pc.createDataChannel("turn-smoke")
    try:
        await pc.setLocalDescription(await pc.createOffer())
        if relay_candidates(pc.localDescription):
            raise AssertionError(f"Allocazione inaspettata con {label}")
        print(f"OK: nessuna allocazione con {label}.")
    finally:
        await pc.close()


async def main(directory):
    if sys.platform != "linux" or {name for index, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError("Eseguire esclusivamente nel namespace Linux di prova con sola interfaccia lo")
    secret = (directory / "secret").read_text().strip()
    with patch.dict(os.environ, SSL_CERT_FILE=str(directory / "ca.crt"),
                    SSL_CERT_DIR=str(directory / "empty-trust")):
        await wait_server()
        await roundtrip(secret)
        await expect_no_allocation(secrets.token_hex(32), "credenziali TURN errate")
        # CA separata: il nome IP e il segreto REST sono gli stessi della prova riuscita.
        with patch.dict(os.environ, SSL_CERT_FILE=str(directory / "unrelated.crt")):
            try:
                _, writer = await asyncio.open_connection(
                    HOST, PORT, ssl=ssl.create_default_context(), server_hostname=HOST)
            except ssl.SSLCertVerificationError:
                pass
            else:
                writer.close()
                await writer.wait_closed()
                raise AssertionError("Il certificato è stato accettato con una CA estranea")
            await expect_no_allocation(secret, "CA non attendibile")
        # Esclude che il mancato candidato dei due controlli dipenda da un relay spento.
        await roundtrip(secret)


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(Path(sys.argv[1])), timeout=75))
