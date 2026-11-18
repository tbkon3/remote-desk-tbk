# RemoteDesk

Assistenza e controllo remoto tra i **tuoi** PC Windows, **senza server propri** e senza limiti di tempo.
Un'unica cartella portabile (`RemoteDesk.exe` + Python incluso): nessuna installazione obbligatoria.

- Rubrica delle macchine della tua rete: quelle accese sono raggiungibili con un clic
- Utenti con password e **permessi per singola macchina**, piu' reti sullo stesso PC
- Schermo, mouse e tastiera, **Ctrl+Alt+Canc**, UAC e schermata di accesso (modalita' servizio)
- Piu' monitor, file manager, appunti condivisi, audio, chat, registro accessi
- Connessione diretta tra i PC (WebRTC, cifrata), segnalazione cifrata end-to-end

> **Download:** scarica `RemoteDesk-<versione>.zip` dalla pagina [Releases](../../releases) ed estrailo
> (es. in `C:\RemoteDesk`). Su ogni PC estrai **lo zip originale**: non copiare una cartella gia' usata.

---

## Indice
1. [Installazione rapida](#installazione-rapida)
2. [Uso](#uso)
3. [Reti, utenti e permessi](#reti-utenti-e-permessi)
4. [Modalita' servizio (Ctrl+Alt+Canc, UAC, accesso)](#modalita-servizio)
5. [Connessione: segnalazione, firewall e TURN](#connessione-segnalazione-firewall-e-turn)
6. [Dove sono i dati](#dove-sono-i-dati)
7. [Sicurezza](#sicurezza)
8. [Limiti noti](#limiti-noti)
9. [Stato dei test](#stato-dei-test)
10. [Sviluppo e build](#sviluppo-e-build)
11. [Risoluzione dei problemi](#risoluzione-dei-problemi)

---

## Installazione rapida

**Requisiti:** Windows 10 o 11 a 64 bit, Microsoft Edge o Google Chrome (gia' presenti su Windows 10/11).

### Primo PC (crea la rete)
1. Estrai lo zip in una cartella fissa, es. `C:\RemoteDesk`, e avvia `RemoteDesk.exe`.
2. Nella console scegli **"Crea una nuova rete"**: nome rete, tuo utente amministratore, password (min. 10 caratteri).
3. Annota la **chiave di rete** mostrata (es. `ABCDEF-GHJKLM-NPQRST-UVWXYZ`); la ritrovi nella sezione **Reti**.

### Ogni altro PC (entra nella rete)
1. Estrai lo zip originale e avvia `RemoteDesk.exe`.
2. Scegli **"Entra in una rete esistente"**: nome rete + chiave di rete + utente e password di un **amministratore**.
   Serve che almeno un altro PC della rete sia acceso.
3. Sui PC da assistere conviene installare la **modalita' servizio** (Impostazioni > Installa servizio).

Al primo avvio Windows puo' chiedere di consentire "Python" nel firewall: rispondi **Consenti**
(oppure usa `tools/Consenti-RemoteDesk-firewall.bat`, vedi [Risoluzione dei problemi](#risoluzione-dei-problemi)).
L'exe non e' firmato: se SmartScreen avvisa, "Ulteriori informazioni" > "Esegui comunque".

---

## Uso

### Console
| Sezione | Contenuto |
|---|---|
| **Macchine** | Le macchine su cui hai permessi, raggruppate per rete. Verde = online. Pulsanti **Controlla**, **Guarda**, **File** (doppio clic = azione principale). |
| **Reti** | Reti di questo PC, stato, il tuo accesso, chiave di rete (solo admin), *Aggiungi una rete*, *Lascia rete*. |
| **Su questo PC** | Chi e' collegato a questo PC adesso (con *Disconnetti*) e registro eventi locale. Visibile anche senza login. |
| **Utenti e permessi** | (admin) Utenti della rete, permessi per macchina, macchine registrate. |
| **Registro accessi** | (admin) Storico raccolto dai PC accesi, filtri ed export CSV. |
| **Impostazioni** | (admin) Impostazioni di questo PC, avvio automatico, servizio, server di segnalazione e TURN. |

### Finestra di sessione
Ogni sessione e' una finestra indipendente e ridimensionabile: puoi controllare **piu' macchine contemporaneamente**, anche di reti diverse.

| Funzione | Dettagli |
|---|---|
| Schermo | *Adatta alla finestra* o *Dimensione reale*, schermo intero (cattura anche Esc, Alt+Tab, tasto Windows in Edge/Chrome) |
| Piu' monitor | Menu **Schermo 1 / Schermo 2 / ...**, **Tutti gli schermi (una finestra)**, **Tutti gli schermi (una finestra per schermo)**; all'avvio si vede il monitor principale |
| Qualita' | Massima fluidita' (30 fps), Alta, Normale, Veloce, Rete lenta |
| Tastiera | Testo con AltGr e lettere accentate, combinazioni; menu **Tasti**: Ctrl+Alt+Canc, Win, Alt+Tab, Gestione attivita', Win+R/E/D, Alt+F4, Stamp |
| Mouse | Clic sinistro/destro/centrale, trascinamento, rotellina, pulsanti avanti/indietro |
| Appunti | Copia/incolla di testo nei due sensi (casella *Appunti*) |
| File | File manager del PC remoto: scarica (cartelle come .zip), carica, rinomina, elimina, nuova cartella; trascina file e cartelle sulla finestra |
| Audio | Pulsante **Audio: off/on** (parte spento): senti l'audio del PC remoto |
| Chat | Pulsante **Chat**: sul PC remoto si apre una finestrella in basso a destra, l'utente risponde da li' |
| Azioni | Invia testo, blocca il PC, blocca mouse/tastiera dell'utente, riavvia, spegni |
| Riconnessione | Automatica se la connessione cade (anche dopo un riavvio del PC remoto con il servizio installato) |

---

## Reti, utenti e permessi

- Una **rete** ha nome, **chiave di rete**, utenti, permessi e registro propri. Un PC puo' far parte di **piu' reti**
  (es. "Ufficio" e "Clienti"), che non si vedono tra loro.
- La chiave di rete serve solo a far trovare le macchine tra loro: per collegarsi servono sempre **utente e password**.
- Si fa il login **separatamente in ogni rete** (gli utenti di reti diverse sono distinti).
- Per aggiungere un PC a un'ulteriore rete serve essere **amministratore di una delle reti di quel PC**.

Permessi assegnabili per ogni macchina (o per "tutte le macchine", anche future):

| Permesso | Cosa consente |
|---|---|
| nessun accesso | la macchina non compare |
| solo visione | vedere lo schermo (e sentire l'audio) |
| visione + file | come sopra + file manager |
| solo file | solo file manager (lo schermo non viene inviato) |
| controllo | schermo, mouse, tastiera, appunti, azioni |
| controllo + file | tutto |
| **amministratore** | tutto su tutte le macchine della rete + gestione utenti e registro |

Le modifiche arrivano alle macchine accese in pochi secondi; se un permesso viene tolto, le sessioni in corso di quell'utente vengono chiuse (o perdono subito la funzione revocata).

Ogni PC puo' inoltre limitare localmente cosa e' consentito (connessioni in ingresso, conferma dell'utente, controllo, file, appunti).

---

## Modalita' servizio

Consigliata sui PC da assistere. Si installa da **Impostazioni > Installa servizio** (Windows chiede la conferma da amministratore).

- Parte con Windows **anche senza nessun utente collegato** e si ricollega da sola dopo un riavvio.
- Abilita **Ctrl+Alt+Canc**, le finestre **UAC** e la **schermata di accesso/blocco**.
- Funzionamento: un'attivita' pianificata parte all'avvio come `SYSTEM` e lancia l'agente come `SYSTEM` dentro la
  sessione della console (segue cambio utente e logout).
- Per sicurezza il servizio viene copiato ed eseguito da `C:\Program Files\RemoteDesk` (non modificabile dagli utenti
  normali) e tiene i dati in `C:\ProgramData\RemoteDesk\data` (solo SYSTEM e Amministratori).
- Il file manager, anche in modalita' servizio, opera **con i diritti dell'utente collegato a Windows**, non come SYSTEM.
- **Rimozione:** tasto destro sull'icona di RemoteDesk > *Rimuovi servizio...*, oppure `tools/Rimuovi-servizio-RemoteDesk.bat`.

---

## Connessione: segnalazione, firewall e TURN

```
 PC A (console)                     ntfy.sh (o tuo server)                 PC B (agente)
  |  presenza/offerta firmate e cifrate  ------->  topic della rete  ------->  |
  |  <-------  risposta firmata dalla macchina, cifrata  <-------              |
  |=================== WebRTC diretto (DTLS-SRTP), schermo/input/file ========|
```

- **Segnalazione:** per presentarsi e scambiarsi i parametri di connessione i PC usano un topic di
  [ntfy](https://ntfy.sh) (servizio pubblico gratuito). I messaggi sono **cifrati AES-256-GCM** con la chiave di rete:
  il server vede solo dati illeggibili. Puoi usare un server ntfy tuo (Impostazioni > Connessione), uguale su tutti i PC.
- **Dati:** schermo, input, file e audio viaggiano **direttamente** tra i PC (WebRTC), con STUN di Google/Cloudflare
  per attraversare i router.
- **Firewall:** RemoteDesk deve poter ricevere connessioni UDP. Se Windows ha bloccato Python, i PC si vedono in
  console ma la sessione non parte: usa `tools/Consenti-RemoteDesk-firewall.bat` su entrambi i PC.
- **TURN (facoltativo):** serve solo se i due PC sono in reti diverse molto restrittive (reti mobili/aziendali con NAT
  simmetrico). Ogni PC usa il TURN delle **proprie** impostazioni: in genere basta su uno, ma e' consigliato
  configurarlo **su entrambi, con lo stesso server** (es. coturn su un VPS o un servizio TURN commerciale).
- **Latenza:** tipicamente 30-80 ms in rete locale, 60-150 ms su Internet. Accorgimenti: canale non affidabile per i
  movimenti del mouse, nessun buffer video, 30 fps durante l'interazione.

---

## Dove sono i dati

| Modalita' | Cartella | Accesso |
|---|---|---|
| Utente | `%LOCALAPPDATA%\RemoteDesk\data` | solo l'utente |
| Servizio | `C:\ProgramData\RemoteDesk\data` | solo SYSTEM e Amministratori |

Contenuto: `config.json` (+ `.bak`), `machine.key` (chiave privata del PC), `audit.jsonl` (registro accessi, 90 giorni),
`logs\`. **Non pubblicare mai questi file.** Se la cartella viene copiata su un altro PC, RemoteDesk se ne accorge e crea
una nuova identita' (salvando una copia di sicurezza di quella vecchia).

---

## Sicurezza

Sintesi (dettagli in [SECURITY.md](SECURITY.md)):

- Le password non lasciano mai il PC: da rete + utente + password si ricava (scrypt) una chiave **Ed25519**.
- Ogni richiesta di connessione e' **firmata dall'utente** (include l'hash dell'offerta WebRTC, quindi l'impronta DTLS);
  ogni risposta e' **firmata dalla macchina**. Niente man-in-the-middle anche se la chiave di rete venisse scoperta.
- Il **registro** (utenti, permessi, macchine) e' una catena di versioni firmate da un amministratore: ogni versione
  contiene l'hash della precedente; una nuova versione e' accettata solo se e' la successiva ed e' firmata da un admin
  della versione corrente.
- La console web locale risponde solo su `127.0.0.1`, con login, cookie `HttpOnly`/`SameSite=Strict`, controlli
  anti-CSRF e anti-DNS-rebinding e Content-Security-Policy.
- Registro accessi per rete: sessioni, file (anche eliminati/rinominati), appunti (primi 300 caratteri), login falliti,
  accessi negati. Le richieste sono firmate e le risposte cifrate solo per l'amministratore che le chiede.
- Chi sta al PC vede sempre chi e' collegato e puo' scollegare tutti; opzione "chiedi conferma".

---

## Limiti noti

- Video codificato via software (VP8): ottimo per assistenza e ufficio, non per giochi/video fluidi come Parsec (GPU).
- Audio solo dal PC remoto verso il tecnico (niente microfono). Appunti: solo testo.
- Il registro accessi di un PC spento si vede solo quando torna acceso.
- Le macchine Windows controllate richiedono Windows 10/11; la console funziona anche su Linux/macOS dai sorgenti
  (controllo di macchine Linux X11 possibile ma secondario).
- Rischi residui documentati in [SECURITY.md](SECURITY.md#rischi-residui).

---

## Stato dei test

Verificato automaticamente (Playwright + Chromium, display virtuale) **su Linux** con piu' istanze e un server ntfy
locale, e **con la build Windows eseguita sotto Wine**:

- creazione/ingresso in rete dall'interfaccia, piu' reti sullo stesso PC, isolamento tra reti, uscita da una rete;
- controllo (mouse, tastiera, selezione con Shift, Ctrl+C/Ctrl+V), appunti nei due sensi, upload/download;
- multi-monitor (simulato), finestre per schermo, audio (sorgente di prova), chat nei due sensi, registro accessi;
- sicurezza: password errate, permessi (visione/file/controllo), tentativi da strumenti sviluppatore, revoca immediata,
  CSRF/origini esterne, accessi anonimi, catena del registro (salti di versione, admin revocato);
- cartella copiata da un altro PC, migrazione da configurazioni precedenti.

Il codice e' stato inoltre sottoposto a una code review con piu' revisori indipendenti e verifica avversaria
(51 problemi confermati, tutti corretti nella 2.2.0).

**Non ancora verificato su Windows reale:** installazione/rimozione del servizio (attivita' pianificata, Program Files,
permessi delle cartelle), Ctrl+Alt+Canc/UAC/schermata di accesso, impersonazione dell'utente per i file, cattura audio
WASAPI, monitor fisici multipli, apertura della finestrella di chat con Edge.

---

## Sviluppo e build

### Struttura
```
app/
  remotedesk.py      avvio: app con icona, --service (supervisore), --session-agent, --install/--uninstall-service
  rd/common.py       configurazione, percorsi dati, impronta macchina, cifratura segnalazione (NetKey)
  rd/auth.py         chiavi utente (scrypt+Ed25519), registro firmato a catena, trust_chain per l'ingresso in rete
  rd/network.py      una istanza per rete: presenza, offerte/risposte firmate, sincronizzazione registro, registro accessi
  rd/agent.py        sessioni in ingresso, cattura schermo, login console per rete, chat, appunti
  rd/web.py          API locale (127.0.0.1) e protezioni
  rd/files.py        file manager sul data channel
  rd/audit.py        registro accessi + cifratura X25519 delle risposte
  rd/audio.py        cattura loopback WASAPI (PyAudioWPatch)
  rd/platform_io.py  cattura (mss), iniezione input, multi-monitor
  rd/winapi.py       ctypes: SendInput, desktop sicuro, SendSAS, appunti, CreateProcessAsUser, impersonazione
  rd/service.py      installazione servizio e supervisore
  web/               console.html, session.html, chat.html (vanilla JS)
build/               build_bundle.sh, avviatore C (launcher.c/.rc), icona, LEGGIMI.txt del pacchetto
tools/               script .bat di supporto (rimozione servizio, firewall)
tests/mock_ntfy.py   server ntfy minimo per prove in locale
```

### Eseguire dai sorgenti
```bash
pip install -r requirements.txt
python app/remotedesk.py              # app con icona e console
python app/remotedesk.py --agent-only --data ./data-test --port 47801 --no-browser   # solo agente
```

### Prove in locale con piu' istanze
```bash
python tests/mock_ntfy.py &
python app/remotedesk.py --agent-only --data A --port 47801 &
python app/remotedesk.py --agent-only --data B --port 47802 &
# poi in entrambe le console (http://127.0.0.1:47801 e :47802): Impostazioni > Server di segnalazione = http://127.0.0.1:8099
```
Variabili utili per i test: `RD_FAKE_MONITORS="0,0,800,900;800,0,800,900"` (simula due monitor),
`RD_FAKE_AUDIO=1` (tono di prova), `RD_FP=<testo>` (impronta macchina fittizia).

### Costruire lo zip per Windows (da Linux)
```bash
sudo apt install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 zip unzip
./build/build_bundle.sh               # crea build/RemoteDesk-<versione>.zip
```
Lo script scarica Python 3.12 per Windows (pacchetto ufficiale NuGet), le wheel delle librerie per `win_amd64`,
compila `RemoteDesk.exe` con mingw-w64 e crea lo zip.

---

## Risoluzione dei problemi

| Sintomo | Causa probabile / soluzione |
|---|---|
| Al primo avvio non compare "Entra in una rete" | Cartella copiata da un PC gia' configurato: dalla 2.2 viene rilevato automaticamente; altrimenti estrai lo zip originale. |
| I PC si vedono ma la sessione non parte ("Connessione diretta non riuscita") | Firewall di Windows: `tools/Consenti-RemoteDesk-firewall.bat` su entrambi i PC (va messo nella cartella di RemoteDesk). Se i PC sono in reti diverse e restrittive: configura un TURN. |
| "Nessuna risposta" | Il PC remoto non riceve: e' acceso? stesso server di segnalazione su entrambi? |
| "Autenticazione non valida" / "non ha il permesso" | Utente o permessi: controlla in *Utenti e permessi*. |
| Ctrl+Alt+Canc non funziona | Serve la modalita' servizio sul PC remoto. |
| Voglio togliere il servizio | Icona > *Rimuovi servizio...* oppure `tools/Rimuovi-servizio-RemoteDesk.bat` (doppio clic, conferma). |
| "registro in conflitto" in *Reti* | Due versioni diverse del registro utenti: lascia la rete e rientra con un amministratore attuale. |

Log: `%LOCALAPPDATA%\RemoteDesk\data\logs\app.log` (modalita' utente) oppure
`C:\ProgramData\RemoteDesk\data\logs\session-agent.log` (servizio). Non contengono password.

---

## Licenza

Nessuna licenza e' ancora stata scelta per questo progetto: finche' non viene aggiunto un file `LICENSE`, tutti i diritti
restano all'autore. Le librerie incluse nel pacchetto (Python, aiortc, PyAV/FFmpeg, aiohttp, cryptography, mss, Pillow,
pystray, PyAudioWPatch, ...) hanno ciascuna la propria licenza, presente nella cartella `runtime` dello zip.
