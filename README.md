# RemoteDesk

## Sorgenti in revisione · protocollo 2

La console gestisce i PC Windows registrati nella stessa rete RemoteDesk. Questa revisione richiede il protocollo 2 su entrambi i PC per avviare una sessione. Lo ZIP 2.3.2 distribuito in precedenza usa il protocollo precedente.

**Gestisci PC** apre un canale dati dedicato. Dalla rubrica seleziona una macchina Windows online con inventario abilitato. Il tecnico deve ricevere il diritto **Inventario** su quella macchina e ottenere la conferma locale. Può consultare condivisioni, unità, servizi e applicazioni installate visibili all'utente. La scheda Applicazioni rimanda a Microsoft Intune per l'assegnazione del software aziendale. L'operatore sceglie il tenant e i destinatari e controlla l'esito in Intune.

I profili di connessione hanno canali distinti per visualizzazione, controllo, file e inventario. Al primo avvio di questa revisione il PC richiede nuovamente l'abilitazione locale di file e appunti. Gli appunti si trasferiscono con i pulsanti di invio e ricezione. La chat locale richiede la scelta di un tecnico quando ce ne sono più di uno. La modalità **In onda** limita alimentazione, blocco dell'input, desktop sicuro e aggiornamenti automatici.

### Uso tra sedi o tramite Internet

1. Configura almeno un relay di segnalazione comune e raggiungibile da entrambe le sedi. La configurazione iniziale usa servizi pubblici. Per un'installazione amministrata puoi inserire endpoint HTTPS, WSS o MQTTS aziendali. I servizi di segnalazione e STUN osservano gli indirizzi e gli orari delle connessioni.
2. In **Impostazioni** configura STUN e un servizio TURN raggiungibile dai due PC. Per una rete che limita UDP, configura il server con certificato valido e prova un URL come `turns:turn.azienda.it:443?transport=tcp`. La porta 443 deve servire TURN/TLS. Disponibilità di rete, DNS, proxy, certificati e policy dei due firewall determinano il risultato.
3. Usa credenziali TURN distinte per l'ambiente. Il segreto coturn opzionale produce credenziali temporanee di un'ora. Chi amministra un endpoint che contiene il segreto può emettere credenziali, quindi distribuiscilo soltanto su endpoint amministrati. Con credenziali statiche il browser autorizzato riceve la password TURN. La console HTTP resta su loopback. Mantieni la porta 47800 fuori dal port forwarding.
4. Collauda due PC pilota su accessi Internet indipendenti, per esempio la sede e un hotspot. Prova prima l'inventario e poi la visualizzazione con consenso. Annota il percorso riportato dall'interfaccia. In una rete di collaudo che richiede un relay, verifica che compaia **Via TURN**. Ripeti con accesso negato, revoca durante la sessione, logout e interruzione della connessione. Una voce TURN nelle impostazioni indica configurazione. La coppia ICE selezionata durante la sessione identifica il percorso realmente utilizzato.

Per gli stati di sicurezza e i prerequisiti di migrazione consulta [SECURITY.md](SECURITY.md).

### Test dai sorgenti

Da un ambiente di sviluppo con Python 3.12, le dipendenze di `requirements.txt` e Node, esegui `python -m unittest discover -s tests` e `node --test tests/*.cjs`. La suite usa identità effimere, file sintetici e inventario simulato. Comprende un test TCP su loopback e test Win32 che dipendono dai permessi del runner. Il collaudo WAN con TURN reale richiede due accessi di rete e credenziali di test.

Il workflow di regressione include anche una prova Linux con un server coturn temporaneo, TLS e due peer su una rete isolata. Il traffico di questo test rimane sul runner. Il collaudo tra sedi verifica in più DNS, certificati, firewall e raggiungibilità dell'infrastruttura destinata alla produzione.

---

## Manuale della distribuzione precedente (2.3.2)

Le istruzioni seguenti descrivono il pacchetto 2.3.2, comprese le sue impostazioni e le prove eseguite prima di questa revisione.

Assistenza e controllo remoto tra i **tuoi** PC Windows, **senza server propri** e senza limiti di tempo.
Un'unica cartella portabile (`RemoteDesk.exe` + Python incluso): nessuna installazione obbligatoria.

- Rubrica delle macchine della tua rete: quelle accese sono raggiungibili con un clic
- Utenti con password e **permessi per singola macchina**, piu' reti sullo stesso PC
- Schermo, mouse e tastiera, **Ctrl+Alt+Canc**, UAC e schermata di accesso (modalita' servizio)
- Piu' monitor, file manager, appunti condivisi, audio, chat, registro accessi
- Connessione diretta tra i PC (WebRTC, cifrata), segnalazione cifrata end-to-end

> ### [⬇ Scarica RemoteDesk 2.3.2 per Windows (zip, 53 MB)](https://github.com/tbkon3/remote-desk-tbk/raw/main/dist/RemoteDesk-2.3.2.zip)
> Il link scarica direttamente lo zip. Impronta SHA-256 in [dist/RemoteDesk-2.3.2.zip.sha256](dist/RemoteDesk-2.3.2.zip.sha256).
> Il binario 2.3.2 è privo di firma Authenticode.
> Estrai lo zip (es. in `C:\RemoteDesk`); su ogni PC usa **lo zip originale**, non una cartella gia' usata.

---

## Indice
1. [Installazione rapida](#installazione-rapida)
2. [Uso](#uso)
3. [Reti, utenti e permessi](#reti-utenti-e-permessi)
4. [Modalita' servizio (Ctrl+Alt+Canc, UAC, accesso)](#modalita-servizio)
4. [Aggiornamenti](#aggiornamenti)
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
| **Macchine** | Le macchine su cui hai permessi, raggruppate per rete. Verde = online, bollino *collegato* = hai una sessione aperta. Pulsanti **Controlla**, **Guarda**, **File** (doppio clic = azione principale); **Aggiorna** chiede a tutte le macchine di ripresentarsi. |
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
| Mouse | Clic sinistro/destro/centrale, trascinamento, rotellina, pulsanti avanti/indietro; il puntatore prende la forma di quello remoto (doppia freccia sui bordi, I nel testo, mano sui link, cursori personalizzati) |
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

## Aggiornamenti

Dalla versione 2.3.0 RemoteDesk si aggiorna da solo (solo Windows):

- **Controllo:** ogni 6 ore (e all'avvio) legge il manifesto `dist/latest.json` di questa repository. Se c'e' una
  versione nuova, nella console compare **"Aggiorna questo PC"** (Impostazioni > Aggiornamenti > *Controlla ora* per
  forzare il controllo).
- **Macchine remote:** nella lista macchine, quelle con una versione vecchia hanno il pulsante **"Aggiorna x -> y"**
  (solo per gli amministratori della rete). Anche dalla finestra di sessione: *Azioni > Aggiorna RemoteDesk su questo
  PC*. Il comando e' firmato dall'amministratore e la macchina lo verifica. **Se sei collegato, la finestra mostra
  "Il PC remoto si sta aggiornando" e si ricollega da sola** (in prova: circa 30 secondi).
- **Servizio:** si aggiorna anche lui. Un'attivita' temporanea `RemoteDeskUpdate` (SYSTEM) ferma il servizio,
  sostituisce `C:\Program Files\RemoteDesk`, riavvia il servizio e l'icona dell'utente collegato, poi si cancella.
- **Automatico (facoltativo):** Impostazioni > Aggiornamenti > *installa da solo le nuove versioni quando nessuno e'
  collegato*.
- **Sicurezza:** viene installato solo un pacchetto il cui manifesto e' **firmato con la chiave di rilascio** (Ed25519,
  la chiave pubblica e' nel programma) e il cui zip ha **l'impronta SHA-256** indicata nel manifesto. Chi riuscisse a
  modificare la repository senza la chiave privata non puo' distribuire aggiornamenti.
- **Ritorno automatico:** se la nuova versione non risponde entro 2 minuti, si torna da soli alla precedente (la copia
  non riuscita resta come `<cartella>.fallito`). Log: `...\data\logs\update.log`.
- Le versioni **precedenti alla 2.3.0** non hanno l'aggiornamento automatico: vanno aggiornate a mano una volta.

### Pubblicare una nuova versione (manutentore)
1. Aggiorna `VERSION` in `app/rd/common.py` e aggiungi la sezione in `CHANGELOG.md` (diventa la nota mostrata nei PC).
2. `RD_RELEASE_KEY=/percorso/remotedesk-release.key ./build/build_bundle.sh` crea `dist/RemoteDesk-<versione>.zip`,
   `.sha256` e `dist/latest.json` **firmato**.
3. Togli dalla cartella `dist/` lo zip della versione precedente, fai commit e push: entro 6 ore tutti i PC la vedono.

La chiave privata (`remotedesk-release.key`) **non deve mai finire nella repository** (e' esclusa da `.gitignore`):
conservala in un posto sicuro. Se la perdi, per cambiarla serve una versione con la nuova chiave pubblica, installata a
mano una volta su ogni PC.

---

## Collaudo automatico del relay TURN/TLS

Il job Linux `turn-tls-loopback` prepara un server coturn temporaneo su `127.0.0.1`, una CA di prova e due peer WebRTC. Entrambi devono negoziare candidati relay distinti e scambiare dati in entrambe le direzioni sul canale DTLS/SCTP. Il test ripete il collegamento dopo aver verificato il rifiuto di credenziali errate e di un certificato emesso da una CA estranea.

Per ripeterlo su un runner Linux dedicato servono `coturn`, `openssl`, `iproute2`, `util-linux`, `coreutils` e il Python dell'applicativo con `aiortc` installato. Dalla radice della repository esegui il comando seguente.

```bash
sudo unshare --net -- bash tests/run_turn_tls_smoke.sh "$(command -v python)"
```

Il test usa solo il loopback del namespace e rimuove server, credenziali e certificati al termine. Per verificare il collegamento Internet di una specifica installazione occorre una prova separata fra due PC autorizzati sulle reti interessate.

## Connessione: segnalazione, firewall e TURN

```
 PC A (console)                     ntfy.sh (o tuo server)                 PC B (agente)
  |  presenza/offerta firmate e cifrate  ------->  topic della rete  ------->  |
  |  <-------  risposta firmata dalla macchina, cifrata  <-------              |
  |=================== WebRTC diretto (DTLS-SRTP), schermo/input/file ========|
```

- **Segnalazione:** per presentarsi e scambiarsi i parametri di connessione i PC usano **piu' server pubblici
  insieme** (predefiniti: [ntfy.sh](https://ntfy.sh) e i broker MQTT pubblici `broker.emqx.io` e `broker.hivemq.com`,
  via TLS). Ogni messaggio viene pubblicato su tutti e vale il primo che arriva: se un server e' irraggiungibile o ha
  esaurito la sua quota, gli altri continuano. I messaggi sono **cifrati AES-256-GCM** con la chiave di rete e firmati:
  i server vedono solo dati illeggibili. L'elenco si cambia in Impostazioni > Connessione (separati da virgola:
  `https://...` per ntfy, `mqtts://host:porta` per MQTT); almeno un server deve essere in comune tra i PC.
- **Limiti dei server pubblici:** ntfy.sh limita le richieste e i messaggi giornalieri per indirizzo IP (i PC dietro lo
  stesso router li condividono). RemoteDesk invia pochi messaggi (all'avvio, allo spegnimento, ogni 10 minuti solo con
  una console aperta e uno di sicurezza ogni 30 minuti) e nella sezione *Reti* mostra lo stato di ogni server. Per
  avere un server tutto tuo: `docker run -d -p 80:80 binwiederhier/ntfy serve` (oppure un broker MQTT come Mosquitto)
  e aggiungilo all'elenco su tutti i PC.
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
Il server di prova simula anche il limite di messaggi (`GET /_limit?n=0`) e il conteggio (`/v1/account`).
Variabili utili per i test: `RD_FAKE_MONITORS="0,0,800,900;800,0,800,900"` (simula due monitor),
`RD_FAKE_AUDIO=1` (tono di prova), `RD_FP=<testo>` (impronta macchina fittizia).

### Costruire lo zip per Windows (da Linux)
```bash
sudo apt install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 zip unzip
./build/build_bundle.sh               # crea dist/RemoteDesk-<versione>.zip (+ .sha256)
```
Lo script scarica Python 3.12 per Windows (pacchetto ufficiale NuGet), le wheel delle librerie per `win_amd64`,
compila `RemoteDesk.exe` con mingw-w64 e crea lo zip.

---

## Risoluzione dei problemi

| Sintomo | Causa probabile / soluzione |
|---|---|
| Al primo avvio non compare "Entra in una rete" | Cartella copiata da un PC gia' configurato: dalla 2.2 viene rilevato automaticamente; altrimenti estrai lo zip originale. |
| I PC si vedono ma la sessione non parte ("Connessione diretta non riuscita") | Firewall di Windows: `tools/Consenti-RemoteDesk-firewall.bat` su entrambi i PC (va messo nella cartella di RemoteDesk). Se i PC sono in reti diverse e restrittive: configura un TURN. |
| Una macchina accesa risulta offline | Premi **Aggiorna**. In *Reti* controlla lo stato dei server di segnalazione: ne basta uno "online" in comune tra i PC. Le versioni fino alla 2.3.0 usano solo ntfy.sh: aggiorna tutti i PC alla 2.3.1. |
| "Nessuna risposta" | Il PC remoto non riceve: e' acceso? stesso server di segnalazione su entrambi? |
| "Autenticazione non valida" / "non ha il permesso" | Utente o permessi: controlla in *Utenti e permessi*. |
| Ctrl+Alt+Canc non funziona | Serve la modalita' servizio sul PC remoto. |
| Voglio togliere il servizio | Icona > *Rimuovi servizio...* oppure `tools/Rimuovi-servizio-RemoteDesk.bat` (doppio clic, conferma). |
| L'aggiornamento non parte o torna indietro | Leggi `...\data\logs\update.log`. In modalita' utente la cartella di RemoteDesk deve essere modificabile dall'utente (non in Program Files). |
| "registro in conflitto" in *Reti* | Due versioni diverse del registro utenti: lascia la rete e rientra con un amministratore attuale. |

Log: `%LOCALAPPDATA%\RemoteDesk\data\logs\app.log` (modalita' utente) oppure
`C:\ProgramData\RemoteDesk\data\logs\session-agent.log` (servizio). Non contengono password.

---

## Licenza

Nessuna licenza e' ancora stata scelta per questo progetto: finche' non viene aggiunto un file `LICENSE`, tutti i diritti
restano all'autore. Le librerie incluse nel pacchetto (Python, aiortc, PyAV/FFmpeg, aiohttp, cryptography, mss, Pillow,
pystray, PyAudioWPatch, ...) hanno ciascuna la propria licenza, presente nella cartella `runtime` dello zip.
