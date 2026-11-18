# Novita'

## 2.3.2
- Corretto: "Esci" dall'icona nella barra non chiudeva RemoteDesk. Ora l'icona sparisce subito, le sessioni vengono
  chiuse in modo ordinato e il programma termina in pochi istanti (al massimo 10 secondi in ogni caso).
- Con il servizio installato la voce si chiama "Chiudi icona (il servizio resta attivo)", per chiarezza.

## 2.3.1
- Piu' server di segnalazione usati insieme: oltre a ntfy.sh, i broker MQTT pubblici EMQX e HiveMQ (TLS). Ogni
  messaggio parte su tutti e vale il primo che arriva: se un server ha esaurito la quota giornaliera o e' bloccato,
  la rete continua a funzionare con gli altri. Le configurazioni con solo ntfy.sh vengono aggiornate da sole.
- Molti meno messaggi: annunci di presenza all'avvio, allo spegnimento e quando una console e' aperta (ogni 10 minuti),
  piu' uno di sicurezza ogni 30 minuti.
- Il limite di ntfy viene riconosciuto con precisione: "troppe richieste" (attesa e nuovo tentativo) oppure "quota
  giornaliera esaurita". L'avviso compare solo se nessun server e' utilizzabile; in *Reti* lo stato di ogni server.
- Script di rimozione del servizio aggiornato anche per le attivita' di aggiornamento.

## 2.3.0
- Aggiornamenti automatici: RemoteDesk controlla ogni 6 ore se c'e' una nuova versione e la console mostra
  "Aggiorna questo PC". Le macchine della rete con una versione vecchia hanno il pulsante "Aggiorna" e si possono
  aggiornare a distanza, anche mentre si e' collegati: la sessione si ricollega da sola dopo il riavvio.
- Si aggiorna anche la modalita' servizio (Program Files), con riavvio del servizio e dell'icona dell'utente.
- Pacchetti firmati con la chiave di rilascio (Ed25519) e verificati con impronta SHA-256; se la nuova versione
  non parte si torna automaticamente alla precedente.
- Opzione "installa automaticamente quando nessuno e' collegato" e indirizzo degli aggiornamenti configurabile.

## 2.2.2
- Pulsante **Aggiorna** nella lista macchine: chiede a tutte le macchine accese di ripresentarsi subito.
- Una macchina con cui hai una sessione aperta risulta sempre online, con il bollino **collegato**; anche ogni
  risposta firmata della macchina conta come segno di vita.
- Annunci di presenza ogni 5 minuti invece che ogni minuto (offline dopo 12 minuti senza segni di vita;
  lo spegnimento regolare e' immediato): molti meno messaggi sul server di segnalazione.
- Se il server di segnalazione rifiuta i messaggi per il limite giornaliero, la console lo segnala e la sezione
  *Reti* mostra i messaggi usati oggi rispetto al limite.
- Corretto: il pallino di stato della rete veniva disegnato come un riquadro arancione.

## 2.2.1
- Il puntatore del mouse assume la forma di quello del PC remoto: doppia freccia sui bordi delle finestre,
  I nel testo, mano sui link, attesa, spostamento, ecc. I cursori personalizzati dei programmi vengono
  inviati come immagine; se il PC remoto nasconde il cursore, viene nascosto anche nella sessione.

## 2.2.0
- **Piu' reti sullo stesso PC**, ciascuna con chiave, utenti, permessi e registro propri; sezione *Reti*
  (aggiungi, esci, lascia rete), login separato per rete.
- Schermata iniziale chiara: *Entra in una rete esistente* / *Crea una nuova rete*.
- Rilevamento della cartella copiata da un altro PC (nuova identita' + copia di sicurezza); dati spostati nel profilo
  utente (`%LOCALAPPDATA%`), migrazione automatica delle configurazioni 2.0/2.1.
- Code review con piu' revisori e verifica avversaria: 51 correzioni, tra cui:
  - permessi verificati lato macchina per file manager, schermo/audio e appunti;
  - presenza firmata e dati ripuliti in console (XSS);
  - servizio installato in Program Files con dati in ProgramData protetti; file manager con i diritti dell'utente;
  - registro a catena con hash della versione precedente, ingresso in rete con catena di fiducia, rilevamento conflitti;
  - risposte di connessione firmate anche in caso di errore; anti-replay comune a tutte le reti;
  - upload con file temporaneo e controllo dimensione, zip annullabile, registro di eliminazioni/rinomine;
  - scadenza del login per inattivita', invalidazione al cambio password, validazione impostazioni;
  - robustezza della segnalazione, audio con piu' sessioni, perdite di risorse Windows.

## 2.1.0
- Piu' monitor: Schermo 1/2/..., tutti in una finestra o una finestra per schermo.
- Audio del PC remoto (on/off), chat con finestrella sul PC remoto, registro accessi per gli amministratori.

## 2.0.0
- Rete di macchine senza codici, utenti con password e permessi per macchina, modalita' servizio
  (Ctrl+Alt+Canc, UAC, schermata di accesso), file manager, appunti, finestre ridimensionabili, pacchetto portabile.
