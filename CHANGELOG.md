# Novita'

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
