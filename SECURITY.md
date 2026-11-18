# Sicurezza di RemoteDesk

## Modello di minaccia
- **Chiave di rete**: cifra la segnalazione e permette di "vedere" la rete. Chi la conosce **non** puo' controllare nulla
  senza utente e password.
- **Utenti**: ogni accesso richiede utente + password validi per quella rete e permessi sulla macchina.
- **Server di segnalazione (ntfy)**: considerato non fidato. Vede solo messaggi cifrati e un nome di topic derivato.
- **Siti web aperti sul PC**: non devono poter pilotare la console locale.
- **Utente seduto al PC controllato**: deve sempre poter vedere chi e' collegato e scollegarlo.

## Meccanismi
| Elemento | Come |
|---|---|
| Segnalazione | AES-256-GCM; chiave e topic derivati con PBKDF2-SHA256 (150k iterazioni) da nome rete + chiave di rete |
| Identita' utente | scrypt (N=2^15, r=8, p=1) su rete + utente + password -> seme Ed25519. La password non viene mai trasmessa |
| Identita' macchina | chiave Ed25519 casuale (`machine.key`), registrata nel registro della rete |
| Richiesta di connessione | firmata dall'utente: mittente, destinatario, id, modalita', orario e **hash dell'offerta SDP** (include l'impronta DTLS) |
| Risposta | firmata dalla macchina (anche le risposte di errore); risposte non firmate vengono ignorate |
| Anti-replay | orario firmato confrontato con l'orario del server (+-120 s), id di richiesta mai riusati, id di sessione locali |
| Presenza | firmata dalla macchina e verificata con la chiave del registro; campi normalizzati |
| Registro (utenti/permessi/macchine) | versioni firmate da un admin, collegate con l'hash della precedente; accettata solo `v+1` firmata da un admin della versione corrente; storico delle ultime 100 versioni per recuperare quelle perse |
| Ingresso in rete | catena ricostruita a partire dall'ultima versione firmata dall'admin di cui si inseriscono le credenziali |
| Permessi | verificati sulla macchina controllata a ogni messaggio (file, appunti, input) e alla creazione dei flussi (schermo/audio solo con "visione") |
| Revoca | applicata alla ricezione del nuovo registro: sessioni chiuse o funzioni disattivate subito |
| Console locale | solo `127.0.0.1`; controllo Host/Origin/Sec-Fetch-Site; cookie HttpOnly SameSite=Strict; CSP; login per rete, scadenza dopo 2 h di inattivita' (12 h massimo); login invalidato se la password cambia |
| Comandi locali privilegiati | `handover` protetto da token casuale scritto nella cartella dati |
| Servizio Windows | eseguito da `C:\Program Files\RemoteDesk`; dati in `C:\ProgramData\RemoteDesk\data` con ACL SYSTEM + Amministratori; file manager con impersonazione dell'utente collegato |
| Registro accessi | per rete; richieste firmate dall'admin, risposte cifrate (X25519 + HKDF + AES-GCM) per la sola console richiedente e firmate dalla macchina |
| Trasporto | WebRTC DTLS-SRTP / SCTP su DTLS |
| Aggiornamenti | manifesto firmato con la chiave di rilascio Ed25519 (pubblica nel codice, privata solo al manutentore), zip verificato con SHA-256 e dimensione, scaricato in una cartella protetta (ProgramData per il servizio); installatore eseguito dalla copia nuova con ritorno automatico alla precedente; comando di aggiornamento remoto firmato da un admin della rete |

## Rischi residui
- **Biforcazione del registro**: un amministratore *gia' revocato* che conosce la chiave di rete potrebbe proporre una
  versione alternativa a un PC rimasto spento durante la revoca e che non ha ancora ricevuto la versione legittima.
  La situazione viene **rilevata** (stato "registro in conflitto" nella sezione Reti) ma va risolta a mano (lasciare e
  rientrare nella rete). Consiglio: dopo aver revocato un admin, verificare che tutti i PC siano aggiornati.
- **PC Windows condiviso da piu' utenti contemporanei** (es. server terminal): un altro utente locale potrebbe occupare per
  primo la porta della console (127.0.0.1:47800). Non rilevante per PC con un solo utente.
- **Fiducia nella macchina locale**: chi e' amministratore di Windows sul PC puo' leggere i dati del servizio.
- **Testo degli appunti nel registro**: vengono salvati i primi 300 caratteri, che possono contenere password copiate.
- **Server di segnalazione pubblici** (ntfy.sh, broker MQTT EMQX/HiveMQ): vedono orari e dimensioni dei messaggi
  (metadati), non il contenuto; chiunque conosca il topic derivato puo' inondarlo di messaggi (vengono scartati perche'
  non decifrabili), con un possibile disturbo ma senza accesso.
- Il pacchetto non e' firmato digitalmente (Authenticode).
- **Chiave di rilascio**: chi la possiede puo' distribuire aggiornamenti a tutti i PC (anche come SYSTEM). Va custodita
  offline e mai pubblicata. L'aggiornamento automatico senza conferma e' disattivato per impostazione predefinita.

## Segnalare un problema
Apri una issue senza includere chiavi di rete, file `machine.key`, `config.json`, `audit.jsonl` o log completi.
