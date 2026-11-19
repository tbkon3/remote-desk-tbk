# RemoteDesk 2.4.0 per Windows

RemoteDesk collega due PC registrati nella stessa rete di assistenza. Dalla rubrica il tecnico può vedere o controllare il desktop, trasferire file in una cartella condivisa e consultare l'inventario Windows. Ogni operazione richiede i permessi previsti sul PC assistito. Il pacchetto portabile include Python per Windows a 64 bit.

[Scarica RemoteDesk 2.4.0 per Windows](https://raw.githubusercontent.com/tbkon3/remote-desk-tbk/main/dist/RemoteDesk-2.4.0.zip) · [Scarica l'impronta SHA-256](https://raw.githubusercontent.com/tbkon3/remote-desk-tbk/main/dist/RemoteDesk-2.4.0.zip.sha256)

## Verifica e prima installazione

1. Scarica lo ZIP e il file `.sha256` dalla distribuzione autorizzata nella stessa cartella. Esegui in PowerShell il controllo riportato sotto. Se il controllo fallisce, interrompi l'installazione.
2. Su ogni PC Windows 10 o 11 a 64 bit estrai una copia dello ZIP originale in una cartella riservata al relativo utente. Apri `RemoteDesk.exe` e accedi alla console dall'icona di RemoteDesk. Edge e Chrome sono i browser supportati per l'interfaccia. Se Windows o la gestione aziendale bloccano l'esecuzione, sottoponi il pacchetto all'amministratore della postazione.
3. Sul primo PC scegli **Crea una nuova rete**, indica un nome e crea l'account amministratore con una password di almeno 10 caratteri. Conserva la chiave di rete nel gestore di segreti autorizzato.
4. Sul secondo PC scegli **Entra in una rete esistente**. Indica nome, chiave e credenziali di un amministratore della stessa rete. Durante la registrazione deve essere raggiungibile almeno un altro PC già iscritto. Riapri la console di ogni PC dall'icona locale.

```powershell
$zip = '.\RemoteDesk-2.4.0.zip'
$atteso = ((Get-Content -LiteralPath "$zip.sha256" -Raw).Trim() -split '\s+')[0]
if ($atteso -notmatch '^[0-9a-fA-F]{64}$') { throw 'Impronta pubblicata non valida' }
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $atteso) { throw 'SHA-256 diverso. Interrompere.' }
'Impronta verificata'
```

L'hash permette di confrontare i byte con quelli pubblicati. Per la provenienza usa il canale di distribuzione approvato dalla tua organizzazione. Il pacchetto include l'avviatore originale, quindi le proprietà di `RemoteDesk.exe` in Esplora file riportano **2.3.2**. Controlla in **Impostazioni** che la console indichi **2.4.0**, la versione dell'applicazione avviata.

## Aggiornamento da 2.3.2

La versione 2.4.0 usa il **protocollo 2**. **Aggiorna entrambi gli estremi** prima di aprire una nuova sessione. Pianifica una finestra con accesso locale o con il tuo strumento di distribuzione aziendale e chiudi le sessioni attive della 2.3.2.

1. Conserva una copia protetta dei dati del singolo PC secondo le procedure aziendali. In modalità utente i dati si trovano in `%LOCALAPPDATA%\RemoteDesk\data`, in modalità servizio in `%ProgramData%\RemoteDesk\data`. Mantieni separati dati, identità e chiavi di ciascuna macchina.
2. **Modalità utente.** Chiudi RemoteDesk dall'icona. Estrai il pacchetto verificato in una nuova cartella e avvialo con lo stesso account Windows. La configurazione viene letta dal profilo utente. Controlla l'identità del PC, le reti presenti e la versione mostrata dalla console. Aggiorna gli eventuali collegamenti che avviano la vecchia copia.
3. **Modalità servizio.** Il servizio usa la copia in `%ProgramFiles%\RemoteDesk`. Affida all'amministratore Windows la sostituzione del pacchetto durante la manutenzione e la verifica del riavvio. Avviare un secondo eseguibile portabile lascia attiva la copia già registrata. Una prima installazione del servizio richiede che l'intero pacchetto sia predisposto nella cartella protetta da un amministratore. Apri la copia amministrata e scegli **Impostazioni → Installa servizio**. Verifica separatamente rete, identità e impostazioni della modalità servizio.
4. Dopo il passaggio, su ogni PC la conferma locale è riattivata. File, appunti, inventario, alimentazione, blocco dell'input e Ctrl+Alt+Canc partono disabilitati. Dalla console del PC assistito il proprietario locale, con un account amministratore di rete se il PC è già iscritto, abilita le funzioni necessarie. Per i file scegli una cartella dedicata e controlla i diritti del tecnico in **Utenti e permessi**.
5. Sul PC del tecnico apri la console della nuova versione, accedi alla rete con il suo account e aggiorna la rubrica. Sul PC assistito accedi a Windows con l'utente che riceverà la richiesta. Avvia una **nuova** sessione. L'utente locale verifica nome dell'operatore, macchina e azioni richieste, poi accetta o rifiuta. **Gestisci PC** richiede sempre questa conferma. Ripeti il controllo dei permessi anche per un utente con accesso limitato.

L'aggiornamento integrato richiede un manifesto di release valido e firmato dal manutentore. La disponibilità dello ZIP per l'installazione manuale e la versione proposta dalla console possono differire.

### Se la versione servizio resta sulla 2.3.2

Il messaggio **Installazione di RemoteDesk 2.4.0** compare dopo la verifica e l'estrazione dello ZIP. Apri una nuova console dall'icona di RemoteDesk per controllare la versione dell'agente. Il servizio registrato usa la copia in `%ProgramFiles%\RemoteDesk` anche se apri l'icona da una cartella portabile.

Alcune installazioni della 2.3.2 hanno ereditato da Windows un permesso di scrittura sulla cartella `%ProgramData%\RemoteDesk`. L'updater 2.4.0 interrompe la migrazione quando trova questo permesso. Sul PC interessato, durante una finestra di manutenzione, un amministratore Windows può verificare questo caso con [Ripara-permessi-servizio.ps1](tools/Ripara-permessi-servizio.ps1). Apri Windows PowerShell a 64 bit come amministratore nella cartella dello script ed esegui prima la verifica in sola lettura.

```powershell
powershell.exe -NoProfile -File .\Ripara-permessi-servizio.ps1
```

Con l'esito `REPAIRABLE`, esegui `powershell.exe -NoProfile -File .\Ripara-permessi-servizio.ps1 -Apply`. Dopo `REPAIRED`, riapri la console della 2.3.2, premi **Controlla ora** e poi **Macchine → Aggiorna questo PC**. L'esito `SAFE` indica che il permesso della cartella è già conforme. Se compare `DA VERIFICARE`, conserva il messaggio per la diagnosi.

## Uso e permessi

| Azione in rubrica | Che cosa permette |
|---|---|
| **Guarda** | Visualizza lo schermo. |
| **Controlla** | Usa tastiera e mouse. L'audio si attiva dalla finestra. I pulsanti **Invia appunti** e **Ricevi appunti** trasferiscono testo su richiesta quando il PC li abilita. |
| **File** | Consulta e scarica contenuti della cartella condivisa. **Scrittura file** consente creazione e caricamento, **Eliminazione file** consente cancellazione. La rinomina richiede entrambi i diritti aggiuntivi. |
| **Gestisci PC** | Mostra condivisioni, unità mappate, servizi e applicazioni visibili nel contesto Windows autorizzato. Richiede un'abilitazione sul PC e il permesso **Inventario** per il tecnico. Le fonti con visibilità limitata vengono segnalate. |

Gli amministratori della rete gestiscono gli utenti. Scrittura ed eliminazione file, inventario, alimentazione, blocco input e sequenza protetta si assegnano esplicitamente anche agli amministratori. Per alimentazione, blocco input e Ctrl+Alt+Canc servono anche il controllo del desktop e la corrispondente autorizzazione locale. **In onda** sospende le azioni di manutenzione indicate nelle impostazioni.

Per assegnare un applicativo aziendale, dalla scheda **Applicazioni** apri il portale Microsoft Intune. Il tecnico si autentica con il proprio account Microsoft, verifica tenant e destinatari e consulta lo stato della distribuzione in Intune. Il portale richiede i ruoli e i dispositivi gestiti previsti dal tenant.

## Uso tra sedi o tramite Internet

1. Configura almeno un relay di segnalazione comune e raggiungibile da entrambe le sedi. La configurazione iniziale usa servizi pubblici. Per un'installazione amministrata puoi inserire endpoint HTTPS, WSS o MQTTS aziendali. I servizi di segnalazione e STUN osservano gli indirizzi e gli orari delle connessioni.
2. In **Impostazioni** configura STUN e un servizio TURN raggiungibile dai due PC. Per una rete che limita UDP, configura il server con certificato valido e prova un URL come `turns:turn.azienda.it:443?transport=tcp`. La porta 443 deve servire TURN/TLS. Disponibilità di rete, DNS, proxy, certificati e policy dei due firewall determinano il risultato.
3. Usa credenziali TURN distinte per l'ambiente. Il segreto coturn opzionale produce credenziali temporanee di un'ora. Chi amministra un endpoint che contiene il segreto può emettere credenziali, quindi distribuiscilo soltanto su endpoint amministrati. Con credenziali statiche il browser autorizzato riceve la password TURN. La console HTTP resta su loopback. Mantieni la porta 47800 fuori dal port forwarding.
4. Collauda due PC pilota su accessi Internet indipendenti, per esempio la sede e un hotspot. Prova prima l'inventario e poi la visualizzazione con consenso. Annota il percorso riportato dall'interfaccia. In una rete di collaudo che richiede un relay, verifica che compaia **Via TURN**. Ripeti con accesso negato, revoca durante la sessione, logout e interruzione della connessione. Una voce TURN nelle impostazioni indica configurazione. La coppia ICE selezionata durante la sessione identifica il percorso realmente utilizzato.

## Collaudo automatico del relay TURN/TLS

Il job Linux `turn-tls-loopback` prepara un server coturn temporaneo su `127.0.0.1`, una CA di prova e due peer WebRTC. Entrambi devono negoziare candidati relay distinti e scambiare dati in entrambe le direzioni sul canale DTLS/SCTP. Il test ripete il collegamento dopo aver verificato il rifiuto di credenziali errate e di un certificato emesso da una CA estranea.

Per ripeterlo su un runner Linux dedicato servono `coturn`, `openssl`, `iproute2`, `util-linux`, `coreutils` e il Python dell'applicativo con `aiortc` installato. Dalla radice della repository esegui il comando seguente.

```bash
sudo unshare --net -- bash tests/run_turn_tls_smoke.sh "$(command -v python)"
```

Il test usa solo il loopback del namespace e rimuove server, credenziali e certificati al termine. Per verificare il collegamento Internet di una specifica installazione occorre una prova separata fra due PC autorizzati sulle reti interessate.

## Diagnostica e sviluppo

Se la rubrica chiede un aggiornamento, verifica la versione dell'agente attivo su entrambi i PC. Se una scheda è disabilitata, controlla con quale account si è entrati nella rete, il permesso sulla macchina e l'impostazione locale. Se la finestra segnala autorizzazione scaduta, rientra dalla console locale e richiedi una nuova sessione.

Per eseguire dai sorgenti installa le dipendenze di `requirements.txt` in un ambiente Python dedicato e avvia `python app/remotedesk.py`. Con Python 3.12 e Node puoi eseguire `python -m unittest discover -s tests -v` e `node --test tests/*.cjs` da una shell che espanda il pattern. In PowerShell passa a Node i percorsi restituiti da `Get-ChildItem tests -Filter '*.cjs'`. Il workflow della repository esegue le regressioni Windows e il collaudo del relay Linux.

I controlli implementati e i limiti che richiedono collaudo sono descritti in [SECURITY.md](SECURITY.md). Le modifiche per versione sono in [CHANGELOG.md](CHANGELOG.md).

## Archivio 2.3.2

Il manuale e i file della 2.3.2 rimangono consultabili nella revisione originale. Le procedure del protocollo 1 appartengono a quella distribuzione.

[Manuale 2.3.2 archiviato](https://github.com/tbkon3/remote-desk-tbk/blob/70b260c46250fdbd38cf0eaf12ceb9cacc38f897/README.md) · [Distribuzione 2.3.2 archiviata](https://github.com/tbkon3/remote-desk-tbk/tree/70b260c46250fdbd38cf0eaf12ceb9cacc38f897/dist)
