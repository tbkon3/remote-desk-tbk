# Sicurezza di RemoteDesk

Questa pagina descrive i sorgenti con protocollo di sessione 2. Per il pacchetto già distribuito consultare la documentazione della versione 2.3.2. Il ramo di sviluppo richiede un collaudo prima della distribuzione sui PC di produzione.

## Confini di fiducia

| Componente | Controlli e limiti |
|---|---|
| Identità | La chiave di rete cifra la segnalazione. Il registro lega utenti e macchine a chiavi Ed25519. La richiesta di sessione lega rete, operatore, dispositivo, destinatario, modalità e descrizione WebRTC. L'agente verifica le firme e la risposta della macchina remota. |
| Sessione | Il PC applica i permessi, la configurazione locale e il consenso. L'inventario usa un canale dati dedicato. I canali scadono in assenza di rinnovo firmato. Logout e revoca impediscono i rinnovi. Il controllo del registro agisce dalla ricezione della nuova versione. I peer con protocollo precedente devono essere aggiornati. |
| Console | L'agente ascolta su 127.0.0.1. Il launcher verifica l'identità locale prima di aprire il browser. Le richieste API legano le credenziali all'origine, inclusa la porta. I ruoli desktop assistito e proprietario locale hanno privilegi differenti. Il login ha scadenze distinte per rete. Il polling della sessione lascia decorrere il tempo di inattività. |
| File | Le operazioni sono confinate alla cartella condivisa. Il servizio usa l'identità dell'utente interattivo. Il server verifica percorsi, reparse point, dimensioni, trasferimenti concorrenti e permessi prima della pubblicazione di un upload. |
| Appunti e chat | Gli appunti di testo sono disattivati inizialmente e richiedono un gesto del tecnico. La chat ha un destinatario per messaggio. L'audit registra metadati degli appunti. All'apertura del registro locale la migrazione elimina il campo testo delle vecchie registrazioni. Eventuali backup precedenti richiedono gestione separata. |
| Aggiornamenti | Il client verifica firma Ed25519, versione, validità temporale dei nuovi manifesti e dimensione e SHA-256 del pacchetto. L'estrazione ha limiti e il processo di aggiornamento controlla un riscontro di avvio della copia installata. La creazione di un rilascio richiede input verificati e la chiave del manutentore. |
| Internet | ICE negozia il percorso. WebRTC protegge media e dati anche sul relay TURN. Il relay di segnalazione vede metadati come IP, dimensioni e orari. I membri con la chiave di gruppo possono decifrare la segnalazione che intercettano. Le firme e le ACL restano necessarie anche su LAN. |

## Adozione

- Distribuire prima a due postazioni pilota. Riabilitare sul singolo PC i permessi necessari e verificare con un account operatore e un account privo di diritti. Provare cambio utente, revoca, login scaduto e disconnessione a metà trasferimento.
- Configurare relay, STUN e TURN per il proprio ambiente. Il percorso selezionato è visibile durante la sessione. Per TURN via TLS servono un endpoint raggiungibile e un certificato valido. Per confrontare percorso diretto e percorso relay seguire il collaudo WAN nel README.
- Per il servizio Windows, predisporre con il processo amministrativo aziendale una copia verificata sotto Program Files. La cartella dati servizio richiede proprietario e ACL compatibili con SYSTEM e Amministratori. Le directory preesistenti con proprietari o permessi incoerenti richiedono verifica amministrativa. Il servizio ha un'identità propria da registrare.
- Rivedere in fase di migrazione le regole firewall, le policy SAS e le copie di segreti create da versioni precedenti. Conservare la chiave di firma dei rilasci in un ambiente controllato. Tenere separati gli endpoint di sviluppo dai PC di regia.
- Per distribuire software, il collegamento dalla scheda Applicazioni porta al portale Microsoft Intune. Individuazione dispositivo, assegnazione dei pacchetti, autorizzazioni e risultati restano nel tenant. Il canale inventario riceve esclusivamente richieste di lettura e rinnovi.

## Rischi aperti e lavoro di prodotto

### Copertura dei rilievi della revisione 2.3.2

| Rilievi | Modifica nei sorgenti | Verifica o lavoro rimanente |
|---|---|---|
| 01–06 · dispositivo, consenso, login e primo avvio | Firma di macchina e operatore, nuova verifica dopo il consenso, modalità distinte, scadenza per rete e prova del launcher | Collaudo della prima installazione e del cambio utente su Windows |
| 07–12 · appunti, chat, reti, logout e segreti | Migrazione del registro, trasferimento manuale, chat per sessione, ruolo proprietario, rinnovi firmati e segreti esclusi dallo stato | Controllare le copie di log già esportate. Le credenziali TURN statiche restano visibili al browser che deve usarle |
| 13–15 · revoche offline e chiavi | Rilevazione dei conflitti e controlli sul registro locale | Autorità centrale o attestazioni a scadenza per la freschezza del registro, identità utente indipendente dalla password, rotazione della chiave di gruppo |
| 16–18 · privilegi Windows e installazione | Confinamento a desktop e logon, controlli distinti sui comandi sensibili, verifica dei percorsi amministrati | Separazione completa del servizio SYSTEM e collaudo di installazione, disinstallazione e UAC |
| 19–21 · file e configurazione storica | Lettura, scrittura ed eliminazione distinte, cartella confinata e pulizia dei trasferimenti | Crash del processo, ACL NTFS e bonifica amministrativa di regole o policy lasciate dalle versioni precedenti |
| 22–24 · relay e risorse | Limiti su messaggi, decompressione, attese, cache e trasferimenti. Controlli su firme, freschezza e trasporto TLS | Misure di capacità su relay amministrati e collaudo WAN con NAT e firewall reali |
| 25–27 · filiera e aggiornamenti | Prerequisiti di firma del pacchetto, hash, validità temporale, estrazione controllata e riscontro del nuovo processo | Lock Windows completo, firma Authenticode, custodia chiavi e prova di rollback su VM |
| 28–30 · audit, browser e verifiche | Audit per rete, risposte firmate, protezione dell'origine del browser, schema del registro e test di regressione | Raccolta audit indipendente dagli endpoint e attivazione del canale privato di segnalazione da parte del manutentore |

Il registro distribuito può rimanere obsoleto durante una partizione di rete. Una revoca aziendale con tempo massimo garantito richiede un'autorità raggiungibile o credenziali di breve durata ancorate a quella autorità. Il progetto conserva una chiave di gruppo e deriva l'identità di firma dell'operatore dalla password. Restano da realizzare rotazione automatica dopo l'esclusione di un membro, MFA/SSO e ciclo di vita centralizzato dei dispositivi.

Il servizio contiene ancora codice di rete con privilegi SYSTEM. La separazione in un processo a basso privilegio e un broker privilegiato minimale è un intervento architetturale aperto. Un amministratore locale conserva accesso ai dati della macchina. L'audit su disco è modificabile da chi controlla l'host. La raccolta centralizzata e la conservazione verificabile richiedono un servizio esterno.

Il percorso ICE può essere diretto anche quando è configurato TURN. Una modalità che nasconda sistematicamente gli indirizzi dei peer richiede una policy relay-only applicata su entrambi. Un'interruzione o saturazione dei servizi pubblici può influire sulla disponibilità. Una build firmata Authenticode, un lock delle dipendenze Windows distribuito e un collaudo tra due reti aziendali reali restano passi di rilascio.

Il profilo In onda offre limiti operativi. I profili prestazionali con encoder GPU, gli inviti temporanei legati a un ticket EMS, l'integrazione diretta del catalogo software e i comandi amministrativi sui servizi richiedono sviluppo dedicato.

## Segnalazioni

Per una vulnerabilità inviare una segnalazione privata al manutentore. Se la repository offre il pulsante **Report a vulnerability**, usare quel canale. Indicare versione, componente interessato, effetto osservato e configurazione rilevante. Omettere credenziali, chiavi, contenuti degli appunti e dati delle postazioni.
