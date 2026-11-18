@echo off
setlocal
title Rimozione servizio RemoteDesk
rem ---- Richiede i diritti di amministratore (Windows mostra la richiesta "Consenti modifiche")
net session >nul 2>&1
if errorlevel 1 (
  echo Serve il permesso di amministratore: conferma la richiesta di Windows...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '\"%USERPROFILE%\"' -Verb RunAs"
  exit /b
)
set "UPROF=%~1"
if "%UPROF%"=="" set "UPROF=%USERPROFILE%"

echo.
echo  Rimozione del servizio RemoteDesk in corso...
echo.

echo  [1/6] Fermo e cancello l'attivita' pianificata "RemoteDesk"
schtasks /End /TN "RemoteDesk" >nul 2>&1
schtasks /Delete /TN "RemoteDesk" /F >nul 2>&1

echo  [2/6] Chiudo i processi di RemoteDesk
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*remotedesk.py*' } | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }"

echo  [3/6] Tolgo l'avvio automatico dell'icona per tutti gli utenti
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v RemoteDeskTray /f >nul 2>&1
reg delete "HKLM\SOFTWARE\RemoteDesk" /f >nul 2>&1

echo  [4/6] Tolgo le regole del firewall
netsh advfirewall firewall delete rule name="RemoteDesk" >nul 2>&1
netsh advfirewall firewall delete rule name="RemoteDesk (pythonw.exe)" >nul 2>&1
netsh advfirewall firewall delete rule name="RemoteDesk (python.exe)" >nul 2>&1

echo  [5/6] Ripristino l'impostazione di Windows per Ctrl+Alt+Canc
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v SoftwareSASGeneration /f >nul 2>&1

echo  [6/6] Cancello il segnale "servizio installato" lasciato dalle versioni 2.0/2.1
if exist "%~dp0data\service.json" del /f /q "%~dp0data\service.json"
powershell -NoProfile -Command "$roots = @('%UPROF%', 'C:\RemoteDesk', (Join-Path '%UPROF%' 'AppData\Local\RemoteDesk')) | Where-Object { Test-Path $_ }; Get-ChildItem -Path $roots -Filter service.json -Recurse -Depth 5 -ErrorAction SilentlyContinue | Where-Object { $_.Directory.Name -eq 'data' -and ((Test-Path (Join-Path $_.Directory.Parent.FullName 'app\remotedesk.py')) -or ($_.Directory.Parent.Name -eq 'RemoteDesk')) } | ForEach-Object { Write-Host ('       rimosso ' + $_.FullName); Remove-Item $_.FullName -Force }"

echo.
echo  FATTO: il servizio RemoteDesk e' stato rimosso.
echo.
echo  - La configurazione (reti, utenti, ID del PC) NON e' stata cancellata.
echo  - Se vuoi continuare a usare RemoteDesk senza servizio, riavvialo con RemoteDesk.exe.
echo  - Se vuoi eliminarlo del tutto, ora puoi cancellare la cartella di RemoteDesk
echo    (e "C:\Program Files\RemoteDesk", se esiste).
echo.
pause
