@echo off
setlocal
title RemoteDesk - consenti nel firewall di Windows
net session >nul 2>&1
if errorlevel 1 (
  echo Serve il permesso di amministratore: conferma la richiesta di Windows...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set "PYW=%~dp0runtime\pythonw.exe"
set "PYC=%~dp0runtime\python.exe"
if not exist "%PYW%" (
  echo.
  echo  ERRORE: metti questo file DENTRO la cartella di RemoteDesk
  echo  ^(quella che contiene RemoteDesk.exe e la cartella runtime^) e rilancialo.
  echo.
  pause
  exit /b 1
)
echo.
echo  Aggiungo le regole del firewall per RemoteDesk...
netsh advfirewall firewall delete rule name="RemoteDesk (utente)" >nul 2>&1
netsh advfirewall firewall add rule name="RemoteDesk (utente)" dir=in action=allow program="%PYW%" enable=yes profile=any >nul
netsh advfirewall firewall add rule name="RemoteDesk (utente)" dir=in action=allow program="%PYC%" enable=yes profile=any >nul
if exist "C:\Program Files\RemoteDesk\runtime\pythonw.exe" (
  netsh advfirewall firewall add rule name="RemoteDesk (utente)" dir=in action=allow program="C:\Program Files\RemoteDesk\runtime\pythonw.exe" enable=yes profile=any >nul
)
rem regole "blocca" create se a suo tempo si e' risposto Annulla alla domanda del firewall
powershell -NoProfile -Command "Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object { $_.Program -like '*RemoteDesk*python*' } | Get-NetFirewallRule | Where-Object { $_.Action -eq 'Block' } | ForEach-Object { Write-Host ('  rimuovo regola di blocco: ' + $_.DisplayName); Remove-NetFirewallRule -Name $_.Name }"
echo.
echo  FATTO. Chiudi RemoteDesk dall'icona e riaprilo, poi riprova la connessione.
echo.
pause
