@echo off
setlocal
title RemoteDesk - regola firewall LAN
"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if errorlevel 1 (
  echo Avvia questo strumento da un prompt amministrativo.
  exit /b 1
)
rem Agisce solo sulla copia gestita e lascia intatte le regole di blocco e i criteri di dominio.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $program=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'RemoteDesk\runtime\pythonw.exe'; if (-not [IO.File]::Exists($program)) { throw 'Copia gestita assente' }; $id='RemoteDesk.Managed.LAN'; $existing=Get-NetFirewallRule -PolicyStore PersistentStore -Name $id -ErrorAction SilentlyContinue; if ($existing) { throw 'Regola gia presente. Verificare la configurazione nel firewall' }; New-NetFirewallRule -PolicyStore PersistentStore -Name $id -DisplayName 'RemoteDesk LAN (gestito)' -Action Allow -Direction Inbound -Program $program -Protocol UDP -Profile Domain,Private -RemoteAddress LocalSubnet -EdgeTraversalPolicy Block | Out-Null"
exit /b %errorlevel%
