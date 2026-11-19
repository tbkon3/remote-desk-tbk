@echo off
setlocal
title Rimozione servizio RemoteDesk
"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if errorlevel 1 (
  echo Avvia questo strumento da un prompt amministrativo.
  exit /b 1
)
rem Nomi esatti. Non interrompere un aggiornamento mentre sostituisce i file.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $up=Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq 'RemoteDeskUpdate'; if ($up.State -eq 'Running') { throw 'Attendere il termine dell aggiornamento' }; foreach ($t in @(Get-ScheduledTask -TaskPath '\' | Where-Object { $_.TaskName -in 'RemoteDesk','RemoteDeskUpdate' })) { if ($t.State -eq 'Running') { Stop-ScheduledTask -InputObject $t }; Unregister-ScheduledTask -InputObject $t -Confirm:$false }; $k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; if ((Get-ItemProperty -LiteralPath $k).RemoteDeskTray) { Remove-ItemProperty -LiteralPath $k -Name RemoteDeskTray }; $k='HKLM:\SOFTWARE\RemoteDesk'; if (Test-Path -LiteralPath $k) { foreach ($n in 'Service','UserData') { if ((Get-Item -LiteralPath $k).GetValueNames() -contains $n) { Remove-ItemProperty -LiteralPath $k -Name $n } } }; $r=Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -eq 'RemoteDesk.Managed.LAN' -and $_.Action -eq 'Allow' }; if ($r) { $r | Remove-NetFirewallRule }"
if errorlevel 1 exit /b 1
echo Servizio rimosso. I dati del servizio restano nel profilo protetto.
exit /b 0
