# Creates the scheduled task that makes the Windows Hello dialog open on face.
# Run once, elevated:  powershell -ExecutionPolicy Bypass -File install-face-default.ps1 <user SID>
# Remove with:         Unregister-ScheduledTask -TaskPath '\WSL-Hello-sudo\' -TaskName FaceDefault
#
# The task runs as SYSTEM and does one fixed thing: set LastLoggedOnProvider to
# the face provider. It takes no input. The given user may start it but not change it.
param([Parameter(Mandatory)][string]$UserSid)
$ErrorActionPreference = 'Stop'
if ($UserSid -notmatch '^S-1-5-21-[0-9-]+$') { throw "Not a user SID: $UserSid" }

$path = '\WSL-Hello-sudo\'
$name = 'FaceDefault'
$face = '{8AF662BF-65A0-4D0A-A540-A338A999D36F}'
$key  = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'

$action    = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\reg.exe" `
               -Argument "add `"$key`" /v LastLoggedOnProvider /t REG_SZ /d $face /f"
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
               -ExecutionTimeLimit (New-TimeSpan -Seconds 30) -MultipleInstances IgnoreNew -Hidden
Register-ScheduledTask -TaskPath $path -TaskName $name -Action $action -Principal $principal `
  -Settings $settings -Force | Out-Null

# SYSTEM and Administrators: full control. The user: read and run only.
$svc = New-Object -ComObject Schedule.Service
$svc.Connect()
$svc.GetFolder($path.TrimEnd('\')).GetTask($name).SetSecurityDescriptor(
  "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;$UserSid)", 0)
"Created $path$name"
