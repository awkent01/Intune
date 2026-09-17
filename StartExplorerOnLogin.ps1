# 1) Create script
New-Item -Path 'C:\ProgramData\HCoA\Scripts' -ItemType Directory -Force | Out-Null

@'
Start-Sleep -Seconds 30

$maxAttempts = 10
$delaySeconds = 30

for ($i = 1; $i -le $maxAttempts; $i++) {
    $mySession = (Get-Process -Id $PID).SessionId
    $explorerInMySession = Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $mySession }

    if (-not $explorerInMySession) {
        Start-Process explorer.exe
        Start-Sleep -Seconds 2
        $explorerInMySession = Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $mySession }
        if ($explorerInMySession) { break }
    }
    else {
        break
    }

    Start-Sleep -Seconds $delaySeconds
}
'@ | Set-Content -Path 'C:\ProgramData\HCoA\Scripts\StartExplorerAtLogon.ps1' -Encoding ASCII

# 2) Remove old task (if present)
Unregister-ScheduledTask -TaskName 'HCoA-StartExplorerAtLogon' -Confirm:$false -ErrorAction SilentlyContinue

# 3) Create new task: any user logon, interactive user context
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\HCoA\Scripts\StartExplorerAtLogon.ps1"'
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName 'HCoA-StartExplorerAtLogon' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Start Explorer at logon if missing in current session'