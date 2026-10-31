# Zadatak sustava za poller C++ verzije: SolarniMonitor.exe --poller od paljenja računala, i kad aplikacija nije otvorena.
# Poziva ga instalacija:  poller_task.ps1 -Register "C:\Program Files\Solarni monitor 2"  |  -Unregister  |  -Stop
# Solarni poslužitelj: ... -TaskName SolarniPosluzitelj -ExeName SolarniServer.exe -Arguments --service
param(
    [string]$Register,
    [switch]$Unregister,
    [switch]$Stop,
    [string]$TaskName = "Solarni monitor 2 - poller",
    [string]$ExeName = "SolarniMonitor.exe",
    [string]$Arguments = "--poller"
)
$ErrorActionPreference = "Stop"

function Remove-PollerTask {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

if ($Stop) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; exit 0 }
if ($Unregister) { Remove-PollerTask; exit 0 }
if ($Register) {
    Remove-PollerTask
    $exe = Join-Path $Register $ExeName
    $action = New-ScheduledTaskAction -Execute $exe -Argument $Arguments -WorkingDirectory $Register
    # pri paljenju računala, a svakih 5 minuta ponovno ako je proces završio (radi li već, IgnoreNew ga ne dira) –
    # Windows "ponovno pokreni nakon greške" ne vrijedi kad program sam izađe s kodom različitim od 0
    $trigger = @(New-ScheduledTaskTrigger -AtStartup)
    try {
        $trigger += New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    } catch {
        Write-Warning "Okidač svakih 5 minuta nije podržan: $($_.Exception.Message)"
    }
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $description = "$TaskName ($ExeName $Arguments)"
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
            -Principal $principal -Description $description | Out-Null
    } catch {
        Write-Warning "Zadatak bez okidača svakih 5 minuta: $($_.Exception.Message)"
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) `
            -Settings $settings -Principal $principal -Description $description | Out-Null
    }
    Start-ScheduledTask -TaskName $TaskName
}
