param([string]$DataDirectory = 'data')
$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dataPath = [System.IO.Path]::GetFullPath((Join-Path $projectRoot $DataDirectory))
if (-not $dataPath.StartsWith($projectRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'DataDirectory must stay inside the project workspace.'
}
$sessionPath = Join-Path $dataPath 'local-processes.json'
if (-not (Test-Path -LiteralPath $sessionPath)) { Write-Host 'No local session record.'; return }
$entries = Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json
foreach ($entry in $entries) {
    $process = Get-Process -Id $entry.ProcessId -ErrorAction SilentlyContinue
    $recordedStart = ([DateTime]$entry.StartTimeUtc).ToUniversalTime()
    if ($process -and $process.ProcessName -like 'python*' -and
        $process.StartTime.ToUniversalTime() -eq $recordedStart) {
        Stop-Process -Id $entry.ProcessId
        Write-Host "Stopped $($entry.Name)."
    }
}
Remove-Item -LiteralPath $sessionPath
