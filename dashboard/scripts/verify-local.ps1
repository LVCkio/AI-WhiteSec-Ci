param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $projectRoot
try {
    & (Join-Path $PSScriptRoot 'run-local.ps1') -Demo -GatewayPort 18080 -CodebertPort 18081 -Python $Python -DataDirectory 'data\verification'
    try {
        & $Python (Join-Path $PSScriptRoot 'smoke_demo.py') --url http://127.0.0.1:18080
        if ($LASTEXITCODE -ne 0) { throw 'HTTP smoke verification failed.' }
        $sessionPath = Join-Path $projectRoot 'data\verification\local-processes.json'
        $startedIds = @(Get-Content -LiteralPath $sessionPath -Raw | ConvertFrom-Json | ForEach-Object { $_.ProcessId })
    } finally {
        & (Join-Path $PSScriptRoot 'stop-local.ps1') -DataDirectory 'data\verification'
    }
    foreach ($processId in $startedIds) {
        if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
            throw "Local process $processId was not stopped."
        }
    }
    Write-Host 'Verified local HTTP pipeline and service shutdown.'
} finally {
    Pop-Location
}
