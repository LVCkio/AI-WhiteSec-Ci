param(
    [switch]$Demo,
    [int]$GatewayPort = 8080,
    [int]$CodebertPort = 8001,
    [string]$Python = 'python',
    [string]$DataDirectory = 'data'
)
$ErrorActionPreference = 'Stop'
if ($GatewayPort -eq $CodebertPort -or $GatewayPort -lt 1 -or $GatewayPort -gt 65535 -or
    $CodebertPort -lt 1 -or $CodebertPort -gt 65535) {
    throw 'Gateway and CodeBERT need two different valid TCP ports (1..65535).'
}
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dataPath = [System.IO.Path]::GetFullPath((Join-Path $projectRoot $DataDirectory))
if (-not $dataPath.StartsWith($projectRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'DataDirectory must stay inside the project workspace.'
}
New-Item -ItemType Directory -Path $dataPath -Force | Out-Null
if (Test-Path -LiteralPath (Join-Path $dataPath 'local-processes.json')) {
    throw 'A local session record already exists. Run scripts/stop-local.ps1 before starting again.'
}
foreach ($port in @($GatewayPort, $CodebertPort)) {
    if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) {
        throw "Port $port is already in use. Choose a different local port."
    }
}
function New-LocalKey {
    $keyBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($keyBytes)
    $rng.Dispose()
    return [Convert]::ToBase64String($keyBytes)
}
if (-not $env:GATEWAY_API_KEY) { $env:GATEWAY_API_KEY = New-LocalKey }
if (-not $env:SERVICE_API_KEY) { $env:SERVICE_API_KEY = New-LocalKey }
$env:MODEL_MODE = if ($Demo) { 'demo' } else { 'real' }
$env:MODEL_DIR = Join-Path $projectRoot 'models\current'
$env:POLICY_PATH = Join-Path $projectRoot 'config\final-policy.json'
$env:CODEBERT_URL = "http://127.0.0.1:$CodebertPort"
$env:DATABASE_URL = 'sqlite:///' + (Join-Path $dataPath 'audit.sqlite3')
$pythonPath = (Get-Command $Python -ErrorAction Stop).Source
$started = @()
try {
    foreach ($service in @(
        @{ Name = 'codebert'; Module = 'app.codebert:app'; Port = $CodebertPort },
        @{ Name = 'gateway'; Module = 'app.gateway:app'; Port = $GatewayPort }
    )) {
        $process = Start-Process -FilePath $pythonPath -ArgumentList @(
            '-m', 'uvicorn', $service.Module, '--host', '127.0.0.1', '--port', $service.Port
        ) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru `
          -RedirectStandardOutput (Join-Path $dataPath ($service.Name + '.stdout.log')) `
          -RedirectStandardError (Join-Path $dataPath ($service.Name + '.stderr.log'))
        $started += @{ Name = $service.Name; ProcessId = $process.Id; Port = $service.Port; StartTimeUtc = $process.StartTime.ToUniversalTime().ToString('o') }
    }
    $started | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dataPath 'local-processes.json') -Encoding utf8
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Milliseconds 500
        try {
            Invoke-RestMethod -Uri "http://127.0.0.1:$GatewayPort/health/ready" -TimeoutSec 2 | Out-Null
            $ready = $true
            break
        } catch { }
    }
    if (-not $ready) { throw 'Local services failed to start. Inspect logs in data/.' }
    Write-Host "Gateway ready: http://127.0.0.1:$GatewayPort/docs; model mode=$env:MODEL_MODE"
    Write-Host "Dashboard: http://127.0.0.1:$GatewayPort/dashboard"
    Write-Host 'API keys are in this PowerShell session. Run scripts/smoke_demo.py from the same session.'
    if ($DataDirectory -eq 'data') {
        Write-Host 'Stop both local services with .\scripts\stop-local.ps1.'
    } else {
        Write-Host ('Stop both local services with .\scripts\stop-local.ps1 -DataDirectory "{0}".' -f $DataDirectory)
    }
} catch {
    foreach ($item in $started) { Stop-Process -Id $item.ProcessId -ErrorAction SilentlyContinue }
    $sessionPath = Join-Path $dataPath 'local-processes.json'
    if (Test-Path -LiteralPath $sessionPath) { Remove-Item -LiteralPath $sessionPath }
    throw
}
