param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [int]$LimitMB = 10
)

$OfficeDir = Join-Path (Join-Path $Root "Office") "office_2024_ltsc"
$SetupPath = Join-Path $OfficeDir "setup.exe"
$ConfigPath = Join-Path $OfficeDir "config.xml"

if (-not (Test-Path $SetupPath)) {
    Write-Error "Missing setup.exe. Run the app's Office 2024 offline download first."
    exit 1
}

if (-not (Test-Path $ConfigPath)) {
    Write-Error "Missing config.xml. Ensure the Office 2024 XML path is set in settings."
    exit 1
}

function Get-DirSizeBytes([string]$Path) {
    $total = 0
    if (Test-Path $Path) {
        Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $total += $_.Length
        }
    }
    return $total
}

$limitBytes = $LimitMB * 1MB
$proc = Start-Process -FilePath $SetupPath -ArgumentList "/download", $ConfigPath -WorkingDirectory $OfficeDir -PassThru -WindowStyle Hidden
$lastBytes = 0
$lastTime = Get-Date

while (-not $proc.HasExited) {
    Start-Sleep -Seconds 1
    $size = Get-DirSizeBytes $OfficeDir
    $now = Get-Date
    $deltaBytes = $size - $lastBytes
    $deltaSeconds = ($now - $lastTime).TotalSeconds
    if ($deltaSeconds -le 0) { $deltaSeconds = 1 }
    $speedMB = [math]::Round(($deltaBytes / $deltaSeconds) / 1MB, 2)
    $sizeMB = [math]::Round($size / 1MB, 2)
    Write-Host ("Downloaded {0} MB / {1} MB @ {2} MB/s" -f $sizeMB, $LimitMB, $speedMB)
    if ($size -ge $limitBytes) {
        Write-Host "Limit reached, stopping download."
        try { $proc.Kill() } catch {}
        break
    }
    $lastBytes = $size
    $lastTime = $now
}

if ($proc.HasExited) {
    Write-Host ("ODT exited with code {0}" -f $proc.ExitCode)
}
