[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8501
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host "Creating the local Python environment..."

    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    $localPython = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"

    if ($pyLauncher) {
        & $pyLauncher.Source -3.12 -m venv .venv
    }
    elseif ($pythonCommand) {
        & $pythonCommand.Source -m venv .venv
    }
    elseif (Test-Path -LiteralPath $localPython) {
        & $localPython -m venv .venv
    }
    else {
        throw "Python 3.12 was not found. Install it from python.org, then run this script again."
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Python could not create the .venv environment."
    }
}

& $venvPython -c "import pandas, plotly, streamlit" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing dashboard dependencies. This is needed only on the first run..."
    & $venvPython -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency installation failed. Check the internet connection and run this script again."
    }
}

& $venvPython -c "import ot_sentinel" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $venvPython -m pip install -e . --no-deps
    if ($LASTEXITCODE -ne 0) {
        throw "The OT Sentinel package could not be installed."
    }
}

Write-Host "Starting OT Sentinel at http://localhost:$Port"
& $venvPython -m streamlit run app.py --server.port $Port

