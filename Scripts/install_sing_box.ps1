[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$version = '1.13.16'
$archiveName = "sing-box-$version-windows-amd64.zip"
$expectedSha256 = '6cbf90ec4ee87122ffce09b73928fb31e763bc1c75a119f79c61d24734c78807'
$releaseUri = "https://github.com/SagerNet/sing-box/releases/download/v$version/$archiveName"
$expectedEntry = "sing-box-$version-windows-amd64/sing-box.exe"
$maximumArchiveBytes = 64MB

if ([Environment]::Is64BitOperatingSystem -ne $true) {
    throw 'Target requires 64-bit Windows for sing-box.'
}

if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'The per-user local application data directory is unavailable.'
}

$engineRoot = Join-Path $env:LOCALAPPDATA 'Target\sing-box'
$binDirectory = Join-Path $engineRoot 'bin'
$installedExecutable = Join-Path $binDirectory 'sing-box.exe'
$runtimeRecord = Join-Path $engineRoot 'runtime\runtime-record.json'
$lifecycleLockPath = Join-Path $engineRoot 'runtime.lifecycle.lock'
$workDirectory = Join-Path ([IO.Path]::GetTempPath()) ("target-sing-box-" + [Guid]::NewGuid().ToString('N'))
$archivePath = Join-Path $workDirectory $archiveName
$extractedExecutable = Join-Path $workDirectory 'sing-box.exe'

function Invoke-PinnedVersion([string] $ExecutablePath) {
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ExecutablePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    # Windows PowerShell 5.1/.NET Framework does not expose ArgumentList.
    # This is a fixed, non-user-controlled argument and is safe to quote as-is.
    $startInfo.Arguments = 'version'

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'The sing-box version command could not be started.'
        }

        $stdout = $process.StandardOutput.ReadLineAsync()
        if (-not $process.WaitForExit(10000)) {
            # This process was created by this invocation and is the exact
            # child whose bounded version check timed out.
            $process.Kill()
            throw 'The sing-box version command timed out.'
        }

        $firstLine = $stdout.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or $firstLine -ne "sing-box version $version") {
            throw 'The sing-box version verification failed.'
        }
    }
    finally {
        $process.Dispose()
    }
}

[IO.Directory]::CreateDirectory($engineRoot) | Out-Null
$lifecycleLock = [IO.FileStream]::new(
    $lifecycleLockPath,
    [IO.FileMode]::OpenOrCreate,
    [IO.FileAccess]::ReadWrite,
    [IO.FileShare]::None)
try {
    if ([IO.File]::Exists($runtimeRecord)) {
        throw 'A runtime ownership record exists. Reconcile or stop the runtime before installing sing-box.'
    }

    [IO.Directory]::CreateDirectory($workDirectory) | Out-Null
    try {
    # Windows PowerShell 5.1 does not load System.Net.Http for type
    # resolution by default.
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $true
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(2)
    try {
        $response = $client.GetAsync(
            $releaseUri,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        [void]$response.EnsureSuccessStatusCode()
        try {
            if ($response.RequestMessage.RequestUri.Scheme -ne 'https') {
                throw 'The release download did not remain on HTTPS.'
            }

            $declaredLength = $response.Content.Headers.ContentLength
            if ($null -ne $declaredLength -and $declaredLength -gt $maximumArchiveBytes) {
                throw 'The sing-box archive exceeds the download size limit.'
            }

            $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $output = [IO.FileStream]::new(
                $archivePath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            try {
                $buffer = [byte[]]::new(64KB)
                [long]$total = 0
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $total += $read
                    if ($total -gt $maximumArchiveBytes) {
                        throw 'The sing-box archive exceeds the download size limit.'
                    }

                    $output.Write($buffer, 0, $read)
                }

                $output.Flush($true)
            }
            finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
        finally {
            $response.Dispose()
        }
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }

    # Source: the digest published beside this asset on the official release page:
    # https://github.com/SagerNet/sing-box/releases/expanded_assets/v1.13.16
    $actualSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        throw 'The sing-box archive checksum verification failed.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $entries = @($archive.Entries | Where-Object { $_.FullName -eq $expectedEntry })
        if ($entries.Count -ne 1 -or $entries[0].Length -le 0 -or $entries[0].Length -gt $maximumArchiveBytes) {
            throw 'The sing-box archive does not contain the expected executable.'
        }

        [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $extractedExecutable, $false)
    }
    finally {
        $archive.Dispose()
    }

    Invoke-PinnedVersion $extractedExecutable
    [IO.Directory]::CreateDirectory($binDirectory) | Out-Null
    $stagedExecutable = Join-Path $binDirectory (".sing-box." + [Guid]::NewGuid().ToString('N') + '.tmp')
    $backupExecutable = Join-Path $binDirectory (".sing-box." + [Guid]::NewGuid().ToString('N') + '.bak')
    $hadExistingExecutable = [IO.File]::Exists($installedExecutable)
    $postInstallVerified = $false
    try {
        [IO.File]::Copy($extractedExecutable, $stagedExecutable, $false)
        if ($hadExistingExecutable) {
            # File.Replace is available on .NET Framework and keeps the
            # replacement on the same volume with a recovery backup.
            [IO.File]::Replace($stagedExecutable, $installedExecutable, $backupExecutable, $true)
        }
        else {
            [IO.File]::Move($stagedExecutable, $installedExecutable)
        }

        try {
            Invoke-PinnedVersion $installedExecutable
            $postInstallVerified = $true
        }
        catch {
            if ($hadExistingExecutable -and [IO.File]::Exists($backupExecutable)) {
                [IO.File]::Delete($installedExecutable)
                [IO.File]::Move($backupExecutable, $installedExecutable)
            }
            elseif (-not $hadExistingExecutable) {
                [IO.File]::Delete($installedExecutable)
            }

            throw
        }

        if ([IO.File]::Exists($backupExecutable)) {
            [IO.File]::Delete($backupExecutable)
        }
    }
    finally {
        if ([IO.File]::Exists($stagedExecutable)) {
            [IO.File]::Delete($stagedExecutable)
        }

        # If post-install verification did not complete, leave any backup in
        # place as recovery evidence instead of deleting it blindly.
        if (-not $postInstallVerified -and [IO.File]::Exists($backupExecutable)) {
            Write-Warning "The previous sing-box executable remains available at '$backupExecutable'."
        }
    }

    Write-Output "Installed sing-box $version for the current user."
    }
    finally {
        if ([IO.Directory]::Exists($workDirectory)) {
            [IO.Directory]::Delete($workDirectory, $true)
        }
    }
}
finally {
    $lifecycleLock.Dispose()
}
