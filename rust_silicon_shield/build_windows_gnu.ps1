#Requires -Version 5.1
<#
.SYNOPSIS
    Build the tauhaulity_silicon_shield cdylib for x86_64-pc-windows-gnu without Visual Studio.

.DESCRIPTION
    The default Rust target on Windows is x86_64-pc-windows-msvc, which needs the
    MSVC linker from Visual Studio Build Tools plus the Windows SDK. Neither is
    present on a bare developer laptop, so this script instead drives the GNU
    target through a portable MinGW-w64 UCRT toolchain that lives inside the
    checkout (.tooling/mingw64) and requires no administrator rights and no
    system wide installation.

    The script:
      1. locates a MinGW-w64 gcc (env override, then the project toolchain, then PATH),
      2. exports CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER for that compiler,
      3. runs 'cargo build --release --target x86_64-pc-windows-gnu' from the crate
         directory using paths derived from this script location,
      4. reports the DLL path, size and SHA-256,
      5. runs the built probe binary's self-test unless -SkipSelfTest is given.

    With -ProvisionToolchain the script downloads the pinned winlibs MinGW-w64
    UCRT archive, verifies its SHA-256 and extracts it under .tooling/mingw64
    before building. The downloaded archive is deleted after a verified
    extraction. Nothing is written outside the checkout.

.PARAMETER ProvisionToolchain
    Download and verify the pinned MinGW-w64 toolchain when it is not present.

.PARAMETER SkipSelfTest
    Skip running the probe binary self-test after a successful build.

.EXAMPLE
    .\rust_silicon_shield\build_windows_gnu.ps1

.EXAMPLE
    .\rust_silicon_shield\build_windows_gnu.ps1 -ProvisionToolchain
#>
[CmdletBinding()]
param(
    [switch]$ProvisionToolchain,
    [switch]$SkipSelfTest
)

$ErrorActionPreference = 'Stop'

# Pinned winlibs release: GCC 16.2.0 (POSIX threads) + MinGW-w64 14.0.0 UCRT, r3.
$ToolchainUrl = 'https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r3.zip'
$ToolchainSha256 = '3C69305081E4A647144339A936244FCF7D3D9E558319E1AD7BE2CD2886D4B6A1'
$ToolchainVersion = 'GCC 16.2.0 (POSIX threads) + MinGW-w64 14.0.0 UCRT (release 3)'

$Target = 'x86_64-pc-windows-gnu'
$CrateName = 'tauhaulity_silicon_shield'

$ScriptDirectory = Split-Path -Parent $PSCommandPath
$CrateDirectory = $ScriptDirectory
$ProjectRoot = Split-Path -Parent $CrateDirectory
$ToolchainRoot = Join-Path $ProjectRoot (Join-Path '.tooling' 'mingw64')
$ToolchainBin = Join-Path $ToolchainRoot 'bin'
$DownloadDirectory = Join-Path $ProjectRoot (Join-Path '.tooling' 'download')
$DownloadArchive = Join-Path $DownloadDirectory 'winlibs-mingw64-ucrt.zip'

function Get-FileSha256 {
    <#
    .SYNOPSIS
        Return the upper case SHA-256 hex digest of a file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Invoke-NativeCommand {
    <#
    .SYNOPSIS
        Run a native executable, replay its output and return its exit code.

    .DESCRIPTION
        PowerShell wraps a native command's stderr in an ErrorRecord. With the
        script wide Stop preference that aborts a healthy build, and left on the
        host error stream it makes powershell.exe -File report failure. Both
        streams are therefore captured into a variable, replayed on the console
        and success is decided by the exit code alone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    foreach ($line in $lines) {
        Write-Host ([string]$line)
    }
    return $exitCode
}

function Invoke-ToolchainDownload {
    <#
    .SYNOPSIS
        Download, verify and extract the pinned MinGW-w64 toolchain.
    #>

    New-Item -ItemType Directory -Force -Path $DownloadDirectory | Out-Null
    Write-Host "Downloading $ToolchainVersion"
    Write-Host "  from $ToolchainUrl"
    # curl.exe ships with Windows 10 1803 and later. Invoke-WebRequest would
    # buffer the whole 270 MiB archive in memory before writing it to disk.
    $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
    if ($null -ne $curl) {
        $downloadExitCode = Invoke-NativeCommand -FilePath $curl.Source -Arguments @(
            '--location', '--fail', '--retry', '3', '--silent', '--show-error',
            '--output', $DownloadArchive, $ToolchainUrl
        )
        if ($downloadExitCode -ne 0) {
            throw "curl failed to download the toolchain (exit code $downloadExitCode)"
        }
    }
    else {
        Invoke-WebRequest -Uri $ToolchainUrl -OutFile $DownloadArchive -UseBasicParsing
    }

    $measured = Get-FileSha256 -Path $DownloadArchive
    if ($measured -ne $ToolchainSha256) {
        throw "toolchain archive SHA-256 mismatch: expected $ToolchainSha256, measured $measured"
    }

    Write-Host 'Extracting into .tooling (no administrator rights required)'
    $destination = Join-Path $ProjectRoot '.tooling'
    $tar = Get-Command 'tar.exe' -ErrorAction SilentlyContinue
    if ($null -ne $tar) {
        $extractExitCode = Invoke-NativeCommand -FilePath $tar.Source -Arguments @('-xf', $DownloadArchive, '-C', $destination)
        if ($extractExitCode -ne 0) {
            throw "tar failed to extract the toolchain (exit code $extractExitCode)"
        }
    }
    else {
        Expand-Archive -Path $DownloadArchive -DestinationPath $destination -Force
    }

    Remove-Item -Path $DownloadArchive -Force -ErrorAction SilentlyContinue
    # The download directory only exists to stage the archive; a non-recursive
    # remove deletes it once it is empty and leaves it alone otherwise.
    Remove-Item -LiteralPath $DownloadDirectory -Force -ErrorAction SilentlyContinue
    Write-Host "Toolchain extracted to $ToolchainRoot"
}

function Resolve-MinGwLinker {
    <#
    .SYNOPSIS
        Return the path of the MinGW-w64 gcc driver used as the Rust linker.
    #>

    $candidates = @()
    if ($env:TAUHAULITY_MINGW_ROOT) {
        $candidates += (Join-Path $env:TAUHAULITY_MINGW_ROOT 'bin\x86_64-w64-mingw32-gcc.exe')
        $candidates += (Join-Path $env:TAUHAULITY_MINGW_ROOT 'bin\gcc.exe')
    }
    $candidates += (Join-Path $ToolchainBin 'x86_64-w64-mingw32-gcc.exe')
    $candidates += (Join-Path $ToolchainBin 'gcc.exe')
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    foreach ($name in @('x86_64-w64-mingw32-gcc.exe', 'gcc.exe')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }
    return $null
}

Write-Host "Building $CrateName for $Target"

$linker = Resolve-MinGwLinker
if ($null -eq $linker -and $ProvisionToolchain) {
    Invoke-ToolchainDownload
    $linker = Resolve-MinGwLinker
}
if ($null -eq $linker) {
    $expectedLinker = Join-Path $ToolchainBin 'x86_64-w64-mingw32-gcc.exe'
    throw @"
MinGW-w64 gcc was not found, so the $Target build cannot be linked and this
script stops before cargo runs. The MSVC linker from Visual Studio cannot stand
in for it, and no partial artifact is produced.

  Rust target     : $Target
  Required driver : x86_64-w64-mingw32-gcc.exe
  Expected path   : $expectedLinker
  Toolchain       : $ToolchainVersion
  Archive URL     : $ToolchainUrl
  Archive SHA-256 : $ToolchainSha256
  Extraction path : $ToolchainRoot
                    (the archive contains a top-level mingw64 directory)
  Search order    : TAUHAULITY_MINGW_ROOT\bin, then the extraction path, then PATH

Options:
  1. Re-run this script with -ProvisionToolchain. It downloads the pinned
     archive above, verifies the SHA-256 and extracts it to the extraction path
     (no administrator rights and no system installation required), then builds.
  2. Point TAUHAULITY_MINGW_ROOT at an existing MinGW-w64 root that contains
     bin\x86_64-w64-mingw32-gcc.exe.
  3. Put x86_64-w64-mingw32-gcc.exe on PATH.
"@
}

Write-Host "Linker: $linker"
$linkerVersion = (& $linker --version | Select-Object -First 1)
Write-Host "        $linkerVersion"

# The Rust compiler invokes the linker named here; the toolchain directory is
# also prepended to PATH so the GCC driver reaches the MinGW runtime that ships
# beside it.
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $linker
$linkerDirectory = Split-Path -Parent $linker
$pathEntries = $env:PATH -split ';'
if ($pathEntries -notcontains $linkerDirectory) {
    $env:PATH = "$linkerDirectory;$env:PATH"
}

$cargo = Get-Command 'cargo.exe' -ErrorAction SilentlyContinue
if ($null -eq $cargo) {
    $cargo = Get-Command 'cargo' -ErrorAction SilentlyContinue
}
if ($null -eq $cargo) {
    throw 'cargo was not found on PATH; install the Rust toolchain or add cargo to PATH.'
}

Push-Location -LiteralPath $CrateDirectory
try {
    $buildExitCode = Invoke-NativeCommand -FilePath $cargo.Source -Arguments @(
        'build', '--release', '--target', $Target
    )
}
finally {
    Pop-Location
}
if ($buildExitCode -ne 0) {
    throw "cargo build failed with exit code $buildExitCode"
}

$libraryPath = Join-Path $CrateDirectory (Join-Path 'target' (Join-Path $Target (Join-Path 'release' "$CrateName.dll")))
if (-not (Test-Path -LiteralPath $libraryPath -PathType Leaf)) {
    throw "the build reported success but $libraryPath does not exist"
}
$library = Get-Item -LiteralPath $libraryPath
Write-Host ''
Write-Host "DLL    $($library.FullName)"
Write-Host "Size   $($library.Length) bytes"
Write-Host "SHA256 $(Get-FileSha256 -Path $library.FullName)"

if (-not $SkipSelfTest) {
    $probePath = Join-Path $CrateDirectory (Join-Path 'target' (Join-Path $Target (Join-Path 'release' 'tauhaulity_shield_probe.exe')))
    if (Test-Path -LiteralPath $probePath -PathType Leaf) {
        Write-Host ''
        Write-Host "Running $probePath --self-test"
        $probeExitCode = Invoke-NativeCommand -FilePath $probePath -Arguments @('--self-test')
        if ($probeExitCode -ne 0) {
            throw "the probe self-test failed with exit code $probeExitCode"
        }
    }
    else {
        throw "the build reported success but $probePath does not exist"
    }
}

Write-Host ''
Write-Host "Done. The loader discovers $CrateName.dll under target\$Target\release automatically."
