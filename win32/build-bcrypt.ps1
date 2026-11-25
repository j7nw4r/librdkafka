<#
.SYNOPSIS

    Build librdkafka with the BCrypt crypto backend, run the local tests, and
    audit the DLL imports.

.DESCRIPTION

    Run from the repository root with Windows PowerShell 5.1 or later. The
    static build runs the local tests 0000, 0004 and 0080. The shared build
    checks that rdkafka.dll imports the BCrypt and NCrypt functions. With
    -TlsBackend none, it also checks that the DLL does not use OpenSSL.

.PARAMETER TlsBackend

    The broker TLS backend: none (default) or openssl.

.PARAMETER WithCurl

    Build with libcurl, which enables OIDC. CMake must find libcurl, for
    example through a vcpkg toolchain file in -CMakeArgs.

.PARAMETER CMakeArgs

    More arguments for the CMake configure steps.
#>

param(
    [ValidateSet('none', 'openssl')]
    [string]$TlsBackend = 'none',
    [switch]$WithCurl,
    [string[]]$CMakeArgs = @()
)

$ErrorActionPreference = 'Stop'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -prerelease -products '*' -property installationPath

$cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
if (!$cmake) {
    $cmake = "$vs\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
}
if (!(Test-Path $cmake)) { throw 'CMake not found' }

function Assert-ExitCode([string]$step) {
    if ($LASTEXITCODE -ne 0) { throw "$step failed with exit code $LASTEXITCODE" }
}

$curl = 'OFF'
if ($WithCurl) { $curl = 'ON' }
$name = "build-bcrypt-$TlsBackend"
if ($WithCurl) { $name += '-curl' }

$common = @('-A', 'x64',
    "-DRDKAFKA_TLS_BACKEND=$TlsBackend", '-DRDKAFKA_CRYPTO_BACKEND=bcrypt',
    '-DRDKAFKA_BUILD_EXAMPLES=OFF', '-DWITH_SASL=ON', "-DWITH_CURL=$curl",
    '-DWITH_ZLIB=OFF', '-DWITH_ZSTD=OFF', '-DWITH_HDRHISTOGRAM=OFF',
    '-DENABLE_LZ4_EXT=OFF') + $CMakeArgs

& $cmake -S . -B "$name-static" @common `
    -DRDKAFKA_BUILD_STATIC=ON -DRDKAFKA_BUILD_TESTS=ON
Assert-ExitCode 'Static configure'
& $cmake --build "$name-static" --config Release --parallel 4
Assert-ExitCode 'Static build'

Push-Location tests
try {
    $env:TESTS = '0000,0004,0080'
    & "..\$name-static\tests\Release\test-runner.exe" -l
    Assert-ExitCode 'Local tests'
} finally {
    Remove-Item Env:TESTS -ErrorAction SilentlyContinue
    Pop-Location
}

& $cmake -S . -B "$name-shared" @common `
    -DRDKAFKA_BUILD_STATIC=OFF -DRDKAFKA_BUILD_TESTS=OFF `
    -DCMAKE_SHARED_LINKER_FLAGS=/MAP
Assert-ExitCode 'Shared configure'
& $cmake --build "$name-shared" --config Release --target rdkafka --parallel 4
Assert-ExitCode 'Shared build'

$dumpbin = Get-ChildItem "$vs\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe" |
    Select-Object -Last 1
$dll = Get-ChildItem "$name-shared" -Recurse -Filter '*rdkafka.dll' |
    Select-Object -First 1
if (!$dumpbin -or !$dll) { throw 'dumpbin or rdkafka.dll not found' }

$dependents = & $dumpbin.FullName /DEPENDENTS $dll.FullName | Out-String
Assert-ExitCode 'dumpbin /DEPENDENTS'
Write-Output $dependents
foreach ($module in @('bcrypt.dll', 'ncrypt.dll', 'crypt32.dll')) {
    if ($dependents -notmatch [regex]::Escape($module)) {
        throw "rdkafka.dll does not import $module"
    }
}

$functions = & $dumpbin.FullName /IMPORTS $dll.FullName | Out-String
Assert-ExitCode 'dumpbin /IMPORTS'
$required = @('BCryptGenRandom', 'BCryptDeriveKeyPBKDF2', 'BCryptCreateHash',
    'NCryptImportKey', 'NCryptSignHash')
# rdkafka.c calls curl_global_init() only when WITH_CURL reaches the compiler.
if ($WithCurl) { $required += 'curl_global_init' }
foreach ($function in $required) {
    if ($functions -notmatch [regex]::Escape($function)) {
        throw "rdkafka.dll does not import $function"
    }
}

if ($TlsBackend -eq 'none') {
    if ($dependents -match 'libssl|libcrypto|ssleay|libeay') {
        throw 'rdkafka.dll depends on OpenSSL'
    }
    $maps = Get-ChildItem "$name-shared" -Recurse -Filter '*.map'
    if (!$maps) { throw 'Linker map not found' }
    foreach ($map in $maps) {
        if ((Get-Content $map.FullName -Raw) -match '(libssl|libcrypto|ssleay|libeay)[^\\/]*\.(lib|a)') {
            throw "OpenSSL library in linker map $($map.Name)"
        }
    }
}
Write-Output "BCrypt build with TLS backend $TlsBackend passed"
