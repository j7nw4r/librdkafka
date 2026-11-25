<#
.SYNOPSIS

    Build librdkafka with the Schannel TLS and BCrypt crypto backends, run
    the local tests, and audit the DLL imports.

.DESCRIPTION

    Run from the repository root. The static build runs the local tests. The
    shared build checks that rdkafka.dll imports the Windows CNG and SSPI
    functions and has no OpenSSL dependency.
#>

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

$common = @('-A', 'x64',
    '-DRDKAFKA_TLS_BACKEND=schannel', '-DRDKAFKA_CRYPTO_BACKEND=bcrypt',
    '-DRDKAFKA_BUILD_EXAMPLES=OFF', '-DWITH_SASL=ON', '-DWITH_CURL=OFF',
    '-DWITH_ZLIB=OFF', '-DWITH_ZSTD=OFF', '-DWITH_HDRHISTOGRAM=OFF',
    '-DENABLE_LZ4_EXT=OFF')

& $cmake -S . -B build-cng-static @common `
    -DRDKAFKA_BUILD_STATIC=ON -DRDKAFKA_BUILD_TESTS=ON
Assert-ExitCode 'Static configure'
& $cmake --build build-cng-static --config Release --parallel 4
Assert-ExitCode 'Static build'

Push-Location tests
try {
    $env:TESTS = '0000,0004,0080,0193'
    & ..\build-cng-static\tests\Release\test-runner.exe -l
    Assert-ExitCode 'Local tests'
} finally {
    Remove-Item Env:TESTS -ErrorAction SilentlyContinue
    Pop-Location
}

& $cmake -S . -B build-cng-shared @common `
    -DRDKAFKA_BUILD_STATIC=OFF -DRDKAFKA_BUILD_TESTS=OFF `
    -DCMAKE_SHARED_LINKER_FLAGS=/MAP
Assert-ExitCode 'Shared configure'
& $cmake --build build-cng-shared --config Release --target rdkafka --parallel 4
Assert-ExitCode 'Shared build'

$dumpbin = Get-ChildItem "$vs\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe" |
    Select-Object -Last 1
$dll = Get-ChildItem build-cng-shared -Recurse -Filter '*rdkafka.dll' |
    Select-Object -First 1
if (!$dumpbin -or !$dll) { throw 'dumpbin or rdkafka.dll not found' }

$imports = & $dumpbin.FullName /DEPENDENTS $dll.FullName | Out-String
if ($LASTEXITCODE -ne 0) { throw 'dumpbin /DEPENDENTS failed' }
Write-Output $imports
if ($imports -match 'libssl|libcrypto|ssleay|libeay|openssl') {
    throw 'rdkafka.dll depends on OpenSSL'
}
foreach ($module in @('bcrypt.dll', 'ncrypt.dll', 'crypt32.dll', 'secur32.dll')) {
    if ($imports -notmatch [regex]::Escape($module)) {
        throw "rdkafka.dll does not import $module"
    }
}

# CMake does not define UNICODE, so a generic SSPI call imports the ANSI form.
# Schannel and SASL GSSAPI pass wide names and must call the W functions.
$functions = & $dumpbin.FullName /IMPORTS $dll.FullName | Out-String
if ($LASTEXITCODE -ne 0) { throw 'dumpbin /IMPORTS failed' }
foreach ($function in @('BCryptGenRandom', 'BCryptDeriveKeyPBKDF2',
        'BCryptCreateHash', 'NCryptSignHash',
        'InitializeSecurityContextW', 'AcquireCredentialsHandleW')) {
    if ($functions -notmatch [regex]::Escape($function)) {
        throw "rdkafka.dll does not import $function"
    }
}
if ($functions -match 'InitializeSecurityContextA') {
    throw 'rdkafka.dll imports InitializeSecurityContextA'
}

$maps = Get-ChildItem build-cng-shared -Recurse -Filter '*.map'
if (!$maps) { throw 'Linker map not found' }
foreach ($map in $maps) {
    if ((Get-Content $map.FullName -Raw) -match '(libssl|libcrypto|ssleay|libeay)\.(lib|a)') {
        throw "OpenSSL library in linker map $($map.Name)"
    }
}
Write-Output 'Schannel and BCrypt build, tests and import audit passed'
