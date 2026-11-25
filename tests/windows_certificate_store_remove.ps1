# Called by windows_certificate_store.py. Removes one journaled test
# identity and makes sure its private key is gone.
$ErrorActionPreference = 'Stop'
$meta = Get-Content -LiteralPath $env:RDKAFKA_FIXTURE_KEY_JOURNAL -Raw -Encoding utf8 | ConvertFrom-Json
$certPath = 'Cert:\CurrentUser\My\' + $meta.thumbprint
if (Test-Path $certPath) { Remove-Item -Path $certPath -DeleteKey -Confirm:$false }
if (Test-Path $certPath) { throw 'Fixture certificate removal was not completed' }
function Open-FixtureKey {
    if ($meta.kind -eq 'cng') {
        return [System.Security.Cryptography.CngKey]::Open([string]$meta.keyName, [System.Security.Cryptography.CngProvider]::new([string]$meta.provider), [System.Security.Cryptography.CngKeyOpenOptions]::None)
    }
    $parameters = [System.Security.Cryptography.CspParameters]::new([int]$meta.providerType, [string]$meta.provider, [string]$meta.keyName)
    $parameters.KeyNumber = [int]$meta.keyNumber
    $parameters.Flags = [System.Security.Cryptography.CspProviderFlags]::UseExistingKey -bor [System.Security.Cryptography.CspProviderFlags]::NoPrompt
    return [System.Security.Cryptography.RSACryptoServiceProvider]::new($parameters)
}
function Is-MissingKeyError($failure) {
    $e = $failure.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    $code = [uint32]($e.HResult -band 0xffffffffL)
    return $code -eq 0x80090016L -or $code -eq 0x80090011L -or $code -eq 0x8009000dL
}
# Delete an owned named key if CertificateProvider did not already remove it.
$key = $null
try { $key = Open-FixtureKey } catch { if (!(Is-MissingKeyError $_)) { throw } }
if ($key) {
    try {
        if ($meta.kind -eq 'cng') { $key.Delete() }
        else { $key.PersistKeyInCsp = $false; $key.Clear() }
    } finally { $key.Dispose() }
}
# Verification uses open-existing operations; it cannot create a replacement.
$key = $null
try { $key = Open-FixtureKey } catch { if (!(Is-MissingKeyError $_)) { throw } }
if ($key) { $key.Dispose(); throw 'Fixture private key is still accessible after cleanup' }
Write-Output 'certificate and named key removed'
