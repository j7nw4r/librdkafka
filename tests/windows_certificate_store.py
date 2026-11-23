"""Explicit test-owned Windows My identities; never writes a trust/root store.

Production Schannel only reads these preprovisioned identities. This fixture
creates unique test identities, records their named-key ownership and verifies
certificate plus private-key deletion even when a test fails.
"""
import contextlib
import os
from pathlib import Path
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

_PROVISION = r'''
$ErrorActionPreference = 'Stop'
$thumb = $env:RDKAFKA_FIXTURE_THUMBPRINT
$certPath = 'Cert:\CurrentUser\My\' + $thumb
if (Test-Path $certPath) { throw 'Fixture certificate already exists; refusing to replace it' }
$flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
$cert = $null; $rsa = $null; $store = $null; $ok = $false
try {
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($env:RDKAFKA_FIXTURE_PFX, $env:RDKAFKA_FIXTURE_PASSWORD, $flags)
    if ($cert.Thumbprint -ne $thumb -or !$cert.HasPrivateKey) { throw 'Fixture PFX identity mismatch' }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($rsa -is [System.Security.Cryptography.RSACng]) {
        if ($rsa.Key.IsMachineKey -or $rsa.Key.IsEphemeral -or !$rsa.Key.KeyName) { throw 'Fixture requires a named current-user key' }
        $meta = @{kind='cng'; keyName=$rsa.Key.KeyName; provider=$rsa.Key.Provider.Provider; thumbprint=$thumb}
    } elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
        $info = $rsa.CspKeyContainerInfo
        if ($info.MachineKeyStore -or !$info.KeyContainerName) { throw 'Fixture requires a named current-user key' }
        $meta = @{kind='csp'; keyName=$info.KeyContainerName; provider=$info.ProviderName; providerType=$info.ProviderType; keyNumber=[int]$info.KeyNumber; thumbprint=$thumb}
    } else { throw 'Fixture RSA key provider is unsupported' }
    [System.IO.File]::WriteAllText($env:RDKAFKA_FIXTURE_KEY_JOURNAL, ($meta | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($cert)
    $ok = $true
    $meta | ConvertTo-Json -Compress
} finally {
    if (!$ok -and $cert) {
        if ($rsa) {
            if ($rsa -is [System.Security.Cryptography.RSACng]) { $rsa.Key.Delete() }
            elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) { $rsa.PersistKeyInCsp = $false; $rsa.Clear() }
            if ($store) { $store.Remove($cert) }
        } elseif ($cert.HasPrivateKey) {
            # If managed RSA discovery fails, let the native Certificate
            # provider remove the key association rather than leaking it.
            $cleanupStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
            try {
                $cleanupStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $cleanupStore.Add($cert)
            } finally { $cleanupStore.Dispose() }
            Remove-Item -Path $certPath -DeleteKey -Confirm:$false
            if (Test-Path $certPath) { throw 'Failed provisioning cleanup left its certificate behind' }
        }
    }
    if ($store) { $store.Dispose() }
    if ($rsa) { $rsa.Dispose() }
    if ($cert) { $cert.Dispose() }
}
'''

_CLEANUP = r'''
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
'''


def _powershell(script, additions):
    result = subprocess.run(["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                            env=dict(os.environ, **additions), text=True,
                            encoding="utf-8", capture_output=True, timeout=45)
    if result.returncode:
        raise RuntimeError("Windows test identity operation failed: " + result.stderr.strip())
    return result.stdout.strip()


@contextlib.contextmanager
def temporary_windows_identities(root, names=("client", "invalid-client", "expired-client")):
    """Yield name -> read-only Schannel selector; remove only our certs/keys."""
    if os.name != "nt":
        raise RuntimeError("Windows identity provisioning requires native Windows")
    root = Path(root)
    owned = []
    selectors = {}
    try:
        for name in names:
            cert = x509.load_pem_x509_certificate((root / f"{name}.crt").read_bytes())
            key = serialization.load_pem_private_key((root / f"{name}.key").read_bytes(), None)
            password = os.urandom(24).hex()
            path = root / f"{name}-store.pfx"
            # Only the leaf enters My. No CA or trust-anchor store is written.
            path.write_bytes(pkcs12.serialize_key_and_certificates(
                b"librdkafka-fixture", key, cert, None,
                serialization.BestAvailableEncryption(password.encode())))
            path.chmod(0o600)
            thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
            journal = root / f"{name}-store-owned.json"
            # Register cleanup before provisioning; native ownership metadata
            # is journaled before adding the certificate to My. Cleanup does
            # not depend on parsing a successful stdout response.
            owned.append((journal, thumbprint))
            _powershell(_PROVISION, {
                "RDKAFKA_FIXTURE_PFX": str(path),
                "RDKAFKA_FIXTURE_PASSWORD": password,
                "RDKAFKA_FIXTURE_THUMBPRINT": thumbprint,
                "RDKAFKA_FIXTURE_KEY_JOURNAL": str(journal),
            })
            if not journal.exists():
                raise RuntimeError("Windows fixture ownership journal missing")
            selectors[name] = "CurrentUser/My/" + thumbprint
        yield selectors
    finally:
        errors = []
        for journal, thumbprint in reversed(owned):
            try:
                if journal.exists():
                    _powershell(_CLEANUP, {"RDKAFKA_FIXTURE_KEY_JOURNAL": str(journal)})
                else:
                    # A failed constructor/import is already a test failure;
                    # still remove a known fixture certificate if it was added.
                    _powershell(r"""
$ErrorActionPreference = 'Stop'
$path = 'Cert:\CurrentUser\My\' + $env:RDKAFKA_FIXTURE_THUMBPRINT
if (Test-Path $path) { Remove-Item -Path $path -DeleteKey -Confirm:$false }
if (Test-Path $path) { throw 'Failed setup certificate cleanup was incomplete' }
""", {"RDKAFKA_FIXTURE_THUMBPRINT": thumbprint})
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise RuntimeError("Windows fixture cleanup failed: " + "; ".join(errors))
