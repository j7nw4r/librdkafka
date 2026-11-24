# Called by windows_certificate_store.py. Adds one test identity to
# CurrentUser\My and journals its key so that cleanup can remove it.
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
