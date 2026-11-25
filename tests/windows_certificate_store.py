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

_SCRIPTS = Path(__file__).resolve().parent


def _powershell(script, additions):
    result = subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
         str(_SCRIPTS / script)],
        env=dict(os.environ, **additions), text=True, encoding="utf-8",
        capture_output=True, timeout=45)
    if result.returncode:
        raise RuntimeError("Windows test identity operation failed: " +
                           result.stderr.strip())
    return result.stdout.strip()


@contextlib.contextmanager
def temporary_windows_identities(
        root, names=("client", "invalid-client", "expired-client")):
    """Yield name -> store selector; remove only the identities added here."""
    if os.name != "nt":
        raise RuntimeError(
            "Windows identity provisioning requires native Windows")
    root = Path(root)
    owned = []
    selectors = {}
    try:
        for name in names:
            cert = x509.load_pem_x509_certificate(
                (root / f"{name}.crt").read_bytes())
            key = serialization.load_pem_private_key(
                (root / f"{name}.key").read_bytes(), None)
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
            _powershell("windows_certificate_store_add.ps1", {
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
                    _powershell("windows_certificate_store_remove.ps1",
                                {"RDKAFKA_FIXTURE_KEY_JOURNAL": str(journal)})
                # Before the journal exists, PowerShell owns failed-import
                # cleanup. In particular, a preexisting certificate rejection
                # must never authorize Python to remove that other identity.
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise RuntimeError(
                "Windows fixture cleanup failed: " +
                "; ".join(errors))
