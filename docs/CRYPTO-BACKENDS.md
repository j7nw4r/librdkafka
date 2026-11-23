# Private crypto services

Broker TLS and authentication crypto are independent build selections. The
private `rdkafka_crypto.h` interface contains no OpenSSL/Windows native types.
It provides SHA-1/256/512 digests, HMAC, PBKDF2, security randomness, ephemeral
signing-key import, RS256/ES256 signing and explicit key cleanup. There is one
provider per build and no dynamic plugin ABI or provider fallback.

SCRAM uses these services for hashing/HMAC/password derivation and a fresh
24-byte cryptographic nonce encoded into 32 URL-safe characters. Admin SCRAM
upsertion uses the same PBKDF2 service and handles derivation failures before
sending a request. Existing nonce/salt/signing call sites no longer rely on a
TLS-specific OpenSSL helper. Password derivation produces the same wire bytes;
it does not resolve SCRAM's FIPS service-boundary or password-derivation policy
questions. No approved-mode or deployment-qualification claim is made here.

`rd_rand_bytes` uses the selected provider when present and propagates a provider
failure directly; it does not switch to another randomness source. A build with
no crypto provider retains its platform entropy source for existing ordinary
uses. Non-security scheduling jitter/partition randomness remain separate.
The OpenSSL adapter retains pre-1.1 initialization/locking for crypto-only builds;
when OpenSSL TLS is selected its existing shared runtime supplies those hooks.
Legacy error queues are released through the crypto thread-cleanup hook on
owned broker/main/background threads, independently of TLS. The adapter was
syntax-checked against official hash-verified OpenSSL 1.0.1u and 1.0.2u headers,
including crypto-only initialization and configurations disabling EC/ECDSA/RSA
and hashes. Legacy libraries were not linked/executed. Modern EC-disabled
adapter execution explicitly rejected ES256 while retaining primitive services.
These are compatibility checks, not a recommendation to deploy old OpenSSL.

Base64 encoding/decoding is an independent utility in every build. Decoding
validates standard alphabet, complete quartets, terminal/canonical padding and
leading/trailing whitespace. URL-safe encoding removes padding. Token payload
parsing maps its URL-safe alphabet before decoding; it is not signature validation.

The OpenSSL signing adapter retains PEM formats and password decoding supported
by the selected OpenSSL library. Algorithm/key mismatches fail. RS256 explicitly
uses RSA PKCS#1 v1.5 with SHA-256. ES256 requires P-256 and emits fixed-width
64-byte `r || s` as JOSE requires, rather than OpenSSL's ASN.1 DER signature.
This fixes the earlier ES256 wire-format behavior. JWT JTI generation fails if
security randomness is unavailable. Temporary file-imported private keys are wiped.

The Windows adapter uses Microsoft BCrypt SHA/HMAC/PBKDF2/RNG services and
Microsoft Software Key Storage Provider ephemeral NCrypt keys. Private-key
signing imports accept unencrypted PKCS#8 PEM or DER. Encrypted PEM/PKCS#12 and
legacy PKCS#1/SEC1 signing-key encodings are explicitly unsupported by this
adapter; convert them offline or choose OpenSSL. Schannel certificate import is
a separate TLS operation with its own supported formats. No key container name
or persistence flag is supplied to the signing-key importer. The provider is
requested silently, and native error diagnostics contain only operation/status.

## Tests and observed results

`tests/crypto/vectors.c` contains known-answer SHA, RFC HMAC and PBKDF2 vectors,
empty input/key checks, invalid algorithm/iteration/key-import checks, RNG and
Base64 valid/malformed cases. `tests/crypto/run_vectors.py` generates temporary
RSA-2048/P-256 PKCS#8 keys, runs the C test, and independently verifies both
signature encodings through Python cryptography. Private keys are not printed
and are removed with their temporary directory.

Native Fedora/OpenSSL shared and static library tests passed, including both
signature verifications. Zig x86_64 Windows cross compilation passed. The
Windows primitive/RNG/codec vectors passed under Wine. Wine's NCrypt PKCS#8
import returned `0x80090027` (`NTE_INVALID_PARAMETER`), including a separate
flags-zero diagnostic experiment. This is an observed Wine compatibility limit,
not a native Windows pass or a substitute implementation. Native Windows CI
results are recorded separately by the coordinating agent; do not infer them
from cross compilation or Wine.

An early empty-key HMAC test found OpenSSL's one-shot helper treats a null key
pointer specially even at length zero. The adapter now supplies an actual empty
key buffer, and the known-answer regression passed. Test fixture PBKDF2-SHA512
expected text was corrected against an independently computed published-style
vector before final passing runs.

## Manual verification

Build with `RDKAFKA_BUILD_STATIC=ON` and `RDKAFKA_BUILD_BACKEND_TESTS=ON`, selecting
TLS and crypto backends independently as documented in the main build guide.
Run `backend-crypto-test` for primitives. With Python cryptography installed, run:

```sh
python tests/crypto/run_vectors.py --binary /path/to/backend-crypto-test
```

On native Windows use the generated `.exe` path. `--runner wine64` is available
for compatibility experiments and deliberately does not count as native
execution. Expect both the C PASS line and independent signature-verification
PASS, with exit status zero. Key-import/provider failures are failures, not skips.

Primary API references: [BCryptDeriveKeyPBKDF2](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekeypbkdf2),
[NCryptImportKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey),
and [BCryptSignHash](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsignhash).
