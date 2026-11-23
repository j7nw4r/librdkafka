# Schannel adapter scope and ownership

The private Windows adapter uses Schannel/SSPI for broker TLS, Crypt32 for X.509
parsing/chain policy, and a read-only preprovisioned Windows identity selector
for mutual TLS. It exposes no
public plugin ABI. TLS 1.2 is explicitly enabled; TLS 1.0/1.1 and TLS 1.3 are not
advertised by this initial adapter. `SCH_USE_STRONG_CRYPTO` is requested where the
SDK supports it. The operating system controls the available suites/signatures.
Backend choice and a Windows FIPS policy flag are not qualification evidence.

## Credentials and verification

Supported trust sources are one explicit PEM file, PEM string, memory PEM/DER
certificate(s), or the native current-user/system chain engine when no explicit
trust is supplied. Explicit roots use a private exclusive-root chain engine;
they never enter a host trust store. Chain URL retrieval is cache-only and AIA
retrieval is disabled where supported, so broker verification does not introduce
an unbounded network lookup. Explicit CRLs/revocation configuration is currently
unsupported and rejected; no independent revocation assurance is claimed.

Each completed handshake obtains the peer certificate and runs Crypt32 chain
building plus `CERT_CHAIN_POLICY_SSL` for server authentication, hostname and
time validity. A successful SSPI handshake alone does not authorize application
traffic. Disabled verification/hostname matching and OpenSSL verification
callbacks are rejected, not mapped to an approximate callback contract.

Mutual TLS selects an existing identity with
`ssl.schannel.certificate=CurrentUser/My/<40-hex thumbprint>` or
`LocalMachine/My/<40-hex thumbprint>`. The SHA-1 thumbprint is only a store
identifier; it does not choose the certificate signature/verification algorithm.
The adapter opens My read-only, requires an existing named private-key
association, and acquires the key with silent/no-healing/public-key-comparison
flags. It neither creates a key nor changes certificate properties or trust.
Caller-owned acquired handles remain live until Schannel credential teardown;
store-owned handles remain owned by their certificate/store.

Plaintext PKCS#8 and PFX parsing are implemented without key persistence, but
native Windows Schannel can reject in-process ephemeral keys even after their
import/public-key comparison succeeds. The adapter returns a named unsupported
identity diagnostic and directs the caller to the read-only selector. It never
silently persists a key to make that acquisition pass. See Microsoft's
[ephemeral-key limitation](https://learn.microsoft.com/en-us/dotnet/core/extensions/sslstream-troubleshooting#handshake-failed-with-ephemeral-keys).
Separate encrypted PEM, PKCS#1/SEC1 keys and PKCS#12 memory setters are rejected
explicitly. Existing ordinary OpenSSL formats/behavior remain unchanged.

The public setter parses supported encodings synchronously, owns its result,
replaces only on successful validation, supports clearing, and shares immutable
refcounted objects across config duplication. Native vector tests cover memory
certificate/key parse and lifetime. The live Schannel test copies a memory CA
configuration and destroys/clears the original before constructing the context;
full ephemeral private-key mTLS remains subject to the operating-system limit.
Temporary key/password bytes are wiped. Private data and certificate contents
never appear in diagnostics.

Explicit OpenSSL provider/engine, cipher-expression, curve/signature-expression,
key-password, CRL and custom Windows-store-list settings are rejected. Native
system trust is selected by leaving CA fields unset. `ssl.ca.location=probe` is
not interpreted as Windows trust. Multiple sources for one credential/trust
component, and a store selector combined with imported certificate/key/PFX
settings, fail early.

## Nonblocking contract

Each session owns bounded 64-KiB encrypted-input, encrypted-output and buffered
plaintext arrays. Handshake output exceeding the bound fails. Application
plaintext is accepted in chunks no larger than 16 KiB or the negotiated maximum.
The accepted prefix is bound to the original request buffer and absolute offset;
it is committed to the caller slice only after ciphertext has reached the
socket send operation. Retries flush existing ciphertext without re-encrypting
or duplicating plaintext. A changed pending request is an error.

The TLS service requests writable readiness independently of Kafka queue state,
and buffered plaintext/complete encrypted input creates readable progress
without a new socket event. Incomplete records retain their encrypted prefix
without creating a synthetic-read spin. SSPI's `SECBUFFER_EXTRA` is preserved.
Handshake completion waits for all final output and certificate verification.
Socket would-block/interrupted operations return to polling. EOF, alerts and
protocol errors use normal broker failure/reconnect accounting. Renegotiation
is explicitly refused with a reconnect error; it is not silently ignored.

Timeout, purge and termination use the neutral started-request predicate,
including accepted prefixes whose visible slice offset is zero. Teardown is
abortive: it discards queued ciphertext and deletes the SSPI context, rather
than transmitting a canceled request while attempting close_notify. Ordinary
socket acceptance still does not prove broker receipt for `acks=0`.

## Test and manual reproduction

`tests/schannel_transport.c` compiles the actual adapter into a test executable
linked against static librdkafka. It inspects private state while retaining real
Schannel API calls and a real TCP/TLS peer; it does not emulate Kafka. Python
`tests/schannel_transport.py --client PATH_TO_EXE` creates temporary CA/server/
client material, explicitly provisions unique test-only identities in CurrentUser/My,
starts an authenticated TLS 1.2 echo peer, and tests exact
131071-byte exchange, forced short I/O/EAGAIN, deferred commitment, changed retry,
buffered plaintext, cancellation, live memory CA duplication and certificate
failures. The fixture owns its My certificates and named keys; it removes both
and verifies that open-existing private-key operations fail afterward. It never
adds a CA to Root/CA trust stores. Production code only reads preprovisioned
identities. Ephemeral import limitations are tested as explicit rejections. Native execution and Wine execution must be reported
separately. `--runner wine` is supplementary compatibility execution only.

Prerequisite: `tests/windows_certificate_store.py` runs `pwsh` (PowerShell 7)
to provision and remove the test identities. Windows Server 2022 includes only
Windows PowerShell 5.1 (`powershell.exe`), so install PowerShell 7 first.
GitHub `windows-latest` runners include it.

Build with the branch's Windows Schannel/BCrypt CMake configuration and backend
test option, then run the Python command. Expect one PASS per case and a final
all-cases PASS with exit status zero. This test proves TLS transport behavior;
the separate Testcontainers Kafka fixture proves actual broker integration.

Primary API contracts used:

- [InitializeSecurityContext](https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--schannel)
- [EncryptMessage](https://learn.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--schannel)
- [DecryptMessage](https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel)
- [Exclusive-root chain engine](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_engine_config)
- [Certificate key-context ownership](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetcertificatecontextproperty)
- [Ephemeral CNG key import](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey)
