# Schannel adapter scope and ownership

The private Windows adapter uses Schannel/SSPI for broker TLS, Crypt32 for X.509
parsing/chain policy, and ephemeral CNG keys for client identities. It exposes no
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

Mutual TLS supports a leaf-first PEM chain with an unencrypted PKCS#8 key
(file/string or public memory setter), and a PKCS#12 keystore file imported with
`PKCS12_ALWAYS_CNG_KSP | PKCS12_NO_PERSIST_KEY`. Separate PKCS#1/SEC1/encrypted PEM
and PKCS#12 memory setters are rejected explicitly. CNG key imports are ephemeral
and silent, without a persistent key name or machine-store writes.
Certificate/key public portions are compared before a separate key is bound.

The public setter parses supported encodings synchronously, owns its result,
replaces only on successful validation, supports clearing, and shares immutable
refcounted objects across config duplication. Client initialization copies the
certificate store before attaching a private-key handle; it never changes the
shared configuration object. Configuration-owned handles remain live through
client credential teardown. File-imported handles and PFX handles returned with
caller-free ownership are retained until the Schannel credential handle and
identity certificate/store have been released. Temporary key/password bytes are
wiped. Neither private data nor certificate contents appear in diagnostics.

Explicit OpenSSL provider/engine, cipher-expression, curve/signature-expression,
key-password, CRL and custom Windows-store-list settings are rejected. Native
system trust is selected by leaving CA fields unset. `ssl.ca.location=probe` is
not interpreted as Windows trust. Multiple sources for one credential/trust
component and PFX combined with separate certificate/key settings fail early.

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
client material, starts an authenticated TLS 1.2 echo peer, and tests exact
131071-byte exchange, forced short I/O/EAGAIN, deferred commitment, changed retry,
buffered plaintext, cancellation, PFX and certificate failures. Temporary keys
are removed after each run. Native execution and Wine execution must be reported
separately. `--runner wine` is supplementary compatibility execution only.

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
