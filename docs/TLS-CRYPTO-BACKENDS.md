# TLS and authentication crypto backends

This branch adds private, build-selected interfaces. Broker TLS owns immutable
credentials and per-socket TLS sessions; authentication crypto owns hashes,
HMAC, PBKDF2, secure randomness and JWT signing. Socket readiness, Kafka request
ordering, timeouts, reconnects and delivery callbacks remain in the existing
broker/transport machinery. There is no public provider ABI or runtime switch.

## Build and capabilities

Default builds retain OpenSSL. CMake selects the two services independently:

```sh
cmake -S . -B build -DRDKAFKA_TLS_BACKEND=openssl \
  -DRDKAFKA_CRYPTO_BACKEND=openssl
cmake --build build --parallel
```

On Windows, select `schannel` and `bcrypt` instead. Schannel uses SSPI/Crypt32
and BCrypt uses BCrypt/NCrypt; this client library has no OpenSSL dependency.
Use `none` for either service to omit it. An empty TLS choice preserves the
legacy `WITH_SSL` option; an empty crypto choice follows the selected TLS
backend. `WITH_SSL` continues to mean the OpenSSL TLS implementation internally,
while `WITH_TLS` and `WITH_CRYPTO` are independent capability gates. CMake
stops with an error when `-DWITH_SSL=ON` is combined with
`RDKAFKA_TLS_BACKEND=schannel` or `none`, instead of silently ignoring it.

SASL GSSAPI on Windows uses SSPI Kerberos, independently of the TLS backend.
It calls the wide-character SSPI functions explicitly (`AcquireCredentialsHandleW`,
`InitializeSecurityContextW`). Before this, MSVC CMake builds, which do not
define `UNICODE`, passed the wide target SPN to `InitializeSecurityContextA`, and
authentication failed with "Target unknown (0x80090303)". The Visual Studio
project defines `UNICODE` and was not affected. With `debug=security` the client
logs the target SPN. The Windows workflow checks that the shared DLL imports
the W functions and does not import `InitializeSecurityContextA` (Schannel also
uses the W form). CI has no KDC, so a Kerberos round trip is not part of CI.

The configure equivalents are `--with-tls-backend=openssl|schannel|none` and
`--with-crypto-backend=openssl|bcrypt|none`. The existing Windows Visual Studio
project retains its ordinary OpenSSL default; CMake provides backend selection.
Linux configure selections were built and exercised. Windows configure/MinGW
execution was not accepted by this matrix; use the tested Windows CMake path.
Use a separate checkout for configure builds: its generated source-root
`config.h` otherwise takes precedence over CMake's generated header on Linux.
Installed CMake targets propagate native libraries and crypto-only OpenSSL
dependencies. Windows pkg-config metadata includes BCrypt/NCrypt where needed.

Query `builtin.features` with `rd_kafka_conf_get()`. `ssl` keeps its name for
compatibility and now means broker TLS from any backend; `tls_openssl` or
`tls_schannel` names the backend. `auth_crypto` means authentication crypto
(SASL SCRAM, OAUTHBEARER/OIDC JWT signing and SCRAM credential upserts);
`auth_crypto_openssl` or `auth_crypto_bcrypt` names its backend. Applications
can set the same property to require a capability at configuration time.

OpenSSL provider/engine options retain OpenSSL-only semantics. In a Schannel
build every OpenSSL-only property fails at `rd_kafka_conf_set()` with
"OpenSSL-only; this build uses Schannel TLS". See [Schannel scope](SCHANNEL-ADAPTER.md)
for certificate formats, trust, protocol and identity restrictions, and
[crypto services](CRYPTO-BACKENDS.md) for signing formats and lifecycle.

HTTPS/OIDC through libcurl is a separate TLS connection and backend. The
OpenSSL SSL-context callback is installed only with an actual OpenSSL curl
backend. Other curl backends use supported CA file/blob options; unsupported
CA directory/probe modes fail. Selecting Schannel for broker TLS does not
select or qualify curl's implementation. A Windows CMake build with
`-DWITH_CURL=ON` and an authentication crypto backend enables OIDC
(`builtin.features` reports `http` and `oidc`); the Windows workflow builds one
with vcpkg libcurl and runs the OIDC unit tests. It does not run an end-to-end
OIDC token exchange.

`https.revocation.check` controls certificate revocation checks for these
HTTPS requests. `default` keeps the libcurl backend behavior: curl with
Schannel checks revocation and fails with "revocation status unknown" for a
private CA without a reachable CRL, and OpenSSL-based curl does not check.
`best_effort` maps to `CURLSSLOPT_REVOKE_BEST_EFFORT` (libcurl 7.70.0 or later)
and `none` to `CURLSSLOPT_NO_REVOKE`. libcurl documents both flags as Schannel
only ([CURLOPT_SSL_OPTIONS](https://curl.se/libcurl/c/CURLOPT_SSL_OPTIONS.html)),
so with another curl backend `rd_kafka_new()` fails and names the property
instead of ignoring the setting.

## Evidence and limits

Native Fedora43 checks passed: OpenSSL C/C++ shared/static builds, CMake and
configure no-TLS/no-crypto and crypto-only builds, installed C/C++ consumers,
crypto known-answer vectors and independently verified RS256/ES256 signatures,
real socketpair blocked-write ownership/cancellation checks, and existing
regressions 0000/0004/0080/0133/0134. TLS-only OpenSSL also built independently
of authentication crypto; crypto-only BCrypt cross compilation passed.
Legacy OpenSSL1.0.1/1.0.2
compatibility was syntax-checked, not linked or executed.

Real Kafka4.1.1 Testcontainers acceptance passed with the OpenSSL adapter:
valid TLS/mTLS; wrong hostname/CA and expired server/client rejection; missing
or invalid client rejection; exact 96-record keys/65536-byte values, watermark
and count checks; fragmented/short I/O, disconnect/reconnect and backpressure;
acks=0 delivery accounting; purge with every callback accounted. The fixture
owns cleanup and uses dynamic ports. A separate direct Java Kafka fixture also
passed on Linux and is explicitly not Testcontainers.

Native Windows CI builds with MSVC and executes actual Windows APIs. The
BCrypt primitive, RNG, codec, RS256/ES256 independent signature checks and
public certificate setter ownership/encoding checks have passed. Actual
Schannel TLS/store-backed mTLS, private trust, memory-CA ownership, exact
partial-I/O exchange, cancellation and rejection cases have also passed on
Windows. Production Win32 broker-loop acceptance also passed against real
Kafka4.1.1 running in a native Windows Java21 process, using the shared
acceptance cases for trust/client rejection, exact record/count checks,
fragmentation, reconnect, acks=0, purge and expired-server rejection. The
shared DLL passed native BCrypt/NCrypt/SSPI function/DLL and no-OpenSSL link-map
audits on the same revision. Both workflow jobs completed successfully.

Native code-tested revision: `bb0cbb1bb3697a6202bb2c83fe55aa2aa6fdad91`.
[Windows run45204554174](https://github.com/j7nw4r/librdkafka/actions/runs/45204554174)
contains the MSVC build and native execution evidence. A subsequent documentation
commit does not change that tested source. Earlier failed runs exposed real
CNG/signing/import, diagnostic and fixture-download issues; their failures are
not included as passes.

Zig cross compilation checks Windows source/link compatibility; Wine checks
are supplementary only. Wine passed primitive/RNG/codec tests but could not
import the NCrypt PKCS8 key or create the required exclusive-root chain
engine. Trust verification was not weakened to obtain a Wine pass.

No test, Windows policy flag or backend name establishes FIPS qualification.
The module/version/environment, approved services and SCRAM PBKDF2 service
boundary require separate qualification evidence. Schannel initially enables
TLS1.2, refuses renegotiation, and rejects unsupported revocation/configuration
settings. These are material scope limits, not silently substituted behavior.

| Platform and selections | Build evidence | Runtime evidence |
| --- | --- | --- |
| Fedora43, OpenSSL TLS + OpenSSL crypto | CMake shared/static and configure C/C++ pass | Vectors, signatures, ownership, socketpair and real Kafka Testcontainers pass |
| Fedora43, no TLS + OpenSSL crypto | CMake/configure pass | Vectors and independent signatures pass |
| Fedora43, OpenSSL TLS + no crypto | CMake C/C++/examples pass | Separate runtime acceptance not run |
| Fedora43, no TLS + no crypto | CMake/configure C/C++ pass | TLS/crypto services deliberately unavailable |
| Windows Server2025 x64, Schannel + BCrypt, MSVC | CMake static/shared C/C++ and native dependency audits pass | Actual crypto/signatures/certificates/TLS/mTLS and native Java Kafka broker loop pass |
| Windows x64 target, no TLS + BCrypt, Zig cross compiler | CMake static/backend-test build pass | Cross build is not native runtime evidence |
| Wine11 on Linux, Schannel + BCrypt | Windows target builds | Primitives pass; NCrypt import/exclusive chain engine fail; not native Windows evidence |
| Windows Visual Studio project, OpenSSL default | Source metadata maintained | Not executed in this matrix |
| Windows configure/MinGW; macOS | Not executed | Not accepted by this matrix |

Remaining qualification evidence, outside these implementation checks:

- [ ] Identify the exact validated module/certificate, binary provenance,
  version, architecture, operating system and approved operating environment.
- [ ] Establish the application's module boundary and allowed services,
  algorithms, key sizes, RNG, key storage and TLS suite policy.
- [ ] Resolve SCRAM's PBKDF2/password-derivation service boundary and parameter
  requirements with applicable validation evidence; identical wire output is
  not proof of an approved service.
- [ ] Verify the deployed module's startup/self-test and failure behavior;
  establish approved-operation evidence beyond a runtime flag or Windows policy.
- [ ] Qualify separately any libcurl HTTPS implementation and other components
  that fall inside the application's claimed boundary.

This checklist is deliberately incomplete qualification work, rather than a
claim that this branch or any tested deployment is FIPS validated. Address and
undefined-behavior sanitizer execution was also unavailable on this host because
the compiler's sanitizer runtime libraries were missing; no sanitizer pass is
claimed.

## Manual reproduction

For portable vectors and public certificate semantics:

```sh
cmake -S . -B build-static -DRDKAFKA_TLS_BACKEND=openssl \
  -DRDKAFKA_CRYPTO_BACKEND=openssl -DRDKAFKA_BUILD_STATIC=ON \
  -DRDKAFKA_BUILD_BACKEND_TESTS=ON -DRDKAFKA_BUILD_TESTS=OFF
cmake --build build-static --parallel
python -m pip install -r tests/tls_backend/requirements.txt
python tests/crypto/run_vectors.py --binary build-static/backend-crypto-test
python tests/tls_backend/run_cert_buffers.py --binary build-static/backend-cert-test
build-static/backend-openssl-test
python tests/tls_backend/acceptance.py --client build-static/backend-kafka-client
```

The last command requires a working Docker-compatible service and runs real
Kafka Testcontainers; it fails when prerequisites are unavailable.

Windows prerequisite: `schannel_transport.py` and `native_java_kafka.py` use
`tests/windows_certificate_store.py`, which runs `pwsh` (PowerShell 7) to
provision and remove the test identities. Windows Server 2022 includes only
Windows PowerShell 5.1 (`powershell.exe`), so install PowerShell 7 first.
GitHub `windows-latest` runners include it.

On Windows, configure Schannel/BCrypt and use `build-static/Release/*.exe`, then run
`python tests/schannel_transport.py --client PATH_TO_EXE` and
`python tests/tls_backend/native_java_kafka.py --client PATH_TO_KAFKA_CLIENT --cache TEMP_CACHE`.
The Java fixture needs Java21 and exercises the production broker loop.
`--cache` downloads the official distribution and verifies its pinned SHA512.
For CI reliability the workflow instead extracts public Java libraries from
the official `apache/kafka:4.1.1` Linux image pinned at
`sha256:7240ff4534bd23dac2f215ba03a2d0aa9d041b45b830804bbdec3b81c2bdf479`,
transfers only those libraries as a one-day artifact, and uses `--distribution`.
The Windows test job requires successful extraction and artifact transfer. The
Kafka JVM itself runs on Windows; Linux Kafka Testcontainers remains separate.
Windows identity fixtures explicitly provision unique test-owned My certificates
and named keys, remove both even on failure and verify key deletion; no Root
store is changed. Expect PASS lines and exit zero, plus no surviving fixture
process/container or identity. The branch-scoped GitHub workflow reproduces
native build, runtime checks and DLL/function/link-map dependency audits.
Existing SCRAM/Admin and OIDC assertion units and crypto vectors were exercised;
new real-broker SCRAM authentication and end-to-end OIDC HTTPS/signing flows
were not added to this acceptance matrix.

The Testcontainers fixture generates a temporary CA, localhost-SAN server
certificate and valid/invalid/expired client identities. It maps Kafka's external
TLS listener to a dynamic host port, places a bounded fault proxy on another
dynamic port and advertises `localhost:PROXY_PORT` back to the client. This
keeps metadata-driven broker connections inside the same fault path. Readiness
requires authenticated metadata from the real client, rather than a fixed
startup sleep; the expired-server case uses the broker's private internal
listener solely to establish readiness before checking TLS rejection. Each
case uses an isolated topic and bounded subprocess/startup deadlines.

Ryuk is disabled because this fixture explicitly owns its container, proxy
threads/sockets, broker subprocesses and temporary credentials. Its `finally`
paths stop/remove those resources on success and failure; teardown failures
remain test failures. Failure output includes bounded broker/client diagnostics,
never PEM contents. To maintain it, preserve the dynamic advertised listener,
authenticated readiness and cleanup paths when changing broker versions or
faults. After a reported cleanup failure, inspect containers with
`docker ps -a --filter ancestor=apache/kafka:4.1.1`; remove only the fixture ID
identified by that run with `docker rm -f CONTAINER_ID`, then repeat the listing
to verify its removal. An unrelated container using the same image is not owned
by this fixture.
