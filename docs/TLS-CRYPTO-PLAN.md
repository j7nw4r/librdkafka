# TLS and crypto backend implementation plan

New direction: separate private TLS and crypto interfaces, implemented with
OpenSSL and Windows Schannel/BCrypt. Base `origin/master`:
`ad4391a0e433a275f4c07a26f98ad70142b3e3a0`. Branch
`feat/tls-crypto-backends`, isolated from the earlier rustls/FIPS experiment.

1. Define private build-selected TLS and crypto interfaces. Preserve public ABI
   and existing default OpenSSL behavior; separate capability/build gates.
2. Route broker I/O through TLS operations and authentication/security randomness
   through crypto operations. Keep codecs independent of cryptography.
3. Implement Schannel TLS/mTLS and BCrypt hash/HMAC/PBKDF2/random/signing paths;
   reject unsupported OpenSSL options explicitly. Preserve bounded nonblocking
   I/O, request ownership, cancellation and delivery accounting.
4. Integrate CMake/configure/Windows metadata; validate OpenSSL, no-TLS and
   Schannel/BCrypt builds. Audit dependencies and installed consumers.
5. Run vector/configuration/transport tests and disposable real Kafka acceptance.
   Distinguish native Linux, cross compilation, Wine and native Windows checks.
6. Review, fix findings, document actual evidence/limitations, commit and push
   only this personal-fork branch. No PR, merge, release or upstream write.

Acceptance: actual adapters, no OpenSSL in Schannel/BCrypt artifacts; separate
TLS/crypto selection; unchanged ordinary OpenSSL contracts; meaningful crypto
vectors and real Kafka TLS/mTLS tests; explicit unsupported paths; clean cleanup;
accurate platform and qualification limits. No FIPS deployment claim follows
from backend selection, Windows policy or a passing test.
