#!/usr/bin/env python3
"""Native Schannel tests against a real TLS echo server, not Kafka emulation."""
import argparse
import contextlib
import datetime as dt
import os
from pathlib import Path
import queue
import shlex
import socket
import ssl
import subprocess
import tempfile
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from windows_certificate_store import temporary_windows_identities


def certificates(root):
    now = dt.datetime.now(dt.timezone.utc)
    def issue(name, ca=None, expired=False, server=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        issuer, signing_key = (ca[0].subject, ca[1]) if ca else (subject, key)
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(days=3))
                   .not_valid_after(now + dt.timedelta(days=-1 if expired else 2))
                   .add_extension(x509.BasicConstraints(ca=ca is None, path_length=None), True))
        if ca:
            builder = builder.add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            if server:
                builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        cert = builder.sign(signing_key, hashes.SHA256())
        (root / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path = root / f"{name}.key"
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        return cert, key
    ca = issue("ca")
    wrong = issue("wrong-ca")
    issue("server", ca, server=True)
    issue("expired-server", ca, expired=True, server=True)
    client = issue("client", ca)
    (root / "client.pfx").write_bytes(pkcs12.serialize_key_and_certificates(
        b"librdkafka-test", client[1], client[0], [ca[0]],
        serialization.BestAvailableEncryption(b"fixture-pass")))
    issue("invalid-client", wrong)
    issue("expired-client", ca, expired=True)


def case(binary, runner, root, name, ca="ca", client="client", hostname="localhost",
         server="server", reject=False, cancel=False, pfx=False,
         selector=None, memory_ca=False, ephemeral_rejection=False,
         require_client=True):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(.1)
    stop = threading.Event()
    port = listener.getsockname()[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(root / f"{server}.crt"), str(root / f"{server}.key"))
    context.load_verify_locations(cafile=str(root / "ca.crt"))
    context.verify_mode = ssl.CERT_REQUIRED if require_client else ssl.CERT_NONE
    errors = queue.Queue()
    active = []
    expected = bytes((i * 31 + i // 97) & 255 for i in range(131071))
    def serve():
        seen = bytearray()
        try:
            while not stop.is_set():
                try:
                    raw, _ = listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            raw.settimeout(15)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            active.append(raw)
            with context.wrap_socket(raw, server_side=True,
                                     do_handshake_on_connect=False) as tls:
                active.append(tls)
                tls.do_handshake()
                while True:
                    try:
                        data = tls.recv(4096)
                    except (ssl.SSLEOFError, ConnectionResetError):
                        break
                    if not data:
                        break
                    seen.extend(data)
                    if cancel:
                        raise AssertionError("canceled Schannel plaintext reached TLS peer")
                    if len(seen) > len(expected):
                        raise AssertionError("duplicate plaintext reached TLS peer")
                    for offset in range(0, len(data), 37):
                        tls.sendall(data[offset:offset + 37])
            if not reject and not cancel and bytes(seen) != expected:
                raise AssertionError(f"TLS peer received {len(seen)} unexpected bytes")
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError) as exc:
            if not stop.is_set() and not reject and not (cancel and not seen):
                errors.put(exc)
        except BaseException as exc:
            errors.put(exc)
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        args = runner + [str(binary), str(root / f"{ca}.crt"),
                         ("store:" + selector) if selector else ("@" + str(root / "client.pfx") if pfx else (str(root / f"{client}.crt") if client else "-")),
                         "fixture-pass" if pfx else (str(root / f"{client}.key") if client else "-"),
                         hostname, str(port), "reject-ephemeral" if ephemeral_rejection else ("reject" if reject else "accept"),
                         "cancel" if cancel else ("memory" if memory_ca else "echo")]
        result = subprocess.run(args, text=True, capture_output=True, timeout=45)
        if result.returncode:
            raise AssertionError(f"{name}: exit {result.returncode}\n{result.stdout}{result.stderr}")
        if reject:
            stop.set()
            listener.close()
        worker.join(5)
        if worker.is_alive():
            raise AssertionError(f"{name}: TLS peer shutdown deadline exceeded")
        if not errors.empty():
            raise errors.get()
        print(f"PASS {name}: {result.stdout.strip()}", flush=True)
    finally:
        stop.set()
        listener.close()
        for sock in active:
            with contextlib.suppress(OSError):
                sock.close()
        worker.join(2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--runner", default="", help="Compatibility runner, e.g. wine; empty means native")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="rdkafka-schannel-") as temp:
        root = Path(temp)
        root.chmod(0o700)
        certificates(root)
        runner = shlex.split(args.runner)
        binary = args.client.resolve()
        failures = []
        def run(name, **kwargs):
            try:
                case(binary, runner, root, name, **kwargs)
            except Exception as exc:
                failures.append(name)
                print(f"FAIL {name}: {exc}", flush=True)
        run("verified server TLS exact/partial IO", client=None, require_client=False)
        if os.name == "nt" and not runner:
            with temporary_windows_identities(root) as selectors:
                run("read-only My identity verified mTLS", selector=selectors["client"])
                run("memory CA duplicate/clear verified mTLS", selector=selectors["client"], memory_ca=True)
                run("cancellation discards pending prefix", selector=selectors["client"], cancel=True)
                run("wrong hostname", selector=selectors["client"], hostname="127.0.0.1", reject=True)
                run("unknown CA", selector=selectors["client"], ca="wrong-ca", reject=True)
                run("expired server", selector=selectors["client"], server="expired-server", reject=True)
                run("missing client", client=None, reject=True)
                run("invalid client", selector=selectors["invalid-client"], reject=True)
                run("expired client", selector=selectors["expired-client"], reject=True)
        else:
            # Compatibility execution never silently provisions native keys.
            run("compatibility file mTLS", client="client")
        # Ephemeral imports must fail explicitly on the affected Windows API;
        # no fallback is allowed to write a private key to disk.
        run("ephemeral PEM limitation diagnostic", reject=True, ephemeral_rejection=True)
        run("ephemeral PFX limitation diagnostic", pfx=True, reject=True, ephemeral_rejection=True)
        if failures:
            raise SystemExit(f"Schannel transport failed {len(failures)} case(s): " + ", ".join(failures))
    print("PASS all Schannel transport cases; no Kafka protocol was emulated", flush=True)


if __name__ == "__main__":
    main()
