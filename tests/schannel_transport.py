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
         server="server", reject=False, cancel=False, pfx=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(20)
    port = listener.getsockname()[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(root / f"{server}.crt"), str(root / f"{server}.key"))
    context.load_verify_locations(cafile=str(root / "ca.crt"))
    context.verify_mode = ssl.CERT_REQUIRED
    errors = queue.Queue()
    active = []
    expected = bytes((i * 31 + i // 97) & 255 for i in range(131071))
    def serve():
        seen = bytearray()
        try:
            raw, _ = listener.accept()
            raw.settimeout(15)
            active.append(raw)
            with context.wrap_socket(raw, server_side=True) as tls:
                active.append(tls)
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
            if not reject and not (cancel and not seen):
                errors.put(exc)
        except BaseException as exc:
            errors.put(exc)
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        args = runner + [str(binary), str(root / f"{ca}.crt"),
                         "@" + str(root / "client.pfx") if pfx else (str(root / f"{client}.crt") if client else "-"),
                         "fixture-pass" if pfx else (str(root / f"{client}.key") if client else "-"),
                         hostname, str(port), "reject" if reject else "accept",
                         "cancel" if cancel else "echo"]
        result = subprocess.run(args, text=True, capture_output=True, timeout=45)
        if result.returncode:
            raise AssertionError(f"{name}: exit {result.returncode}\n{result.stdout}{result.stderr}")
        worker.join(5)
        if worker.is_alive():
            raise AssertionError(f"{name}: TLS peer shutdown deadline exceeded")
        if not errors.empty():
            raise errors.get()
        print(f"PASS {name}: {result.stdout.strip()}", flush=True)
    finally:
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
        case(binary, runner, root, "verified mTLS exact/partial IO")
        case(binary, runner, root, "PFX verified mTLS ephemeral identity", pfx=True)
        case(binary, runner, root, "cancellation discards pending prefix", cancel=True)
        case(binary, runner, root, "wrong hostname", hostname="127.0.0.1", reject=True)
        case(binary, runner, root, "unknown CA", ca="wrong-ca", reject=True)
        case(binary, runner, root, "expired server", server="expired-server", reject=True)
        case(binary, runner, root, "missing client", client=None, reject=True)
        case(binary, runner, root, "invalid client", client="invalid-client", reject=True)
        case(binary, runner, root, "expired client", client="expired-client", reject=True)
    print("PASS all Schannel transport cases; no Kafka protocol was emulated", flush=True)


if __name__ == "__main__":
    main()
