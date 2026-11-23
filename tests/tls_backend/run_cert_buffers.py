#!/usr/bin/env python3
"""Public certificate setter lifetime regression, independent of Kafka."""
import argparse
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from schannel_transport import certificates
from cryptography import x509
from cryptography.hazmat.primitives import serialization

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--runner', default='')
args = parser.parse_args()
runner = shlex.split(args.runner)
def argument(path):
    value = str(path.resolve())
    return 'Z:' + value.replace('/', '\\') if runner and Path(runner[0]).name.startswith('wine') else value
with tempfile.TemporaryDirectory(prefix='rdkafka-cert-buffers-') as temp:
    root = Path(temp)
    root.chmod(0o700)
    certificates(root)
    for name in ('ca', 'client'):
        cert = x509.load_pem_x509_certificate((root / (name + '.crt')).read_bytes())
        (root / (name + '.der')).write_bytes(cert.public_bytes(serialization.Encoding.DER))
    key = serialization.load_pem_private_key((root / 'client.key').read_bytes(), None)
    (root / 'key.der').write_bytes(key.private_bytes(serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    paths = [root / name for name in ('ca.crt', 'client.crt', 'client.key', 'ca.der', 'client.der', 'key.der')]
    subprocess.run(runner + [str(args.binary.resolve())] + [argument(path) for path in paths],
                   check=True, timeout=45)
print('PASS public certificate setters: immediate validation, ownership, replacement, duplication and clearing')
