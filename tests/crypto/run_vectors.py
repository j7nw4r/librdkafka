#!/usr/bin/env python3
"""Generate ephemeral keys and independently verify the backend's JOSE outputs."""
import argparse
from pathlib import Path
import shlex
import subprocess
import tempfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

p=argparse.ArgumentParser()
p.add_argument('--binary',type=Path,required=True)
p.add_argument('--runner',default='',help='Optional compatibility runtime, e.g. wine64; not native execution')
a=p.parse_args()
runner=shlex.split(a.runner)
def argument(path):
    value=str(path.resolve())
    return 'Z:'+value.replace('/','\\') if runner and runner[0].split('/')[-1].startswith('wine') else value
with tempfile.TemporaryDirectory(prefix='rdkafka-crypto-vectors-') as temp:
    root=Path(temp)
    root.chmod(0o700)
    keys=[rsa.generate_private_key(public_exponent=65537,key_size=2048),ec.generate_private_key(ec.SECP256R1())]
    paths=[]
    for name,key in zip(('rsa','ec'),keys):
        path=root/(name+'.pem')
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        path.chmod(0o600)
        paths.append(path)
    command=runner+[str(a.binary.resolve())]+[argument(path) for path in paths]+[argument(root)]
    subprocess.run(command,check=True,timeout=90)
    data=b'backend-signature-vector'
    signature=(root/'rs256.bin').read_bytes()
    keys[0].public_key().verify(signature,data,padding.PKCS1v15(),hashes.SHA256())
    signature=(root/'es256.bin').read_bytes()
    if len(signature)!=64:
        raise SystemExit('ES256 must be the 64-byte JOSE r||s encoding')
    der=utils.encode_dss_signature(int.from_bytes(signature[:32],'big'),int.from_bytes(signature[32:],'big'))
    keys[1].public_key().verify(der,data,ec.ECDSA(hashes.SHA256()))
print('PASS independent RS256/ES256 verification; ephemeral keys removed')
