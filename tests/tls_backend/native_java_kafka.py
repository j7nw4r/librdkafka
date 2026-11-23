#!/usr/bin/env python3
"""Additional native-host Java Kafka acceptance, distinct from Testcontainers.

This exercises the actual Windows broker/WSA loop where Linux containers are not
available on the runner. Linux acceptance.py remains the Testcontainers suite.
"""
import argparse
import contextlib
import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import acceptance as checks

VERSION = '4.1.1'
ARCHIVE = 'kafka_2.13-4.1.1.tgz'
URL = 'https://archive.apache.org/dist/kafka/4.1.1/' + ARCHIVE
SHA512 = ('eb2433e5330e4915a777fcc47447780e81a5041aacf0f787e5b5d06d767da7d4'
          '84afb9f2ca8651e61769f2256f36967f6481baf17429b289bc2b1e6962640deb')


def kafka_distribution(cache):
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / ARCHIVE
    if not archive.exists():
        partial = cache / (ARCHIVE + '.partial')
        deadline = time.monotonic() + 600
        try:
            print('Downloading official Kafka', VERSION, 'distribution:', URL, flush=True)
            with urllib.request.urlopen(URL, timeout=30) as response, partial.open('wb') as output:
                received = 0
                while block := response.read(1024 * 1024):
                    if time.monotonic() > deadline:
                        raise TimeoutError('Kafka archive download deadline exceeded')
                    output.write(block)
                    received += len(block)
                    if received // (16 * 1024 * 1024) != (received - len(block)) // (16 * 1024 * 1024):
                        print('Kafka download:', received // (1024 * 1024), 'MiB', flush=True)
            partial.replace(archive)
        finally:
            partial.unlink(missing_ok=True)
    with archive.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha512').hexdigest()
    if digest != SHA512:
        raise RuntimeError('Kafka distribution SHA512 mismatch; refusing execution')
    home = cache / ('kafka_2.13-' + VERSION)
    if not home.exists():
        with tarfile.open(archive) as bundle:
            if sum(member.size for member in bundle.getmembers()) > 2 * 1024 ** 3:
                raise RuntimeError('Unexpected Kafka extraction size')
            bundle.extractall(cache, filter='data')
    if not (home / 'libs').is_dir():
        raise RuntimeError('Kafka distribution is incomplete')
    return home


def unused_port():
    # A private runner has no fixed-port dependency. Java cannot inherit these
    # sockets; collisions are observable startup failures, never passing skips.
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        return reserve.getsockname()[1]


def stop_process(process):
    if process.poll() is None:
        try:
            process.terminate()
        except OSError:
            if process.poll() is None:
                raise
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def suite(java, home, binary, root, expired_server=False, identities=None):
    proxy = checks.FaultProxy()
    broker_port, internal_port, controller_port = unused_port(), unused_port(), unused_port()
    if len({broker_port, internal_port, controller_port}) != 3:
        proxy.close()
        raise RuntimeError('Dynamic Kafka port allocation collision')
    proxy.target = ('127.0.0.1', broker_port)
    server = 'expired-server' if expired_server else 'server'
    server_pem = root / ('server-expired.pem' if expired_server else 'server.pem')
    server_pem.write_bytes((root / (server + '.key')).read_bytes() + (root / (server + '.crt')).read_bytes())
    server_pem.chmod(0o600)
    config_path = root / ('expired.properties' if expired_server else 'server.properties')
    config_path.write_text(f'''process.roles=broker,controller
node.id=1
controller.quorum.voters=1@127.0.0.1:{controller_port}
controller.listener.names=CONTROLLER
listeners=INTERNAL://127.0.0.1:{internal_port},EXTERNAL://127.0.0.1:{broker_port},CONTROLLER://127.0.0.1:{controller_port}
advertised.listeners=INTERNAL://127.0.0.1:{internal_port},EXTERNAL://localhost:{proxy.port}
listener.security.protocol.map=INTERNAL:PLAINTEXT,EXTERNAL:SSL,CONTROLLER:PLAINTEXT
inter.broker.listener.name=INTERNAL
log.dirs={(root / ('data-expired' if expired_server else 'data')).as_posix()}
num.partitions=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
ssl.keystore.type=PEM
ssl.keystore.location={server_pem.as_posix()}
ssl.truststore.type=PEM
ssl.truststore.location={(root / 'ca.crt').as_posix()}
ssl.client.auth=required
''')
    classpath = str(home / 'libs' / '*')
    base = [java, '-Xms256m', '-Xmx512m', '-Djava.net.preferIPv4Stack=true', '-cp', classpath]
    log_path = root / ('broker-expired.log' if expired_server else 'broker.log')
    process = None
    def config(name, **updates):
        properties = {'bootstrap.servers': f'localhost:{proxy.port}', 'security.protocol': 'ssl',
                      'broker.address.family': 'v4', 'ssl.ca.location': str(root / 'ca.crt'),
                      'ssl.certificate.location': str(root / 'client.crt'),
                      'ssl.key.location': str(root / 'client.key')}
        properties.update(updates)
        if identities is not None:
            cert = properties.pop('ssl.certificate.location', None)
            properties.pop('ssl.key.location', None)
            if cert:
                properties['ssl.schannel.certificate'] = identities[Path(cert).stem]
        path = root / (name + '.conf')
        path.write_text(''.join(f'{key}={value}\n' for key, value in properties.items() if value is not None))
        return path
    try:
        subprocess.run(base + ['kafka.tools.StorageTool', 'format', '-t', 'MkU3OEVBNTcwNTJENDM2Qk',
                              '-c', str(config_path)], check=True, timeout=60, capture_output=True)
        with log_path.open('wb') as log:
            process = subprocess.Popen(base + ['kafka.Kafka', str(config_path)], stdout=log, stderr=log)
            good = config('good')
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError('Native Java Kafka exited during startup')
                if expired_server:
                    probe = subprocess.run(base + ['org.apache.kafka.tools.BrokerApiVersionsCommand',
                            '--bootstrap-server', f'127.0.0.1:{internal_port}'],
                            capture_output=True, text=True, timeout=12)
                    ready = probe.returncode == 0
                else:
                    ready = checks.run_client(binary, 'probe', good, timeout=12).returncode == 0
                if ready:
                    break
            else:
                raise RuntimeError('Authenticated native Kafka readiness deadline exceeded')
            if expired_server:
                result = checks.run_client(binary, 'probe', good)
                checks.require(result.returncode == 3, result.stdout + result.stderr)
                print(f'PASS native Java Kafka {binary.name}: expired server rejected', flush=True)
            else:
                checks.exercise_client(binary, root, proxy, config, good)
    except BaseException:
        if log_path.exists():
            print(log_path.read_text(errors='replace')[-18000:], flush=True)
        raise
    finally:
        errors = []
        try:
            proxy.close()
        except Exception as exc:
            errors.append(str(exc))
        if process:
            try:
                stop_process(process)
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise RuntimeError('Native Kafka cleanup failed: ' + '; '.join(errors))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--distribution', type=Path,
                        help='Existing distribution with libs/, for explicit local reproduction')
    args = parser.parse_args()
    java = shutil.which('java')
    if not java:
        raise SystemExit('UNMET native Kafka prerequisite: Java17+ is required')
    version = subprocess.run([java, '-version'], capture_output=True, text=True, timeout=15)
    print('Native Java Kafka fixture (not Testcontainers):', version.stderr.splitlines()[0], flush=True)
    if args.distribution:
        home = args.distribution.resolve()
        if not (home / 'libs').is_dir():
            parser.error('--distribution must contain Kafka libs/')
        print('Using explicit existing Kafka distribution:', home, flush=True)
    elif args.cache:
        home = kafka_distribution(args.cache.resolve())
    else:
        parser.error('--cache or --distribution is required')
    with tempfile.TemporaryDirectory(prefix='rdkafka-native-kafka-') as temp:
        root = Path(temp)
        root.chmod(0o700)
        checks.certificates(root)
        if os.name == 'nt':
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            from windows_certificate_store import temporary_windows_identities
            identity_context = temporary_windows_identities(root)
        else:
            identity_context = contextlib.nullcontext(None)
        with identity_context as identities:
            suite(java, home, args.client.resolve(), root, identities=identities)
            suite(java, home, args.client.resolve(), root, expired_server=True, identities=identities)
    print('PASS native Java Kafka TLS/mTLS and broker transport acceptance; all temporary resources removed', flush=True)


if __name__ == '__main__':
    main()
