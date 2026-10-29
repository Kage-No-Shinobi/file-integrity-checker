# File Integrity Checker

Offline SHA-256 baseline and verification tool. Built with Python standard library and no network or privileged access.

## Commands

```bash
python3 integrity.py baseline samples/test_folder --manifest samples/baseline.json
python3 integrity.py verify samples/test_folder --manifest samples/baseline.json
python3 -m unittest discover -s tests -v
```

The baseline JSON records relative paths, modification timestamps, sizes and SHA-256 hashes, including files in nested directories. Verification reports **modified**, **new**, **deleted** and **unchanged**. Byte-level modifications are detected even if file length and timestamp do not change. Symbolic links are skipped to avoid following external files. Inaccessible files cause an incomplete scan (never silently treated as deletion); errors are reported rather than crashing a scan.

## One-byte tamper demonstration

```bash
cp -R samples/test_folder /tmp/integrity-demo
python3 integrity.py baseline /tmp/integrity-demo --manifest /tmp/integrity-demo-baseline.json
python3 -c "from pathlib import Path; p=Path('/tmp/integrity-demo/readme.txt'); b=p.read_bytes(); p.write_bytes(bytes([b[0]^1])+b[1:])"
python3 integrity.py verify /tmp/integrity-demo --manifest /tmp/integrity-demo-baseline.json
```

Expected result: `modified` contains `readme.txt`, even though its size is unchanged. **Security note:** A baseline must be stored somewhere attackers cannot modify; comparing a file to an untrusted manifest is not sufficient evidence of integrity. Do not use this to claim malware has been detected.
