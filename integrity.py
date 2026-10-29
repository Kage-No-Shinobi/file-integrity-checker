"""SHA-256 file integrity baselines and offline comparisons."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def scan(folder: Path, excluded: Path | None = None) -> tuple[dict, list[str]]:
    """Hash regular files recursively; collect errors without aborting."""
    found, errors = {}, []
    for root, dirs, files in os.walk(folder, followlinks=False, onerror=lambda exc: errors.append(str(exc))):
        dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink())
        for name in sorted(files):
            path = Path(root) / name
            try:
                if path.is_symlink() or (excluded and path.resolve() == excluded.resolve()):
                    continue
                stat = path.stat()
                if not path.is_file():
                    continue
                found[path.relative_to(folder).as_posix()] = {
                    'sha256': sha256(path), 'size': stat.st_size,
                    'modified_utc': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
                }
            except (OSError, PermissionError) as exc:
                errors.append(f'{path}: {exc}')
    return found, errors


def baseline(folder: Path, manifest: Path) -> dict:
    files, errors = scan(folder, manifest)
    if errors:
        return {'saved': False, 'errors': errors, 'message': 'Baseline not saved: unreadable files would make it incomplete.'}
    payload = {'version': 1, 'root': str(folder.resolve()), 'created_utc': datetime.now(timezone.utc).isoformat(), 'files': files}
    # A manifest inside the scanned folder is excluded from hashes.
    manifest.parent.mkdir(parents=True, exist_ok=True)
    temporary = manifest.with_name(manifest.name + '.tmp')
    temporary.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    temporary.replace(manifest)
    return {'saved': True, 'file_count': len(files), 'manifest': str(manifest)}


def verify(folder: Path, manifest: Path) -> dict:
    reference = json.loads(manifest.read_text(encoding='utf-8'))
    if reference.get('version') != 1 or not isinstance(reference.get('files'), dict):
        raise ValueError('Unsupported manifest structure')
    before = reference['files']
    after, errors = scan(folder, manifest)
    # An unreadable file is not safely classified as deleted.
    if errors:
        return {'complete': False, 'errors': errors, 'message': 'Verification incomplete. Resolve access errors before interpreting missing files.'}
    old_names, new_names = set(before), set(after)
    return {'complete': True,
            'modified': sorted(name for name in old_names & new_names if before[name]['sha256'] != after[name]['sha256']),
            'new': sorted(new_names - old_names),
            'deleted': sorted(old_names - new_names),
            'unchanged_count': sum(before[name]['sha256'] == after[name]['sha256'] for name in old_names & new_names)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('baseline', 'verify'))
    parser.add_argument('folder', type=Path)
    parser.add_argument('--manifest', type=Path, default=Path('baseline.json'))
    args = parser.parse_args()
    folder = args.folder.resolve()
    manifest = args.manifest.resolve()
    if not folder.is_dir(): parser.error('Folder does not exist')
    if args.command == 'verify' and not manifest.is_file(): parser.error('Manifest does not exist')
    try:
        output = baseline(folder, manifest) if args.command == 'baseline' else verify(folder, manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(output, indent=2))
    if output.get('errors'):
        raise SystemExit(2)


if __name__ == '__main__': main()
