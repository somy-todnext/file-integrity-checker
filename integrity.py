"""Offline SHA-256 folder integrity checks using Python's standard library."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


def snapshot(folder):
    root = Path(folder).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Target must be a directory')
    files = {}
    skipped = []
    def fail(error):
        raise error
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=fail):
        for name in list(dirs):
            path = Path(directory) / name
            if path.is_symlink():
                skipped.append(path.relative_to(root).as_posix())
                dirs.remove(name)
        for name in names:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode):
                skipped.append(relative)
                continue
            digest = hashlib.sha256()
            with path.open('rb') as source:
                opened = os.fstat(source.fileno())
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError(f'File changed while scanning: {relative}')
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    digest.update(chunk)
                after = os.fstat(source.fileno())
            if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError(f'File changed while scanning: {relative}')
            files[relative] = digest.hexdigest()
    return {'version': 1, 'algorithm': 'sha256', 'files': dict(sorted(files.items())),
            'skipped': sorted(skipped)}


def validate(data):
    if not isinstance(data, dict) or data.get('version') != 1 or data.get('algorithm') != 'sha256':
        raise ValueError('Unsupported baseline format')
    files = data.get('files')
    if not isinstance(files, dict):
        raise ValueError('Baseline files must be a mapping')
    for name, digest in files.items():
        p = PurePosixPath(name)
        if not name or p.is_absolute() or '..' in p.parts or '\\' in name or p.as_posix() != name:
            raise ValueError('Invalid relative path in baseline')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Invalid SHA-256 hash in baseline')
    return data


def compare(baseline, current):
    old, new = validate(baseline)['files'], validate(current)['files']
    return {'added': sorted(new.keys() - old.keys()),
            'deleted': sorted(old.keys() - new.keys()),
            'modified': sorted(name for name in old.keys() & new.keys() if old[name] != new[name]),
            'unchanged': sum(old[name] == new[name] for name in old.keys() & new.keys()),
            'skipped': current.get('skipped', [])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['baseline', 'check'])
    parser.add_argument('folder')
    parser.add_argument('--baseline', required=True, help='JSON baseline outside the target folder')
    args = parser.parse_args(argv)
    try:
        root = Path(args.folder).resolve(strict=True)
        baseline_path = Path(args.baseline).resolve()
        if baseline_path == root or root in baseline_path.parents:
            raise ValueError('Store the baseline outside the target folder')
        current = snapshot(root)
        if args.command == 'baseline':
            # Exclusive creation protects an existing trusted baseline.
            with baseline_path.open('x', encoding='utf-8') as target:
                json.dump(current, target, indent=2)
                target.write('\n')
            print(json.dumps({'baselined_files': len(current['files']), 'skipped': current['skipped']}, indent=2))
            return 0
        with baseline_path.open(encoding='utf-8') as source:
            report = compare(json.load(source), current)
        print(json.dumps(report, indent=2))
        return int(any(report[key] for key in ('added', 'deleted', 'modified')))
    except (OSError, ValueError, TypeError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
