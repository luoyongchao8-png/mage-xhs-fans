"""Restore all audited file blocks from the standalone Markdown; Python 3.9+."""
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

PATTERN = re.compile(
    r'^<!-- MAGE_REPLICA_FILE (\{[^\n]+\}) -->\n'
    r'~{8}[a-z0-9-]*\n(.*?)\n~{8}\n<!-- /MAGE_REPLICA_FILE -->$',
    re.MULTILINE | re.DOTALL,
)


def extract(document):
    files = {}
    for match in PATTERN.finditer(document.replace('\r\n', '\n')):
        metadata = json.loads(match.group(1))
        name = metadata['path']
        path = PurePosixPath(name)
        if (not name or '\\' in name or ':' in name or path.is_absolute()
                or '..' in path.parts or str(path) != name or name in files):
            raise ValueError('Unsafe or duplicate path: ' + name)
        payload = match.group(2)
        if metadata['encoding'] == 'base64':
            data = base64.b64decode(''.join(payload.split()), validate=True)
        elif metadata['encoding'] == 'utf-8':
            if metadata.get('newline') == 'crlf':
                payload = payload.replace('\n', '\r\n')
            data = payload.encode('utf-8')
        else:
            raise ValueError('Unknown file encoding: ' + name)
        if len(data) != metadata['bytes'] or hashlib.sha256(data).hexdigest() != metadata['sha256']:
            raise ValueError('File integrity mismatch: ' + name)
        files[name] = data
    if not files or 'extension/manifest.json' not in files or 'package-lock.json' not in files:
        raise ValueError('Missing source appendix; download the original Markdown, not HTML')
    index = json.loads(files['SOURCE-MANIFEST.json'].decode('utf-8'))
    expected = {entry['path'] for entry in index['files']}
    if set(files) != expected | {'SOURCE-MANIFEST.json'}:
        raise ValueError('Source appendix file list mismatch')
    for entry in index['files']:
        data = files[entry['path']]
        if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError('Source manifest mismatch: ' + entry['path'])
    return files


def restore(document_path, output_path):
    with Path(document_path).open(encoding='utf-8', newline='') as stream:
        files = extract(stream.read())
    output = Path(output_path).expanduser().resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('Output must be a new or empty directory')
    output.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        target = output.joinpath(*PurePosixPath(name).parts)
        if not target.resolve().is_relative_to(output):
            raise ValueError('Output path escaped destination')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return {'version': '0.3.1', 'files_restored': len(files), 'all_hashes_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--document', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    print(json.dumps(restore(args.document, args.output)))


if __name__ == '__main__':
    main()
