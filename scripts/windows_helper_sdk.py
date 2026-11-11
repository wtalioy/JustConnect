"""Stage only the project-pinned native Wintun payloads for a Windows helper build."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / 'resource/network-helper-windows.json'


def stage(contract, destination, arch):
    sdk = contract['sdk']
    if arch not in sdk['architectures']:
        raise ValueError('Unsupported native Windows helper architecture')
    with urllib.request.urlopen(sdk['url'], timeout=30) as response:
        data = response.read(16 * 1024 * 1024 + 1)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > 16 * 1024 * 1024 or digest != sdk['archive_sha256']:
        raise ValueError('Windows helper SDK archive does not match its pinned source')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        driver = archive.read(sdk['driver_entry'].format(arch=arch))
        license = archive.read(sdk['license_entry'])
        header = archive.read(sdk['header_entry'])
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    driver_path = destination / contract['driver_library']
    license_path = destination / contract['driver_license']
    driver_path.write_bytes(driver)
    license_path.write_bytes(license)
    header_path = destination / sdk['header_file']
    header_path.write_bytes(header)
    metadata = {
        'archive_sha256': digest, 'version': sdk['version'], 'arch': arch,
        'driver': str(driver_path), 'license': str(license_path), 'header': str(header_path),
        'driver_sha256': hashlib.sha256(driver).hexdigest(),
        'license_sha256': hashlib.sha256(license).hexdigest(),
        'header_sha256': hashlib.sha256(header).hexdigest(),
    }
    (destination / 'source.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    return metadata


def main():
    contract = json.loads(CONTRACT.read_text(encoding='utf-8'))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--arch', required=True, choices=contract['sdk']['architectures'])
    args = parser.parse_args()
    print(json.dumps(stage(contract, args.destination, args.arch)))


if __name__ == '__main__':
    main()
