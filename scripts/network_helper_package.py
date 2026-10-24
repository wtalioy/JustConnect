"""Inspect the privileged system package without executing its payload or maintainer scripts."""

import argparse
import configparser
from email.parser import Parser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
LAYOUT = json.loads((ROOT / 'resource/network-helper.json').read_text())
EXECUTABLE = LAYOUT['executable'].lstrip('/')
POLICY = f'usr/share/polkit-1/actions/{LAYOUT["action"]}.policy'
DOCUMENTATION = 'usr/share/doc/justconnect-network-helper/'
RECOVERY_UNIT = 'usr/lib/systemd/system/' + LAYOUT['recovery_unit']
FILES = {EXECUTABLE, POLICY, DOCUMENTATION + 'LICENSE', DOCUMENTATION + 'source-revision.txt',
         RECOVERY_UNIT + '.service', RECOVERY_UNIT + '.timer'}


def verify_recovery_units(files):
    def read(kind, expected):
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        try:
            parser.read_string(files[RECOVERY_UNIT + '.' + kind].decode())
        except configparser.Error as error:
            raise ValueError('Invalid recovery unit') from error
        if parser.defaults() or set(parser.sections()) != {'Unit', *expected} or set(parser['Unit']) != {'Description'}:
            raise ValueError('Unexpected recovery unit sections or dependencies')
        for section, properties in expected.items():
            if dict(parser[section]) != properties:
                raise ValueError('Recovery unit expands its privilege or execution contract')
        return parser

    service = read('service', {'Service': {
        'Type': 'oneshot', 'User': 'root', 'ExecStart': LAYOUT['executable'] + ' --recover-stale',
        'StateDirectory': str(PurePosixPath(LAYOUT['state_directory']).relative_to('/var/lib').parent) + ' '
                          + str(PurePosixPath(LAYOUT['state_directory']).relative_to('/var/lib')),
        'StateDirectoryMode': '0700',
        'NoNewPrivileges': 'yes', 'ProtectSystem': 'strict', 'ReadWritePaths': LAYOUT['state_directory'],
        'ProtectHome': 'yes', 'PrivateTmp': 'yes', 'PrivateDevices': 'yes', 'ProtectKernelTunables': 'yes',
        'ProtectKernelModules': 'yes', 'ProtectControlGroups': 'yes', 'CapabilityBoundingSet': 'CAP_NET_ADMIN',
        'RestrictAddressFamilies': 'AF_UNIX AF_NETLINK'}})
    timer = read('timer', {'Timer': {'OnActiveSec': '1s', 'OnUnitInactiveSec': '5s', 'AccuracySec': '1s',
                                   'Unit': LAYOUT['recovery_unit'] + '.service'},
                           'Install': {'WantedBy': 'timers.target'}})
    return service, timer


def read_tar(contents, allowed, executable=None):
    files = {}
    directories = {str(parent) for name in allowed for parent in PurePosixPath(name).parents}
    with tarfile.open(fileobj=io.BytesIO(contents)) as archive:
        seen = set()
        for entry in archive:
            name = entry.name.removeprefix('./').rstrip('/')
            if entry.uid != 0 or entry.gid != 0 or entry.mode & 0o7022 or (entry.isdir() and entry.mode != 0o755):
                raise ValueError('Package entry is not root-owned or has unsafe permissions')
            if not name or name == '.':
                if entry.isdir():
                    continue
                raise ValueError('Unexpected archive root')
            if name in seen or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts:
                raise ValueError('Duplicate or escaping package path')
            seen.add(name)
            if entry.isdir() and name in directories:
                continue
            if name not in allowed or not entry.isfile() or entry.mode != (0o755 if name == executable else 0o644):
                raise ValueError('Unexpected package file, executable or link')
            files[name] = archive.extractfile(entry).read()
    return files


def verify_policy(contents):
    policy = ET.fromstring(contents)
    actions = policy.findall('action')
    if policy.tag != 'policyconfig' or len(actions) != 1 or actions[0].attrib != {'id': LAYOUT['action']}:
        raise ValueError('Unexpected privileged policy action')
    action = actions[0]
    defaults = action.findall('defaults')
    expected = {'allow_any': 'no', 'allow_inactive': 'no', 'allow_active': 'auth_admin'}
    if len(defaults) != 1 or len(defaults[0]) != len(expected) or {row.tag: row.text for row in defaults[0]} != expected:
        raise ValueError('Policy grants unexpected or retained authorization')
    annotations = action.findall('annotate')
    if len(annotations) != 1 or annotations[0].attrib != {'key': 'org.freedesktop.policykit.exec.path'} or annotations[0].text != LAYOUT['executable']:
        raise ValueError('Policy does not select only the fixed installed helper')


def inspect_package(path, revision):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('A full source revision is required')
    members = subprocess.check_output(['ar', 't', str(path)], text=True).splitlines()
    if len(members) != 3 or members[0] != 'debian-binary' or not members[1].startswith('control.tar.') or not members[2].startswith('data.tar.'):
        raise ValueError('Unexpected Debian archive structure')
    read = lambda name: subprocess.check_output(['ar', 'p', str(path), name])
    if read('debian-binary') != b'2.0\n':
        raise ValueError('Unknown Debian package version')
    control = read_tar(read(members[1]), {'control', 'md5sums'})
    if 'control' not in control:
        raise ValueError('Missing Debian control metadata')
    metadata = control['control'].decode()
    headers = Parser().parsestr(metadata)
    expected = {'Package', 'Version', 'Section', 'Priority', 'Architecture', 'Installed-Size', 'Maintainer', 'Description', 'Homepage', 'Depends'}
    if headers.defects or set(headers.keys()) != expected or len(headers.keys()) != len(expected):
        raise ValueError('Unexpected package control fields')
    if headers['Package'] != 'justconnect-network-helper' or headers['Architecture'] not in ('amd64', 'arm64'):
        raise ValueError('Wrong helper package or architecture')
    if not re.fullmatch(r'0~git[0-9]+\.' + revision, headers['Version']):
        raise ValueError('Package version does not match the source revision')
    dependencies = headers['Depends']
    if not all(name in dependencies for name in ('libqt6core6', 'libqt6dbus6', 'libc6', 'libstdc++6', 'iproute2', 'pkexec')):
        raise ValueError('Missing actual system runtime or authorization dependencies')
    if not re.search(r'(^|,\s*)systemd(?:\s*\([^)]*\))?(?=,|$)', dependencies):
        raise ValueError('Missing the system recovery manager dependency')
    files = read_tar(read(members[2]), FILES, EXECUTABLE)
    if set(files) != FILES or files[DOCUMENTATION + 'source-revision.txt'] != (revision + '\n').encode():
        raise ValueError('Missing files or mismatched source revision')
    if files[EXECUTABLE][:4] != b'\x7fELF':
        raise ValueError('Helper payload is not an ELF executable')
    verify_policy(files[POLICY])
    verify_recovery_units(files)
    return files, {'source_commit': revision, 'archive_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                   'control': metadata, 'files': {name: hashlib.sha256(value).hexdigest() for name, value in files.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    _, report = inspect_package(args.package.resolve(strict=True), args.revision)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: root-owned bounded helper package, system dependencies, fixed authorization action and source revision')


if __name__ == '__main__':
    main()
