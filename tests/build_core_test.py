import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'build_core', Path(__file__).resolve().parents[1] / 'scripts/build-core.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BuildCoreTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.archive = self.root / 'source.tar.gz'
        self.manifest = dict(commit='test', patches=[])
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, content in [('LICENSE', b'license'), ('go.sum', b'locked modules'),
                                  ('value', b'first\n')]:
                entry = tarfile.TarInfo(f'zju-connect-test/{name}')
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        self.manifest.update(source_sha256=builder.sha256(self.archive),
                             license_sha256=hashlib.sha256(b'license').hexdigest(),
                             go_sum_sha256=hashlib.sha256(b'locked modules').hexdigest())

    def prepare(self):
        return builder.prepare_source(self.archive, self.manifest, self.root / 'extract', self.root)

    def test_rejects_modified_source_before_extraction(self):
        self.archive.write_bytes(b'corrupt source')
        with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
            self.prepare()
        self.assertFalse((self.root / 'extract').exists())

    def test_rejects_modified_license_or_module_lock(self):
        for field in ('license_sha256', 'go_sum_sha256'):
            with self.subTest(field=field):
                original = self.manifest[field]
                self.manifest[field] = '0' * 64
                with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
                    self.prepare()
                self.manifest[field] = original

    def test_rejects_archive_path_traversal(self):
        with tarfile.open(self.archive, 'w:gz') as archive:
            entry = tarfile.TarInfo('../outside')
            entry.size = 4
            archive.addfile(entry, io.BytesIO(b'fail'))
        self.manifest['source_sha256'] = builder.sha256(self.archive)
        with self.assertRaises(tarfile.TarError):
            self.prepare()
        self.assertFalse((self.root / 'outside').exists())

    def test_applies_checked_patches_in_manifest_order(self):
        for index, (before, after) in enumerate([('first', 'second'), ('second', 'third')]):
            path = self.root / f'{index}.patch'
            path.write_text(f'diff --git a/value b/value\n--- a/value\n+++ b/value\n'
                            f'@@ -1 +1 @@\n-{before}\n+{after}\n', encoding='utf-8', newline='\n')
            self.manifest['patches'].append(dict(file=path.name, sha256=builder.sha256(path)))
        source = self.prepare()
        self.assertEqual((source / 'value').read_text(), 'third\n')

    def test_rejects_modified_patch_before_applying(self):
        path = self.root / 'bad.patch'
        path.write_bytes(b'corrupt patch')
        self.manifest['patches'] = [dict(file=path.name, sha256='0' * 64)]
        with patch.object(builder.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
                self.prepare()
            run.assert_not_called()

    def test_rejects_patch_outside_manifest_directory(self):
        self.manifest['patches'] = [dict(file='../outside.patch', sha256='0' * 64)]
        with self.assertRaisesRegex(RuntimeError, 'Patch path'):
            self.prepare()

    def test_rejects_different_compiler_before_downloading(self):
        with patch.object(builder.subprocess, 'check_output', return_value='go version go1.0 linux/amd64'), \
                patch.object(builder, 'urlopen') as download:
            with self.assertRaisesRegex(RuntimeError, 'Required Go'):
                builder.build(self.root / 'output')
            download.assert_not_called()

    def bundle(self):
        provenance = self.root / 'bundle/core-provenance'
        provenance.mkdir(parents=True)
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps(self.manifest), encoding='utf-8')
        shutil.copy2(manifest, provenance / 'manifest.json')
        shutil.copy2(self.archive, provenance / 'source.tar.gz')
        (provenance / 'LICENSE.zju-connect').write_bytes(b'license')
        binary = provenance.parent / 'zju-connect'
        binary.write_bytes(b'core executable')
        record = dict(goos='linux', version='ZJU Connect v0.0.0-justconnect-test',
                      manifest_sha256=builder.sha256(manifest),
                      unsigned_binary_sha256=builder.sha256(binary))
        (provenance / 'build.json').write_text(json.dumps(record), encoding='utf-8')
        return provenance.parent, manifest

    def test_verifies_packaged_core_and_ignores_inherited_credentials(self):
        directory, manifest = self.bundle()
        with patch.object(builder, 'MANIFEST', manifest), \
                patch.object(builder.subprocess, 'check_output',
                             return_value='ZJU Connect v0.0.0-justconnect-test\n') as run, \
                patch.dict(os.environ, ZJU_CONNECT_PASSWORD='private'):
            builder.verify(directory)
            self.assertNotIn('ZJU_CONNECT_PASSWORD', run.call_args.kwargs['env'])

    def test_rejects_replaced_binary_or_manifest_before_execution(self):
        for filename in ('zju-connect', 'core-provenance/manifest.json'):
            with self.subTest(filename=filename):
                directory, manifest = self.bundle()
                path = directory / filename
                original = path.read_bytes()
                path.write_bytes(b'replaced')
                with patch.object(builder, 'MANIFEST', manifest), \
                        patch.object(builder.subprocess, 'check_output') as run:
                    with self.assertRaisesRegex(RuntimeError, 'SHA-256'):
                        builder.verify(directory)
                    run.assert_not_called()
                path.write_bytes(original)
                shutil.rmtree(directory)

    def test_rejects_unexpected_packaged_version(self):
        directory, manifest = self.bundle()
        with patch.object(builder, 'MANIFEST', manifest), \
                patch.object(builder.subprocess, 'check_output', return_value='ZJU Connect v1.3.1'):
            with self.assertRaisesRegex(RuntimeError, 'Unexpected bundled core'):
                builder.verify(directory)


if __name__ == '__main__':
    unittest.main()
