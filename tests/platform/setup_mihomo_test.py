import gzip
import hashlib
import io
import unittest
import zipfile

import setup_mihomo


class RuntimeArchiveTests(unittest.TestCase):
    def test_pinned_gzip_and_digest_mismatch(self):
        data = gzip.compress(b'native executable')
        asset = {'file': 'mihomo.gz', 'sha256': hashlib.sha256(data).hexdigest()}
        self.assertEqual(setup_mihomo.unpack(data, asset), b'native executable')
        with self.assertRaises(ValueError):
            setup_mihomo.unpack(data + b'tampered', asset)

    def test_zip_extracts_only_one_bounded_executable(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('mihomo.exe', b'windows executable')
            archive.writestr('LICENSE', b'license')
        data = stream.getvalue()
        asset = {'file': 'mihomo.zip', 'sha256': hashlib.sha256(data).hexdigest()}
        self.assertEqual(setup_mihomo.unpack(data, asset), b'windows executable')
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('first.exe', b'one')
            archive.writestr('second.exe', b'two')
        data = stream.getvalue()
        asset['sha256'] = hashlib.sha256(data).hexdigest()
        with self.assertRaises(ValueError):
            setup_mihomo.unpack(data, asset)


if __name__ == '__main__':
    unittest.main()
