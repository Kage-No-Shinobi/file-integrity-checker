import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integrity import baseline, verify

class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / 'tracked'
        self.folder.mkdir()
        (self.folder / 'nested').mkdir()
        (self.folder / 'a.txt').write_bytes(b'abc')
        (self.folder / 'nested' / 'b.bin').write_bytes(b'xyz')
        self.manifest = self.root / 'baseline.json'
        self.assertTrue(baseline(self.folder, self.manifest)['saved'])

    def test_unchanged(self):
        self.assertEqual(verify(self.folder, self.manifest)['unchanged_count'], 2)
    def test_modified_same_size_and_timestamp(self):
        file = self.folder / 'a.txt'
        old = file.stat()
        file.write_bytes(b'abd')
        import os
        os.utime(file, ns=(old.st_atime_ns, old.st_mtime_ns))
        self.assertEqual(verify(self.folder, self.manifest)['modified'], ['a.txt'])
    def test_new_deleted_nested(self):
        (self.folder / 'a.txt').unlink()
        (self.folder / 'nested' / 'new.txt').write_text('new')
        report = verify(self.folder, self.manifest)
        self.assertEqual(report['deleted'], ['a.txt'])
        self.assertEqual(report['new'], ['nested/new.txt'])
    def test_manifest_inside_root_is_excluded(self):
        inside = self.folder / 'manifest.json'
        baseline(self.folder, inside)
        self.assertNotIn('manifest.json', json.loads(inside.read_text())['files'])
    def test_errors_do_not_save_baseline(self):
        from unittest.mock import patch
        with patch('integrity.scan', return_value=({}, ['access denied'])):
            self.assertFalse(baseline(self.folder, self.root / 'blocked.json')['saved'])

if __name__ == '__main__': unittest.main()
