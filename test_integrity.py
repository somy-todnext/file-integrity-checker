import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from integrity import snapshot, compare, main, validate


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'watched'
        self.root.mkdir()
        (self.root / 'a.txt').write_text('original')

    def test_unchanged(self):
        state = snapshot(self.root)
        self.assertEqual(compare(state, snapshot(self.root))['unchanged'], 1)

    def test_added_modified_deleted(self):
        (self.root / 'delete.txt').write_text('remove')
        before = snapshot(self.root)
        (self.root / 'a.txt').write_text('modified')
        (self.root / 'delete.txt').unlink()
        (self.root / 'new.txt').write_text('new')
        report = compare(before, snapshot(self.root))
        self.assertEqual(report['added'], ['new.txt'])
        self.assertEqual(report['modified'], ['a.txt'])
        self.assertEqual(report['deleted'], ['delete.txt'])

    def test_nested_empty_and_binary(self):
        nested = self.root / 'nested'
        nested.mkdir()
        (nested / 'empty').write_bytes(b'')
        (nested / 'binary').write_bytes(bytes(range(256)))
        files = snapshot(self.root)['files']
        self.assertEqual(files['nested/empty'], 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        self.assertIn('nested/binary', files)

    def test_symlinks_skipped(self):
        link = self.root / 'linked'
        try:
            link.symlink_to(self.root / 'a.txt')
        except OSError:
            self.skipTest('Symlinks unavailable')
        self.assertEqual(snapshot(self.root)['skipped'], ['linked'])

    def test_bad_baseline(self):
        for data in ({}, {'version': 1, 'algorithm': 'sha256', 'files': {'../escape': 'a'*64}},
                     {'version': 1, 'algorithm': 'sha256', 'files': {'a': 'invalid'}}):
            with self.assertRaises(ValueError):
                validate(data)

    def test_cli_and_no_overwrite(self):
        baseline = str(Path(self.temp.name) / 'baseline.json')
        args = [str(self.root), '--baseline', baseline]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['baseline'] + args), 0)
            self.assertEqual(main(['check'] + args), 0)
            self.assertEqual(main(['baseline'] + args), 2)
            (self.root / 'a.txt').write_text('changed')
            self.assertEqual(main(['check'] + args), 1)

    def test_baseline_inside_target_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['baseline', str(self.root), '--baseline', str(self.root / 'state.json')]), 2)

    def test_missing_target(self):
        with self.assertRaises(OSError):
            snapshot(self.root / 'missing')


if __name__ == '__main__':
    unittest.main()
