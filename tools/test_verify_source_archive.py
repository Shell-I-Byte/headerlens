"""Local self-contained positive and falsification controls for archive preflight."""
from __future__ import annotations

import contextlib
import io
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile

from verify_source_archive import UnsafeArchive, verify

ROOT = 'headerlens-test-archive'
MANIFEST = 'RELEASE_SOURCE_MANIFEST_SHA256.json'


def make_archive(path, source=None, *, extra=None, replace=None):
    source = source or {'README.md': b'valid source'}
    manifest = {'algorithm': 'SHA-256', 'files': {
        name: hashlib.sha256(data).hexdigest() for name, data in source.items()}}
    members = {ROOT + '/' + name: data for name, data in source.items()}
    members[ROOT + '/' + MANIFEST] = json.dumps(manifest).encode()
    if replace:
        members.update(replace)
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
        if extra:
            name, data = extra
            z.writestr(name, data)


class ArchivePreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.zip = Path(self.tmp.name) / 'source.zip'
        make_archive(self.zip)

    def must_reject(self):
        with self.assertRaises((UnsafeArchive, ValueError, zipfile.BadZipFile)):
            verify(self.zip)

    def test_good(self):
        self.assertEqual(2, verify(self.zip)['members'])

    def test_outside_sibling(self):
        make_archive(self.zip, extra=('sibling/unlisted.sh', b'synthetic'))
        self.must_reject()

    def test_unlisted_in_root(self):
        make_archive(self.zip, extra=(ROOT + '/unlisted.sh', b'synthetic'))
        self.must_reject()

    def test_parent_traversal(self):
        make_archive(self.zip, extra=(ROOT + '/../escaping.txt', b'synthetic'))
        self.must_reject()

    def test_absolute_path(self):
        make_archive(self.zip, extra=('/tmp/escaping.txt', b'synthetic'))
        self.must_reject()

    def test_windows_backslash(self):
        make_archive(self.zip, extra=(ROOT + r'\..\escape.bat', b'synthetic'))
        self.must_reject()

    def test_casefold_name_collision(self):
        # Even distinct ZIP entries could overwrite on a case-insensitive FS.
        make_archive(self.zip, extra=(ROOT + "/readme.md", b"synthetic"))
        self.must_reject()

    def test_reject_windows_device_names_even_with_manifest_hash(self):
        # A matching file digest must not turn a Windows device alias into
        # portable, safely extractable source. Include nested directory forms.
        for member in ["NUL", "nul.txt", "CON.tar.gz", "PRN", "AUX.dat",
                       "COM1.txt", "LPT9.dat", "COM¹.txt", "LPT².data",
                       "fixture/NUL.txt", "NUL/README.md", "CONIN$.txt"]:
            with self.subTest(member=member):
                make_archive(self.zip, source={member: b"synthetic"})
                self.must_reject()

    def test_reject_windows_illegal_character_even_with_manifest_hash(self):
        for member in ["bad?.md", "bad*.md", "bad<.md", "bad>.md",
                       "bad|.md", 'bad".md', "bad\x01.md", "bad\x7f.md"]:
            with self.subTest(member=member):
                make_archive(self.zip, source={member: b"synthetic"})
                self.must_reject()

    def test_allow_nonreserved_portable_components(self):
        for member in ["README.md", ".github/workflows/ci.yml", "nulled.txt",
                       "COM10.txt", "HELPER_CON.md", "scripts/test_file.py"]:
            with self.subTest(member=member):
                make_archive(self.zip, source={member: b"synthetic"})
                self.assertEqual(2, verify(self.zip)['members'])

    def test_reject_git_control_directories_even_when_fully_manifested(self):
        # Valid checksums do not make Git administrative paths safe to unpack.
        for name in (".git/config", ".GIT/HEAD", "docs/.GiT/hooks/pre-commit"):
            with self.subTest(name=name):
                make_archive(self.zip, source={name: b"synthetic"})
                self.must_reject()

    def test_reject_casefold_directory_aliases_with_different_children(self):
        # Whole-filename comparisons miss directory aliases on Windows/macOS.
        make_archive(self.zip, source={"docs/Foo/a.txt": b"one", "docs/foo/b.txt": b"two"})
        self.must_reject()

    def test_reject_unicode_canonical_full_file_alias(self):
        # Distinct UTF-8 spellings can canonically normalize to the same path.
        make_archive(self.zip, source={"docs/caf\u00e9.txt": b"one", "docs/cafe\u0301.txt": b"two"})
        self.must_reject()

    def test_reject_unicode_canonical_parent_alias(self):
        make_archive(self.zip, source={"docs/caf\u00e9/a.txt": b"one", "docs/cafe\u0301/b.txt": b"two"})
        self.must_reject()

    def test_reject_unicode_canonical_parent_plus_case_alias(self):
        make_archive(self.zip, source={"docs/Caf\u00c9/a.txt": b"one", "docs/cafe\u0301/b.txt": b"two"})
        self.must_reject()

    def test_allow_distinct_files_under_one_unicode_directory(self):
        make_archive(self.zip, source={"docs/caf\u00e9/a.txt": b"one", "docs/caf\u00e9/b.txt": b"two"})
        self.assertEqual(3, verify(self.zip)["members"])

    def test_reject_file_directory_conflict(self):
        # A regular-file member cannot also be a parent directory.
        make_archive(self.zip, source={"docs/conflict": b"file", "docs/conflict/child.txt": b"child"})
        self.must_reject()

    def test_allow_shared_exact_directory_name_with_distinct_files(self):
        make_archive(self.zip, source={"docs/Foo/a.txt": b"one", "docs/Foo/b.txt": b"two"})
        self.assertEqual(3, verify(self.zip)["members"])

    def test_reserved_root(self):
        # The root name is not a regular file, but must also be portable.
        with zipfile.ZipFile(self.zip, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('NUL/README.md', b"test")
            z.writestr('NUL/' + MANIFEST, json.dumps({
                'algorithm': 'SHA-256',
                'files': {'README.md': hashlib.sha256(b"test").hexdigest()}
            }).encode())
        self.must_reject()

    def test_duplicate_name(self):
        with contextlib.redirect_stderr(io.StringIO()):
            make_archive(self.zip, extra=(ROOT + '/README.md', b'override'))
        self.must_reject()

    def test_tampered_content(self):
        make_archive(self.zip, replace={ROOT + '/README.md': b'tampered'})
        self.must_reject()

    def test_symlink(self):
        with zipfile.ZipFile(self.zip, 'a') as z:
            link = zipfile.ZipInfo(ROOT + '/link')
            link.create_system = 3
            link.external_attr = 0o120777 << 16
            z.writestr(link, b'../outside')
        self.must_reject()

    def test_no_manifest(self):
        with zipfile.ZipFile(self.zip, 'w') as z:
            z.writestr(ROOT + '/README.md', b'test')
        self.must_reject()

    def test_empty_archive(self):
        with zipfile.ZipFile(self.zip, 'w'):
            pass
        self.must_reject()

    def test_duplicate_json_keys(self):
        manifest = b'{"algorithm":"SHA-256","files":{},"files":{}}'
        make_archive(self.zip, replace={ROOT + '/' + MANIFEST: manifest})
        self.must_reject()

    def test_wrong_hash_shape(self):
        manifest = {'algorithm': 'SHA-256', 'files': {'README.md': 'BAD'}}
        make_archive(self.zip, replace={ROOT + '/' + MANIFEST: json.dumps(manifest).encode()})
        self.must_reject()

    def test_uncompressed_size_limit(self):
        make_archive(self.zip, source={'README.md': b'a' * (128 * 1024 * 1024 + 1)})
        self.must_reject()

    def test_real_source_package(self):
        # No network or source archive extraction, only the release pipeline's own sealer.
        import subprocess
        original = Path(__file__).resolve().parents[1]
        # Require the Git workspace to be clean only when running a full release.
        if not (original / '.git').exists():
            self.skipTest('No Git checkout: real package covered by independent sealed acceptance')
        if subprocess.run(['git','status','--porcelain'],cwd=original,stdout=subprocess.PIPE,
                          check=True).stdout:
            self.skipTest('Git checkout dirty during development; full sealed ZIP tested after commit')
        subprocess.run(['python3',str(original/'tools/seal_release_source.py'),
                        str(self.zip),ROOT],cwd=original,check=True)
        self.assertGreater(verify(self.zip)['members'],100)


if __name__ == '__main__':
    unittest.main()
