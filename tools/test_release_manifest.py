"""Positive and falsification controls for the offline source manifest check."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from verify_release_manifest import MANIFEST, validate
from seal_release_source import seal


class ManifestCheckTests(unittest.TestCase):
    def test_current_checkout_matches_manifest(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(validate(root), [])

    @staticmethod
    def fixture(root):
        (root / "module.go").write_text("package example\n", encoding="utf-8")
        sha = hashlib.sha256((root / "module.go").read_bytes()).hexdigest()
        (root / MANIFEST).write_text(json.dumps({"algorithm": "SHA-256", "files": {"module.go": sha}}))

    def test_valid_fixture_passes(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            self.assertEqual(validate(root), [])

    def test_unlisted_file_is_rejected(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            (root / "extra.txt").write_text("unknown")
            self.assertIn("unlisted source: extra.txt", validate(root))

    def test_corruption_is_rejected(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            (root / "module.go").write_text("tampered")
            self.assertIn("digest mismatch: module.go", validate(root))

    def test_packaged_bytecode_is_rejected(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            record = json.loads((root / MANIFEST).read_text())
            record["files"]["tools/__pycache__/stale.pyc"] = "0" * 64
            (root / MANIFEST).write_text(json.dumps(record))
            self.assertTrue(any("unsafe/non-source" in err for err in validate(root)))

    def test_clean_sealed_fixture_passes(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            self.assertEqual(validate(root, sealed=True), [])

    def test_build_cache_is_ignored_only_in_checkout_mode(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            cache = root / "tools" / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "foreign.pyc").write_bytes(b"synthetic untracked payload")
            self.assertEqual(validate(root), [])
            self.assertTrue(any("non-source file in sealed archive" in issue
                                for issue in validate(root, sealed=True)))

    def test_sealed_cli_rejects_hidden_file_with_actionable_error(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            cache = root / "tools" / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "foreign.pyc").write_bytes(b"synthetic")
            script = Path(__file__).resolve().parent / "verify_release_manifest.py"
            result = subprocess.run([sys.executable, str(script), "--sealed", str(root)],
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertIn("non-source file in sealed archive", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_sealed_rejects_untracked_ds_store(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            (root / ".DS_Store").write_bytes(b"synthetic")
            self.assertEqual(validate(root), [])
            self.assertIn("non-source file in sealed archive: .DS_Store", validate(root, sealed=True))

    def test_sealed_rejects_hidden_symlink(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            cache = root / "tools" / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "extra.pyc").symlink_to(root / "module.go")
            self.assertEqual(validate(root), [])
            self.assertIn("symlink in source archive: tools/__pycache__/extra.pyc", validate(root, sealed=True))

    def test_sealer_fails_closed_for_unsafe_archive_roots(self):
        with TemporaryDirectory() as d:
            root = Path(d) / "fixture-repo"
            root.mkdir()
            self.fixture(root)
            subprocess.run(["git", "init", "-q", str(root)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Release Test",
                            "-c", "user.email=release@example.invalid",
                            "commit", "-qm", "Initial fixture"], check=True)
            for bad in ("", ".", "..", "../escape", "a/../../escape", "/absolute",
                        "a\\b", "C:temp", " leading", "nul\x00byte"):
                with self.subTest(folder=repr(bad)):
                    dst = Path(d) / "unsafe.zip"
                    with self.assertRaisesRegex(ValueError, "unsafe source ZIP root"):
                        seal(root, dst, bad)
                    self.assertFalse(dst.exists())
            import zipfile
            good = Path(d) / "safe.zip"
            seal(root, good, "HeaderLens_v0.1.20")
            with zipfile.ZipFile(good) as z:
                self.assertEqual(set(z.namelist()), {
                    "HeaderLens_v0.1.20/module.go",
                    "HeaderLens_v0.1.20/" + MANIFEST,
                })
                extract = Path(d) / "unpacked"
                z.extractall(extract)
            self.assertEqual(validate(extract / "HeaderLens_v0.1.20", sealed=True), [])

    def test_path_escape_is_rejected(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            self.fixture(root)
            record = json.loads((root / MANIFEST).read_text())
            record["files"]["../outside.txt"] = "0" * 64
            (root / MANIFEST).write_text(json.dumps(record))
            self.assertTrue(any("unsafe/non-source" in err for err in validate(root)))


if __name__ == "__main__":
    unittest.main()
