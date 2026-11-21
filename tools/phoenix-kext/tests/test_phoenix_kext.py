import plistlib
import tempfile
import unittest
from pathlib import Path
from phoenix_kext import KextError, analyze

def write_kext(root, folder, info):
    path = root / folder / "Contents"
    path.mkdir(parents=True, exist_ok=True)
    (path / "Info.plist").write_bytes(plistlib.dumps(info))

class KextAnalyzerTests(unittest.TestCase):
    def test_resolves_dependency_and_reports_unresolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_kext(root, "Provider.kext", {
                "CFBundleIdentifier": "com.example.provider",
                "CFBundleVersion": "1.0",
            })
            write_kext(root, "Consumer.kext", {
                "CFBundleIdentifier": "com.example.consumer",
                "OSBundleLibraries": {
                    "com.example.provider": "1.0",
                    "com.example.missing": "2.0",
                },
            })
            report = analyze(root)
            self.assertEqual(report["bundle_count"], 2)
            self.assertEqual(report["resolved_dependency_count"], 1)
            self.assertEqual(report["unresolved_dependency_count"], 1)
            self.assertEqual(report["unresolved_dependencies"][0]["dependency"], "com.example.missing")

    def test_detects_duplicate_bundle_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("One.kext", "Two.kext"):
                write_kext(root, name, {"CFBundleIdentifier": "com.example.same"})
            report = analyze(root)
            self.assertEqual(report["duplicate_bundle_id_count"], 1)

    def test_reports_missing_info_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Broken.kext").mkdir()
            report = analyze(root)
            self.assertEqual(report["invalid_bundle_count"], 1)

    def test_rejects_non_dictionary_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "Bad.kext" / "Contents"
            path.mkdir(parents=True)
            (path / "Info.plist").write_bytes(plistlib.dumps(["not", "a", "dict"]))
            with self.assertRaises(KextError):
                analyze(root)

    def test_rejects_missing_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(KextError):
                analyze(Path(tmp) / "does-not-exist")

if __name__ == "__main__":
    unittest.main()
