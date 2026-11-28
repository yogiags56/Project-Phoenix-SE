import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phoenix_evidence_bundle import BundleError, build


class EvidenceBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.manifest = self.root / "manifest.json"

    def tearDown(self):
        self.tmp.cleanup()

    def write_manifest(self, files):
        self.manifest.write_text(json.dumps({
            "schema_version": 1,
            "tool": "Phoenix Evidence Bundle Manifest",
            "target": {"product_type": "iPhone8,4", "build": "synthetic"},
            "donor": {"product_type": "synthetic-donor", "build": "synthetic"},
            "files": files,
        }), encoding="utf-8")

    def test_builds_bundle_with_hash_manifest_and_no_firmware(self):
        data = b'{"tool":"synthetic","status":"ok"}\n'
        (self.root / "report.json").write_bytes(data)
        self.write_manifest([{"name": "sample", "path": "report.json"}])
        output = self.root / "out" / "bundle.zip"
        report = build(self.manifest, output, 1024, 4096)
        self.assertTrue(output.is_file())
        self.assertEqual(report["reports"][0]["sha256"], hashlib.sha256(data).hexdigest())
        with zipfile.ZipFile(output) as archive:
            self.assertIn("bundle-manifest.json", archive.namelist())
            self.assertIn("reports/report.json", archive.namelist())
            self.assertFalse(any(name.lower().endswith((".ipsw", ".img4", ".im4p")) for name in archive.namelist()))

    def test_refuses_firmware_extension(self):
        (self.root / "donor.ipsw").write_bytes(b"firmware")
        self.write_manifest([{"name": "donor", "path": "donor.ipsw"}])
        with self.assertRaises(BundleError):
            build(self.manifest, self.root / "bundle.zip", 1024, 4096)

    def test_refuses_sensitive_identifier(self):
        (self.root / "report.txt").write_text("ECID=0x123456789", encoding="utf-8")
        self.write_manifest([{"name": "device", "path": "report.txt"}])
        with self.assertRaises(BundleError):
            build(self.manifest, self.root / "bundle.zip", 1024, 4096)

    def test_refuses_path_escape(self):
        outside = self.root.parent / (self.root.name + "-outside.txt")
        outside.write_text("safe text", encoding="utf-8")
        try:
            self.write_manifest([{"name": "outside", "path": "../" + outside.name}])
            with self.assertRaises(BundleError):
                build(self.manifest, self.root / "bundle.zip", 1024, 4096)
        finally:
            outside.unlink(missing_ok=True)

    def test_refuses_oversized_file(self):
        (self.root / "big.txt").write_text("x" * 2048, encoding="utf-8")
        self.write_manifest([{"name": "big", "path": "big.txt"}])
        with self.assertRaises(BundleError):
            build(self.manifest, self.root / "bundle.zip", 100, 4096)


if __name__ == "__main__":
    unittest.main()
