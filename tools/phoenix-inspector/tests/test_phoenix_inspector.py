import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from phoenix_inspector import compare_reports, inspect_ipsw, safe_archive_name

class InspectorTests(unittest.TestCase):
    def test_safe_paths(self):
        self.assertTrue(safe_archive_name("Firmware/iBoot.im4p"))
        self.assertFalse(safe_archive_name("../escape"))
        self.assertFalse(safe_archive_name("/absolute/path"))

    def test_inspect_fixture(self):
        manifest = {
            "ProductVersion": "16.1", "ProductBuildVersion": "20B82",
            "SupportedProductTypes": ["iPhone8,4"],
            "BuildIdentities": [{
                "Info": {"DeviceClass": "n69", "Variant": "Erase Install", "RestoreBehavior": "Erase"},
                "Manifest": {"KernelCache": {"Info": {"Path": "kernelcache"}, "Digest": b"test", "Trusted": True}}
            }]
        }
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "fixture.ipsw"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("BuildManifest.plist", plistlib.dumps(manifest))
                z.writestr("kernelcache", b"fixture")
            r = inspect_ipsw(path, True, True)
            self.assertEqual(r["product_version"], "16.1")
            self.assertIn("kernelcache", r["component_sha256"])
            self.assertEqual(r["identity_count"], 1)

    def test_compare(self):
        a = {"source_file": "a", "manifest_sha256": "a", "build_identities": [
            {"device_class": "n69", "variant": "erase", "restore_behavior": "Erase",
             "components": [{"component": "KernelCache"}]}]}
        b = {"source_file": "b", "manifest_sha256": "b", "build_identities": [
            {"device_class": "j71t", "variant": "erase", "restore_behavior": "Erase",
             "components": [{"component": "DeviceTree"}]}]}
        result = compare_reports(a, b)
        self.assertEqual(result["components_only_left"], ["KernelCache"])
        self.assertEqual(result["components_only_right"], ["DeviceTree"])

if __name__ == "__main__":
    unittest.main()
