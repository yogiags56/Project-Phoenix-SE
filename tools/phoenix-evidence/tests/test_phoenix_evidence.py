import plistlib,tempfile,unittest,zipfile
from pathlib import Path
from phoenix_evidence import inspect_ipsw

class TestEvidenceInspector(unittest.TestCase):
 def fixture(self,root):
  p=root/"fixture.ipsw"
  manifest={"ProductBuildVersion":"20B82","ProductVersion":"16.1",
    "SupportedProductTypes":["iPad6,11","iPad6,12"]}
  with zipfile.ZipFile(p,"w",zipfile.ZIP_DEFLATED) as z:
   z.writestr("BuildManifest.plist",plistlib.dumps(manifest))
   z.writestr("kernelcache.release.ipad6f",b"fixture-kernelcache-bytes")
  return p
 def test_manifest_and_kernelcache_hash(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);ipsw=self.fixture(root)
   r=inspect_ipsw(ipsw,"kernelcache.release.ipad6f")
   self.assertEqual(r["build_manifest"]["product_build_version"],"20B82")
   self.assertEqual(r["build_manifest"]["supported_product_types"],["iPad6,11","iPad6,12"])
   self.assertEqual(r["kernelcache"]["uncompressed_size_bytes"],25)
   self.assertEqual(len(r["kernelcache"]["sha256_uncompressed_member"]),64)
 def test_extract_and_refuse_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);ipsw=self.fixture(root);out=root/"local"/"kernelcache"
   r=inspect_ipsw(ipsw,"kernelcache.release.ipad6f",out)
   self.assertEqual(out.read_bytes(),b"fixture-kernelcache-bytes")
   self.assertEqual(r["kernelcache"]["extracted"]["sha256"],r["kernelcache"]["sha256_uncompressed_member"])
   with self.assertRaisesRegex(ValueError,"refusing to overwrite"):
    inspect_ipsw(ipsw,"kernelcache.release.ipad6f",out)
 def test_ambiguous_kernelcache_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);ipsw=self.fixture(root)
   with zipfile.ZipFile(ipsw,"a") as z:z.writestr("extra/kernelcache.release.ipad6f",b"duplicate")
   with self.assertRaisesRegex(ValueError,"exactly one"):
    inspect_ipsw(ipsw,"kernelcache.release.ipad6f")
 def test_missing_manifest_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"bad.ipsw"
   with zipfile.ZipFile(p,"w") as z:z.writestr("kernelcache.release.ipad6f",b"x")
   with self.assertRaisesRegex(ValueError,"BuildManifest"):
    inspect_ipsw(p,"kernelcache.release.ipad6f")
if __name__=="__main__":unittest.main()
