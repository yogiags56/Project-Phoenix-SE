import json
import tempfile
import unittest
from pathlib import Path
from phoenix_compat import MapperError, compare, load_reports

def reports(target, donor):
    return (
        [{"path":"target.json","sha256":"a","data":target}],
        [{"path":"donor.json","sha256":"b","data":donor}],
    )

class CompatibilityMapperTests(unittest.TestCase):
    def test_shared_arch_and_identifier_is_potential(self):
        t,d=reports({"tool":"target","architecture":{"cpu_type":16777228},"bundles":[{"bundle_id":"com.example.driver"}]},
                    {"tool":"donor","architecture":{"cpu_type":16777228},"bundles":[{"bundle_id":"com.example.driver"}]})
        r=compare(t,d)
        self.assertEqual(r["status"],"Potential")
        self.assertEqual(r["comparison"]["shared_identifiers"],["com.example.driver"])

    def test_disjoint_architectures_are_incompatible(self):
        t,d=reports({"architecture":{"cpu_type":16777228}},{"architecture":{"cpu_type":12}})
        self.assertEqual(compare(t,d)["status"],"Incompatible")

    def test_missing_architecture_is_unknown(self):
        t,d=reports({"product_version":"x"},{"product_version":"y"})
        self.assertEqual(compare(t,d)["status"],"Unknown")

    def test_version_match_alone_does_not_claim_compatibility(self):
        t,d=reports({"product_version":"16.1"},{"product_version":"16.1"})
        r=compare(t,d)
        self.assertEqual(r["status"],"Unknown")
        self.assertEqual(r["comparison"]["same_version_strings"],["16.1"])

    def test_product_type_overlap_is_context_only(self):
        t,d=reports({"supported_product_types":["iPhone8,4"]},{"supported_product_types":["iPhone8,4"]})
        self.assertEqual(compare(t,d)["status"],"Unknown")
        self.assertEqual(r if False else compare(t,d)["comparison"]["target_product_types_or_devices_also_listed_by_donor"],["iPhone8,4"])

    def test_load_reports_rejects_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(MapperError):
                load_reports(tmp)

    def test_load_reports_rejects_non_object_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,"bad.json").write_text(json.dumps(["not","an","object"]))
            with self.assertRaises(MapperError):
                load_reports(tmp)

if __name__=="__main__":
    unittest.main()
