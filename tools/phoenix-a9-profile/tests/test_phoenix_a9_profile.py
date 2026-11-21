import unittest
from phoenix_a9_profile import ProfileError, build_report, SUBSYSTEMS

def profile():
    return {
        "schema_version": 1,
        "profile_type": "phoenix-a9-platform-profile",
        "device": {
            "name": "iPhone SE (1st generation)",
            "identity": {
                "product_type": None, "board_variant": None, "soc_variant": None,
                "model_number": None, "firmware_build": None
            }
        },
        "subsystems": {
            name: {"status": "not_assessed", "evidence_level": "none", "evidence": []}
            for name in SUBSYSTEMS
        }
    }

class A9ProfileTests(unittest.TestCase):
    def test_accepts_complete_unknown_baseline(self):
        report=build_report(profile(),"abc123","fixture.json")
        self.assertEqual(report["subsystem_count"],len(SUBSYSTEMS))
        self.assertFalse(report["device"]["identity_complete"])
        self.assertEqual(report["device_tested_subsystem_count"],0)

    def test_rejects_missing_subsystem(self):
        p=profile()
        p["subsystems"].pop("camera_isp")
        with self.assertRaises(ProfileError):
            build_report(p,"x","fixture.json")

    def test_rejects_invalid_status(self):
        p=profile()
        p["subsystems"]["wifi"]["status"]="probably"
        with self.assertRaises(ProfileError):
            build_report(p,"x","fixture.json")

    def test_working_requires_device_test_evidence(self):
        p=profile()
        p["subsystems"]["wifi"]["status"]="working"
        with self.assertRaises(ProfileError):
            build_report(p,"x","fixture.json")

    def test_working_accepts_complete_device_test_record(self):
        p=profile()
        p["subsystems"]["wifi"]={
            "status":"working","evidence_level":"device_tested",
            "evidence":[{
                "test_type":"device_test","device":"iPhone SE A1662",
                "build":"test-build-1","method":"associate to WPA2 AP",
                "result":"connected and passed DHCP","date":"2026-11-21"
            }]
        }
        report=build_report(p,"x","fixture.json")
        self.assertEqual(report["device_tested_subsystem_count"],1)

    def test_rejects_unknown_subsystem(self):
        p=profile()
        p["subsystems"]["made_up"]={"status":"not_assessed"}
        with self.assertRaises(ProfileError):
            build_report(p,"x","fixture.json")

if __name__=="__main__":
    unittest.main()
