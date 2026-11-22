import struct,unittest
from phoenix_pmu_vmmap import analyze,MappingError,map_match

def fileset_with_image(executable=True, duplicate_segment=False):
    sig=struct.pack("<II",0xD2800015,0x7100811f)
    # Embedded image: Mach-O header + one LC_SEGMENT_64 + signature.
    header_size=32;cmd_size=72;image_size=header_size+cmd_size+len(sig)
    vm=0xFFFFFFF007004000
    prot=5 if executable else 3
    seg=struct.pack("<II16sQQQQiiII",0x19,72,b"__TEXT",vm,image_size,0,image_size,7,prot,0,0)
    commands=seg+(seg if duplicate_segment else b"")
    ncmds=2 if duplicate_segment else 1
    outer_offset=80
    entry_command=bytearray(40)
    struct.pack_into("<IIQQII",entry_command,0,0x80000035,40,vm,outer_offset,32,0)
    entry_command[32:36]=b"pmu\x00"
    outer=struct.pack("<8I",0xFEEDFACF,0x0100000C,0,0xC,1,40,0,0)+bytes(entry_command)
    image_header=struct.pack("<8I",0xFEEDFACF,0x0100000C,0,2,ncmds,len(commands),0,0)
    image=image_header+commands+sig
    return outer+b"\x00"*(outer_offset-len(outer))+image

class VMMapTests(unittest.TestCase):
    def rules(self):
        return [{"rule_index":3,"rule_name":"synthetic PMU","signature_id":3,
                 "words":[(0xD2800015,0xffffffff),(0x7100811f,0xffffffff)]}]
    def test_maps_signature_to_executable_vm_address(self):
        raw=fileset_with_image()
        r=analyze(raw,self.rules())
        m=r["entries"][0]["matches"][0]
        self.assertEqual(m["file_offset"],184)
        self.assertEqual(m["mapping"]["mapping_status"],"mapped_executable")
        self.assertEqual(m["mapping"]["virtual_address"],"0xffffff f007004098".replace(" ",""))
    def test_non_executable_segment_has_no_vm_address(self):
        r=analyze(fileset_with_image(executable=False),self.rules())
        m=r["entries"][0]["matches"][0]["mapping"]
        self.assertEqual(m["mapping_status"],"mapped_non_executable")
        self.assertIsNone(m["virtual_address"])
    def test_no_segment_mapping_is_reported(self):
        m=map_match({"file_offset":999,"match_size":8},80,{"segments":[]})
        self.assertEqual(m["mapping_status"],"not_covered_by_segment_file_range")
    def test_rejects_non_fileset(self):
        with self.assertRaises(MappingError): analyze(b"not fileset",self.rules())
if __name__=="__main__":unittest.main()
