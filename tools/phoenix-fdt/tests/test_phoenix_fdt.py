import struct
import unittest
from phoenix_fdt import FDTError, parse_fdt

def fixture():
    strings=b"compatible\x00reg\x00status\x00"
    names={n:strings.index(n.encode()) for n in ("compatible","reg","status")}
    st=bytearray()
    def word(n): st.extend(struct.pack(">I",n))
    def text(s):
        st.extend(s.encode()+b"\x00")
        while len(st)%4: st.append(0)
    word(1); text("")
    value=b"apple,n69\x00"
    word(3); word(len(value)); word(names["compatible"]); st.extend(value)
    while len(st)%4: st.append(0)
    word(1); text("soc")
    word(3); word(8); word(names["reg"]); st.extend(struct.pack(">II",0x10000000,0x1000))
    value=b"okay\x00"
    word(3); word(len(value)); word(names["status"]); st.extend(value)
    while len(st)%4: st.append(0)
    word(2); word(2); word(9)
    reserve=b"\x00"*16
    off_rsv=40; off_st=off_rsv+len(reserve); off_strings=off_st+len(st)
    total=off_strings+len(strings)
    header=struct.pack(">10I",0xD00DFEED,total,off_st,off_strings,off_rsv,17,16,0,len(strings),len(st))
    return header+reserve+bytes(st)+strings

class FDTTests(unittest.TestCase):
    def test_parse_tree(self):
        r=parse_fdt(fixture(),"fixture.dtb")
        self.assertEqual(r["summary"]["node_count"],2)
        self.assertEqual(r["summary"]["property_count"],3)
        self.assertEqual(r["root"]["properties"]["compatible"]["value"],"apple,n69")
        self.assertEqual(r["node_index"][1]["path"],"/soc")
        self.assertEqual(r["node_index"][1]["properties"]["reg"]["u32_cells"],[0x10000000,0x1000])
    def test_bad_magic(self):
        with self.assertRaises(FDTError): parse_fdt(b"\x00"*40)
    def test_short_header(self):
        with self.assertRaises(FDTError): parse_fdt(b"short")
    def test_invalid_block_size(self):
        raw=bytearray(fixture())
        struct.pack_into(">I",raw,4,len(raw)+10)
        with self.assertRaises(FDTError): parse_fdt(bytes(raw))

if __name__=="__main__": unittest.main()
