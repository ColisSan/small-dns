from dns_resolver import response
from dns_resolver.constants import header_flags
import pytest
from dns_resolver import query

ROOT_HEADER = bytes.fromhex("5e 6e 82 00 00 01 00 00 00 0d 00 0b")
ROOT_HEADER_PARSED = response.Header(query_id=0x5e6e, flags=header_flags.Flags(qr=1, tc=1), qdcount=1, ancount=0, nscount=13, arcount=11)
BBC_NAME = bytes(12) + bytes.fromhex(
    "03 62 62 63 02 63 6f 02 75 6b 00"      # bbc.co.uk
)
GOOGLE_REPLY = bytes.fromhex(
    "59 87 81 80 00 01 00 01 00 00 00 00"  
    "06 67 6f 6f 67 6c 65 03 63 6f 6d 00"   
    "00 01 00 01"                           
    "c0 0c 00 01 00 01 00 00 00 3f 00 04"   
    "8e fa cb ce"                           
)

@pytest.mark.parametrize("value, expected", [
    (0b1000000110000000,   header_flags.Flags(qr=1, rd=1, ra=1)),
    (0b1000001000000000,   header_flags.Flags(qr=1, tc=1)),
])
def test_assert_parse_flags(value, expected):
    assert response.parse_flags(value) == expected
    
def test_assert_parse_flags_minimal():
    assert response.parse_flags(0b0000000000000000) == header_flags.Flags()
    
def test_assert_parse_flags_maximum():
    assert response.parse_flags(0b1111111111111111) == header_flags.Flags(qr=1, opcode=0b1111, aa=1, tc=1, rd=1, ra=1, z=0b111, rcode=0b1111)
    
def test_assert_multi_bit_field_with_non_trivial_value_persists():
    assert response.parse_flags(0b1000000110000011) == header_flags.Flags(qr=1, rd=1, ra=1, rcode=0b0011)

@pytest.mark.parametrize("value, expected", [
    (ROOT_HEADER, ROOT_HEADER_PARSED),
    (ROOT_HEADER + b"\x00" * 20, ROOT_HEADER_PARSED),
])
def test_parse_header_root_reply(value, expected):
    assert response.parse_header(value) == expected

def test_parse_header_round_trip():
    some_flags = header_flags.Flags(rd=1, opcode=5, rcode=3)
    header_bytes = query.build_header(0xbeef, some_flags)
    test_response = response.parse_header(header_bytes)
    assert test_response == response.Header(0xbeef, some_flags, 1, 0, 0, 0)

def test_short_header_cannot_be_parsed():
    short_bytes = bytes(11)
    with pytest.raises(ValueError, match="Response too short for parsing!"):
        response.parse_header(short_bytes)
        
def test_parse_name_decodes():
    name, offset = response.parse_name(GOOGLE_REPLY, 12)
    
    assert name == 'google.com'
    assert offset == 24

def test_parse_name_decodes_multiple_labels():
    name, offset = response.parse_name(BBC_NAME, 12)

    assert name == 'bbc.co.uk'
    assert offset == 23

def test_parse_name_returns_empty_string():
    name, offset = response.parse_name(b"\x00", 0)

    assert name == ""
    assert offset == 1

def test_parse_name_offset_is_respected():
    name,offset = response.parse_name(bytes.fromhex("ff ff 03 62 62 63 00"), 2)

    assert name == "bbc"
    assert offset == 7