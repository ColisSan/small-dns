from dns_resolver import response
from dns_resolver.constants import header_flags
import pytest
from dns_resolver import query

ROOT_HEADER = bytes.fromhex("5e 6e 82 00 00 01 00 00 00 0d 00 0b")
ROOT_HEADER_PARSED = response.Header(query_id=0x5e6e, flags=header_flags.Flags(qr=1, tc=1), qdcount=1, ancount=0, nscount=13, arcount=11)

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