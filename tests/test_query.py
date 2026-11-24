from dns_resolver import query
import pytest
from dns_resolver.constants import header_flags

GOOGLE_QUERY = bytes.fromhex(
    "be ef 00 00 00 01 00 00 00 00 00 00"   
    "06 67 6f 6f 67 6c 65 03 63 6f 6d 00"   
    "00 01 00 01"                          
)


def test_assert_build_header_with_explicit_query_id():
    result = query.build_header(0xbeef, header_flags.Flags())
    assert result == bytes.fromhex("be ef 00 00 00 01 00 00 00 00 00 00")
    
def test_assert_build_header_with_set_explicit_params():
    result = query.build_header(0xbeef, header_flags.Flags(rd=1))
    assert result == bytes.fromhex("be ef 01 00 00 01 00 00 00 00 00 00")
    
def test_build_header_random_query_id():    
    result = query.build_header()
    
    assert len(result) == 12
    assert result[2:] == bytes.fromhex("00 00 00 01 00 00 00 00 00 00")
    
@pytest.mark.parametrize("name, expected", [
    ("google.com",   bytes.fromhex("06 67 6f 6f 67 6c 65 03 63 6f 6d 00")),
    ("google.com.",  bytes.fromhex("06 67 6f 6f 67 6c 65 03 63 6f 6d 00")),
    (".",            b"\x00"),
    ("",             b"\x00"),
    ("Google.COM",   b"\x06Google\x03COM\x00"),
])
def test_encode_name(name, expected):
    assert query.encode_name(name) == expected
    
def test_encode_maximum_length_name():
    assert query.encode_name("a" * 63 + ".com") == bytes([63]) + b"a" * 63 + bytes([3]) + b"com" + b"\x00"
    assert len(query.encode_name(".".join(["a" * 63] * 3) + "." + "a" * 61)) == 255
    
def test_improper_names_throw_errors():
    with pytest.raises(ValueError):
        query.encode_name("google..com")
    with pytest.raises(ValueError):
        query.encode_name(".google.com")
    with pytest.raises(ValueError):
        query.encode_name("a" * 64 + ".com")
    with pytest.raises(ValueError):
        query.encode_name(".".join(["a" * 63] * 4))
        
def test_build_query_full_packet():
    assert query.build_query("google.com", 0xbeef, 1) == GOOGLE_QUERY

def test_build_query_passes_rd():
    result = query.build_query("google.com", 0xbeef, 1, 1)

    assert result[2] == 0x01            
    assert result[2] & 0b00000001 == 1
    assert result[:2] + result[3:] == GOOGLE_QUERY[:2] + GOOGLE_QUERY[3:]

def test_build_query_passes_qtype():
    result = query.build_query("google.com", 0xbeef, qtype=28) 

    assert result[-4:] == bytes.fromhex("00 1c 00 01")  
    assert result[:-4] == GOOGLE_QUERY[:-4]              


def test_build_query_random_id():
    result = query.build_query("google.com")

    assert len(result) == 28
    assert result[2:] == GOOGLE_QUERY[2:]                


def test_build_query_rejects_invalid_name():
    with pytest.raises(ValueError):
        query.build_query("google..com")