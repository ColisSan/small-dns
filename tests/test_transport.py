from dns_resolver import transport
import pytest

def test_response_validator():
    transport.validate_response(b"\xbe\xef" + 10 * b"\x00", 48879)
    
def test_validator_raises_wrong_id_error():
    with pytest.raises(ValueError, match="doesn't match"):
        transport.validate_response(b"\x12\x34" + 10 * b"\x00", 48879)
    
def test_validator_raises_short_data_error():
    with pytest.raises(ValueError, match="Response body invalid!"):
        transport.validate_response(b"\xbe\xef" + 9 * b"\x00", 48879)
  