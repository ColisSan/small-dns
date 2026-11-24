from dataclasses import dataclass
from dns_resolver.constants import header_flags
import struct

@dataclass
class Header:
    query_id: int
    flags: header_flags.Flags
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

def parse_response(response: bytes)-> Header:
    parsed_response = parse_header(response)
    return parsed_response
    
def parse_header(response: bytes)-> Header:    
    if len(response) < 12:
        raise ValueError('Response too short for parsing!')
    (query_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack(">HHHHHH", response[:12])
    parsed_flags = parse_flags(flags)
    return Header(query_id, parsed_flags, qdcount, ancount, nscount, arcount)
        
def parse_flags(flags: int)-> header_flags.Flags:

    return_flags = header_flags.Flags()
    
    for name, (width, shift) in header_flags.FLAG_SPECS.items():
        mask = (1 << width) - 1
        value = (flags >> shift) & mask
        setattr(return_flags, name, value)

    return return_flags