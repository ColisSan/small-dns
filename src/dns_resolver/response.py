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
class Message:
    header: Header    

def parse_response(response: bytes)-> Header:
    offset = 12
    parsed_header = parse_header(response)
    name, offset = parse_name(response, offset)
    return parsed_header
    
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

def parse_name(response: bytes, offset: int)-> tuple[str, int]:    
    labels = []

    while(True):
        label_length = response[offset]
        offset += 1
        if label_length == 0:
            break
        labels.append(response[offset:(label_length+offset)].decode('ascii'))
        offset += label_length
        
    return ".".join(labels), offset
        