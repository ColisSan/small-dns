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
@dataclass
class Message:
    header: Header    
    res_type: int
    res_class: int
    question: str
    answer: str

def parse_response(response: bytes)-> Message:    
    parsed_header, offset = parse_header(response)
    question, offset = parse_name(response, offset)
    (res_type, res_class), offset = parse_type_and_class(response, offset)
    answer, offset = parse_name(response, offset)

    message = Message(
        parsed_header,
        res_type,
        res_class,
        question,
        answer
    )
    
    return message
    
def parse_header(response: bytes, offset: int = 12)-> tuple[Header, int]:
    if len(response) < 12:
        raise ValueError('Response too short for parsing!')
    (query_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack(">HHHHHH", response[:offset])
    parsed_flags = parse_flags(flags)
    return Header(query_id, parsed_flags, qdcount, ancount, nscount, arcount), offset
        
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
        if((response[offset] & 0b11000000) == 0b11000000):
            pointer = ((response[offset] & 0b00111111) << 8) | response[offset + 1]
            rest, _ = parse_name(response,pointer)
            labels.append(rest)
            offset += 2 
            break
        label_length = response[offset]
        offset += 1
        if label_length == 0:
            break
        labels.append(response[offset:(label_length+offset)].decode('ascii'))
        offset += label_length
        
    return ".".join(labels), offset
        

def parse_type_and_class(response: bytes, offset: int)-> tuple[tuple[int,int], int]: 
    return struct.unpack(">HH", response[offset:(offset + 4)]), (offset + 4)
        