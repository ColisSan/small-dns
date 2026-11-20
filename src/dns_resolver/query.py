import secrets
import struct

#DNS HEADER ANATOMY -> 
#   QR (query or not) 1 bit;
#   OPCODE (0 for query) 4 bits;
#   AA (Authoritative Answer - 0 for request) 1 bit
#   TC (Truncation - specifies that this message was truncated) 1 bit
#   RD (Recursion Desired) - (this bit directs the name server to pursue the query recursively - use 1) 1 bit
#   RA (Recursion Available) - (this is set or cleared in a response, and denotes whether recursive query support is available in the name server - optional) 1 bit
#   Z (Reserved for future use - set 0) 3 bits
#   RCODE (Response code) 4 bits 
#       0 No error condition
#       1 Format error - The name server was unable to interpret the query.
#       2 Server failure - The name server was unable to process this query due to a problem with
#       the name server.
#       3 Name Error - Meaningful only for responses from an authoritative name server, this code
#       signifies that the domain name referenced in the query does not exist.
#       4 Not Implemented - The name server does not support the requested kind of query.
#       5 Refused - The name server refuses to perform the specified operation for policy reasons.
#   QDCOUNT (specifies the number of entries in the question section) 16 bit (NUMBER OF QUESTIONS)
#   ANCOUNT (specifies the number of resource records in the answer section) 16 bit (NUMBER OF ANSWERS)
#   NSCOUNT (specifies the number of name server resource records in the authority records section)
#   ARCOUNT (specifying the number of resource records in the additional records section) 16 bit 
    
FLAG_SHIFTS: dict[str, tuple[int,int]] = {
    "qr": (0,15), 
    "opcode": (0,11), 
    "aa": (0,10), 
    "tc": (0,9), 
    "rd": (0,8), 
    "ra": (0,7), 
    "z": (0,4), 
    "rcode": (0,0)
}
DOMAIN_NAME_ALLOWED_BYTES = 63
ENCODED_NAME_END = b"\x00"
NAME_BYTE_LENGTH_LIMIT = 255
QCLASS = 1

def build_query(name: str, query_id: int | None = None, rd: int = 0, qtype: int = 1)-> bytes:
    query = build_header(query_id, rd) + encode_name(name) + struct.pack('>HH', qtype, QCLASS)
    return query

def build_header(query_id: int | None = None, rd: int = 0) -> bytes:    
    
    if query_id is None:
        query_id = secrets.randbits(16)
    
    flags = 0
    for name, (value, shift) in FLAG_SHIFTS.items():
        value = rd if name == "rd" else value
        flags = flags | (value << shift)

    #number of questions provided
    qdcount = 1
    #number of answers provided
    ancount = 0
    #number of server resource records in the authority records section
    nscount = 0
    # number of resource records in the additional records section
    arcount = 0
    
    header = struct.pack('>HHHHHH', query_id, flags, qdcount, ancount, nscount, arcount)
    
    return header

def encode_name(name: str)->bytes:
    
    if name == '.' or name == "":
        return ENCODED_NAME_END
    name_array = name.split(".")
    
    encoded_name: bytes = b""
    for index, name_part in enumerate(name_array):        
        if not name_part:
            if index != (len(name_array) - 1):
                raise ValueError("Invalid domain name")
            else:
                continue
        
        label_bytes = name_part.encode('ascii')

        if len(label_bytes) > DOMAIN_NAME_ALLOWED_BYTES:
            raise ValueError("Domain name too long")
        label_length = bytes([len(label_bytes)])
        
        encoded_name += (label_length + label_bytes)
    
    encoded_name += ENCODED_NAME_END
    
    if len(encoded_name) > NAME_BYTE_LENGTH_LIMIT:
        raise ValueError("Name too long")

    return encoded_name