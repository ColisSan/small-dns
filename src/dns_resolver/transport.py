import secrets
import socket
from dns_resolver import query
import struct

def main():
    send_query('1.1.1.1', "google.com", rd=1)

def send_query(server_ip: str, name: str, qtype: int = 1, rd: int = 0) -> bytes:
    query_id = secrets.randbits(16)
    packet = query.build_query(name, query_id, rd, qtype)
    
    sock_instance = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    with  sock_instance as sock:
        sock.settimeout(3)
        sock.sendto(packet, (server_ip, 53))        
        data, addr = sock.recvfrom(4096)

    validate_response(data, query_id)
        
    return data
    
def validate_response(response_data: bytes, query_id: int)->None:
    
    if len(response_data) < 12:    
        raise ValueError("Response body invalid!")
    
    reply_id_int = struct.unpack('>H', response_data[:2])[0]

    if query_id != reply_id_int:    
        raise ValueError(f"Reply id {reply_id_int:#06x} doesn't match with sent id {query_id:#06x}")

if __name__ == "__main__":
    main()