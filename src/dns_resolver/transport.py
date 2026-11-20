import secrets
import socket
from dns_resolver import query

def send_query(server_ip: str, name: str, qtype: int = 1, rd: int = 0) -> bytes:
    query_id = secrets.randbits(16)
    
    response = query.build_query(name, query_id, rd, qtype)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(response) 