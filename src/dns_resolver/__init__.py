from dns_resolver import transport
from dns_resolver import response

def main() -> None:
    reply_bytes = transport.send_query("1.1.1.1", "bbc.co.uk", rd=1)
    reply = response.parse_response(reply_bytes)
    
    print(reply)

