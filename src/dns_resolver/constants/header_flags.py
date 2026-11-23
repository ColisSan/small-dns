from dataclasses import dataclass

FLAG_SPECS: dict[str, tuple[int,int]] = {
    "qr": (1,15), 
    "opcode": (4,11), 
    "aa": (1,10), 
    "tc": (1,9), 
    "rd": (1,8), 
    "ra": (1,7), 
    "z": (3,4), 
    "rcode": (4,0)
}

@dataclass
class Flags:
    qr: int = 0
    opcode: int = 0
    aa: int = 0
    tc: int = 0
    rd: int = 0
    ra: int = 0
    z: int = 0
    rcode: int = 0