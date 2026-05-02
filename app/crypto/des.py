# Educational DES-style 16-round Feistel cipher from scratch. It exposes 16 round keys.
# It is intentionally compact for coursework demonstration, not production cryptography.
from hashlib import sha256
BLOCK=8

def _pad(b):
    p=BLOCK-len(b)%BLOCK; return b+bytes([p])*p

def _unpad(b): return b[:-b[-1]]

def _f(r: int, k: int) -> int:
    x=(r^k)&0xffffffff
    x=((x<<3)|(x>>29))&0xffffffff
    x=(x*0x45d9f3b)&0xffffffff
    return x ^ ((x>>16)&0xffffffff)

def round_keys(key: bytes):
    if len(key)!=8: raise ValueError('DES demo key must be 8 bytes')
    seed=key
    keys=[]
    for i in range(16):
        seed=sha256(seed+bytes([i])).digest()
        keys.append(int.from_bytes(seed[:4],'big'))
    return keys

def enc_block(block: bytes, key: bytes) -> bytes:
    l=int.from_bytes(block[:4],'big'); r=int.from_bytes(block[4:],'big')
    for k in round_keys(key): l,r=r,l^_f(r,k)
    return (r.to_bytes(4,'big')+l.to_bytes(4,'big'))

def dec_block(block: bytes, key: bytes) -> bytes:
    r=int.from_bytes(block[:4],'big'); l=int.from_bytes(block[4:],'big')
    for k in reversed(round_keys(key)): l,r=r^_f(l,k),l
    return (l.to_bytes(4,'big')+r.to_bytes(4,'big'))

def encrypt(plaintext: str, key: bytes) -> str:
    data=_pad(plaintext.encode())
    return b''.join(enc_block(data[i:i+8],key) for i in range(0,len(data),8)).hex()

def decrypt(cipher_hex: str, key: bytes) -> str:
    data=bytes.fromhex(cipher_hex)
    return _unpad(b''.join(dec_block(data[i:i+8],key) for i in range(0,len(data),8))).decode(errors='replace')

def auto_key(): return b'DESKEY!!'
def round_keys_hex(key: bytes): return [f'{k:08x}' for k in round_keys(key)]
