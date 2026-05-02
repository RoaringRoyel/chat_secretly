import random, math

def egcd(a,b):
    if b==0: return a,1,0
    g,x1,y1=egcd(b,a%b); return g,y1,x1-(a//b)*y1

def modinv(a,m):
    g,x,y=egcd(a,m)
    if g!=1: raise ValueError('No modular inverse')
    return x%m

def is_probable_prime(n,k=8):
    if n<2: return False
    small=[2,3,5,7,11,13,17,19,23,29,31,37]
    if n in small: return True
    if any(n%p==0 for p in small): return False
    d=n-1; s=0
    while d%2==0: s+=1; d//=2
    for _ in range(k):
        a=random.randrange(2,n-2); x=pow(a,d,n)
        if x in (1,n-1): continue
        for _ in range(s-1):
            x=pow(x,2,n)
            if x==n-1: break
        else: return False
    return True

def gen_prime(bits):
    while True:
        n=random.getrandbits(bits)|1|(1<<(bits-1))
        if is_probable_prime(n): return n

def generate_keys(bits=512):
    bits=max(64,int(bits)); p=gen_prime(bits//2); q=gen_prime(bits//2)
    n=p*q; phi=(p-1)*(q-1); e=65537
    if math.gcd(e,phi)!=1: return generate_keys(bits)
    d=modinv(e,phi)
    return {'public':(e,n),'private':(d,n),'p':p,'q':q}

def text_to_int(text): return int.from_bytes(text.encode(),'big')
def int_to_text(num): return num.to_bytes((num.bit_length()+7)//8,'big').decode(errors='replace')
def encrypt(text, public):
    e,n=public; m=text_to_int(text)
    if m>=n: raise ValueError('Message too large for key size')
    return pow(m,e,n)
def decrypt(cipher_int, private):
    d,n=private; return int_to_text(pow(int(cipher_int),d,n))
def factor_attack(n, limit=200000):
    for i in range(2,min(limit,int(n**0.5)+1)):
        if n%i==0: return {'success':True,'p':i,'q':n//i}
    return {'success':False,'message':f'No factor found by trial division up to {limit}'}
