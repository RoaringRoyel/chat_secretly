O=None

def inv_mod(k,p): return pow(k%p,-1,p)
def is_on_curve(P,a,b,p):
    if P is O: return True
    x,y=P; return (y*y-(x*x*x+a*x+b))%p==0

def add(P,Q,a,p):
    if P is O: return Q
    if Q is O: return P
    x1,y1=P; x2,y2=Q
    if x1==x2 and (y1+y2)%p==0: return O
    if P==Q: m=((3*x1*x1+a)*inv_mod(2*y1,p))%p
    else: m=((y2-y1)*inv_mod(x2-x1,p))%p
    x3=(m*m-x1-x2)%p; y3=(m*(x1-x3)-y1)%p
    return (x3,y3)

def mul(k,P,a,p):
    R=O; Q=P
    while k:
        if k&1: R=add(R,Q,a,p)
        Q=add(Q,Q,a,p); k//=2
    return R

def list_points(p,a,b):
    pts=[]
    for x in range(p):
        rhs=(x**3+a*x+b)%p
        for y in range(p):
            if (y*y)%p==rhs: pts.append((x,y))
    return pts

def demo(p=97,a=2,b=3,G=(3,6),alice=17,bob=29):
    points=list_points(p,a,b)
    A=mul(alice,G,a,p); B=mul(bob,G,a,p)
    s1=mul(alice,B,a,p); s2=mul(bob,A,a,p)
    return {'parameters':{'p':p,'a':a,'b':b,'G':G},'points':points,'alice_private':alice,'bob_private':bob,'alice_public':A,'bob_public':B,'shared_key_alice':s1,'shared_key_bob':s2}
