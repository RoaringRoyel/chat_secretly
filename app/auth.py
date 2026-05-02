from itsdangerous import URLSafeSerializer, BadSignature
from .db import get_conn
from .crypto.hash_demo import new_salt, hash_password, verify_password

SECRET='change-this-demo-secret'
serializer=URLSafeSerializer(SECRET, salt='session')

def create_user(username,password):
    salt=new_salt(); h=hash_password(password,salt)
    with get_conn() as conn:
        conn.execute('INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)',(username,h,salt))

def authenticate(username,password):
    with get_conn() as conn:
        user=conn.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
    if user and verify_password(password,user['salt'],user['password_hash']): return dict(user)
    return None

def make_cookie(user_id): return serializer.dumps({'uid':user_id})
def read_cookie(cookie):
    if not cookie: return None
    try: return serializer.loads(cookie).get('uid')
    except BadSignature: return None

def current_user(request):
    uid=read_cookie(request.cookies.get('session'))
    if not uid: return None
    with get_conn() as conn:
        u=conn.execute('SELECT id,username FROM users WHERE id=?',(uid,)).fetchone()
    return dict(u) if u else None
