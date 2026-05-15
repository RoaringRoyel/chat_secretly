from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import time
from .db import init_db, get_conn
from .auth import create_user, authenticate, make_cookie, current_user
from .crypto import substitution, double_transposition, aes, des, rsa, ecc

app=FastAPI(title='CSE721 Crypto Project')
app.mount('/static', StaticFiles(directory='app/static'), name='static')
templates=Jinja2Templates(directory='app/templates')
CHAT_AES_KEY=aes.auto_key()
RSA_CACHE={}

@app.on_event('startup')
def startup(): init_db()

def ctx(request, **kw):
    kw['request']=request; kw['user']=current_user(request); return kw

@app.get('/')
def index(request: Request): return templates.TemplateResponse('index.html', ctx(request))

@app.get('/register')
def register_page(request: Request): return templates.TemplateResponse('register.html', ctx(request))

@app.post('/register')
def register(username: str=Form(...), password: str=Form(...)):
    try: create_user(username.strip(), password)
    except Exception as e: return RedirectResponse('/register?error=Username+already+exists',303)
    u=authenticate(username,password); resp=RedirectResponse('/chat',303); resp.set_cookie('session',make_cookie(u['id']),httponly=True); return resp

@app.get('/login')
def login_page(request: Request): return templates.TemplateResponse('login.html', ctx(request))

@app.post('/login')
def login(username: str=Form(...), password: str=Form(...)):
    u=authenticate(username,password)
    if not u: return RedirectResponse('/login?error=Invalid+credentials',303)
    resp=RedirectResponse('/chat',303); resp.set_cookie('session',make_cookie(u['id']),httponly=True); return resp

@app.get('/logout')
def logout():
    resp=RedirectResponse('/',303); resp.delete_cookie('session'); return resp

@app.get('/chat')
def chat(request: Request, q: str=''):
    user=current_user(request)
    if not user: return RedirectResponse('/login',303)
    with get_conn() as conn:
        users=[]
        if q:
            users=[dict(x) for x in conn.execute('SELECT id,username FROM users WHERE username LIKE ? AND id<>?',(f'%{q}%',user['id']))]
        rows=[dict(x) for x in conn.execute('''SELECT m.*, s.username sender, r.username receiver FROM messages m JOIN users s ON s.id=m.sender_id JOIN users r ON r.id=m.receiver_id WHERE sender_id=? OR receiver_id=? ORDER BY created_at DESC LIMIT 30''',(user['id'],user['id']))]
    search_demo = substitution.encrypt(q, 'QWERTYUIOPASDFGHJKLZXCVBNM') if q else ''
    return templates.TemplateResponse('chat.html', ctx(request, users=users, messages=rows, q=q, search_demo=search_demo, aes_key=CHAT_AES_KEY.hex()))

@app.post('/send')
def send(request: Request, receiver_id: int=Form(...), message: str=Form(...)):
    user=current_user(request)
    if not user: return RedirectResponse('/login',303)
    cipher=aes.encrypt(message, CHAT_AES_KEY)
    with get_conn() as conn:
        conn.execute('INSERT INTO messages(sender_id,receiver_id,ciphertext_hex,plaintext_demo) VALUES(?,?,?,?)',(user['id'],receiver_id,cipher,message))
    return RedirectResponse('/chat',303)

@app.get('/lab')
def lab(request: Request): return templates.TemplateResponse('lab.html', ctx(request, result=None))

@app.post('/lab')
def run_lab(request: Request, algorithm: str=Form(...), text: str=Form(''), key: str=Form(''), key2: str=Form(''), bits: int=Form(128)):
    start=time.perf_counter(); result={}
    try:
        if algorithm=='substitution':
            c=substitution.encrypt(text,key); result={'ciphertext':c,'decrypted':substitution.decrypt(c,key),'frequency':substitution.frequency_analysis(c),'caesar_bruteforce':substitution.brute_force_caesar_only(c)[:5]}
        elif algorithm=='double':
            c=double_transposition.encrypt(text,key,key2); result={'ciphertext':c,'decrypted':double_transposition.decrypt(c,key,key2),'frequency':double_transposition.analyze(c)}
        elif algorithm=='aes':
            k=aes.auto_key(); c=aes.encrypt(text,k); result={'auto_key_hex':k.hex(),'ciphertext':c,'decrypted':aes.decrypt(c,k),'round_keys':aes.round_keys_hex(k)}
        elif algorithm=='des':
            k=des.auto_key(); c=des.encrypt(text,k); result={'auto_key_hex':k.hex(),'ciphertext':c,'decrypted':des.decrypt(c,k),'round_keys':des.round_keys_hex(k),'note':'Compact educational DES-style Feistel implementation.'}
        elif algorithm=='rsa':
            keys=rsa.generate_keys(bits); c=rsa.encrypt(text,keys['public']); result={'public_key':keys['public'],'private_key':keys['private'],'p':keys['p'],'q':keys['q'],'ciphertext':c,'decrypted':rsa.decrypt(c,keys['private']),'factorization_attack':rsa.factor_attack(keys['public'][1])}
        elif algorithm=='ecc':
            result=ecc.demo()
        else: result={'error':'Unknown algorithm'}
    except Exception as e: result={'error':str(e)}
    result['time_ms']=round((time.perf_counter()-start)*1000,3)
    return templates.TemplateResponse('lab.html', ctx(request, result=result, algorithm=algorithm))