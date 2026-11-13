"""HTTPS cloud entry point. Run one Gunicorn worker; sessions/limits live in RAM."""
import os, json, time, hmac, threading
from urllib.parse import urlsplit
from functools import wraps
from pathlib import Path
from flask import Flask,request,jsonify,send_from_directory,make_response
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
if os.environ.get('QAZGUARD_TESTING')!='1':
    load_dotenv(Path(__file__).with_name('.env.local'),override=False)
import business,server,gemini_provider

ROOT=Path(__file__).parent
WEB=ROOT/'web' if (ROOT/'web').is_dir() else ROOT
TESTING=os.environ.get('QAZGUARD_TESTING')=='1'
ORIGIN=os.environ.get('PUBLIC_ORIGIN',os.environ.get('RENDER_EXTERNAL_URL','')).rstrip('/')
if not ORIGIN or (not TESTING and not ORIGIN.startswith('https://')):
    raise RuntimeError('Configure PUBLIC_ORIGIN as the public HTTPS URL.')
if not TESTING and not os.environ.get('DATABASE_URL'):
    raise RuntimeError('DATABASE_URL is required: cloud data must be persistent.')
if os.environ.get('DATABASE_URL'):
    import postgres_store
    postgres_store.initialize(business)
    import pg8000.dbapi as pg
    DB_ERRORS=(business.sqlite3.IntegrityError,pg.IntegrityError)
else:
    # Test-only temporary SQLite, never a public storage fallback.
    business.DB=Path(os.environ['QAZGUARD_TEST_DB'])
    business.init()
    DB_ERRORS=(business.sqlite3.IntegrityError,)
app=Flask(__name__,static_folder=None)
app.config.update(MAX_CONTENT_LENGTH=100000,TRUSTED_HOSTS=[urlsplit(ORIGIN).netloc])
app.wsgi_app=ProxyFix(app.wsgi_app,x_for=1,x_proto=1)
gateway,info=server.prepare()
attempts={}; auth_lock=threading.Lock()

def current_user():return business.session(request.cookies.get('session',''))
def protected(admin=False):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args,**kwargs):
            user=current_user()
            if not user:return jsonify(message='Войдите в кабинет.'),401
            if admin and user['role']!='admin':return jsonify(message='Требуется администратор.'),403
            return fn(user,*args,**kwargs)
        return wrapped
    return decorate

@app.before_request
def origin_check():
    if request.path=='/healthz' and request.method=='GET':return None
    if not TESTING and not request.is_secure:return jsonify(message='Используйте HTTPS.'),403
    if request.method=='POST':
        if request.headers.get('Origin')!=ORIGIN:return jsonify(message='Неверный источник запроса.'),403
        if request.mimetype!='application/json':return jsonify(message='Нужен JSON.'),415

@app.after_request
def secure_headers(response):
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    response.headers['Referrer-Policy']='no-referrer'
    if not TESTING:response.headers['Strict-Transport-Security']='max-age=31536000'
    return response

@app.errorhandler(Exception)
def failure(exc):
    from werkzeug.exceptions import HTTPException
    if isinstance(exc,HTTPException):return jsonify(message='Запрос не выполнен.'),exc.code
    if isinstance(exc,gemini_provider.ProviderError):return jsonify(message=str(exc)),502
    if isinstance(exc,PermissionError):return jsonify(message=str(exc)),403
    if isinstance(exc,DB_ERRORS):return jsonify(message='Проверьте уникальность и связанные записи.'),400
    if isinstance(exc,(ValueError,KeyError,TypeError)):return jsonify(message='Проверьте введённые данные.'),400
    # Do not emit credentials, SQL, provider bodies, or request contents into logs.
    return jsonify(message='Ошибка сервера. Повторите позже.'),500

def body():
    data=request.get_json()
    if not isinstance(data,dict):raise ValueError('JSON object required')
    return data

@app.get('/healthz')
def health():return jsonify(status='ok')

@app.get('/api/session')
def session():
    with business.connect() as c:setup=c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0
    return jsonify(user=current_user(),setup=setup,cloud=True)

@app.post('/api/auth')
def auth():
    data=body();now=time.time();ip=request.remote_addr
    with auth_lock:
        # Global ceiling also bounds memory and distributed-login attempts.
        recent=[t for t in attempts.get('global',[]) if t>now-60]
        local=[t for t in attempts.get(ip,[]) if t>now-60]
        if len(recent)>=100 or len(local)>=10:return jsonify(message='Слишком много попыток. Подождите минуту.'),429
        if len(attempts)>2048:attempts.clear()
        attempts['global']=recent+[now];attempts[ip]=local+[now]
        with business.LOCK:
            with business.connect() as c:setup=c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0
            if setup:
                expected=os.environ.get('SETUP_CODE','')
                supplied=data.get('setup_code','')
                if not isinstance(supplied,str) or not expected or not hmac.compare_digest(expected,supplied):
                    return jsonify(message='Для первого входа нужен код настройки владельца.'),403
                business.create_user(data.get('username'),data.get('password'),'admin')
        user=business.authenticate(str(data.get('username','')),str(data.get('password','')))
        if not user:return jsonify(message='Неверный логин или пароль.'),401
        response=jsonify(user=user)
        response.set_cookie('session',business.login(user),secure=not TESTING,httponly=True,samesite='Strict',max_age=28800)
        return response

@app.post('/api/logout')
@protected()
def logout(user):
    with business.LOCK:business.SESSIONS.pop(request.cookies.get('session',''),None)
    response=jsonify(ok=True);response.delete_cookie('session',secure=not TESTING,httponly=True,samesite='Strict')
    return response

@app.get('/api/business')
@protected()
def snapshot(user):return jsonify(business.snapshot(user))

@app.post('/api/create')
@protected()
def create(user):
    data=body();business.mutate(user,data.get('kind'),data)
    return jsonify(ok=True)

@app.post('/api/report')
@protected()
def report(user):
    data=body()
    if data.get('mode') not in ('summary','debt','late','letter','check'):raise ValueError('Unknown report')
    result=business.report(user,data['mode'],data.get('order_id',0))
    if result:result['source']='PostgreSQL'
    return jsonify(result)

@app.post('/api/assistant')
@protected()
def assistant(user):return jsonify(business.assistant(gateway,user,body()))

@app.post('/api/user')
@protected(admin=True)
def user_create(user):
    data=body()
    if data.get('role') not in ('manager','analyst'):raise ValueError('Invalid role')
    business.create_user(data.get('username'),data.get('password'),data.get('role'))
    business.event(user,'create_user');return jsonify(ok=True)

@app.post('/api/settings')
@protected(admin=True)
def settings(user):
    data=body()
    if data.get('provider') not in ('gemini','offline'):raise ValueError('Cloud provider must be Gemini or SQL')
    business.SETTINGS.update(provider=data['provider'],fallback=False)
    business.event(user,'settings');return jsonify(ok=True)

@app.get('/api/backup')
@protected(admin=True)
def backup(user):
    # Portable business-data export; never include account password hashes.
    clients,orders,payments=business.records()
    response=make_response(json.dumps(dict(clients=clients,orders=orders,payments=payments),ensure_ascii=False))
    response.headers['Content-Type']='application/json; charset=utf-8'
    response.headers['Content-Disposition']='attachment; filename="qazguard-business-backup.json"'
    business.event(user,'download_backup');return response

@app.get('/api/info')
def lab_info():return jsonify(info)

@app.post('/api/test')
@app.post('/api/check')
@protected()
def check(user):
    prompt=body().get('prompt')
    if not isinstance(prompt,str) or not 1<=len(prompt.strip())<=5000:raise ValueError('Invalid prompt')
    return jsonify(server.process(gateway,prompt.strip(),demo=True))

@app.get('/')
def index():return send_from_directory(WEB,'business.html')
@app.get('/lab')
def lab():return send_from_directory(WEB,'index.html')
@app.get('/<name>')
def asset(name):
    if name not in {'business.js','business.css','output.js','app.js','style.css'}:
        return jsonify(message='Не найдено.'),404
    return send_from_directory(WEB,name)
