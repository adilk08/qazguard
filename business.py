"""Single-workspace logistics pilot. Synthetic seed data, SQLite and local sessions."""
import sqlite3, secrets, hashlib, hmac, time, json, threading, os
from pathlib import Path
from datetime import date, timedelta
from urllib.request import Request, urlopen
import core, gemini_provider

DB = Path(__file__).with_name('business.sqlite3')
SESSIONS = {}
LOCK = threading.Lock()
AI_LOCK = threading.Lock()
AI_QUEUE = threading.BoundedSemaphore(4)
CACHE = {}
CALLS = {}
SETTINGS = {'provider':'gemini' if os.environ.get('QAZGUARD_PROVIDER')=='gemini' else 'offline', 'ollama_model':'qwen2.5:3b','fallback':False}

def ollama(payload):
    body=json.dumps({'model':SETTINGS['ollama_model'],'stream':False,'messages':[{'role':'system','content':'Answer in the user language using supplied facts. Preserve supplied tokens exactly; never invent tokens.'},{'role':'user','content':payload}]}).encode()
    try:
        with urlopen(Request('http://127.0.0.1:11434/api/chat',data=body,headers={'Content-Type':'application/json'}),timeout=60) as r:return json.load(r)['message']['content']
    except Exception:raise gemini_provider.ProviderError('Ollama недоступна. Запустите локальную модель или выберите SQL-сводку.') from None

class Connection(sqlite3.Connection):
    def __exit__(self,*args):
        try:return super().__exit__(*args)
        finally:self.close()
def connect():
    c=sqlite3.connect(DB, timeout=10,factory=Connection); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def init():
    with connect() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt TEXT, password TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS clients(id INTEGER PRIMARY KEY, name TEXT, company TEXT, iin TEXT, email TEXT, phone TEXT, address TEXT);
        CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, client_id INTEGER REFERENCES clients(id), route TEXT, amount INTEGER CHECK(amount>0), status TEXT, due TEXT);
        CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), amount INTEGER CHECK(amount>0), created TEXT);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, created TEXT DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, action TEXT, entities INTEGER DEFAULT 0, provider TEXT, result TEXT);''')
        if c.execute('SELECT COUNT(*) FROM clients').fetchone()[0]: return
        for i in range(1,13):
            c.execute('INSERT INTO clients VALUES(?,?,?,?,?,?,?)',(i,f'Демо Клиент {i:02}',f'Test Logistics {i:02}',f'{i:012}',f'client{i}@example.test',f'+7 (701) 000-00-{i:02}',f'Тестовый город, Учебная улица {i}'))
        routes=['Алматы → Астана','Астана → Шымкент','Атырау → Алматы','Караганда → Астана']
        for i in range(1,25):
            c.execute('INSERT INTO orders VALUES(?,?,?,?,?,?)',(100+i,(i-1)%12+1,routes[i%4],(80+i*13)*1000,['В пути','Доставлен','Ожидает','Задержан'][i%4],(date.today()+timedelta(days=i%10-4)).isoformat()))
            if i%3: c.execute('INSERT INTO payments(order_id,amount,created) VALUES(?,?,?)',(100+i,(80+i*13)*1000//(2 if i%4==0 else 1),date.today().isoformat()))

def password_hash(password,salt):return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),300000).hex()
def create_user(username,password,role):
    if not isinstance(username,str) or not 3<=len(username)<=40 or not isinstance(password,str) or not 10<=len(password)<=128 or role not in ('admin','manager','analyst'):raise ValueError('Логин: 3–40 символов; пароль: 10–128.')
    salt=secrets.token_hex(16)
    with connect() as c:c.execute('INSERT INTO users(username,salt,password,role) VALUES(?,?,?,?)',(username,salt,password_hash(password,salt),role))
def authenticate(username,password):
    with connect() as c:r=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
    if not r or not hmac.compare_digest(r['password'],password_hash(password,r['salt'])):return None
    return {'id':r['id'],'username':r['username'],'role':r['role']}
def session(token):
    with LOCK:
        v=SESSIONS.get(token)
        if v and v[1]>time.time():return v[0]
        SESSIONS.pop(token,None)
def login(user):
    token=secrets.token_urlsafe(32)
    with LOCK:SESSIONS[token]=(user,time.time()+8*3600)
    return token
def event(user,action,entities=0,provider='',result='ok'):
    with connect() as c:c.execute('INSERT INTO events(user_id,action,entities,provider,result) VALUES(?,?,?,?,?)',(user['id'],action,entities,provider,result))
def records():
    with connect() as c:
        clients=[dict(r) for r in c.execute('SELECT * FROM clients ORDER BY id DESC')]
        orders=[dict(r) for r in c.execute('SELECT o.*,c.name,c.company,COALESCE((SELECT SUM(amount) FROM payments p WHERE p.order_id=o.id),0) paid FROM orders o JOIN clients c ON c.id=o.client_id ORDER BY o.id DESC')]
        payments=[dict(r) for r in c.execute('SELECT * FROM payments ORDER BY id DESC')]
    return clients,orders,payments
def snapshot(user):
    clients,orders,payments=records()
    total=sum(o['amount'] for o in orders);paid=sum(p['amount'] for p in payments)
    stats={'orders':len(orders),'clients':len(clients),'total':total,'paid':paid,'debt':total-paid,'late':sum(o['status']=='Задержан' for o in orders)}
    with connect() as c: events=[dict(r) for r in c.execute('SELECT e.id,e.created,u.username,e.action,e.entities,e.provider,e.result FROM events e LEFT JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 100')]
    return {'user':user,'stats':stats,'clients':clients if user['role']!='analyst' else [],'orders':orders if user['role']!='analyst' else [],'payments':payments if user['role']!='analyst' else [],'events':events if user['role']=='admin' else [],'statuses':{s:sum(o['status']==s for o in orders) for s in ['Ожидает','В пути','Доставлен','Задержан']},'settings':dict(SETTINGS),'synthetic':True}
def mutate(user,kind,data):
    if user['role']=='analyst':raise PermissionError('Роль аналитика разрешает только агрегированную статистику.')
    with connect() as c:
        if kind=='client':
            fields=[str(data.get(k,'')).strip() for k in ('name','company','iin','email','phone','address')]
            if not fields[0] or any(len(x)>250 for x in fields):raise ValueError('Проверьте имя и длину полей.')
            if data.get('id'):
                if c.execute('UPDATE clients SET name=?,company=?,iin=?,email=?,phone=?,address=? WHERE id=?',fields+[int(data['id'])]).rowcount!=1:raise ValueError('Клиент не найден.')
            else:c.execute('INSERT INTO clients(name,company,iin,email,phone,address) VALUES(?,?,?,?,?,?)',fields)
        elif kind=='order':
            amount=int(data['amount']);due=date.fromisoformat(data['due']).isoformat()
            if amount<=0 or amount>1000000000 or data['status'] not in ('Ожидает','В пути','Доставлен','Задержан') or not 1<=len(data['route'])<=200:raise ValueError('Проверьте заказ.')
            c.execute('INSERT INTO orders(client_id,route,amount,status,due) VALUES(?,?,?,?,?)',(int(data['client_id']),data['route'],amount,data['status'],due))
        elif kind=='status':
            if data['status'] not in ('Ожидает','В пути','Доставлен','Задержан'):raise ValueError('Неверный статус.')
            if c.execute('UPDATE orders SET status=? WHERE id=?',(data['status'],int(data['id']))).rowcount!=1:raise ValueError('Заказ не найден.')
        elif kind=='payment':
            amount=int(data['amount']);oid=int(data['order_id'])
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT amount-COALESCE((SELECT SUM(amount) FROM payments WHERE order_id=?),0) FROM orders WHERE id=?',(oid,oid)).fetchone()
            if not row or not 0<amount<=row[0]:raise ValueError('Платёж превышает остаток или заказ не найден.')
            c.execute('INSERT INTO payments(order_id,amount,created) VALUES(?,?,?)',(oid,amount,date.today().isoformat()))
        else:raise ValueError('Неизвестное действие.')
    with LOCK:CACHE.clear()
    event(user,'create_'+kind)

def report(user,mode='summary',order_id=0):
    _,orders,_=records()
    if mode=='check':return None
    if mode=='letter':
        if user['role']=='analyst':raise PermissionError('Нет доступа к клиентским письмам.')
        orders=[o for o in orders if o['id']==int(order_id)]
    elif mode=='debt':orders=[o for o in orders if o['paid']<o['amount']]
    elif mode=='late':orders=[o for o in orders if o['status']=='Задержан']
    amounts=[o['amount'] for o in orders]
    import math
    width=max(1000,math.ceil((max(amounts,default=0)+1)/4000)*1000)
    bins=[(i*width,(i+1)*width) for i in range(4)]
    hist=[{'label':f'{lo//1000}–{hi//1000} тыс. ₸','value':sum(lo<=a<hi for a in amounts)} for lo,hi in bins]
    statuses=[{'label':s,'value':sum(o['status']==s for o in orders)} for s in ('Ожидает','В пути','Доставлен','Задержан')]
    rows=[[o['id'],o['company'],o['route'],o['amount'],o['paid'],o['amount']-o['paid'],o['status'],o['due']] for o in orders] if user['role']!='analyst' else []
    return {'title':{'summary':'Все заказы','debt':'Заказы с задолженностью','late':'Задержанные заказы','letter':'Выбранный заказ'}.get(mode,'Заказы'),
            'columns':['Заказ','Клиент / компания','Маршрут','Сумма, ₸','Оплачено, ₸','Долг, ₸','Статус','Срок'],
            'rows':rows,'statuses':statuses,'histogram':hist,'count':len(orders),'total':sum(amounts),'paid':sum(o['paid'] for o in orders),'debt':sum(o['amount']-o['paid'] for o in orders),'restricted':user['role']=='analyst','source':'PostgreSQL','generated':date.today().isoformat()}

def gateway_trace(tok,original,payload,raw,answer,prediction,provider,action):
    import re
    mappings=[]
    for token,value in tok.vault.items():
        kind=re.match(r'<TOKEN_(.+)_[A-F0-9]+>',token).group(1)
        used=(raw or '').count(token)
        mappings.append({'type':kind,'original':value,'token':token,'length':len(value),
                         'remaining_in_payload':(payload or '').count(value),
                         'restored_count':used})
    external=provider!='offline' and provider!='none'
    return {'request_id':secrets.token_hex(8),'classification':prediction,
            'decision':action,'provider':provider,'provider_called':external,
            'served_from_cache':False,'original':original,'prepared_payload':payload,
            'sent_payload':payload if external else None,'raw_response':raw,
            'restored_response':answer,'mappings':mappings,
            'restored_count':sum(m['restored_count'] for m in mappings)}

def assistant(gateway,user,data):
    demo=data.get('demo_trace') is True
    if demo and user['role']!='admin':raise PermissionError('Разбор шлюза доступен только администратору.')
    prompt=str(data.get('prompt','')).strip();mode=data.get('mode','summary')
    if not 1<=len(prompt)<=3000 or mode not in ('summary','debt','late','letter','check'):raise ValueError('Проверьте запрос.')
    if user['role']=='analyst' and mode=='letter':raise PermissionError('Аналитик не имеет доступа к клиентским письмам.')
    tok=core.QazDataTokenizer()
    prediction=gateway.ml_model.predict(gateway.vectorizer.transform([prompt]))[0]
    if prediction=='JAILBREAK':
        answer='Запрос заблокирован классификатором.'
        result={'action':'BLOCK_AND_ALERT','provider':'none','answer':answer,'payload':None,'raw':None,'entities':0}
        if demo:result['trace']=gateway_trace(tok,prompt,None,None,answer,prediction,'none','BLOCK_AND_ALERT')
        event(user,'BLOCK_AND_ALERT');return result
    snap=snapshot(user);context={'our_company':'QazLogistics','summary':snap['stats'],'statuses':snap['statuses']}
    if mode!='check' and user['role']!='analyst':
        _,orders,_=records()
        if mode=='debt':orders=[o for o in orders if o['paid']<o['amount']]
        elif mode=='late':orders=[o for o in orders if o['status']=='Задержан']
        elif mode=='letter':
            orders=[o for o in orders if o['id']==int(data.get('order_id',0))]
            if not orders:raise ValueError('Выберите заказ для письма.')
        else:orders=[]
        protected=[]
        for o in orders[:30]:
            item=dict(o)
            for f in ('name','company'):item[f]=tok._get_token('CLIENT_NAME' if f=='name' else 'CLIENT_COMPANY',item[f])
            item['customer_name']=item.pop('name')
            item['customer_company']=item.pop('company')
            protected.append(item)
        context['orders']=protected
    elif mode=='letter':raise PermissionError('Аналитик не имеет доступа к клиентским письмам.')
    text=prompt if mode=='check' else prompt+'\nUse ONLY this database snapshot; do not invent records. Amounts are KZT. Our company is QazLogistics; customer_name and customer_company identify the recipient, not the sender.\n'+json.dumps(context,ensure_ascii=False)
    payload,entities=tok.inspect_and_tokenize(text)
    original=tok.detokenize(text) if demo else None
    provider=SETTINGS['provider']; cachekey=(user['id'],provider,demo,hashlib.sha256(text.encode()).hexdigest())
    with LOCK:
        cached=CACHE.get(cachekey)
        if cached and cached[0]>time.time():
            result=dict(cached[1],cached=True)
            if demo and result.get('trace'):result['trace']=dict(result['trace'],served_from_cache=True,provider_called=False)
            return result
        recent=[t for t in CALLS.get(user['id'],[]) if t>time.time()-60]
        if len(recent)>=5:raise ValueError('Лимит кабинета: 5 запросов в минуту. Подождите.')
        CALLS[user['id']]=recent+[time.time()]
    if not AI_QUEUE.acquire(blocking=False):raise ValueError('Очередь заполнена (4 запроса). Повторите позже.')
    if not AI_LOCK.acquire(timeout=65):
        AI_QUEUE.release()
        raise ValueError('Время ожидания в очереди истекло. Повторите запрос.')
    try:
        if provider=='gemini':
            try:
                raw=gemini_provider.generate(payload)
            except gemini_provider.ProviderError:
                if not SETTINGS['fallback']:raise
                raw=ollama(payload);provider='ollama (резерв после ошибки Gemini)'
        elif provider=='ollama':raw=ollama(payload)
        else:raw=f"SQL-сводка без ИИ. Заказов: {snap['stats']['orders']}; сумма: {snap['stats']['total']:,} ₸; оплачено: {snap['stats']['paid']:,} ₸; долг: {snap['stats']['debt']:,} ₸; задержано: {snap['stats']['late']}."
        import re
        if set(re.findall(r'<TOKEN_[^<>\s]+>',raw))-set(tok.vault):raise gemini_provider.ProviderError('Модель изменила токены. Повторите запрос.')
        result={'action':'TOKENIZE_AND_FORWARD' if tok.vault else 'ALLOW_DIRECT','provider':provider,'answer':tok.detokenize(raw),'raw':raw if demo else None,'payload':payload if demo else None,'entities':len(tok.vault),'cached':False,'report':report(user,mode,data.get('order_id',0))}
        if demo:result['trace']=gateway_trace(tok,original,payload,raw,result['answer'],prediction,provider,result['action'])
        with LOCK:
            if len(CACHE)>100:CACHE.clear()
            CACHE[cachekey]=(time.time()+60,result)
        event(user,result['action'],len(tok.vault),provider)
        return result
    except gemini_provider.ProviderError:
        event(user,'AI_ERROR',len(tok.vault),provider,'provider_error');raise
    finally:
        AI_LOCK.release()
        AI_QUEUE.release()
