"""Small DB-API adapter for the project's fixed SQL queries; secrets stay in env."""
import os
import ssl
from urllib.parse import urlsplit,unquote
import pg8000.dbapi as pg

class Row(dict):
    def __getitem__(self,key):
        return list(self.values())[key] if isinstance(key,int) else super().__getitem__(key)

class Cursor:
    def __init__(self,cursor):self.cursor=cursor
    @property
    def rowcount(self):return self.cursor.rowcount
    def fetchone(self):
        row=self.cursor.fetchone()
        return Row(zip((x[0] for x in self.cursor.description),row)) if row is not None else None
    def fetchall(self):return [Row(zip((x[0] for x in self.cursor.description),r)) for r in self.cursor.fetchall()]
    def __iter__(self):return iter(self.fetchall())

class Connection:
    def __init__(self,url=None):
        parts=urlsplit(url or os.environ['DATABASE_URL'])
        self.raw=pg.connect(user=unquote(parts.username),password=unquote(parts.password),host=parts.hostname,port=parts.port or 5432,database=unquote(parts.path.lstrip('/')),ssl_context=ssl.create_default_context(),timeout=20)
    def __enter__(self):return self
    def __exit__(self,kind,value,tb):
        try:
            if kind:self.raw.rollback()
            else:self.raw.commit()
        finally:self.raw.close()
    def execute(self,sql,args=None):
        if sql=='BEGIN IMMEDIATE':
            sql='LOCK TABLE payments IN SHARE ROW EXCLUSIVE MODE'
        sql=sql.replace('?', '%s')
        cursor=self.raw.cursor()
        cursor.execute(sql,args) if args is not None else cursor.execute(sql)
        return Cursor(cursor)
    def executescript(self,script):
        script=script.replace('id INTEGER PRIMARY KEY','id SERIAL PRIMARY KEY')
        script=script.replace('created TEXT DEFAULT CURRENT_TIMESTAMP','created TEXT DEFAULT (CURRENT_TIMESTAMP::text)')
        for statement in script.split(';'):
            if statement.strip():self.execute(statement)

def connect():return Connection()

def initialize(business):
    # Schema setup uses direct connection; normal app requests use the pooler.
    business.connect=lambda:Connection(os.environ.get('DATABASE_URL_UNPOOLED') or os.environ['DATABASE_URL'])
    business.init()
    with connect() as c:
        for name in ('users','clients','orders','payments','events'):
            c.execute(f"SELECT setval(pg_get_serial_sequence('{name}','id'), COALESCE(MAX(id),0)+1, false) FROM {name}")
    business.connect=connect
