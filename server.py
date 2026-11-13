"""Loopback QazGuard server: demo by default, optional server-side Gemini API."""
import argparse
import json
import random
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import numpy as np
import core
import os
import gemini_provider
import business
from http.cookies import SimpleCookie

ROOT = Path(__file__).resolve().parent

def prepare():
    df = core.generate_synthetic_dataset()
    gateway = core.PromptSecurityGateway()
    r = gateway.train_and_evaluate(df)
    metrics = {
        "ml": r["ml_summary"], "baseline": r["base_summary"],
        "matrix": r["cm_ml"].tolist(), "labels": core.LABELS,
        "train": r["train_size"], "test": r["test_size"],
        "train_templates": r["train_templates"], "test_templates": r["test_templates"],
        "mean_accuracy": float(np.mean(r["repeat"]["acc_ml"])),
        "dlp": gateway.evaluate_dlp(df), "decoys": gateway.evaluate_decoys(),
    }
    rng = random.Random(2026)
    pii = {"iin": core.make_iin(rng), "bin": core.make_bin(rng),
           "iban": core.make_iban(rng), "card": core.make_card(rng)}
    return gateway, {"provider": "gemini" if os.environ.get("QAZGUARD_PROVIDER") == "gemini" else "demo", "metrics": metrics, "pii": pii,
                     "edges": df[df.id > 150].prompt_text.tolist()}

def process(gateway, prompt, demo=False):
    # A fresh vault per request prevents any cross-user/cross-request restoration.
    isolated = core.PromptSecurityGateway()
    isolated.vectorizer, isolated.ml_model = gateway.vectorizer, gateway.ml_model
    if not demo and os.environ.get('QAZGUARD_PROVIDER') == 'gemini':
        isolated.external_llm_stub = gemini_provider.generate
    result = isolated.process_request(prompt)
    result['provider'] = 'gemini' if os.environ.get('QAZGUARD_PROVIDER') == 'gemini' else 'demo'
    return result

def handler_for(gateway, info):
    business.init()
    auth_attempts=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body, content_type="application/json; charset=utf-8", cookie=None):
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            if cookie:self.send_header('Set-Cookie',cookie)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)

        def valid_host(self):
            return self.headers.get("Host") in {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}

        def user(self):
            cookie=SimpleCookie(self.headers.get('Cookie',''))
            return business.session(cookie['session'].value) if 'session' in cookie else None

        def do_GET(self):
            if not self.valid_host():
                return self.reply(403, {"error": "origin"})
            if self.path=='/api/session':
                with business.connect() as c: setup=c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0
                return self.reply(200,{'user':self.user(),'setup':setup})
            if self.path=='/api/backup':
                user=self.user()
                if not user or user['role']!='admin':return self.reply(403,{'message':'Требуется администратор.'})
                with business.connect() as c:data=c.serialize()
                business.event(user,'download_backup')
                return self.reply(200,data,'application/vnd.sqlite3')
            if self.path.startswith('/api/business'):
                user=self.user()
                if not user:return self.reply(401,{'message':'Войдите в кабинет.'})
                return self.reply(200,business.snapshot(user))
            if self.path == "/api/info":
                return self.reply(200, info)
            files = {"/": ("business.html", "text/html"), "/lab": ("index.html", "text/html"), "/output.js": ("output.js", "text/javascript"), "/business.js": ("business.js", "text/javascript"), "/business.css": ("business.css", "text/css"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
            if self.path not in files:
                return self.reply(404, {"error": "not_found"})
            name, mime = files[self.path]
            self.reply(200, (ROOT / "web" / name).read_bytes(), mime + "; charset=utf-8")

        def do_POST(self):
            if not self.valid_host() or self.headers.get("Origin") not in {f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"}:
                return self.reply(403, {"error": "origin"})
            if self.path not in ('/api/auth','/api/logout','/api/create','/api/assistant','/api/report','/api/settings','/api/user','/api/check','/api/test'):
                return self.reply(404, {"error": "not_found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 100000:
                    return self.reply(413, {"error": "length"})
                if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    return self.reply(415, {"error": "format"})
                body = json.loads(self.rfile.read(length))
                if not isinstance(body,dict):return self.reply(400,{'message':'Неверный формат.'})
                if self.path=='/api/auth':
                    with business.LOCK:
                        now=business.time.time()
                        auth_attempts[:]=[t for t in auth_attempts if t>now-60]
                        if len(auth_attempts)>=10:return self.reply(429,{'message':'Слишком много попыток входа. Подождите минуту.'})
                        auth_attempts.append(now)
                        with business.connect() as c:setup=c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0
                        if setup:business.create_user(body.get('username'),body.get('password'),'admin')
                    user=business.authenticate(str(body.get('username','')),str(body.get('password','')))
                    if not user:return self.reply(401,{'message':'Неверный логин или пароль.'})
                    token=business.login(user)
                    return self.reply(200,{'user':user},cookie=f'session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800')
                user=self.user()
                if not user:return self.reply(401,{'message':'Войдите в кабинет.'})
                if self.path=='/api/logout':
                    cookie=SimpleCookie(self.headers.get('Cookie',''))
                    with business.LOCK:business.SESSIONS.pop(cookie['session'].value,None)
                    return self.reply(200,{},cookie='session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
                if self.path=='/api/create':
                    business.mutate(user,body.get('kind'),body)
                    return self.reply(200,{'ok':True})
                if self.path=='/api/assistant':return self.reply(200,business.assistant(gateway,user,body))
                if self.path=='/api/report':
                    if body.get('mode') not in ('summary','debt','late','letter','check'):raise ValueError('Неизвестный отчёт.')
                    return self.reply(200,business.report(user,body['mode'],body.get('order_id',0)))
                if self.path in ('/api/settings','/api/user'):
                    if user['role']!='admin':raise PermissionError('Требуется роль администратора.')
                    if self.path=='/api/user':business.create_user(body.get('username'),body.get('password'),body.get('role'))
                    else:
                        if body.get('provider') not in ('gemini','ollama','offline'):raise ValueError('Выберите провайдер.')
                        model=str(body.get('ollama_model','qwen2.5:3b'))
                        if not model or len(model)>100:raise ValueError('Проверьте модель.')
                        business.SETTINGS.update(provider=body['provider'],ollama_model=model,fallback=body.get('fallback')=='on')
                    business.event(user,'settings' if self.path=='/api/settings' else 'create_user')
                    return self.reply(200,{'ok':True})
                prompt = body.get("prompt") if isinstance(body, dict) else None
                if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 5000:
                    return self.reply(400, {"error": "input"})
                self.reply(200, process(gateway, prompt.strip(),demo=self.path=='/api/test'))
            except gemini_provider.ProviderError as exc:
                self.reply(502, {"error": "provider", "message": str(exc)})
            except PermissionError as exc:
                self.reply(403, {'message':str(exc)})
            except (ValueError, UnicodeError, KeyError, business.sqlite3.IntegrityError) as exc:
                self.reply(400, {"error": "input", 'message':str(exc) if not isinstance(exc,business.sqlite3.IntegrityError) else 'Проверьте уникальность и связанные записи.'})
            except Exception:
                self.reply(500, {"error": "internal"})
    return Handler

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    print("Preparing QazGuard model...", flush=True)
    business.init()
    gateway, info = prepare()
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(gateway, info))
    except OSError:
        raise SystemExit("Port is busy. Close the previous QazGuard window or use --port 8766.")
    url = f"http://127.0.0.1:{server.server_port}"
    print(f"QazGuard ready: {url}\nKeep this window open. Ctrl+C stops the app.", flush=True)
    if not args.no_browser:
        threading.Timer(0.6, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
