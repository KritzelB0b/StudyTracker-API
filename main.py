import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import psycopg
from psycopg.types.json import Jsonb
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash

DATABASE_URL = os.environ.get('DATABASE_URL', '')
JWT_SECRET = os.environ.get('JWT_SECRET', '')
OWNER_EMAIL = os.environ.get('OWNER_EMAIL', '').lower().strip()
FRONTEND_ORIGIN = os.environ.get('FRONTEND_ORIGIN', 'https://kritzelb0b.github.io').rstrip('/')
if not DATABASE_URL or len(JWT_SECRET) < 32 or not OWNER_EMAIL:
    raise RuntimeError('DATABASE_URL, OWNER_EMAIL and JWT_SECRET (>=32 chars) are required')

app = FastAPI(title='StudyTracker Sync API', docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=[FRONTEND_ORIGIN], allow_methods=['GET','POST','PUT'], allow_headers=['Authorization','Content-Type'])
hasher = PasswordHash.recommended()

class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)

class SyncPayload(BaseModel):
    revision: int = Field(ge=0)
    data: dict[str, Any]

def connect():
    return psycopg.connect(DATABASE_URL, connect_timeout=10)

@app.on_event('startup')
def init_db():
    with connect() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS user_data (user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, revision BIGINT NOT NULL DEFAULT 0, data JSONB NOT NULL DEFAULT \'{"modules":[],"topics":[],"entries":[]}\'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())')

def login_token(user_id: int):
    now = datetime.now(timezone.utc)
    return jwt.encode({'sub': str(user_id), 'iat': now, 'exp': now + timedelta(days=7)}, JWT_SECRET, algorithm='HS256')

def auth(authorization: str | None = Header(default=None)) -> int:
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(401, 'Anmeldung erforderlich')
    try:
        claims = jwt.decode(authorization.split(' ',1)[1], JWT_SECRET, algorithms=['HS256'])
        return int(claims['sub'])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise HTTPException(401, 'Sitzung abgelaufen oder ungültig')

@app.get('/health')
def health():
    return {'status':'ok'}

@app.post('/auth/register')
def register(payload: Credentials):
    if payload.email.lower() != OWNER_EMAIL:
        raise HTTPException(403, 'Registrierung nicht freigegeben')
    with connect() as conn:
        existing = conn.execute('SELECT id FROM users LIMIT 1').fetchone()
        if existing:
            raise HTTPException(403, 'Registrierung bereits abgeschlossen')
        try:
            user_id = conn.execute('INSERT INTO users (email, password_hash) VALUES (%s,%s) RETURNING id', (OWNER_EMAIL, hasher.hash(payload.password))).fetchone()[0]
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, 'Konto existiert bereits')
        conn.execute('INSERT INTO user_data (user_id) VALUES (%s)', (user_id,))
    return {'token':login_token(user_id)}

@app.post('/auth/login')
def login(payload: Credentials):
    with connect() as conn:
        row = conn.execute('SELECT id, password_hash FROM users WHERE email=%s', (payload.email.lower(),)).fetchone()
    if not row or not hasher.verify(payload.password, row[1]):
        raise HTTPException(401, 'E-Mail oder Passwort falsch')
    return {'token':login_token(row[0])}

@app.get('/sync')
def pull(user_id: int = Depends(auth)):
    with connect() as conn:
        row = conn.execute('SELECT revision, data, updated_at FROM user_data WHERE user_id=%s', (user_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'Kein Datensatz')
    return {'revision': row[0], 'data': row[1], 'updated_at': row[2].isoformat()}

@app.put('/sync')
def push(payload: SyncPayload, user_id: int = Depends(auth)):
    d = payload.data
    if not {'modules','topics','entries'}.issubset(d.keys()) or set(d.keys()) - {'modules','topics','entries','study'} or any(not isinstance(d[k],list) for k in ['modules','topics','entries']) or (d.get('study') is not None and not isinstance(d['study'],dict)):
        raise HTTPException(422, 'Ungültiges Datenformat')
    if len(str(d)) > 1_500_000:
        raise HTTPException(413, 'Datensatz zu groß')
    with connect() as conn:
        row = conn.execute('UPDATE user_data SET data=%s, revision=revision+1, updated_at=NOW() WHERE user_id=%s AND revision=%s RETURNING revision', (Jsonb(d), user_id, payload.revision)).fetchone()
        if not row:
            raise HTTPException(409, 'Datenkonflikt: Bitte neuesten Stand laden und Änderungen zusammenführen')
    return {'revision':row[0]}


# Public, read-only statistics. Never expose raw records, notes, Moodle links,
# task titles, email addresses, authentication tokens, or individual timestamps.
@app.get('/public/stats')
def public_stats():
    if os.environ.get('PUBLIC_DASHBOARD_ENABLED', 'false').lower() != 'true':
        raise HTTPException(404, 'Öffentliches Dashboard ist deaktiviert')
    with connect() as conn:
        row = conn.execute('''SELECT d.data, d.updated_at FROM user_data d
                              JOIN users u ON u.id=d.user_id
                              WHERE u.email=%s LIMIT 1''', (OWNER_EMAIL,)).fetchone()
    if not row:
        return {'modules': [], 'total_hours': 0, 'session_count': 0, 'last_updated': None}
    data, updated_at = row
    modules = data.get('modules', []) if isinstance(data, dict) else []
    entries = data.get('entries', []) if isinstance(data, dict) else []
    summary = []
    for mod in modules[:100]:
        if not isinstance(mod, dict):
            continue
        mid = mod.get('id')
        mins = sum(max(0, min(int(e.get('minutes', 0)), 1440))
                   for e in entries if isinstance(e, dict) and e.get('moduleId') == mid
                   and isinstance(e.get('minutes'), (int, float)))
        summary.append({'name': str(mod.get('name', 'Modul'))[:120],
                        'hours': round(mins / 60, 1),
                        'sessions': sum(1 for e in entries if isinstance(e, dict) and e.get('moduleId') == mid)})
    summary.sort(key=lambda x:x['hours'],reverse=True)
    return {'modules':summary, 'total_hours':round(sum(m['hours'] for m in summary),1),
            'session_count':len(entries), 'last_updated':updated_at.isoformat()}
