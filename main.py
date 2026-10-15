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



# Version 2.5: strict server-side projection; never return full records to visitors.
from datetime import date
PUBLIC_FIELDS = {'dashboard','modules','calendar','tasks','exams','cockpit'}
class PrivacySettings(BaseModel):
    enabled: bool = False
    fields: list[str] = Field(default_factory=list)

@app.on_event('startup')
def init_privacy():
    with connect() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS public_preferences (user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, settings JSONB NOT NULL DEFAULT '{}'::jsonb)")

@app.get('/privacy')
def get_privacy(user_id: int = Depends(auth)):
    with connect() as conn:
        row=conn.execute('SELECT settings FROM public_preferences WHERE user_id=%s',(user_id,)).fetchone()
    data=row[0] if row else {}
    return {'enabled':bool(data.get('enabled',False)),'fields':sorted(set(data.get('fields',[])) & PUBLIC_FIELDS)}

@app.put('/privacy')
def put_privacy(prefs:PrivacySettings,user_id:int=Depends(auth)):
    fields=sorted(set(prefs.fields) & PUBLIC_FIELDS)
    with connect() as conn:
        conn.execute('INSERT INTO public_preferences(user_id,settings) VALUES(%s,%s) ON CONFLICT (user_id) DO UPDATE SET settings=EXCLUDED.settings',(user_id,Jsonb({'enabled':prefs.enabled,'fields':fields})))
    return {'enabled':prefs.enabled,'fields':fields}

def clean_date(v):
    s=str(v or '')[:10]
    try:date.fromisoformat(s);return s
    except (ValueError,TypeError):return None

def safe_minutes(v):
    return float(v) if isinstance(v,(int,float)) and 0<=v<=1440 else 0

@app.get('/public/view')
def public_view():
    with connect() as conn:
        row=conn.execute("""SELECT d.data,p.settings FROM user_data d JOIN users u ON d.user_id=u.id
        LEFT JOIN public_preferences p ON p.user_id=u.id WHERE u.email=%s LIMIT 1""",(OWNER_EMAIL,)).fetchone()
    if not row or not isinstance(row[1],dict) or not row[1].get('enabled'):
        raise HTTPException(404,'Öffentliche Freigabe deaktiviert')
    raw,prefs=row
    fields=set(prefs.get('fields',[])) & PUBLIC_FIELDS
    mods=raw.get('modules',[]) if isinstance(raw,dict) else []
    topics=raw.get('topics',[]) if isinstance(raw,dict) else []
    entries=raw.get('entries',[]) if isinstance(raw,dict) else []
    study=raw.get('study',{}) if isinstance(raw,dict) else {}
    if not isinstance(study,dict):study={}
    r={'fields':sorted(fields),'readonly':True}
    allowed_ids={m.get('id') for m in mods if isinstance(m,dict)}
    if 'modules' in fields:
        r['modules']=[{'id':str(m.get('id',''))[:60], 'name':str(m.get('name','Modul'))[:120],
                        'ects':m.get('ects') if isinstance(m.get('ects'),(int,float)) else None,
                        'self':m.get('self') if isinstance(m.get('self'),(int,float)) else None}
                      for m in mods[:100] if isinstance(m,dict)]
        r['topics']=[{'moduleId':str(t.get('moduleId',''))[:60], 'name':str(t.get('name',''))[:120],
                      'parentId':str(t.get('parentId',''))[:60], 'mastery':max(0,min(5,int(t.get('mastery') or 0)))}
                     for t in topics[:1500] if isinstance(t,dict) and t.get('moduleId') in allowed_ids]
    if 'dashboard' in fields or 'cockpit' in fields:
        usable=[e for e in entries if isinstance(e,dict)]
        total=sum(safe_minutes(e.get('minutes')) for e in usable)
        r['summary']={'hours':round(total/60,1),'sessions':len(usable)}
        r['by_module']=[{'moduleId':str(m.get('id',''))[:60],'name':str(m.get('name','Modul'))[:120],
                         'hours':round(sum(safe_minutes(e.get('minutes')) for e in usable if e.get('moduleId')==m.get('id'))/60,1)}
                       for m in mods if isinstance(m,dict)][:100]
        r['by_day']=[{'date':d,'hours':round(sum(safe_minutes(e.get('minutes')) for e in usable if e.get('date')==d)/60,1)}
                     for d in sorted(set(e.get('date') for e in usable if clean_date(e.get('date'))))][-120:]
    if 'calendar' in fields:
        events=study.get('events',[]) or []
        r['events']=[{'date':clean_date(e.get('date')),'start':str(e.get('start',''))[:5],
                      'end':str(e.get('end',''))[:5],'title':str(e.get('name','Veranstaltung'))[:130],
                      'kind':str(e.get('type','Vorlesung'))[:35]}
                     for e in events[:3000] if isinstance(e,dict) and clean_date(e.get('date'))]
    all_tasks=[t for t in (study.get('tasks',[]) or []) if isinstance(t,dict)]
    if 'tasks' in fields:
        r['tasks']=[{'title':str(t.get('title','Aufgabe'))[:130], 'date':clean_date(t.get('date')),
                     'done':bool(t.get('done',False)), 'moduleId':str(t.get('moduleId',''))[:60]}
                    for t in all_tasks[:1000] if t.get('kind','task')=='task' and clean_date(t.get('date'))]
    if 'exams' in fields:
        r['exams']=[{'title':str(e.get('title','Prüfung'))[:130], 'date':clean_date(e.get('date')),
                     'moduleId':str(e.get('moduleId',''))[:60]}
                    for e in all_tasks[:1000] if e.get('kind')=='exam' and clean_date(e.get('date'))]
    if 'calendar' in fields:
        # Only expose scheduled study blocks when the calendar itself is approved.
        r['study_blocks']=[{'title':str(t.get('title','Lernblock'))[:130], 'date':clean_date(t.get('date'))}
                          for t in all_tasks[:1000] if t.get('kind')=='study' and clean_date(t.get('date'))]
    return r

# Trigger Railway deployment for StudyTracker 2.5
