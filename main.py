import os
import secrets
import hashlib
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
app.add_middleware(CORSMiddleware, allow_origins=[FRONTEND_ORIGIN], allow_methods=['GET','POST','PUT','DELETE'], allow_headers=['Authorization','Content-Type'])
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
    return jwt.encode({'sub': str(user_id), 'iat': now, 'exp': now + timedelta(hours=24)}, JWT_SECRET, algorithm='HS256')

def auth(authorization: str | None = Header(default=None)) -> int:
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(401, 'Anmeldung erforderlich')
    try:
        token = authorization.split(' ', 1)[1]
        claims = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = int(claims['sub'])
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        with connect() as conn:
            revoked = conn.execute('SELECT 1 FROM revoked_auth_tokens WHERE token_hash=%s AND expires_at > NOW()', (token_hash,)).fetchone()
        if revoked:
            raise HTTPException(401, 'Sitzung wurde abgemeldet')
        return user_id
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

# Brute-force protection for the single authorized account.
# Keep a transactional row lock so concurrent attempts cannot bypass the limit.
AUTH_LIMIT = 5
AUTH_WINDOW = timedelta(minutes=15)

@app.on_event('startup')
def init_auth_security():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS auth_login_limits (
            login_hash TEXT PRIMARY KEY,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            window_started TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS revoked_auth_tokens (
            token_hash TEXT PRIMARY KEY,
            expires_at TIMESTAMPTZ NOT NULL
        )""")

@app.post('/auth/login')
def login(payload: Credentials):
    email = payload.email.lower().strip()
    # This application has one account. Do not create limiter rows for arbitrary emails.
    if email != OWNER_EMAIL:
        raise HTTPException(401, 'E-Mail oder Passwort falsch')
    login_hash = hashlib.sha256((JWT_SECRET + ':' + email).encode('utf-8')).hexdigest()
    denied = False
    authenticated_id = None
    with connect() as conn:
        conn.execute('INSERT INTO auth_login_limits(login_hash) VALUES(%s) ON CONFLICT DO NOTHING', (login_hash,))
        attempts, started = conn.execute(
            'SELECT failed_attempts,window_started FROM auth_login_limits WHERE login_hash=%s FOR UPDATE',
            (login_hash,)
        ).fetchone()
        now = datetime.now(timezone.utc)
        if now - started >= AUTH_WINDOW:
            attempts = 0
            conn.execute('UPDATE auth_login_limits SET failed_attempts=0,window_started=%s WHERE login_hash=%s', (now, login_hash))
        if attempts >= AUTH_LIMIT:
            denied = True
        else:
            row = conn.execute('SELECT id,password_hash FROM users WHERE email=%s', (email,)).fetchone()
            if row and hasher.verify(payload.password, row[1]):
                authenticated_id = row[0]
                conn.execute('DELETE FROM auth_login_limits WHERE login_hash=%s', (login_hash,))
                conn.execute('DELETE FROM revoked_auth_tokens WHERE expires_at <= NOW()')
            else:
                conn.execute('UPDATE auth_login_limits SET failed_attempts=failed_attempts+1 WHERE login_hash=%s', (login_hash,))
    if denied:
        raise HTTPException(429, 'Zu viele Anmeldeversuche. Bitte in 15 Minuten erneut versuchen.', headers={'Retry-After':'900'})
    if authenticated_id is None:
        raise HTTPException(401, 'E-Mail oder Passwort falsch')
    return {'token':login_token(authenticated_id)}

@app.post('/auth/logout')
def logout(authorization: str | None = Header(default=None), user_id: int = Depends(auth)):
    token = authorization.split(' ', 1)[1]
    claims = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    digest = hashlib.sha256(token.encode('utf-8')).hexdigest()
    expiry = datetime.fromtimestamp(int(claims['exp']), tz=timezone.utc)
    with connect() as conn:
        conn.execute(
            'INSERT INTO revoked_auth_tokens(token_hash,expires_at) VALUES(%s,%s) ON CONFLICT (token_hash) DO NOTHING',
            (digest, expiry)
        )
    return {'logged_out':True}

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
    # Semester workload is stored in study.modules, not in the editable module list.
    # Publish only the numeric handbook totals and public module labels.
    if 'cockpit' in fields and 'modules' in fields:
        handbook = study.get('modules', []) or []
        if not isinstance(handbook, list):
            handbook = []
        r['workload'] = [
            {'moduleId': str(x.get('localId') or '')[:60],
             'name': str(x.get('name') or 'Modul')[:120],
             'ects': x.get('ects') if isinstance(x.get('ects'), (int, float)) else None,
             'total': x.get('total') if isinstance(x.get('total'), (int, float)) else None,
             'presence': x.get('presence') if isinstance(x.get('presence'), (int, float)) else None,
             'self': x.get('self') if isinstance(x.get('self'), (int, float)) else None}
            for x in handbook[:100] if isinstance(x, dict)
        ]
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
        # Learning totals do not implicitly disclose module titles. They require the modules permission.
        if 'modules' in fields:
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


# StudyTracker 3.0: private file storage with large-PDF streaming
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
from pydantic import field_validator
import io
import re
from uuid import uuid4, UUID

# Files above the legacy PostgreSQL limit are streamed into the private object bucket.
# Existing BYTEA files remain readable and are not migrated automatically.
from tempfile import SpooledTemporaryFile
from starlette.concurrency import run_in_threadpool
from botocore.config import Config
from boto3.s3.transfer import TransferConfig
import boto3

MAX_PRIVATE_FILE = int(os.getenv('MAX_PRIVATE_FILE_MB','125')) * 1024 * 1024
MAX_PRIVATE_TOTAL = int(os.getenv('MAX_PRIVATE_TOTAL_MB','1024')) * 1024 * 1024
S3_ENDPOINT = os.environ.get('STORAGE_ENDPOINT','')
S3_BUCKET = os.environ.get('STORAGE_BUCKET','')
S3_REGION = os.environ.get('STORAGE_REGION','auto')
S3_ACCESS_KEY = os.environ.get('STORAGE_ACCESS_KEY_ID','')
S3_SECRET_KEY = os.environ.get('STORAGE_SECRET_ACCESS_KEY','')
def bucket_client():
    if not all([S3_ENDPOINT,S3_BUCKET,S3_ACCESS_KEY,S3_SECRET_KEY]):
        raise HTTPException(503,'Dateispeicher vorübergehend nicht konfiguriert')
    return boto3.client('s3',endpoint_url=S3_ENDPOINT,region_name=S3_REGION,
        aws_access_key_id=S3_ACCESS_KEY,aws_secret_access_key=S3_SECRET_KEY,
        config=Config(signature_version='s3v4',s3={'addressing_style':'virtual'},retries={'max_attempts':3}))

ALLOWED_EXTENSIONS = {'.pdf','.txt','.csv','.png','.jpg','.jpeg','.webp','.xlsx','.xls','.docx','.pptx','.step','.stp','.stl'}
class FolderInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    parent_id: str | None = None

class AnnotationInput(BaseModel):
    data: dict[str, Any]
    revision: int = Field(ge=0)

@app.on_event('startup')
def init_private_documents():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS private_folders(
            id UUID PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            parent_id UUID REFERENCES private_folders(id) ON DELETE RESTRICT,
            name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
        conn.execute("""CREATE TABLE IF NOT EXISTS private_documents(
            id UUID PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            folder_id UUID REFERENCES private_folders(id) ON DELETE SET NULL,
            filename TEXT NOT NULL, mime TEXT NOT NULL, bytes BYTEA NOT NULL,
            size_bytes INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
        conn.execute("""CREATE TABLE IF NOT EXISTS private_document_notes(
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            document_id UUID NOT NULL REFERENCES private_documents(id) ON DELETE CASCADE,
            data JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY(user_id, document_id))""")
        conn.execute('CREATE INDEX IF NOT EXISTS private_folders_owner_idx ON private_folders(user_id,parent_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS private_documents_owner_idx ON private_documents(user_id,folder_id)')
        conn.execute('ALTER TABLE private_document_notes ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0')
        conn.execute('ALTER TABLE private_documents ADD COLUMN IF NOT EXISTS storage_key TEXT')

def checked_uuid(value: str | None):
    if value is None: return None
    try: return str(UUID(value))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(422, 'Ungültige Kennung')

def folder_exists(conn, owner, id):
    id = checked_uuid(id)
    if id is None: return True
    return bool(conn.execute('SELECT 1 FROM private_folders WHERE id=%s AND user_id=%s',(id,owner)).fetchone())

def valid_filename(name):
    name=name.strip()
    if not name or len(name)>200 or '/' in name or '\\' in name or any(ord(c)<32 for c in name):
        raise HTTPException(422,'Ungültiger Dateiname')
    ext=os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS: raise HTTPException(415,'Dateityp nicht erlaubt')
    return name,ext

@app.get('/private/folders')
def list_private_folders(user_id:int=Depends(auth)):
    with connect() as conn:
        rows=conn.execute('SELECT id,parent_id,name FROM private_folders WHERE user_id=%s ORDER BY name',(user_id,)).fetchall()
    return [{'id':str(a),'parent_id':str(b) if b else None,'name':c} for a,b,c in rows]

@app.post('/private/folders')
def create_private_folder(payload:FolderInput,user_id:int=Depends(auth)):
    name=payload.name.strip()
    if not name or '/' in name or '\\' in name: raise HTTPException(422,'Ungültiger Ordnername')
    parent_id=checked_uuid(payload.parent_id)
    with connect() as conn:
        if not folder_exists(conn,user_id,parent_id): raise HTTPException(404,'Überordner nicht gefunden')
        new_id=str(uuid4())
        conn.execute('INSERT INTO private_folders(id,user_id,parent_id,name) VALUES(%s,%s,%s,%s)',(new_id,user_id,parent_id,name))
    return {'id':new_id,'name':name,'parent_id':parent_id}

@app.delete('/private/folders/{folder_id}')
def delete_private_folder(folder_id:str,user_id:int=Depends(auth)):
    folder_id=checked_uuid(folder_id)
    with connect() as conn:
        row=conn.execute('SELECT 1 FROM private_folders WHERE id=%s AND user_id=%s',(folder_id,user_id)).fetchone()
        if not row: raise HTTPException(404,'Ordner nicht gefunden')
        if conn.execute('SELECT 1 FROM private_folders WHERE parent_id=%s LIMIT 1',(folder_id,)).fetchone() or conn.execute('SELECT 1 FROM private_documents WHERE folder_id=%s LIMIT 1',(folder_id,)).fetchone():
            raise HTTPException(409,'Ordner ist nicht leer')
        conn.execute('DELETE FROM private_folders WHERE id=%s AND user_id=%s',(folder_id,user_id))
    return {'deleted':True}

@app.get('/private/documents')
def list_private_documents(folder_id:str|None=None,user_id:int=Depends(auth)):
    with connect() as conn:
        folder_id=checked_uuid(folder_id)
        if not folder_exists(conn,user_id,folder_id):raise HTTPException(404,'Ordner nicht gefunden')
        rows=conn.execute('SELECT id,folder_id,filename,mime,size_bytes,created_at FROM private_documents WHERE user_id=%s AND folder_id IS NOT DISTINCT FROM %s::uuid ORDER BY filename',(user_id,folder_id)).fetchall()
    return [{'id':str(i),'folder_id':str(f) if f else None,'filename':n,'mime':m,'size':size,'created_at':created.isoformat()} for i,f,n,m,size,created in rows]

@app.post('/private/documents')
async def upload_private_document(request:Request,filename:str,folder_id:str|None=None,user_id:int=Depends(auth)):
    filename,ext=valid_filename(filename)
    folder_id=checked_uuid(folder_id)
    if request.headers.get('content-length') and int(request.headers['content-length'])>MAX_PRIVATE_FILE:
        raise HTTPException(413,'Datei zu groß (Limit: '+str(MAX_PRIVATE_FILE//1048576)+' MB)')
    with connect() as conn:
        if not folder_exists(conn,user_id,folder_id):raise HTTPException(404,'Ordner nicht gefunden')
    temp=SpooledTemporaryFile(max_size=4*1024*1024)
    size=0
    try:
        async for chunk in request.stream():
            size+=len(chunk)
            if size>MAX_PRIVATE_FILE:raise HTTPException(413,'Datei zu groß (Limit: '+str(MAX_PRIVATE_FILE//1048576)+' MB)')
            temp.write(chunk)
        if not size:raise HTTPException(422,'Datei leer')
        if ext=='.pdf':
            temp.seek(0)
            if not temp.read(1024).lstrip().startswith(b'%PDF-'):raise HTTPException(415,'Ungültiges PDF')
        temp.seek(0)
        doc_id=str(uuid4())
        key='owners/'+str(user_id)+'/documents/'+doc_id
        mime='application/pdf' if ext=='.pdf' else 'application/octet-stream'
        client=bucket_client()
        try:
            await run_in_threadpool(client.upload_fileobj,temp,S3_BUCKET,key,
                ExtraArgs={'ContentType':mime},Config=TransferConfig(
                    multipart_threshold=8*1024*1024,multipart_chunksize=8*1024*1024,
                    max_concurrency=2))
        except Exception:
            raise HTTPException(502,'Cloud-Upload fehlgeschlagen. Bitte erneut versuchen.')
        try:
            with connect() as conn:
                conn.execute('SELECT pg_advisory_xact_lock(%s)',(user_id,))
                current_bytes=conn.execute('SELECT COALESCE(SUM(size_bytes),0) FROM private_documents WHERE user_id=%s',(user_id,)).fetchone()[0]
                if current_bytes+size>MAX_PRIVATE_TOTAL:
                    raise HTTPException(413,'Speicherplatz voll (Limit: '+str(MAX_PRIVATE_TOTAL//1048576)+' MB)')
                conn.execute('INSERT INTO private_documents(id,user_id,folder_id,filename,mime,bytes,size_bytes,storage_key) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',(doc_id,user_id,folder_id,filename,mime,b'',size,key))
        except Exception:
            await run_in_threadpool(client.delete_object,Bucket=S3_BUCKET,Key=key)
            raise
        return {'id':doc_id,'filename':filename,'size':size,'folder_id':folder_id}
    finally:
        temp.close()

@app.get('/private/documents/{doc_id}')
def download_private_document(doc_id:str,user_id:int=Depends(auth)):
    doc_id=checked_uuid(doc_id)
    with connect() as conn:
        row=conn.execute('SELECT filename,mime,bytes,size_bytes,storage_key FROM private_documents WHERE id=%s AND user_id=%s',(doc_id,user_id)).fetchone()
    if not row:raise HTTPException(404,'Datei nicht gefunden')
    name,mime,data,size,key=row
    from urllib.parse import quote
    headers={'Content-Disposition':"attachment; filename*=UTF-8''"+quote(name),
        'X-Content-Type-Options':'nosniff','Cache-Control':'no-store',
        'Content-Length':str(size),'Accept-Ranges':'none'}
    if not key:
        return Response(content=bytes(data),media_type=mime,headers=headers)
    try:
        response=bucket_client().get_object(Bucket=S3_BUCKET,Key=key)
    except Exception:
        raise HTTPException(502,'Datei ist vorübergehend nicht aus dem privaten Speicher abrufbar')
    stream=response['Body']
    def chunks():
        try:
            for chunk in stream.iter_chunks(chunk_size=1024*1024):
                if chunk:yield chunk
        finally:stream.close()
    return StreamingResponse(chunks(),media_type=mime,headers=headers)

@app.delete('/private/documents/{doc_id}')
def delete_private_document(doc_id:str,user_id:int=Depends(auth)):
    doc_id=checked_uuid(doc_id)
    with connect() as conn:
        row=conn.execute('DELETE FROM private_documents WHERE id=%s AND user_id=%s RETURNING storage_key',(doc_id,user_id)).fetchone()
        if not row:raise HTTPException(404,'Datei nicht gefunden')
    if row[0]:
        try:bucket_client().delete_object(Bucket=S3_BUCKET,Key=row[0])
        except Exception:pass  # The owner has lost access in the DB; storage garbage collection can be retried.
    return {'deleted':True}

@app.get('/private/documents/{doc_id}/notes')
def private_document_notes(doc_id:str,user_id:int=Depends(auth)):
    doc_id=checked_uuid(doc_id)
    with connect() as conn:
        found=conn.execute('SELECT 1 FROM private_documents WHERE id=%s AND user_id=%s',(doc_id,user_id)).fetchone()
        if not found:raise HTTPException(404,'Datei nicht gefunden')
        row=conn.execute('SELECT data, revision FROM private_document_notes WHERE document_id=%s AND user_id=%s',(doc_id,user_id)).fetchone()
    return {'data':row[0] if row else {'pages':{}}, 'revision':row[1] if row else 0}

@app.put('/private/documents/{doc_id}/notes')
def save_private_document_notes(doc_id:str,payload:AnnotationInput,user_id:int=Depends(auth)):
    doc_id=checked_uuid(doc_id)
    if len(str(payload.data))>250_000:raise HTTPException(413,'Anmerkungen zu umfangreich')
    with connect() as conn:
        found=conn.execute('SELECT 1 FROM private_documents WHERE id=%s AND user_id=%s',(doc_id,user_id)).fetchone()
        if not found:raise HTTPException(404,'Datei nicht gefunden')
        conn.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',(doc_id,))
        row=conn.execute('SELECT revision FROM private_document_notes WHERE user_id=%s AND document_id=%s FOR UPDATE',(user_id,doc_id)).fetchone()
        actual=row[0] if row else 0
        if actual!=payload.revision:
            raise HTTPException(409,'Neuere Anmerkungen vorhanden: Bitte Dokument erneut laden')
        if row:
            conn.execute('UPDATE private_document_notes SET data=%s,revision=revision+1,updated_at=NOW() WHERE user_id=%s AND document_id=%s',(Jsonb(payload.data),user_id,doc_id))
        else:
            conn.execute('INSERT INTO private_document_notes(user_id,document_id,data,revision) VALUES(%s,%s,%s,1)',(user_id,doc_id,Jsonb(payload.data)))
    return {'saved':True,'revision':actual+1}


class FolderChange(BaseModel):
    name: str | None = None
    parent_id: str | None = None

class DocumentChange(BaseModel):
    filename: str | None = None
    folder_id: str | None = None

def valid_folder_name(value):
    name=value.strip()
    if not name or len(name)>120 or '/' in name or '\\' in name or any(ord(c)<32 for c in name):
        raise HTTPException(422,'Ungültiger Ordnername')
    return name

@app.put('/private/folders/{folder_id}')
def rename_or_move_folder(folder_id:str, payload:FolderChange,user_id:int=Depends(auth)):
    folder_id=checked_uuid(folder_id)
    updates=payload.model_fields_set
    if not updates or updates-{'name','parent_id'}:raise HTTPException(422,'Keine Änderungen')
    with connect() as conn:
        row=conn.execute('SELECT name,parent_id FROM private_folders WHERE id=%s AND user_id=%s',(folder_id,user_id)).fetchone()
        if not row:raise HTTPException(404,'Ordner nicht gefunden')
        name=valid_folder_name(payload.name) if 'name' in updates and payload.name is not None else row[0]
        parent=checked_uuid(payload.parent_id) if 'parent_id' in updates else (str(row[1]) if row[1] else None)
        if not folder_exists(conn,user_id,parent):raise HTTPException(404,'Zielordner nicht gefunden')
        if parent==folder_id:raise HTTPException(409,'Ein Ordner kann nicht in sich selbst verschoben werden')
        cursor=parent
        while cursor is not None:
            found=conn.execute('SELECT parent_id FROM private_folders WHERE id=%s AND user_id=%s',(cursor,user_id)).fetchone()
            if not found:raise HTTPException(404,'Zielordner nicht gefunden')
            cursor=str(found[0]) if found[0] else None
            if cursor==folder_id:raise HTTPException(409,'Ein Ordner kann nicht in einen Unterordner verschoben werden')
        conn.execute('UPDATE private_folders SET name=%s,parent_id=%s WHERE id=%s AND user_id=%s',(name,parent,folder_id,user_id))
    return {'id':folder_id,'name':name,'parent_id':parent}

@app.put('/private/documents/{doc_id}')
def rename_or_move_document(doc_id:str,payload:DocumentChange,user_id:int=Depends(auth)):
    doc_id=checked_uuid(doc_id)
    updates=payload.model_fields_set
    if not updates or updates-{'filename','folder_id'}:raise HTTPException(422,'Keine Änderungen')
    with connect() as conn:
        row=conn.execute('SELECT filename,folder_id FROM private_documents WHERE id=%s AND user_id=%s',(doc_id,user_id)).fetchone()
        if not row:raise HTTPException(404,'Datei nicht gefunden')
        name=valid_filename(payload.filename)[0] if 'filename' in updates and payload.filename is not None else row[0]
        # Forbid changing file type by renaming: it would undermine type checks.
        if os.path.splitext(name)[1].lower()!=os.path.splitext(row[0])[1].lower():
            raise HTTPException(422,'Dateiendung darf nicht geändert werden')
        parent=checked_uuid(payload.folder_id) if 'folder_id' in updates else (str(row[1]) if row[1] else None)
        if not folder_exists(conn,user_id,parent):raise HTTPException(404,'Zielordner nicht gefunden')
        conn.execute('UPDATE private_documents SET filename=%s,folder_id=%s WHERE id=%s AND user_id=%s',(name,parent,doc_id,user_id))
    return {'id':doc_id,'filename':name,'folder_id':parent}

@app.get('/private/storage')
def private_storage(user_id:int=Depends(auth)):
    with connect() as conn:
        used,count=conn.execute('SELECT COALESCE(SUM(size_bytes),0),COUNT(*) FROM private_documents WHERE user_id=%s',(user_id,)).fetchone()
        directories=conn.execute('SELECT COUNT(*) FROM private_folders WHERE user_id=%s',(user_id,)).fetchone()[0]
    return {'used_bytes':int(used),'quota_bytes':MAX_PRIVATE_TOTAL,'file_count':count,'folder_count':directories}
