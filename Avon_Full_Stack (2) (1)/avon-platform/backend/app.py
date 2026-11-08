import base64, hashlib, hmac, json, os, re, secrets, time
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from .core import Store, MODULES, b64, un64, canonical, digest, password_hash, password_ok, analyze, validate_readings, response_options

class Strict(BaseModel): model_config=ConfigDict(extra='forbid')
class Login(Strict):
    username:str=Field(min_length=1,max_length=64,pattern=r'^[a-zA-Z0-9_.@-]+$')
    password:str=Field(min_length=1,max_length=256)
class Packet(Strict):
    version:Literal[1]
    device_id:str=Field(min_length=1,max_length=64,pattern=r'^[a-zA-Z0-9_-]+$')
    key_id:str=Field(min_length=1,max_length=64)
    collected_at:float=Field(gt=0,allow_inf_nan=False)
    nonce:str=Field(min_length=16,max_length=64,pattern=r'^[a-zA-Z0-9_-]+$')
    readings:dict[str,float]
class Action(Strict):
    action:Literal['acknowledge','assign','note','resolve','escalate','dispatch','work_order','inspect','complete_step','scope']
    value:str=Field(default='',max_length=4000)
class Member(Strict):
    username:str=Field(min_length=3,max_length=64,pattern=r'^[a-zA-Z0-9_.@-]+$')
    name:str=Field(min_length=1,max_length=80)
    module:Literal['eog','northmark','winstead']
    role:Literal['operator','viewer','admin']='operator'
    password:str=Field(min_length=12,max_length=256)
class Toggle(Strict): enabled:bool
class Note(Strict): text:str=Field(min_length=1,max_length=20000)
class Message(Strict):
    key_id:str=Field(pattern=r'^[a-f0-9]{16}$')
    iv:str=Field(min_length=16,max_length=16)
    ciphertext:str=Field(min_length=24,max_length=16000)

FRONT=Path(__file__).resolve().parent.parent/'frontend'

def create_app(directory=None):
    s=Store(directory or os.getenv('AVON_DATA_DIR','data'))
    app=FastAPI(title='Avon connected operations API',version='1.0.0',docs_url=None,redoc_url=None)
    app.state.store=s
    secure=os.getenv('AVON_SECURE_COOKIE','0')=='1'
    allowed=set(os.getenv('AVON_ALLOWED_ORIGINS','http://127.0.0.1:8000,http://localhost:8000').split(','))

    @app.middleware('http')
    async def guard(request, call_next):
        if request.method in ('POST','PUT','PATCH','DELETE'):
            origin=request.headers.get('origin')
            if origin and origin not in allowed: return JSONResponse({'detail':'Origin is not allowed'},403)
            if 'application/json' not in request.headers.get('content-type',''): return JSONResponse({'detail':'JSON content type required'},415)
            try:
                if int(request.headers.get('content-length','0'))>65536: return JSONResponse({'detail':'Body too large'},413)
            except ValueError: return JSONResponse({'detail':'Invalid content length'},400)
            # Bound chunked requests as well as Content-Length requests.
            total=0; chunks=[]
            async for chunk in request.stream():
                total+=len(chunk)
                if total>65536: return JSONResponse({'detail':'Body too large'},413)
                chunks.append(chunk)
            request._body=b''.join(chunks)
        response=await call_next(request)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers['Cache-Control']='no-store'
        if secure: response.headers['Strict-Transport-Security']='max-age=31536000'
        return response

    def auth(request:Request,module:str):
        if module not in MODULES: raise HTTPException(404,'Unknown portal')
        token=request.cookies.get('avon_'+module,'')
        with s.db() as db:
            row=db.execute('SELECT u.username,u.name,u.module,u.role,u.active,se.csrf,se.expires FROM sessions se JOIN users u ON se.username=u.username WHERE token_hash=?',(digest(token),)).fetchone()
        if not row or not row['active'] or row['expires']<time.time() or row['module']!=module: raise HTTPException(401,'Please sign in to this portal')
        user=dict(row)
        if request.method!='GET':
            if not hmac.compare_digest(request.headers.get('x-csrf-token',''),user['csrf']): raise HTTPException(403,'CSRF token missing or invalid')
            if user['role']=='viewer' and request.url.path!='/api/'+module+'/logout': raise HTTPException(403,'This account is read only')
        return user
    def admin(user):
        if user['module']!='winstead' or user['role']!='admin': raise HTTPException(403,'Winstead administrator access required')
    def incident_access(db,id,user):
        r=db.execute('SELECT * FROM incidents WHERE id=? AND module=?',(id,user['module'])).fetchone()
        if not r: raise HTTPException(404,'Incident not found in your portal')
        row=dict(r); row['detail']=s.open(row.pop('body'),id); return row
    def room_access(db,case,user):
        if not db.execute('SELECT 1 FROM incidents WHERE case_id=? AND module=?',(case,user['module'])).fetchone(): raise HTTPException(404,'No case access for this portal')

    @app.get('/api/health')
    def health(): return {'status':'ok','version':'1.0.0'}
    @app.get('/api/verification-key')
    def verification_key(): return {'algorithm':'Ed25519','public_key':s.public_key}
    @app.post('/api/{module}/login')
    def login(module:str,body:Login,request:Request,response:Response):
        if module not in MODULES: raise HTTPException(404,'Unknown portal')
        t=time.time(); username=body.username.lower(); buckets=[module+':'+username,'ip:'+(request.client.host if request.client else 'unknown')]; blocked=False; good=False; user=None
        with s.db() as db:
            for bucket,limit in zip(buckets,[6,40]):
                a=db.execute('SELECT * FROM login_attempts WHERE bucket=?',(bucket,)).fetchone()
                if a and a['since']>t-600 and a['count']>=limit: blocked=True
            if not blocked:
                user=db.execute('SELECT * FROM users WHERE username=? AND module=?',(username,module)).fetchone()
                # Equal password-work cost for unknown accounts.
                stored=user['password'] if user else b64(b'0'*16)+':'+b64(b'0'*64)
                good=password_ok(body.password,stored) and bool(user and user['active'])
                if not good:
                    for bucket in buckets:
                        db.execute('INSERT INTO login_attempts VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=CASE WHEN since<? THEN 1 ELSE count+1 END,since=CASE WHEN since<? THEN excluded.since ELSE since END',(bucket,t,t-600,t-600))
                    s.audit(db,'winstead','anonymous','login.failed',module)
                else:
                    token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(24)
                    old=request.cookies.get('avon_'+module,'')
                    db.execute('DELETE FROM sessions WHERE token_hash=? OR expires<?',(digest(old),t))
                    db.execute('INSERT INTO sessions VALUES(?,?,?,?)',(digest(token),username,csrf,t+8*3600))
                    db.execute('DELETE FROM login_attempts WHERE bucket=?',(buckets[0],))
                    s.audit(db,module,username,'login.succeeded',module)
        if blocked: raise HTTPException(429,'Too many attempts. Try again in 10 minutes.')
        if not good: raise HTTPException(401,'Incorrect credentials for this portal')
        response.set_cookie('avon_'+module,token,httponly=True,secure=secure,samesite='strict',max_age=8*3600,path='/')
        return {'name':user['name'],'module':module,'role':user['role'],'csrf':csrf}

    @app.get('/api/{module}/me')
    def me(module:str,user=Depends(auth)): return {k:user[k] for k in ('username','name','module','role','csrf')}
    @app.post('/api/{module}/logout')
    def logout(module:str,request:Request,response:Response,user=Depends(auth)):
        with s.db() as db:
            db.execute('DELETE FROM sessions WHERE token_hash=?',(digest(request.cookies.get('avon_'+module,'')),))
            s.audit(db,module,user['username'],'logout',module)
        response.delete_cookie('avon_'+module,path='/');return {'ok':True}

    @app.post('/api/telemetry')
    async def ingest(request:Request):
        raw=await request.body()
        try:
            original=json.loads(raw)
            p=Packet.model_validate(original)
            if any(isinstance(v,bool) or not isinstance(v,(int,float)) for v in original.get('readings',{}).values()): raise ValueError('Readings must be numeric')
        except (ValueError,ValidationError): raise HTTPException(422,'Invalid telemetry envelope')
        t=time.time()
        if p.collected_at>t+60 or p.collected_at<t-86400: raise HTTPException(422,'Packet timestamp must be within the last 24 hours; future skew at most 60 seconds')
        with s.db() as db:
            dev=db.execute('SELECT * FROM devices WHERE id=?',(p.device_id,)).fetchone()
            if not dev or not dev['active'] or dev['key_id']!=p.key_id: raise HTTPException(401,'Device or key is not active')
            secret=un64(s.open(dev['secret'],dev['id']))
            signature=hmac.new(secret,raw,hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature,request.headers.get('x-avon-signature','')):
                s.audit(db,'winstead','ingress','telemetry.signature_rejected',dev['id'])
                s.incident(db,'winstead','CASE-'+secrets.token_hex(4).upper(),dev['asset'],'Telemetry integrity failure','High','A request claiming this device failed signature verification. This does not prove the device was compromised.','Inspect gateway logs and validate device key provisioning.')
                db.commit()
                raise HTTPException(401,'Telemetry signature rejected')
            try: validate_readings(dev['module'],original['readings'])
            except ValueError as e: raise HTTPException(422,str(e))
            prior=db.execute('SELECT receipt FROM packets WHERE nonce=?',(p.nonce,)).fetchone()
            if prior:
                receipt=json.loads(prior['receipt'])
                previous=json.loads(un64(receipt['body']))
                if previous['packet_sha256']!=hashlib.sha256(raw).hexdigest(): raise HTTPException(409,'Nonce reused with different data')
                return {'duplicate':True,'receipt':receipt}
            if db.execute("SELECT value FROM settings WHERE key='core_online'").fetchone()['value']=='false': raise HTTPException(503,'Simulated core outage; gateway must queue this packet')
            latest=db.execute('SELECT max(collected) AS t FROM packets WHERE device=?',(p.device_id,)).fetchone()['t'] or 0
            backfill=p.collected_at<t-120 or p.collected_at<latest
            result=analyze(dev['module'],p.readings);result['historical']=backfill
            linked=[]
            if not backfill:
                for alert in result['alerts']:
                    case='CASE-'+secrets.token_hex(4).upper()
                    id=s.incident(db,dev['module'],case,dev['asset'],alert['kind'],alert['severity'],alert['evidence'],alert['next'])
                    case=db.execute('SELECT case_id FROM incidents WHERE id=?',(id,)).fetchone()['case_id'];linked.append(id)
                    if dev['module']=='eog':
                        linked.append(s.incident(db,'northmark',case,dev['asset'],'Edge: '+alert['kind'],alert['severity'],'Authenticated EOG event received. '+alert['evidence'],'Verify packet freshness and coordinate with EOG operator.',linked=True))
                    linked.append(s.incident(db,'winstead',case,dev['asset'],'Review: '+alert['kind'],alert['severity'],'Operational event forwarded through authenticated ingress. A cyber cause is not established. '+alert['evidence'],'Review source integrity, document scope, and coordinate response.',linked=True))
            result['linked_incidents']=linked
            receipt=s.receipt({'nonce':p.nonce,'device_id':p.device_id,'packet_sha256':hashlib.sha256(raw).hexdigest(),'received_at':t,'collected_at':p.collected_at,'result':result})
            db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?,?)',(p.nonce,p.device_id,p.collected_at,t,s.seal(original,p.nonce),s.seal(result,p.nonce+':result'),json.dumps(receipt)))
            s.audit(db,dev['module'],dev['id'],'telemetry.backfill' if backfill else 'telemetry.accepted',p.nonce)
        return {'duplicate':False,'receipt':receipt}

    @app.post('/api/{module}/simulate')
    async def simulate(module:str,body:Note,user=Depends(auth)):
        import httpx
        from .samples import sample
        choices={'eog':('normal','pump_failure','flow_mismatch','sensor_anomaly','sensor_conflict'),'northmark':('normal','cooling')}
        if module not in choices or body.text not in choices[module]: raise HTTPException(422,'Unsupported scenario')
        with s.db() as db:
            dev=db.execute("SELECT * FROM devices WHERE module=? AND source='simulator' AND active=1 LIMIT 1",(module,)).fetchone()
            if not dev: raise HTTPException(409,'Provision an active simulator device first')
            secret=un64(s.open(dev['secret'],dev['id']))
        packet={'version':1,'device_id':dev['id'],'key_id':dev['key_id'],'nonce':secrets.token_hex(16),'collected_at':time.time(),'readings':sample(module,body.text)}
        raw=canonical(packet);signature=hmac.new(secret,raw,hashlib.sha256).hexdigest()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://internal') as client:
            result=await client.post('/api/telemetry',content=raw,headers={'content-type':'application/json','x-avon-signature':signature})
        if result.status_code!=200: raise HTTPException(result.status_code,result.json().get('detail','Ingestion failed'))
        with s.db() as db: s.audit(db,module,user['username'],'simulation.sent',body.text)
        return result.json()

    @app.get('/api/{module}/state')
    def state(module:str,user=Depends(auth)):
        with s.db() as db:
            incidents=[]
            for row in db.execute('SELECT id FROM incidents WHERE module=? ORDER BY created DESC',(module,)):
                incidents.append(incident_access(db,row['id'],user))
            allocated=sum(bool(s.open(r['body'],r['id']).get('dispatched')) for r in db.execute("SELECT id,body FROM incidents WHERE module='eog' AND status!='Resolved'"))
            available=max(0,3-allocated)
            telemetry=[]
            for dev in db.execute('SELECT id,module,asset,source,key_id,active,rotated FROM devices ORDER BY id'):
                if module!='winstead' and dev['module']!=module: continue
                d=dict(dev); row=db.execute('SELECT * FROM packets WHERE device=? ORDER BY collected DESC LIMIT 1',(dev['id'],)).fetchone()
                if row:
                    d.update(collected_at=row['collected'],received_at=row['received'],fresh=time.time()-row['collected']<120)
                    if module!='winstead':
                        d['readings']=s.open(row['payload'],row['nonce'])['readings'];d['analysis']=s.open(row['result'],row['nonce']+':result')
                        history=db.execute('SELECT nonce,collected,payload FROM packets WHERE device=? ORDER BY collected DESC LIMIT 24',(dev['id'],)).fetchall()
                        d['history']=[{'at':h['collected'],'readings':s.open(h['payload'],h['nonce'])['readings']} for h in reversed(history)]
                        if module=='eog': d['plans']=response_options(d['readings'],trucks=available)
                telemetry.append(d)
            audits=[dict(r) for r in db.execute('SELECT * FROM audit '+('' if module=='winstead' else 'WHERE module=? ')+'ORDER BY id DESC LIMIT 60',() if module=='winstead' else (module,))]
            handoffs=[{**{k:r[k] for k in ('id','module','actor','created')},'text':s.open(r['body'],'handoff:'+module)} for r in db.execute('SELECT * FROM handoffs WHERE module=? ORDER BY id DESC LIMIT 5',(module,))]
            result={'module':module,'server_time':time.time(),'core_online':db.execute("SELECT value FROM settings WHERE key='core_online'").fetchone()['value']=='true','incidents':incidents,'telemetry':telemetry,'audit':audits,'handoffs':handoffs,'mode':'Development integration; sensor provenance is shown per device.'}
            if module=='eog': result['available_trucks']=available
            if module=='winstead':
                result['audit_verification']=s.verify_audit(db)
                if user['role']=='admin': result['users']=[dict(r) for r in db.execute('SELECT username,name,module,role,active FROM users')]
            return result

    @app.post('/api/{module}/incidents/{id}/action')
    def action(module:str,id:str,body:Action,user=Depends(auth)):
        with s.db() as db:
            row=incident_access(db,id,user); d=row['detail'];a=body.action;v=body.value.strip()
            if row['status']=='Resolved' and a not in ('note','scope'): raise HTTPException(409,'Incident is already resolved')
            if a=='acknowledge': row['status']='Acknowledged';row['owner']=user['name']
            elif a=='assign':
                if not v or len(v)>100: raise HTTPException(422,'Supply an owner under 100 characters')
                row['owner']=v;row['status']='Assigned'
            elif a=='note':
                if not v: raise HTTPException(422,'Supply a note')
            elif a=='resolve':
                if not v: raise HTTPException(422,'Provide resolution notes')
                row['status']='Resolved';d['next_action']='Review resolution and monitor readings'
            elif a=='scope':
                if module!='winstead' or v not in ('Confirmed','Suspected','Unknown','Locked','Exfiltrated','Contained'): raise HTTPException(422,'Select a supported scope state in Winstead')
                d['scope']=v
            elif a=='escalate': row['status']='Escalated'; row['severity']='Critical';d['next_action']='Supervisor review required'
            elif a=='dispatch':
                if module!='eog' or row['kind']!='Pump failure': raise HTTPException(403,'Dispatch recording is limited to EOG pump failures')
                if d.get('dispatched'): raise HTTPException(409,'A truck is already assigned to this incident')
                used=sum(bool(s.open(r['body'],r['id']).get('dispatched')) for r in db.execute("SELECT id,body FROM incidents WHERE module='eog' AND status!='Resolved'"))
                if used>=3: raise HTTPException(409,'All three demo trucks are allocated')
                d['dispatched']=True;d['next_action']='Recorded truck allocation; confirm dispatch through field operations';row['status']='Assigned'
            elif a=='work_order':
                if module!='northmark': raise HTTPException(403,'Work orders belong to NorthMark')
                d['work_order']='WO-'+id; d['next_action']='Complete '+d['work_order']
            elif a=='inspect': d['next_action']='Inspection requested; awaiting field confirmation'
            elif a=='complete_step':
                if module!='winstead': raise HTTPException(403,'Response playbook belongs to Winstead')
                steps=['Preserve evidence','Validate source','Record containment','Verify recovery','Review and close']
                count=len(d['playbook'])
                if count>=len(steps): raise HTTPException(409,'Playbook complete')
                d['playbook'].append(steps[count]);row['status']='Resolved' if count==4 else ['Triage','Triage','Containment','Recovery'][count]
            d['notes'].append({'at':time.time(),'actor':user['username'],'action':a,'text':v or a})
            db.execute('UPDATE incidents SET severity=?,status=?,owner=?,updated=?,body=? WHERE id=?',(row['severity'],row['status'],row['owner'],time.time(),s.seal(d,id),id))
            s.audit(db,module,user['username'],'incident.'+a,id)
        return {'ok':True}

    @app.post('/api/{module}/core')
    def core(module:str,body:Toggle,user=Depends(auth)):
        if module!='northmark': raise HTTPException(403,'NorthMark controls this simulation')
        with s.db() as db:
            db.execute("UPDATE settings SET value=? WHERE key='core_online'",('true' if body.enabled else 'false',));s.audit(db,module,user['username'],'core.restored' if body.enabled else 'core.outage_simulated','core')
        return {'online':body.enabled}

    @app.post('/api/{module}/users')
    def users(module:str,body:Member,user=Depends(auth)):
        admin(user)
        with s.db() as db:
            if db.execute('SELECT 1 FROM users WHERE username=?',(body.username.lower(),)).fetchone(): raise HTTPException(409,'Username already exists')
            if body.role=='admin' and body.module!='winstead': raise HTTPException(422,'Administrator role is scoped to Winstead')
            db.execute('INSERT INTO users(username,name,module,role,password) VALUES(?,?,?,?,?)',(body.username.lower(),body.name,body.module,body.role,password_hash(body.password)));s.audit(db,module,user['username'],'user.created',body.username.lower())
        return {'ok':True}
    @app.post('/api/{module}/users/{username}/active')
    def active_user(module:str,username:str,body:Toggle,user=Depends(auth)):
        admin(user)
        if username==user['username']: raise HTTPException(409,'Cannot disable your own session')
        with s.db() as db:
            if not db.execute('UPDATE users SET active=? WHERE username=?',(int(body.enabled),username)).rowcount: raise HTTPException(404,'Unknown user')
            db.execute('DELETE FROM sessions WHERE username=?',(username,));s.audit(db,module,user['username'],'user.enabled' if body.enabled else 'user.disabled',username)
        return {'ok':True}
    @app.post('/api/{module}/devices/{id}/active')
    def active_device(module:str,id:str,body:Toggle,user=Depends(auth)):
        admin(user)
        with s.db() as db:
            if not db.execute('UPDATE devices SET active=? WHERE id=?',(int(body.enabled),id)).rowcount: raise HTTPException(404,'Unknown device')
            s.audit(db,module,user['username'],'device.enabled' if body.enabled else 'device.disabled',id)
        return {'ok':True}

    @app.get('/api/{module}/rooms/{case}')
    def get_messages(module:str,case:str,user=Depends(auth)):
        with s.db() as db:
            room_access(db,case,user)
            return [dict(r) for r in db.execute('SELECT * FROM (SELECT * FROM messages WHERE case_id=? ORDER BY id DESC LIMIT 100) ORDER BY id',(case,))]
    @app.post('/api/{module}/rooms/{case}')
    def send_message(module:str,case:str,body:Message,user=Depends(auth)):
        try:
            if len(un64(body.iv))!=12 or len(un64(body.ciphertext))<16: raise ValueError()
        except ValueError: raise HTTPException(422,'Invalid AES-GCM ciphertext or nonce')
        with s.db() as db:
            room_access(db,case,user)
            db.execute('INSERT INTO messages(case_id,sender,created,key_id,iv,ciphertext) VALUES(?,?,?,?,?,?)',(case,user['username'],time.time(),body.key_id,body.iv,body.ciphertext))
            s.audit(db,module,user['username'],'room.ciphertext_posted',case)
        return {'ok':True}
    @app.post('/api/{module}/handoff')
    def handoff(module:str,body:Note,user=Depends(auth)):
        with s.db() as db:
            db.execute('INSERT INTO handoffs(module,actor,created,body) VALUES(?,?,?,?)',(module,user['username'],time.time(),s.seal(body.text,'handoff:'+module)));s.audit(db,module,user['username'],'handoff.saved',module)
        return {'ok':True}

    app.mount('/assets',StaticFiles(directory=FRONT),name='assets')
    @app.get('/')
    def portal(): return FileResponse(FRONT/'index.html')
    @app.get('/login/{module}')
    @app.get('/portal/{module}')
    def shell(module:str):
        if module not in MODULES: raise HTTPException(404)
        return FileResponse(FRONT/'index.html')
    return app
