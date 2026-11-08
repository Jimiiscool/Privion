"""Persistence, cryptography and deterministic telemetry analysis. No paid API calls."""
import base64, hashlib, hmac, json, math, os, secrets, sqlite3, time
from contextlib import contextmanager
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

MODULES = ('eog', 'northmark', 'winstead')
def canonical(obj): return json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def b64(b): return base64.b64encode(b).decode()
def un64(s): return base64.b64decode(s, validate=True)
def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def password_hash(password):
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return b64(salt) + ':' + b64(key)
def password_ok(password, stored):
    salt, expected = stored.split(':')
    actual = hashlib.scrypt(password.encode(), salt=un64(salt), n=16384, r=8, p=1)
    return hmac.compare_digest(actual, un64(expected))

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, name TEXT NOT NULL, module TEXT NOT NULL, role TEXT NOT NULL, password TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS login_attempts (bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, since REAL NOT NULL);
CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, module TEXT NOT NULL, asset TEXT NOT NULL, source TEXT NOT NULL, key_id TEXT NOT NULL, secret TEXT NOT NULL, active INTEGER NOT NULL, rotated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS packets (nonce TEXT PRIMARY KEY, device TEXT NOT NULL, collected REAL NOT NULL, received REAL NOT NULL, payload TEXT NOT NULL, result TEXT NOT NULL, receipt TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS packet_device_time ON packets(device, collected);
CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, module TEXT NOT NULL, asset TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL, module TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, sender TEXT NOT NULL, created REAL NOT NULL, key_id TEXT NOT NULL, iv TEXT NOT NULL, ciphertext TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS handoffs (id INTEGER PRIMARY KEY AUTOINCREMENT, module TEXT NOT NULL, actor TEXT NOT NULL, created REAL NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
'''

class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        if not (self.directory/'keys.json').exists():
            raise RuntimeError('Run python -m backend.manage init before starting the server.')
        keys = json.loads((self.directory/'keys.json').read_text())
        self.aes = AESGCM(un64(keys['encryption']))
        self.audit_key = un64(keys['audit'])
        self.signer = Ed25519PrivateKey.from_private_bytes(un64(keys['receipt']))
        self.public_key = b64(self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.path = self.directory/'avon.sqlite'
        with self.db() as db:
            db.executescript(SCHEMA)
            db.execute("INSERT OR IGNORE INTO settings VALUES ('core_online','true')")
        os.chmod(self.path, 0o600)
    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute('PRAGMA foreign_keys=ON')
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('BEGIN IMMEDIATE')
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally: conn.close()
    def seal(self, obj, context):
        nonce = secrets.token_bytes(12)
        return b64(nonce + self.aes.encrypt(nonce, canonical(obj), context.encode()))
    def open(self, value, context):
        raw = un64(value)
        return json.loads(self.aes.decrypt(raw[:12], raw[12:], context.encode()))
    def audit(self, db, module, actor, action, target):
        last = db.execute('SELECT hash FROM audit ORDER BY id DESC LIMIT 1').fetchone()
        fields = dict(timestamp=time.time(), module=module, actor=actor, action=action, target=target, previous=last['hash'] if last else '0'*64)
        tag = hmac.new(self.audit_key, canonical(fields), hashlib.sha256).hexdigest()
        db.execute('INSERT INTO audit(timestamp,module,actor,action,target,previous,hash) VALUES (:timestamp,:module,:actor,:action,:target,:previous,:hash)', {**fields, 'hash':tag})
    def verify_audit(self, db):
        previous = '0'*64; count = 0
        for row in db.execute('SELECT * FROM audit ORDER BY id'):
            r = dict(row); r.pop('id'); tag = r.pop('hash')
            expected = hmac.new(self.audit_key, canonical(r), hashlib.sha256).hexdigest()
            if r['previous'] != previous or not hmac.compare_digest(tag, expected): return {'valid':False,'records':count,'first_invalid_id':row['id']}
            previous=tag; count+=1
        return {'valid':True,'records':count,'head':previous,'scope':'Detects edited chain records; external anchors are needed to detect a removed tail.'}
    def receipt(self, body):
        raw = canonical(body)
        return {'body':b64(raw), 'signature':b64(self.signer.sign(raw)), 'algorithm':'Ed25519'}
    def incident(self, db, module, case, asset, kind, severity, evidence, next_action, linked=False):
        old = db.execute("SELECT id FROM incidents WHERE module=? AND asset=? AND kind=? AND status!='Resolved'",(module,asset,kind)).fetchone()
        if linked:
            old = db.execute("SELECT id FROM incidents WHERE module=? AND case_id=? AND asset=? AND kind=?", (module,case,asset,kind)).fetchone()
        if old: return old['id']
        id = module.upper()[:3]+'-'+secrets.token_hex(3).upper()
        body = {'evidence':evidence,'next_action':next_action,'scope':'Unknown','notes':[], 'playbook':[], 'origin':'telemetry'}
        t=time.time()
        db.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?)',(id,case,module,asset,kind,severity,'Open','Unassigned',t,t,self.seal(body,id)))
        self.audit(db,module,'rules-engine','incident.created',id)
        return id

EOG_BOUNDS = {'tank_pct':(0,100),'capacity_bbl':(1,1000000),'inflow_bph':(0,100000),'pump_bph':(0,100000),'received_bph':(0,100000),'pressure_psi':(0,20000),'oil_bph':(0,100000),'gas_mcfph':(0,100000),'laser_raw':(0,4095),'water_raw':(0,4095),'ir_raw':(0,4095),'vibration_g':(0,20),'ambient_c':(-40,85),'humidity_pct':(0,100),'local_score':(0,1),'csi_score':(0,1)}
DC_BOUNDS = {'temperature_c':(-40,120),'humidity_pct':(0,100),'facility_kw':(0,1000000),'it_kw':(0,1000000),'facility_kwh':(0,100000000),'it_kwh':(0,100000000),'water_liters':(0,100000000),'period_seconds':(1,86400)}
def validate_readings(module, readings):
    bounds = EOG_BOUNDS if module=='eog' else DC_BOUNDS
    if not readings or len(readings)>30: raise ValueError('Supply between 1 and 30 readings.')
    for k,v in readings.items():
        if k not in bounds or isinstance(v,bool) or not isinstance(v,(int,float)) or not math.isfinite(v): raise ValueError('Unknown or non-finite reading: '+k)
        lo,hi=bounds[k]
        if not lo<=v<=hi: raise ValueError('Reading outside allowed range: '+k)

def analyze(module,r):
    result={'method':'Deterministic rules v1; scores are heuristic, not calibrated probabilities.','alerts':[]}
    if module=='eog':
        if all(k in r for k in ('tank_pct','capacity_bbl','inflow_bph','pump_bph')):
            net=r['inflow_bph']-r['pump_bph']; remaining=max(0,(90-r['tank_pct'])/100*r['capacity_bbl'])
            result.update(shutdown_minutes=round(remaining/net*60,1) if net>0 else None,net_inflow_bph=round(net,2),tank_volume_bbl=round(r['tank_pct']/100*r['capacity_bbl'],1))
            if r['pump_bph']<1 and r['inflow_bph']>0: result['alerts'].append({'kind':'Pump failure','severity':'Critical','evidence':'Pump flow below 1 bbl/hr while inflow remains positive. Tank estimate uses remaining barrel capacity divided by net inflow.','next':'Review response costs; assign a field inspection.'})
            if r['tank_pct']>=90: result['alerts'].append({'kind':'Shutdown threshold','severity':'Critical','evidence':'Tank is at or above the configured 90% threshold. No physical command is sent by this app.','next':'Follow site shutdown procedure and verify readings.'})
        if r.get('pump_bph',0)>10 and 'received_bph' in r and (r['pump_bph']-r['received_bph'])/r['pump_bph']>.15:
            result['alerts'].append({'kind':'Flow mismatch','severity':'High','evidence':'Receiving flow is more than 15% below pumped flow. A leak is suspected, not confirmed.','next':'Inspect pipeline and validate both flow meters.'})
        if 'laser_raw' in r and 'ir_raw' in r:
            core=round(((1-r['laser_raw']/4095)+r['ir_raw']/4095)/2,3)
            local=r.get('local_score',r.get('csi_score'))
            result.update(core_score=core,local_score=local,fusion='Core only' if local is None else 'Agreement: anomaly' if core>=.65 and local>=.65 else 'Agreement: normal' if core<.65 and local<.65 else 'Disagreement: inspect')
            if core>=.65 or (local is not None and local>=.65): result['alerts'].append({'kind':'Sensor anomaly review','severity':'Warning','evidence':f'Optical heuristic {core}; local score {local}. These sensors do not confirm oil contamination.','next':'Check calibration and inspect the sample; compare local and core readings.'})
    else:
        if r.get('it_kwh',0)>0 and 'facility_kwh' in r and 'period_seconds' in r:
            result['pue']=round(r['facility_kwh']/r['it_kwh'],3)
            if 'water_liters' in r: result['wue_l_per_kwh']=round(r['water_liters']/r['it_kwh'],3)
        if r.get('temperature_c',0)>27: result['alerts'].append({'kind':'Cooling temperature high','severity':'High','evidence':f"Temperature {r['temperature_c']}°C exceeds the 27°C demo threshold.",'next':'Assign cooling team; inspect airflow and cooling equipment.'})
        if result.get('pue',0)>1.5: result['alerts'].append({'kind':'Energy efficiency warning','severity':'Warning','evidence':f"PUE {result['pue']} exceeds configured demo target 1.5.",'next':'Review IT load, facility load and reporting period.'})
        if result.get('wue_l_per_kwh',0)>2: result['alerts'].append({'kind':'Water use warning','severity':'Warning','evidence':'Water use exceeds 2 L/kWh in the reported period.','next':'Inspect cooling water loop and validate meter.'})
    return result

def response_options(readings, repair_hours=6, arrival_minutes=75, trip_cost=905, capacity=150, cycle_minutes=90, trucks=3):
    """Compare explicit candidate schedules at 1 minute resolution, not a global optimizer."""
    if not all(k in readings for k in ('tank_pct','capacity_bbl','inflow_bph','pump_bph','oil_bph','gas_mcfph')): return []
    if readings['pump_bph'] >= 1 or readings['inflow_bph'] <= 0: return []
    hourly=readings['oil_bph']*70+readings['gas_mcfph']*2.5
    candidates=[]
    for name,n,reduce in [('Do nothing',0,0),('Shut in 50% of wells',0,.5),('One truck',min(trucks,1),0),('One truck + 50% shut-in',min(trucks,1),.5),('All available trucks',trucks,0)]:
        level=readings['tank_pct']/100*readings['capacity_bbl']; loss=0; trips=0; tripped=False; peak=level
        for minute in range(int(repair_hours*60)):
            if n and minute>=arrival_minutes and (minute-arrival_minutes)%cycle_minutes==0:
                level=max(0,level-capacity*n); trips+=n
            if level>=readings['capacity_bbl']*.9: tripped=True
            lost=1 if tripped else reduce
            loss+=hourly*lost/60
            if not tripped: level+=readings['inflow_bph']*(1-reduce)/60-readings['pump_bph']/60
            level=max(0,level);peak=max(peak,level)
            if level>=readings['capacity_bbl']*.9: tripped=True
        candidates.append({'plan':name,'cost':round(loss+trips*trip_cost,2),'trips':trips,'avoids_shutdown':not tripped,'peak_pct':round(peak/readings['capacity_bbl']*100,1),'trucks':n})
    return sorted(candidates,key=lambda x:(not x['avoids_shutdown'],x['cost']))
