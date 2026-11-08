"""ESP32 serial / JSONL / simulator adapter with encrypted store-and-forward and signed receipts."""
import argparse, hashlib, hmac, json, os, secrets, sqlite3, time, urllib.request, urllib.error
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from backend.core import canonical, b64, un64, analyze, validate_readings
from backend.samples import sample

class Gateway:
    def __init__(self,config,spool):
        self.config=config;self.path=Path(spool);self.path.parent.mkdir(parents=True,exist_ok=True)
        keypath=self.path.with_suffix('.key')
        if not keypath.exists():
            fd=os.open(keypath,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as f: f.write(secrets.token_bytes(32))
        self.aes=AESGCM(keypath.read_bytes())
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS queue (nonce TEXT PRIMARY KEY, body BLOB NOT NULL, signature TEXT NOT NULL, status TEXT NOT NULL, error TEXT NOT NULL, receipt BLOB)')
        os.chmod(self.path,0o600)
        url=config['url']
        from urllib.parse import urlparse
        parsed=urlparse(url)
        if parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','localhost','::1')): raise ValueError('Use HTTPS for non-loopback gateway connections')
        self.key=Ed25519PublicKey.from_public_bytes(un64(config['receipt_public_key']))
    def db(self): return sqlite3.connect(self.path)
    def seal(self,raw):
        iv=secrets.token_bytes(12);return iv+self.aes.encrypt(iv,raw,b'avon-gateway-v1')
    def open(self,raw): return self.aes.decrypt(raw[:12],raw[12:],b'avon-gateway-v1')
    def enqueue(self,readings):
        validate_readings(self.config['module'],readings)
        result=analyze(self.config['module'],readings)
        if self.config['module']=='eog' and 'core_score' in result and 'local_score' not in readings and 'csi_score' not in readings:
            # Reuses deterministic optical rule locally. No independently trained CSI model is implied.
            readings={**readings,'local_score':result['core_score']}
        packet={'version':1,'device_id':self.config['device_id'],'key_id':self.config['key_id'],'nonce':secrets.token_hex(16),'collected_at':time.time(),'readings':readings}
        raw=canonical(packet);signature=hmac.new(un64(self.config['secret']),raw,hashlib.sha256).hexdigest()
        with self.db() as db: db.execute('INSERT INTO queue VALUES(?,?,?,\'pending\',\'\',NULL)',(packet['nonce'],self.seal(raw),signature))
        return result
    def verify_receipt(self,receipt,raw):
        body=un64(receipt['body']);self.key.verify(un64(receipt['signature']),body)
        payload=json.loads(body);packet=json.loads(raw)
        if payload['packet_sha256']!=hashlib.sha256(raw).hexdigest() or payload['nonce']!=packet['nonce'] or payload['device_id']!=packet['device_id']: raise ValueError('Receipt does not match the queued packet')
        return payload
    def flush(self):
        with self.db() as db: rows=db.execute("SELECT nonce,body,signature FROM queue WHERE status='pending' ORDER BY rowid LIMIT 100").fetchall()
        for nonce,ciphertext,signature in rows:
            raw=self.open(ciphertext)
            req=urllib.request.Request(self.config['url'].rstrip('/')+'/api/telemetry',data=raw,headers={'Content-Type':'application/json','X-Avon-Signature':signature},method='POST')
            try:
                with urllib.request.urlopen(req,timeout=8) as response: data=json.load(response)
                self.verify_receipt(data['receipt'],raw)
                with self.db() as db: db.execute("UPDATE queue SET status='delivered',error='',receipt=? WHERE nonce=?",(self.seal(canonical(data['receipt'])),nonce))
            except urllib.error.HTTPError as e:
                status='quarantined' if e.code in (400,401,403,409,422) else 'pending'
                with self.db() as db: db.execute('UPDATE queue SET status=?,error=? WHERE nonce=?',(status,'HTTP '+str(e.code),nonce))
                if status=='pending': break
            except (OSError,ValueError,KeyError) as e:
                with self.db() as db: db.execute('UPDATE queue SET error=? WHERE nonce=?',('Transport or receipt validation failed: '+type(e).__name__,nonce))
                break
            except Exception as e:
                # Invalid signatures and malformed responses never acknowledge a queued packet.
                with self.db() as db: db.execute('UPDATE queue SET error=? WHERE nonce=?',('Receipt not trusted: '+type(e).__name__,nonce))
                break
        with self.db() as db: return dict(db.execute('SELECT status,count(*) FROM queue GROUP BY status').fetchall())

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--spool');p.add_argument('--mode',choices=['simulate','jsonl','serial','flush'],default='simulate');p.add_argument('--scenario',default='normal');p.add_argument('--count',type=int,default=1);p.add_argument('--interval',type=float,default=3);p.add_argument('--input');p.add_argument('--serial-port')
    a=p.parse_args();config=json.loads(Path(a.config).read_text());g=Gateway(config,a.spool or str(Path(a.config).with_suffix('.spool.sqlite')))
    if a.mode=='flush': print(g.flush());return
    allowed=('normal','pump_failure','flow_mismatch','sensor_anomaly','sensor_conflict') if config['module']=='eog' else ('normal','cooling')
    if a.mode=='simulate' and a.scenario not in allowed: p.error('Unsupported scenario for '+config['module'])
    if a.mode=='serial':
        import serial
        source=serial.Serial(a.serial_port,115200,timeout=5)
    elif a.mode=='jsonl': source=open(a.input) if a.input else __import__('sys').stdin
    else: source=None
    i=0
    try:
        while a.count==0 or i<a.count:
            if source:
                line=source.readline()
                if not line:
                    print('Queue:',g.flush())
                    if a.mode=='jsonl': break
                    continue
                try: readings=json.loads(line)
                except ValueError: continue
            else: readings=sample(config['module'],a.scenario,i)
            result=g.enqueue(readings);print('Local rules:',[x['kind'] for x in result['alerts']] or ['normal'],'Queue:',g.flush())
            i+=1
            if not source and (a.count==0 or i<a.count): time.sleep(max(1,a.interval))
    except KeyboardInterrupt: print('Stopped. Pending packets remain in the encrypted spool.')
    finally:
        if source and source is not __import__('sys').stdin: source.close()
if __name__=='__main__': main()
