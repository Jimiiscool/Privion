import json, tempfile, time, unittest, secrets, hashlib, hmac
from pathlib import Path
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from backend.manage import initialize, add_user, provision_device
from backend.app import create_app
from backend.core import canonical, b64, un64, analyze
from backend.samples import sample
from gateway import Gateway

class SystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name);self.store=initialize(self.path)
        for m in ('eog','northmark','winstead'): add_user(self.store,m,m,m,'test-password-long-123','admin' if m=='winstead' else 'operator')
        self.config=json.loads(provision_device(self.store,'sensor-1','eog','Facility C').read_text())
        self.client=TestClient(create_app(self.path));self.tokens={}
        for m in ('eog','northmark','winstead'):
            r=self.client.post('/api/'+m+'/login',json={'username':m,'password':'test-password-long-123'});self.assertEqual(r.status_code,200,r.text);self.tokens[m]=r.json()['csrf']
    def tearDown(self):self.client.close();self.tmp.cleanup()
    def post(self,m,path,body):return self.client.post('/api/'+m+path,json=body,headers={'X-CSRF-Token':self.tokens[m]})
    def packet(self,changes=None):
        p={'version':1,'device_id':self.config['device_id'],'key_id':self.config['key_id'],'collected_at':time.time(),'nonce':secrets.token_hex(16),'readings':sample('eog','pump_failure')};p.update(changes or {});return p
    def send(self,p,signature=None):
        raw=canonical(p);sig=signature or hmac.new(un64(self.config['secret']),raw,hashlib.sha256).hexdigest()
        return self.client.post('/api/telemetry',content=raw,headers={'Content-Type':'application/json','X-Avon-Signature':sig})
    def test_portal_auth_and_csrf(self):
        c=TestClient(create_app(self.path));self.assertEqual(c.post('/api/eog/login',json={'username':'eog','password':'test-password-long-123'}).status_code,200)
        self.assertEqual(c.get('/api/northmark/state').status_code,401)
        self.assertEqual(c.post('/api/northmark/login',json={'username':'eog','password':'test-password-long-123'}).status_code,401)
        self.assertEqual(self.client.post('/api/eog/handoff',json={'text':'x'}).status_code,403)
        self.assertEqual(self.post('eog','/core',{'enabled':False}).status_code,403)
        self.assertEqual(c.post('/api/eog/login',json={'username':'eog','password':'x'},headers={'Origin':'https://evil.example'}).status_code,403)
    def test_signature_idempotence_receipt_and_cases(self):
        p=self.packet();r=self.send(p);self.assertEqual(r.status_code,200,r.text);receipt=r.json()['receipt']
        Ed25519PublicKey.from_public_bytes(un64(self.store.public_key)).verify(un64(receipt['signature']),un64(receipt['body']))
        self.assertTrue(self.send(p).json()['duplicate']);p['readings']['tank_pct']=60;self.assertEqual(self.send(p).status_code,409)
        cases=[]
        for m in ('eog','northmark','winstead'):
            items=self.client.get('/api/'+m+'/state').json()['incidents'];self.assertEqual(len(items),1);cases.append(items[0]['case_id'])
        self.assertEqual(len(set(cases)),1)
        self.assertEqual(self.send(self.packet(),signature='0'*64).status_code,401)
        self.assertTrue(any(i['kind']=='Telemetry integrity failure' for i in self.client.get('/api/winstead/state').json()['incidents']))
    def test_simulation_and_recurrent_case_correlation(self):
        r=self.post('eog','/simulate',{'text':'pump_failure'});self.assertEqual(r.status_code,200,r.text)
        initial=self.client.get('/api/eog/state').json()['incidents'][0]
        self.assertEqual(self.post('eog','/incidents/'+initial['id']+'/action',{'action':'resolve','value':'Repair confirmed'}).status_code,200)
        self.assertEqual(self.post('eog','/simulate',{'text':'pump_failure'}).status_code,200)
        primary=self.client.get('/api/eog/state').json()['incidents'][0]
        self.assertNotEqual(primary['case_id'],initial['case_id'])
        for m in ('northmark','winstead'):
            cases=self.client.get('/api/'+m+'/state').json()['incidents']
            self.assertTrue(any(i['case_id']==primary['case_id'] for i in cases))

    def test_countdown_and_historical_data(self):
        self.assertEqual(analyze('eog',sample('eog','pump_failure'))['shutdown_minutes'],268.8)
        self.assertEqual(self.send(self.packet({'collected_at':time.time()+120})).status_code,422)
        self.assertEqual(self.send(self.packet({'collected_at':time.time()-3600})).status_code,200)
        self.assertEqual(self.client.get('/api/eog/state').json()['incidents'],[])
    def test_actions_storage_and_tamper_detection(self):
        self.send(self.packet());id=self.client.get('/api/eog/state').json()['incidents'][0]['id']
        self.assertEqual(self.post('northmark','/incidents/'+id+'/action',{'action':'resolve','value':'x'}).status_code,404)
        self.assertEqual(self.post('eog','/incidents/'+id+'/action',{'action':'dispatch'}).status_code,200)
        self.assertEqual(self.post('eog','/incidents/'+id+'/action',{'action':'dispatch'}).status_code,409)
        self.assertEqual(self.post('eog','/handoff',{'text':'Sensitive field note'}).status_code,200)
        c=TestClient(create_app(self.path));c.cookies.update(self.client.cookies);self.assertEqual(c.get('/api/eog/state').json()['handoffs'][0]['text'],'Sensitive field note')
        with self.store.db() as db:
            self.assertNotIn('Sensitive',db.execute('SELECT body FROM handoffs').fetchone()['body']);self.assertTrue(self.store.verify_audit(db)['valid']);db.execute("UPDATE audit SET action='edited' WHERE id=1")
        self.assertFalse(self.client.get('/api/winstead/state').json()['audit_verification']['valid'])
    def test_end_to_end_encrypted_room(self):
        self.send(self.packet());case=self.client.get('/api/eog/state').json()['incidents'][0]['case_id'];key=AESGCM.generate_key(256);kid=hashlib.sha256(key).hexdigest()[:16];iv=secrets.token_bytes(12);aad=f'avon-room-v1|{case}|{kid}|eog'.encode();ct=AESGCM(key).encrypt(iv,b'Confidential room message',aad)
        self.assertEqual(self.post('eog','/rooms/'+case,{'key_id':kid,'iv':b64(iv),'ciphertext':b64(ct)}).status_code,200)
        r=self.client.get('/api/northmark/rooms/'+case);msg=r.json()[0]
        self.assertEqual(AESGCM(key).decrypt(un64(msg['iv']),un64(msg['ciphertext']),aad),b'Confidential room message');self.assertNotIn('Confidential',r.text)
        self.assertEqual(self.client.get('/api/eog/rooms/unrelated').status_code,404)
    def test_viewer_revocation_and_key_rotation(self):
        self.assertEqual(self.post('winstead','/users',{'username':'read.only','name':'Viewer','module':'eog','role':'viewer','password':'long-password-for-viewer'}).status_code,200)
        c=TestClient(create_app(self.path));v=c.post('/api/eog/login',json={'username':'read.only','password':'long-password-for-viewer'}).json()
        self.assertEqual(c.get('/api/eog/state').status_code,200);self.assertEqual(c.post('/api/eog/handoff',json={'text':'x'},headers={'X-CSRF-Token':v['csrf']}).status_code,403)
        self.assertEqual(c.post('/api/eog/logout',json={},headers={'X-CSRF-Token':v['csrf']}).status_code,200)
        c.post('/api/eog/login',json={'username':'read.only','password':'long-password-for-viewer'})
        self.post('winstead','/users/read.only/active',{'enabled':False});self.assertEqual(c.get('/api/eog/state').status_code,401)
        old=self.packet();path=provision_device(self.store,'sensor-1','eog','Facility C',rotate=True);self.assertEqual(self.send(old).status_code,401)
        self.config=json.loads(path.read_text());self.assertEqual(self.send(self.packet()).status_code,200)
    def test_gateway_flush_recovers_after_outage(self):
        from unittest.mock import patch
        from urllib.error import HTTPError
        from io import BytesIO
        def transport(req,timeout=8):
            r=self.client.post('/api/telemetry',content=req.data,headers=dict(req.header_items()))
            if r.status_code>=400: raise HTTPError(req.full_url,r.status_code,r.text,{},None)
            return BytesIO(r.content)
        g=Gateway(self.config,self.path/'offline.sqlite')
        g.enqueue(sample('eog','pump_failure'))
        with patch('urllib.request.urlopen',side_effect=transport):
            self.post('northmark','/core',{'enabled':False})
            self.assertEqual(g.flush(),{'pending':1})
            self.post('northmark','/core',{'enabled':True})
            self.assertEqual(g.flush(),{'delivered':1})
            self.assertEqual(g.flush(),{'delivered':1})
        self.assertEqual(len(self.client.get('/api/eog/state').json()['incidents']),1)

    def test_lockout_outage_spool_and_receipt_trust(self):
        c=TestClient(create_app(self.path))
        for _ in range(6):self.assertEqual(c.post('/api/eog/login',json={'username':'missing','password':'wrong'}).status_code,401)
        self.assertEqual(c.post('/api/eog/login',json={'username':'missing','password':'wrong'}).status_code,429)
        g=Gateway(self.config,self.path/'spool.sqlite');g.enqueue(sample('eog','pump_failure'))
        with g.db() as db:rawenc=db.execute('SELECT body FROM queue').fetchone()[0]
        self.assertNotIn(b'tank_pct',rawenc);raw=g.open(rawenc);p=json.loads(raw)
        self.post('northmark','/core',{'enabled':False});self.assertEqual(self.send(p).status_code,503)
        self.post('northmark','/core',{'enabled':True});receipt=self.send(p).json()['receipt'];self.assertEqual(g.verify_receipt(receipt,raw)['nonce'],p['nonce'])
        receipt['signature']=b64(b'0'*64)
        with self.assertRaises(Exception):g.verify_receipt(receipt,raw)
if __name__=='__main__':unittest.main()
