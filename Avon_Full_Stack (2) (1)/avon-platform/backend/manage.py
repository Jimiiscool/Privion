"""Provision on the server. Secrets are printed only when the operator runs init."""
import argparse, json, os, secrets, re
from pathlib import Path
from .core import Store, b64, password_hash, MODULES

def initialize(directory):
    p=Path(directory); p.mkdir(parents=True,exist_ok=True); os.chmod(p,0o700)
    keys=p/'keys.json'
    if not keys.exists():
        with keys.open('x') as f: json.dump({k:b64(secrets.token_bytes(32)) for k in ('encryption','audit','receipt')},f)
        os.chmod(keys,0o600)
    return Store(p)

def add_user(store, username, name, module, password, role='operator'):
    if module not in MODULES or role not in ('operator','admin','viewer'): raise ValueError('Invalid module or role')
    if len(password)<12: raise ValueError('Passwords must have at least 12 characters')
    with store.db() as db:
        db.execute('INSERT INTO users(username,name,module,role,password) VALUES(?,?,?,?,?)',(username,name,module,role,password_hash(password)))
        store.audit(db,'winstead','provisioner','user.created',username)

def provision_device(store, id, module, asset, source='simulator', url='http://127.0.0.1:8000', rotate=False):
    import time
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',id): raise ValueError('Device ID must contain only letters, digits, underscore or hyphen')
    if module not in ('eog','northmark') or source not in ('simulator','hardware'): raise ValueError('Invalid device type')
    secret=secrets.token_bytes(32); kid=secrets.token_hex(8)
    with store.db() as db:
        if rotate:
            old=db.execute('SELECT * FROM devices WHERE id=?',(id,)).fetchone()
            if not old: raise ValueError('Unknown device')
            module,asset,source=old['module'],old['asset'],old['source']
            db.execute('UPDATE devices SET key_id=?,secret=?,rotated=? WHERE id=?',(kid,store.seal(b64(secret),id),time.time(),id))
        else:
            db.execute('INSERT INTO devices VALUES(?,?,?,?,?,?,1,?)',(id,module,asset,source,kid,store.seal(b64(secret),id),time.time()))
        store.audit(db,'winstead','provisioner','device.key_rotated' if rotate else 'device.registered',id)
    config={'device_id':id,'key_id':kid,'secret':b64(secret),'module':module,'asset':asset,'source':source,'url':url,'receipt_public_key':store.public_key}
    out=store.directory/(id+'.json'); out.write_text(json.dumps(config,indent=2));os.chmod(out,0o600)
    return out

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--data',default=os.getenv('AVON_DATA_DIR','data'))
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('init')
    d=sub.add_parser('device');d.add_argument('id');d.add_argument('--module',choices=['eog','northmark'],default='eog');d.add_argument('--asset',default='S1 / Facility C');d.add_argument('--source',choices=['hardware','simulator'],default='hardware');d.add_argument('--url',default='http://127.0.0.1:8000');d.add_argument('--rotate',action='store_true')
    a=parser.parse_args(); s=initialize(a.data)
    if a.command=='init':
        for module in MODULES:
            with s.db() as db: exists=db.execute('SELECT 1 FROM users WHERE username=?',(module+'.demo',)).fetchone()
            if not exists:
                pw=secrets.token_urlsafe(16);add_user(s,module+'.demo',module.title()+' operator',module,pw,'admin' if module=='winstead' else 'operator')
                print(f'{module}: username={module}.demo password={pw}')
        for id,module,asset in [('eog-sim-01','eog','S1 / Facility C'),('dc-sim-01','northmark','Hall A / Zone 3')]:
            with s.db() as db: exists=db.execute('SELECT 1 FROM devices WHERE id=?',(id,)).fetchone()
            if not exists: print('Provisioned simulator config:',provision_device(s,id,module,asset))
        print('Keep credentials and data/ private. Start with: python -m backend.run')
    else: print('Device configuration written to',provision_device(s,a.id,a.module,a.asset,a.source,a.url,a.rotate))
if __name__=='__main__': main()
