"""Code-only transactions on an existing Docker container. Never create/remove it."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid

def cli(args, input_text=None):
    p = subprocess.run(['docker'] + args, input=input_text, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
    if p.returncode:
        mismatch = re.search(r'PAUL_RUNTIME_REQUIREMENT: ([A-Za-z0-9_.<>=,-]+)', p.stderr)
        if mismatch:
            raise RuntimeError('Existing runtime cannot satisfy ' + mismatch.group(1) + '; no container replacement performed')
        raise RuntimeError('Existing-container command failed: docker ' + args[0])
    return p.stdout

class Transport:
    def __init__(self, docker, cid):
        self.docker, self.cid = docker, cid

    def copy_out(self, destination):
        destination.mkdir(parents=True, exist_ok=True)
        cli(['cp', '-a', self.cid + ':/app/.', str(destination)])

    def copy_in(self, source):
        cli(['cp', '-a', str(source) + '/.', self.cid + ':/app/'])

    def preflight(self, source, requirements=None, node=False):
        stage = '/tmp/paul-code-check-' + uuid.uuid4().hex
        cli(['exec', self.cid, 'python', '-c', 'import os;os.mkdir(' + repr(stage) + ')'])
        try:
            cli(['cp', str(source) + '/.', self.cid + ':' + stage + '/'])
            # No RF, DB or user-data access; only compile and imports from stage.
            script = '''import ast,os,pathlib,re,sys,threading
folder=pathlib.Path(STAGE)
for p in folder.glob('*.py'): compile(p.read_text(),str(p),'exec')
if REQUIREMENTS:
 try:
  from importlib.metadata import version
 except ImportError:
  from pkg_resources import get_distribution
  version=lambda name:get_distribution(name).version
 for line in REQUIREMENTS.splitlines():
  line=line.strip()
  if not line or line.startswith('#'):continue
  match=re.fullmatch(r'([A-Za-z0-9_.-]+)((?:(?:>=|<=|==|>|<)[0-9.]+)(?:,(?:>=|<=|==|>|<)[0-9.]+)*)',line)
  if not match:raise RuntimeError('Requirement syntax needs explicit runtime review')
  try:installed=version(match.group(1))
  except Exception:raise RuntimeError('PAUL_RUNTIME_REQUIREMENT: '+line)
  def number(v):
   if not re.fullmatch(r'[0-9]+(?:\\.[0-9]+)*',v):raise RuntimeError('Runtime version needs explicit review')
   t=tuple(map(int,v.split('.')));return t+(0,)*(4-len(t))
  actual=number(installed)
  for op,wanted in re.findall(r'(>=|<=|==|>|<)([0-9.]+)',match.group(2)):
   target=number(wanted)
   if not {'>=':actual>=target,'<=':actual<=target,'==':actual==target,'>':actual>target,'<':actual<target}[op]:
    raise RuntimeError('PAUL_RUNTIME_REQUIREMENT: '+line)
if NODE:
 os.environ['DATA_DIR']=str(folder/'unused-data')
 os.environ['COLLECTOR_URL']=''
 os.environ['GATEWAY_EUI']='0000000000000000'
 sys.path.insert(0,str(folder))
 for name in ('node','protocol','rtk','messenger','messenger_web','wifi_agent'):__import__(name)
 t=threading.Thread(target=lambda:None);t.start();t.join()
print('PASS: existing runtime accepts staged application')
'''
            script = 'STAGE=' + repr(stage) + '\nREQUIREMENTS=' + repr(requirements) + '\nNODE=' + repr(node) + '\n' + script
            cli(['exec', '-i', self.cid, 'python', '-'], script)
        finally:
            cli(['exec', self.cid, 'python', '-c', 'import shutil;shutil.rmtree(' + repr(stage) + ',ignore_errors=True)'])

    def cleanup(self, absent):
        # Old code has already been restored and started. Only transaction-owned
        # additions and bytecode for the managed flat /app code are removed.
        script = '''import pathlib
root=pathlib.Path('/app')
for name in ABSENT:
 p=root/name
 if p.is_symlink():raise RuntimeError('Update-owned path became symlink')
 if p.exists():p.unlink()
for p in (root/'__pycache__').glob('*.pyc'):
 if p.is_file() and not p.is_symlink():p.unlink()
'''
        cli(['exec', '-i', self.cid, 'python', '-'], 'ABSENT=' + repr(absent) + '\n' + script)

def fingerprint(d):
    return {'Id': d['Id'], 'Image': d['Image'], 'Name': d['Name'],
            'Config': d['Config'], 'HostConfig': d['HostConfig'],
            # Mount inspection order is not an application setting. Preserve
            # every field and duplicate, but compare the records canonically.
            'Mounts': sorted(d['Mounts'], key=lambda m: json.dumps(m, sort_keys=True))}

class Update:
    def __init__(self, docker, root, health, transport=None, identity=None):
        self.docker, self.root, self.health = docker, Path(root), health
        self.factory, self.identity = transport or Transport, identity
        self.pending = self.root / 'code-transaction.json'

    def inspect(self, tx):
        current = self.docker.inspect(tx['cid'])
        # Older recovery records stored the unsorted inspection array.
        if not current or fingerprint(current) != fingerprint(tx['fingerprint']):
            raise RuntimeError('Container ID/image/name/settings changed; refusing automatic recovery')
        return current

    def recover(self, rollback_committed=False):
        if not self.pending.exists():return
        tx=json.loads(self.pending.read_text())
        if tx.get('schema')!=1:raise RuntimeError('Unknown code transaction')
        self.inspect(tx)
        if tx['phase']=='committed' and not rollback_committed:
            self.finish(tx);return
        if tx['phase']=='prepared':
            # Code was not written. Restore only the prior running state.
            if tx['running']:self.docker.start(tx['cid'])
        else:
            self.docker.stop(tx['cid'])
            source=Path(tx['backup'])/'restore'
            for name,digest in tx['backup_hashes'].items():
                if hashlib.sha256((source/name).read_bytes()).hexdigest()!=digest:
                    raise RuntimeError('Code backup was modified; recovery stopped')
            self.factory(self.docker,tx['cid']).copy_in(source)
            if self.identity:self.identity(tx, True)
            if tx['running']:self.docker.start(tx['cid'])
            self.factory(self.docker,tx['cid']).cleanup(tx['absent'])
            self.health(tx['cid'],None,tx['restart_baseline'])
        self.inspect(tx)
        self.pending.unlink()
        print('ROLLBACK: code restored in the SAME container ' + tx['cid'][:12])

    def finish(self, tx):
        self.inspect(tx)
        # Keep one explicit last-success descriptor for manual code rollback.
        from paul_node import atomic_json
        previous = self.root/'last-code-update.json'
        old = json.loads(previous.read_text()) if previous.exists() else None
        atomic_json(previous,tx)
        self.pending.unlink()
        if old and old.get('backup') != tx['backup']:
            path = Path(old['backup'])
            if path.parent == self.root/'code-backups' and re.fullmatch('[0-9a-f]{32}', path.name) and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)

    def apply(self, cid, payload, version=None, requirements=None, node=False, before_write=None):
        from paul_node import atomic_json
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.recover()
        old=self.docker.inspect(cid)
        if not old or not old['State'].get('Running') or old['State'].get('Restarting'):
            raise RuntimeError('Existing container must be running normally')
        if old['HostConfig'].get('ReadonlyRootfs'):
            raise RuntimeError('Read-only container filesystem; code update needs explicit configuration work')
        if old['HostConfig'].get('AutoRemove'):
            raise RuntimeError('AutoRemove would delete the existing container when stopped')
        if any(m['Destination']=='/app' or m['Destination'].startswith('/app/') for m in old.get('Mounts',[])):
            raise RuntimeError('Mounted application source requires a separate reviewed update path')
        source=Path(payload)
        names=sorted(p.name for p in source.iterdir())
        if not names or any(not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:py|html|js|css|txt)',n) for n in names):
            raise RuntimeError('Code payload contains unsupported paths')
        if any(not (source/n).is_file() or (source/n).is_symlink() for n in names):
            raise RuntimeError('Code payload must contain only regular flat application files')
        adapter=self.factory(self.docker,cid)
        adapter.preflight(source,requirements,node)
        if fingerprint(self.docker.inspect(cid))!=fingerprint(old):
            raise RuntimeError('Container changed during preflight')
        backup=self.root/'code-backups'/uuid.uuid4().hex
        backup.mkdir(parents=True,mode=0o700)
        adapter.copy_out(backup/'app')
        restore=backup/'restore';restore.mkdir(mode=0o700)
        absent=[];hashes={}
        for name in names:
            original=backup/'app'/name
            if original.is_symlink() or (original.exists() and not original.is_file()):
                raise RuntimeError('Managed application path is not a regular file')
            if original.exists():
                shutil.copy2(original,restore/name)
                hashes[name]=hashlib.sha256(original.read_bytes()).hexdigest()
            else:absent.append(name)
        # Remove cached bytecode via a prepared empty /app/__pycache__ cannot
        # erase files with cp. Use source mtimes guaranteed to invalidate caches.
        for name in names:
            p=source/name
            if name.endswith('.py'):
                old_file=backup/'app'/name
                old_time=old_file.stat().st_mtime if old_file.exists() else 0
                os.utime(str(p),(time.time(),max(time.time(),old_time+2)))
        tx={'schema':1,'cid':cid,'fingerprint':fingerprint(old),'phase':'prepared',
            'running':old['State']['Running'],'backup':str(backup),'backup_hashes':hashes,
            'absent':absent,'version':version,'restart_baseline':old.get('RestartCount',0)}
        if self.identity:self.identity(tx,False)
        atomic_json(self.pending,tx)
        try:
            self.docker.stop(cid)
            if before_write:before_write()
            # Last descriptor check while stopped, before any /app mutation.
            self.inspect(tx)
            tx['phase']='writing';atomic_json(self.pending,tx)
            adapter.copy_in(source)
            self.docker.start(cid)
            self.health(cid,version,tx['restart_baseline'])
            self.inspect(tx)
            tx['phase']='committed';atomic_json(self.pending,tx)
        except Exception:
            self.recover();raise
        self.finish(tx)
        print('UPDATED IN PLACE: same container ID ' + cid[:12])
