#!/usr/bin/env python3
"""Run real, offline acceptance checks against a HeaderLens executable.

Only loopback servers are used. No source or user projects are modified.
Requires Python >=3.9 and OpenSSL. Writes reports only to a NEW --out directory.
A pass applies only to these checks on the recorded platform, not all software.
"""
import argparse
import concurrent.futures
import copy
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

P = argparse.ArgumentParser(description=__doc__)
P.add_argument('--binary', required=True, type=Path)
P.add_argument('--source', required=True, type=Path)
P.add_argument('--out', required=True, type=Path)
P.add_argument('--expected-version', default='0.1.21-rc11')
A = P.parse_args()
BIN = A.binary.resolve(); SRC = A.source.resolve(); OUT = A.out.resolve()
if not BIN.is_file() or not (SRC/'tools/verify_evidence_v15.py').is_file():
    P.error('binary or source verifier not found')
if not shutil.which('openssl'):
    P.error('OpenSSL is required for positive AND negative TLS tests')
OUT.mkdir(parents=True, exist_ok=False)
SECRET='HL_ACCEPTANCE_SYNTHETIC_COOKIE_7e32'
AUTH='HL_ACCEPTANCE_SYNTHETIC_AUTH_c42b'
REDIRECT_SECRET='HL_ACCEPTANCE_SYNTHETIC_REDIRECT_91df'
FIXED_DATE='Sun, 11 Oct 2026 12:00:00 GMT'

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args): pass
    def date_time_string(self,*args): return FIXED_DATE
    def do_GET(self):
        path=self.path.split('?',1)[0]
        with self.server.count_lock:
            self.server.counts[path]=self.server.counts.get(path,0)+1
        try:
            if path == '/slow': time.sleep(0.6)
            if path == '/early':
                self.wfile.write(('HTTP/1.1 103 Early Hints\r\nSet-Cookie: hint='+SECRET+'\r\nWWW-Authenticate: Bearer '+AUTH+'\r\n\r\n').encode())
                self.wfile.flush()
            status=302 if path in ('/redirect','/same-redirect') else 200
            self.send_response(status)
            self.send_header('Content-Length','0')
            self.send_header('Connection','close')
            self.send_header('Content-Type','text/html; charset=utf-8')
            if path == '/redirect':
                self.send_header('Location',self.server.destination+'/landed?token='+REDIRECT_SECRET)
            elif path == '/same-redirect':
                self.send_header('Location','/good?token='+REDIRECT_SECRET)
            elif path == '/large': self.send_header('X-Large','Z'*16384)
            if path != '/bad':
                self.send_header('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'")
                self.send_header('X-Content-Type-Options','nosniff')
                self.send_header('Referrer-Policy','no-referrer')
                self.send_header('X-Frame-Options','DENY')
            if isinstance(self.connection,ssl.SSLSocket):
                self.send_header('Strict-Transport-Security','max-age=31536000')
            cookie='session='+SECRET+'; Path=/'
            if path != '/bad': cookie+='; Secure; HttpOnly; SameSite=Strict'
            self.send_header('Set-Cookie',cookie)
            self.send_header('WWW-Authenticate','Bearer '+AUTH)
            self.end_headers()
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError): pass

class Server(http.server.ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=64
    def __init__(self,address):
        self.counts={}; self.count_lock=threading.Lock(); self.destination=''
        super().__init__(address,Handler)
    def handle_error(self,*args): pass

class Acceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch=tempfile.TemporaryDirectory(prefix='headerlens-selftest-')
        cls.tmp=Path(cls.scratch.name)
        cls.servers=[]; cls.threads=[]; cls.records=[]; cls.rec_lock=threading.Lock()
        # Keys are ephemeral synthetic test material, never written to --out.
        conf=cls.tmp/'leaf.cnf'
        conf.write_text('[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        commands=[
          ['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','90','-subj','/CN=HeaderLens local acceptance CA','-addext','basicConstraints=critical,CA:TRUE'],
          ['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout','leaf.key','-out','leaf.csr','-config','leaf.cnf'],
          ['openssl','x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','leaf.pem','-days','90','-extfile','leaf.cnf','-extensions','ext']]
        for i,cmd in enumerate(commands):
            r=subprocess.run(cmd,cwd=cls.tmp,capture_output=True,timeout=20)
            (OUT/f'certificate-setup-{i}.log').write_bytes(r.stdout+r.stderr)
            if r.returncode: raise RuntimeError('OpenSSL fixture setup failed')
        (cls.tmp/'empty-trust-dir').mkdir()
        cls.trust={'SSL_CERT_FILE':str(cls.tmp/'ca.pem'),'SSL_CERT_DIR':str(cls.tmp/'empty-trust-dir')}
        cls.first=cls.start_server(('127.0.0.1',0))
        cls.second=cls.start_server(('127.0.0.1',0))
        cls.tls=cls.start_server(('127.0.0.1',0),tls=True)
        cls.http=f'http://127.0.0.1:{cls.first.server_port}'
        cls.https=f'https://localhost:{cls.tls.server_port}'
        cls.first.destination=f'http://127.0.0.1:{cls.second.server_port}'
    @classmethod
    def start_server(cls,address,tls=False,ipv6=False):
        srvtype=Server
        if ipv6:
            class IPv6(Server): address_family=socket.AF_INET6
            srvtype=IPv6
        s=srvtype(address)
        if tls:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version=ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cls.tmp/'leaf.pem',cls.tmp/'leaf.key')
            s.socket=ctx.wrap_socket(s.socket,server_side=True)
        t=threading.Thread(target=s.serve_forever,daemon=True);t.start()
        cls.servers.append(s);cls.threads.append(t)
        return s
    @classmethod
    def tearDownClass(cls):
        for s in cls.servers: s.shutdown();s.server_close()
        for t in cls.threads: t.join(timeout=2)
        (OUT/'commands.json').write_text(json.dumps(cls.records,indent=2)+'\n')
        cls.scratch.cleanup()
    def call(self,name,args,expected=0,env=None):
        e=os.environ.copy()
        for k in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','SSL_CERT_FILE','SSL_CERT_DIR']:
            e.pop(k,None)
        e['NO_PROXY']='*'; e['PYTHONDONTWRITEBYTECODE']='1'
        if env: e.update(env)
        started=time.monotonic()
        r=subprocess.run([str(BIN),*args],capture_output=True,timeout=12,env=e)
        (OUT/(name+'.stdout')).write_bytes(r.stdout)
        (OUT/(name+'.stderr')).write_bytes(r.stderr)
        with self.rec_lock:
            self.records.append({'name':name,'args':args,'exit_code':r.returncode,'expected_exit':expected,'duration_seconds':round(time.monotonic()-started,4)})
        self.assertEqual(r.returncode,expected,name+': unexpected exit: '+r.stderr.decode(errors='replace'))
        return r
    def report(self,name,url,opts=None,env=None):
        r=self.call(name,['-json',*(opts or []),url],env=env)
        obj=json.loads(r.stdout)
        self.assertEqual(obj['schema_version'],'headerlens.result/v15')
        self.assertEqual(obj['tool_version'],A.expected_version)
        (OUT/(name+'.json')).write_bytes(r.stdout)
        return obj
    def verify(self,name,obj,expected=0):
        path=OUT/(name+'.json');path.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
        r=subprocess.run([sys.executable,'-B',str(SRC/'tools/verify_evidence_v15.py'),str(path)],capture_output=True,timeout=10)
        (OUT/(name+'.verify.log')).write_bytes(r.stdout+r.stderr)
        self.assertEqual(r.returncode,expected)
    def test_01_missing_security_controls_are_detected(self):
        obj=self.report('01-insecure',self.http+'/bad')
        f={x['id']:x['severity'] for x in obj['findings']}
        for key in ['HL-CSP-001','HL-XCTO-002','HL-FRAME-002','HL-REF-001','HL-COOKIE-SECURE-SESSION']:
            self.assertEqual(f.get(key),'WARN',key)
        self.assertIn('HL-COOKIE-HTTPONLY-SESSION',f)
        self.assertIn('HL-COOKIE-SAMESITE-SESSION',f)
        self.verify('01-insecure-verified',obj)
    def test_02_hardened_https_controls_are_recognized(self):
        obj=self.report('02-hardened',self.https+'/good',env=self.trust)
        self.assertTrue(obj['tls_verification']['verified'])
        f={x['id']:x['severity'] for x in obj['findings']}
        for key in ['HL-HSTS-002','HL-XCTO-001','HL-FRAME-001','HL-REF-003']:
            self.assertEqual(f.get(key),'PASS',key)
        self.assertFalse([x for x in obj['findings'] if x['severity'] in ('WARN','FAIL')])
        self.assertEqual(f.get('HL-CSP-002'),'INFO') # Partial CSP is not a general security PASS.
        self.verify('02-hardened-verified',obj)
    def test_03_cookie_and_auth_redaction(self):
        obj=self.report('03-private',self.http+'/bad')
        text=json.dumps(obj)
        self.assertNotIn(SECRET,text);self.assertNotIn(AUTH,text)
        self.assertTrue(obj['headers_redacted'])
    def test_04_sensitive_capture_requires_explicit_optin(self):
        obj=self.report('04-optin',self.http+'/bad',['-include-sensitive-headers'])
        self.assertIn(SECRET,json.dumps(obj));self.assertIn(AUTH,json.dumps(obj))
        self.assertFalse(obj['headers_redacted'])
    def test_05_cross_port_redirect_is_blocked(self):
        with self.second.count_lock: before=self.second.counts.get('/landed',0)
        obj=self.report('05-blocked',self.http+'/redirect')
        self.assertEqual(obj['status_code'],302);self.assertTrue(obj.get('redirect_blocked'))
        with self.second.count_lock: self.assertEqual(self.second.counts.get('/landed',0),before)
        self.assertNotIn(REDIRECT_SECRET,json.dumps(obj))
    def test_06_authorized_cross_port_redirect_is_followed(self):
        with self.second.count_lock: before=self.second.counts.get('/landed',0)
        obj=self.report('06-followed',self.http+'/redirect',['-allow-cross-port-redirects'])
        self.assertEqual(obj['status_code'],200)
        self.assertEqual(len(obj['redirect_responses']),1)
        with self.second.count_lock: self.assertEqual(self.second.counts.get('/landed',0),before+1)
        self.assertNotIn(REDIRECT_SECRET,json.dumps(obj))
        self.verify('06-followed-verified',obj)
    def test_07_untrusted_certificate_is_not_trusted(self):
        obj=self.report('07-untrusted',self.https+'/good')
        self.assertFalse(obj['tls_verification']['verified'])
        self.assertEqual(obj['tls_verification']['error_kind'],'unknown_authority')
        self.assertTrue(any(x['id']=='HL-CERT-005' and x['severity']=='FAIL' for x in obj['findings']))
        self.verify('07-untrusted-verified',obj)
    def test_08_timeout_terminates_without_report(self):
        r=self.call('08-timeout',['-json','-timeout','100ms',self.http+'/slow'],expected=1)
        self.assertEqual(r.stdout,b'');self.assertNotIn(SECRET,r.stderr.decode())
    def test_09_large_headers_rejected_without_echo(self):
        r=self.call('09-large',['-json','-max-header-bytes','1024',self.http+'/large'],expected=1)
        self.assertEqual(r.stdout,b'');self.assertNotIn('ZZZZ',r.stderr.decode())
    def test_10_invalid_flags_and_unsafe_urls(self):
        cases=[(['-unknown-private-option'],2),(['-timeout','0s',self.http],2),(['-json','http://name:private@127.0.0.1'],1),(['-json',self.http+'/#private'],1),(['-json','file:///private'],1)]
        for i,(args,code) in enumerate(cases):
            with self.subTest(case=i):
                r=self.call('10-invalid-'+str(i),args,expected=code)
                self.assertEqual(r.stdout,b'')
                self.assertNotIn('name:private',r.stderr.decode())
    def test_11_concurrent_runs_have_equal_observation_hashes(self):
        def job(i):return self.report('11-concurrent-'+str(i),self.http+'/good')
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex: docs=list(ex.map(job,range(12)))
        self.assertEqual(len({d['evidence_sha256'] for d in docs}),1)
        for d in docs:self.assertEqual(d['status_code'],200)
    def test_12_modified_observation_is_detected(self):
        obj=self.report('12-original',self.http+'/good');changed=copy.deepcopy(obj);changed['status_code']=201
        self.verify('12-tampered',changed,expected=1)
    def test_13_derived_findings_are_not_authenticated_by_hash(self):
        obj=self.report('13-original',self.http+'/good');obj['findings']=[]
        self.verify('13-unbound-findings',obj,expected=0) # Documented limitation, not a signature.
    def test_14_informational_headers_are_recorded_and_redacted(self):
        obj=self.report('14-early',self.http+'/early')
        self.assertEqual(obj['status_code'],200)
        self.assertEqual(len(obj['interim_responses']),1)
        self.assertEqual(obj['interim_responses'][0]['status_code'],103)
        self.assertNotIn(SECRET,json.dumps(obj));self.assertNotIn(AUTH,json.dumps(obj))
        self.verify('14-early-verified',obj)
    def test_15_ipv6_loopback(self):
        s=self.start_server(('::1',0),ipv6=True)
        obj=self.report('15-ipv6',f'http://[::1]:{s.server_port}/good')
        self.assertEqual(obj['status_code'],200)
    def test_16_output_failure_is_not_success(self):
        if sys.platform != 'linux':
            self.skipTest('/dev/full writer-failure check is Linux-specific')
        with open('/dev/full','wb') as out:
            r=subprocess.run([str(BIN),'-json',self.http+'/good'],stdout=out,stderr=subprocess.PIPE,timeout=12)
        (OUT/'16-writer-error.stderr').write_bytes(r.stderr)
        self.assertEqual(r.returncode,1)

start=datetime.datetime.now(datetime.timezone.utc).isoformat()
r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Acceptance))
summary={'started_utc':start,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'binary_sha256':hashlib.sha256(BIN.read_bytes()).hexdigest(),'platform':sys.platform,'python':sys.version,'tests_run':r.testsRun,'failures':len(r.failures),'errors':len(r.errors),'skipped':len(r.skipped),'status':'PASS' if r.wasSuccessful() and not r.skipped else 'FAIL_OR_INCOMPLETE','scope':'Observed behavior in these loopback-only scenarios; not a general security guarantee or a stable release approval.'}
(OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
raise SystemExit(0 if summary['status']=='PASS' else 1)
