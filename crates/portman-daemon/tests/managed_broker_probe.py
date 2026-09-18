"""Isolated Linux runtime qualification against a supplied daemon binary.

Uses only temporary state, ephemeral ports, and synthetic credentials.
"""
import hashlib, http.client, http.server, json, os, pathlib, secrets, signal, socket, struct, subprocess, sys, tempfile, threading, time
binary = str(pathlib.Path(sys.argv[1]).resolve())
result = {}
with tempfile.TemporaryDirectory(prefix='portman-u2-state-') as root:
    root = pathlib.Path(root)
    state = root / 'data' / 'portman'
    token = secrets.token_hex(32)
    upstream_key = 'synthetic-upstream-portman-u2-only'
    seen = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(dict(self.headers))
            self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
        def log_message(self, *args): pass
    upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    def free_port():
        with socket.socket() as s: s.bind(('127.0.0.1', 0)); return s.getsockname()[1]
    ports = [free_port() for _ in range(4)]
    args = [binary, '--docker-socket', str(root / 'no-docker.sock'), '--dns-port', str(ports[0]), '--proxy-port', str(ports[1]), '--tls-port', str(ports[2]), '--dashboard-port', str(ports[3])]
    env = {'HOME': str(root), 'XDG_DATA_HOME': str(root / 'data'), 'USER': 'morten', 'PATH': '/usr/bin:/bin', 'RUST_LOG': 'warn'}
    log = open(root / 'daemon.log', 'wb')
    proc = None
    def start():
        global proc
        proc = subprocess.Popen(args + ['--managed-broker'], env=env, stdout=log, stderr=log, start_new_session=True)
        for _ in range(100):
            if proc.poll() is not None: raise RuntimeError('daemon startup failed: ' + (root / 'daemon.log').read_text())
            if (state / 'portman.sock').exists() and (state / 'dashboard-token').exists():
                try:
                    with socket.socket(socket.AF_UNIX) as ready: ready.connect(str(state/'portman.sock'))
                    return
                except OSError: pass
            time.sleep(.1)
        raise RuntimeError('startup timed out')
    def stop():
        global proc
        if proc is not None and proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
        proc = None
    def read_exact(s, n):
        data = b''
        while len(data) < n:
            chunk = s.recv(n-len(data))
            if not chunk: raise RuntimeError('short IPC response')
            data += chunk
        return data
    def ipc(request, auth=True):
        if auth:
            admin = (state / 'dashboard-token').read_text().strip()
            request = {'kind': 'authenticated', 'token': admin, 'request': request}
        raw = json.dumps(request).encode()
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(5); s.connect(str(state / 'portman.sock')); s.sendall(struct.pack('>I', len(raw)) + raw)
            return json.loads(read_exact(s, struct.unpack('>I', read_exact(s, 4))[0]))
    def ok(request):
        response = ipc(request)
        assert response['kind'] == ('sync_report' if request['kind']=='sync_services' else 'ok'), response
    def call(host='qwen.localhost', bearer=None, duplicate=False):
        conn = http.client.HTTPConnection('127.0.0.1', ports[1], timeout=5)
        conn.putrequest('GET', '/v1/models', skip_host=True); conn.putheader('Host', host)
        if bearer is not None: conn.putheader('Authorization', 'Bearer ' + bearer)
        if duplicate: conn.putheader('Authorization', 'Bearer ' + bearer)
        conn.endheaders(); response = conn.getresponse(); status=response.status; response.read(); conn.close(); return status
    def issue(id, expires):
        return ipc({'kind':'issue_egress_grant', 'grant_id':id, 'host':'qwen.localhost', 'token_sha256':hashlib.sha256(token.encode()).hexdigest(), 'expires_at':expires, 'expected_route_revision':route_revision})
    try:
        start()
        status = ipc({'kind':'status'})
        assert status['managed_broker'] is True and status['egress_grants_version'] == 1
        assert ipc({'kind':'status'}, auth=False)['kind'] == 'err'
        assert ipc({'kind':'authenticated','token':token,'request':{'kind':'status'}}, auth=False)['kind'] == 'err'
        result['separate_admin_auth'] = True
        ok({'kind':'set_local_secret','key':'SYNTHETIC_TOKEN','value':upstream_key})
        spec = {'require_caller_token':False,'secrets':'probe','key':'SYNTHETIC_TOKEN','header':'Authorization','format':'Bearer {value}','upstream_host':'localhost','tls':False}
        target = '127.0.0.1:' + str(upstream.server_port)
        routes = {name:{'host':host,'target':target,'spec':spec} for name, host in [('qwen','qwen.localhost'),('alias','alias.localhost')]}
        ok({'kind':'sync_services','root':str(root),'services':[],'secrets':{'probe':{'provider':'local','keys':['SYNTHETIC_TOKEN']}},'egress':routes})
        inventory = ipc({'kind':'list_egress_routes'})
        route_revision = next(r['revision'] for r in inventory['routes'] if r['host']=='qwen.localhost')
        assert target not in json.dumps(inventory) and 'SYNTHETIC_TOKEN' not in json.dumps(inventory)
        wrong_revision = ipc({'kind':'issue_egress_grant', 'grant_id':'wrong-revision', 'host':'qwen.localhost', 'token_sha256':hashlib.sha256(token.encode()).hexdigest(), 'expires_at':int(time.time())+60, 'expected_route_revision':'0'*64})
        assert wrong_revision['kind']=='err'
        result['expected_route_revision_enforced'] = True
        expiry = int(time.time()) + 60
        assert issue('probe-run',expiry)['kind'] == 'ok'
        assert issue('probe-run',expiry)['kind'] == 'ok'
        for kwargs in [{},{'bearer':'wrong-token-0123456789012345678901'},{'bearer':token,'duplicate':True},{'bearer':token,'host':'alias.localhost'}]: assert call(**kwargs)==403
        assert not seen
        result['denied_before_upstream'] = True
        assert call(bearer=token)==200
        assert seen[-1]['Authorization']=='Bearer '+upstream_key and token not in json.dumps(seen)
        result['upstream_injection_without_local_bearer'] = True
        persisted = json.loads((state/'services.json').read_text())
        assert all(item['route']['spec']['require_caller_token'] for item in persisted['egress'].values())
        assert ipc({'kind':'service_up','names':[]})['kind']=='err'
        assert ipc({'kind':'start_service','host':'qwen.localhost'})['kind']=='err'
        assert ipc({'kind':'bridge_enable'})['kind']=='err'
        result['managed_policy_and_start_denial'] = True
        ok({'kind':'revoke_egress_grant','grant_id':'probe-run'})
        assert call(bearer=token)==403
        assert issue('probe-run',expiry)['kind']=='err'
        stop(); start()
        assert call(bearer=token)==403
        result['revocation_survives_restart'] = True
        stop()
        legacy = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        assert legacy.returncode != 0 and b'cannot be opened in legacy mode' in legacy.stdout
        result['legacy_reopen_denied'] = True
        start()
        token = secrets.token_hex(32)
        assert issue('expiry-run', int(time.time())+2)['kind']=='ok'
        assert call(bearer=token)==200
        time.sleep(2.1)
        assert call(bearer=token)==403
        stop(); start()
        assert call(bearer=token)==403
        result['expiry_survives_restart'] = True
        # Fresh bearer to prove persistent rollback denial without changing host time.
        token = secrets.token_hex(32)
        expiry = int(time.time()) + 120
        assert issue('clock-run',expiry)['kind']=='ok'
        assert call(bearer=token)==200
        grant_state = json.loads((state/'egress-grants.json').read_text())
        grant_state['observed_unix']=int(time.time())+300
        (state/'egress-grants.json').write_text(json.dumps(grant_state))
        assert call(bearer=token)==403
        stop(); start()
        assert call(bearer=token)==403
        result['clock_rollback_denied_after_restart'] = True
        stop(); log.flush()
        assert token not in (root/'daemon.log').read_text() and upstream_key not in (root/'daemon.log').read_text()
        result['synthetic_credentials_absent_from_logs'] = True
        result['platform'] = os.uname().sysname + ' ' + os.uname().machine
        print(json.dumps(result, sort_keys=True))
    finally:
        stop(); upstream.shutdown(); upstream.server_close(); log.close()
