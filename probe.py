"""Synthetic GitHub OIDC compatibility probe; emits only a fixed result."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import urllib.parse
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def get_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with opener.open(req, timeout=10) as response:
        data = response.read(131073)
    if len(data) > 131072:
        raise ValueError('response limit')
    return json.loads(data)

STAGE = 'setup'

def run():
    global STAGE
    STAGE = 'source'
    source = Path(__file__).with_name('secret_scan_oidc.py').read_bytes()
    if hashlib.sha256(source).hexdigest() != 'df81ba1c5fffe2533738f39bc6b173525f8300d38323db71b8f76e0b2cfecf45':
        raise ValueError('source hash')
    # Dataclasses require a registered module.
    import types, sys
    module = types.ModuleType('synthetic_verifier')
    sys.modules[module.__name__] = module
    exec(compile(source, '<verifier>', 'exec'), module.__dict__)
    del source
    run_id = os.environ['GITHUB_RUN_ID']
    attempt = os.environ['GITHUB_RUN_ATTEMPT']
    repo = os.environ['GITHUB_REPOSITORY']
    if repo != 'ari-wilson/scan-merge-race-synthetic-20261028' or not run_id.isdecimal() or not attempt.isdecimal():
        raise ValueError('scope')
    STAGE = 'job_metadata'
    jobs = get_json(f'https://api.github.com/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100', {'Accept':'application/vnd.github+json','User-Agent':'synthetic-oidc-probe'})
    if jobs.get('total_count') != 1 or len(jobs.get('jobs', [])) != 1:
        raise ValueError('ambiguous jobs')
    job = jobs['jobs'][0]
    if job.get('name') != 'synthetic-oidc-probe' or str(job.get('run_id')) != run_id:
        raise ValueError('job identity')
    check_url = job.get('check_run_url', '')
    match = re.fullmatch(r'https://api\.github\.com/repos/ari-wilson/scan-merge-race-synthetic-20261028/check-runs/([0-9]+)', check_url)
    if not match:
        raise ValueError('check identity')
    STAGE = 'token_request'
    audience = 'synthetic-oidc-' + secrets.token_urlsafe(32)
    STAGE = 'token_endpoint'
    url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in ('pipelines.actions.githubusercontent.com', 'token.actions.githubusercontent.com'):
        if parsed.scheme == 'https' and parsed.hostname == 'vstoken.actions.githubusercontent.com':
            STAGE = 'token_endpoint_vstoken'
        elif (parsed.hostname or '').endswith('.actions.githubusercontent.com'):
            STAGE = 'token_endpoint_githubusercontent'
        else:
            STAGE = 'token_endpoint_other'
        raise ValueError('token endpoint')
    STAGE = 'token_http'
    token_url = url + ('&' if parsed.query else '?') + urllib.parse.urlencode({'audience': audience})
    request_token = os.environ.pop('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
    token = get_json(token_url, {'Authorization': 'bearer ' + request_token})['value']
    del request_token
    STAGE = 'trusted_keys'
    jwks = json.dumps(get_json('https://token.actions.githubusercontent.com/.well-known/jwks')).encode()
    expected = module.ExpectedIdentity(audience, os.environ['GITHUB_REPOSITORY_ID'], os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_WORKFLOW_REF'], os.environ['GITHUB_WORKFLOW_SHA'], run_id, attempt, match.group(1))
    STAGE = 'verification'
    module.verify_token(token, jwks, expected)

try:
    run()
except BaseException:
    print('FAIL:' + STAGE)
    raise SystemExit(1) from None
print('PASS')
