"""HTTP boundaries and report contracts without external provider calls."""
import pytest
from fastapi.testclient import TestClient
import backend.main as api
from backend.schemas import ScanResult

@pytest.fixture(scope="module")
def shared_client():
    # A production ASGI app enters its session-manager lifespan exactly once.
    with TestClient(api.app) as client:
        yield client

@pytest.fixture
def client(monkeypatch, shared_client):
    api.SCANS.clear()
    api.LIMITS.clear()
    api.ACTIVITY.clear()
    async def finish(scan):
        scan.status = 'completed'
        scan.progress = 100
        scan.completed_at = api.now()
    monkeypatch.setattr(api, 'run_scan', finish)
    yield shared_client
    api.SCANS.clear()
    api.LIMITS.clear()

def stored_scan(status='completed'):
    scan = ScanResult(id='test-audit', repository='pallets/flask', created_at=api.now(), status=status)
    api.SCANS[scan.id] = scan
    return scan

@pytest.mark.parametrize('repository', ['https://evil.example/pallets/flask', '../flask', 'https://github.com/pallets/flask/settings', 'owner/repo?token=secret'])
def test_repository_input_cannot_select_arbitrary_hosts(client, repository):
    response = client.post('/api/scans', json={'repository': repository})
    assert response.status_code == 422
    assert not api.SCANS

def test_scan_normalizes_github_url_and_exposes_polling_contract(client):
    response = client.post('/api/scans', json={'repository': 'https://github.com/pallets/flask', 'modules': ['repository']})
    assert response.status_code == 202
    scan = response.json()
    assert scan['repository'] == 'pallets/flask'
    assert scan['status'] == 'running'
    assert client.get('/api/scans/' + scan['id']).status_code == 200
    assert client.get('/api/scans').json()[0]['id'] == scan['id']

@pytest.mark.parametrize('modules', [[], ['shell'], ['repository', 'shell']])
def test_scan_rejects_unsupported_modules(client, modules):
    assert client.post('/api/scans', json={'repository': 'pallets/flask', 'modules': modules}).status_code == 422

def test_export_json_and_html_escape_upstream_text(client):
    scan = stored_scan()
    scan.findings = [{'package': 'example', 'id': 'TEST-1', 'summary': '<script>alert(1)</script>', 'severity': 'UNKNOWN'}]
    exported = client.get('/api/scans/test-audit/export?format=json')
    assert exported.status_code == 200
    assert exported.json()['findings'] == scan.findings
    assert 'attachment' in exported.headers['content-disposition']
    rendered = client.get('/api/scans/test-audit/export?format=html')
    assert rendered.status_code == 200
    assert '<script>alert(1)</script>' not in rendered.text
    assert '&lt;script&gt;' in rendered.text
    assert 'sandbox' in rendered.headers['content-security-policy']
    assert client.get('/api/scans/test-audit/export?format=pdf').status_code == 422

def test_running_and_missing_audits_cannot_be_exported(client):
    stored_scan('running')
    assert client.get('/api/scans/test-audit/export').status_code == 409
    assert client.get('/api/scans/missing').status_code == 404

def test_cross_origin_and_large_requests_are_rejected(client):
    assert client.post('/api/scans', json={'repository': 'pallets/flask'}, headers={'Origin': 'https://evil.example'}).status_code == 403
    assert client.post('/api/scans', content='x' * 200001).status_code == 413

def test_chat_cannot_use_another_repositorys_audit(client, monkeypatch):
    stored_scan()
    async def forbidden(*args, **kwargs):
        pytest.fail('Provider must not be called for mismatched audit context')
    monkeypatch.setattr(api.agent, 'chat', forbidden)
    response = client.post('/api/chat', json={'repository': 'django/django', 'scan_id': 'test-audit', 'message': 'Explain findings'})
    assert response.status_code == 422

def test_scan_budget_is_enforced_before_work(client):
    for _ in range(10):
        # Invalid requests still consume the abuse budget.
        assert client.post('/api/scans', json={'repository': 'bad'}).status_code == 422
    response = client.post('/api/scans', json={'repository': 'pallets/flask'})
    assert response.status_code == 429
    assert response.headers['retry-after'] == '300'

def test_mcp_discovery_resource_prompt_and_tool_allowlist(client):
    catalog = client.get('/api/mcp/discover')
    assert catalog.status_code == 200
    data = catalog.json()
    assert len(data['tools']) == 13
    assert len(data['resources']) == 2
    assert len(data['templates']) == 3
    assert len(data['prompts']) == 3
    assert client.post('/api/mcp/resource', json={'uri': 'repoguard://about'}).status_code == 200
    assert client.post('/api/mcp/prompt', json={'name': 'analyze_repository', 'arguments': {'repository': 'pallets/flask'}}).status_code == 200
    assert client.post('/api/mcp/call', json={'name': 'run_shell', 'arguments': {}}).status_code == 422
    assessment = client.post('/api/mcp/call', json={'name': 'evaluate_release_readiness', 'arguments': {'evidence': {}}})
    assert assessment.status_code == 200
    assert assessment.json()['result']['status'] != 'ready'

@pytest.mark.parametrize('length', ['invalid', '-1'])
def test_malformed_content_length_is_rejected(client, length):
    response = client.post('/api/scans', content='{}', headers={'Content-Length': length})
    assert response.status_code == 400
    assert not api.SCANS

def test_actual_request_size_is_capped_when_length_is_understated(client):
    response = client.post('/api/scans', content='x' * 200001, headers={'Content-Length': '2'})
    assert response.status_code == 413
    assert not api.SCANS


@pytest.mark.parametrize('method', ['GET', 'POST', 'DELETE'])
def test_mcp_endpoint_redirects_both_url_forms(client, method):
    response = client.request(method, '/mcp', follow_redirects=False)
    assert response.status_code == 307
    assert response.headers['location'] == '/mcp/'


def test_hosted_scan_export_survives_empty_worker_memory(client, monkeypatch):
    monkeypatch.setattr(api, 'HOSTED', True)
    monkeypatch.setenv('REPORT_SIGNING_SECRET', 'test-signing-secret-only')
    response = client.post('/api/scans', json={'repository': 'pallets/flask'})
    assert response.status_code == 202
    report = response.json()
    assert report['status'] == 'completed' and report['report_token']
    api.SCANS.clear()
    assert client.get('/api/scans').json() == []
    exported = client.post('/api/reports/export', json={'token': report['report_token'], 'format': 'json'})
    assert exported.status_code == 200
    assert exported.json()['repository'] == 'pallets/flask'
    assert 'report_token' not in exported.json()
    html = client.post('/api/reports/export', json={'token': report['report_token'], 'format': 'html'})
    assert html.status_code == 200 and 'sandbox' in html.headers['content-security-policy']
    tampered = 'x' + report['report_token'][1:]
    assert client.post('/api/reports/export', json={'token': tampered, 'format': 'json'}).status_code == 422


def test_saved_report_chat_survives_worker_change_and_validates_repository(client, monkeypatch):
    from backend.services.receipts import seal
    monkeypatch.setenv('REPORT_SIGNING_SECRET', 'test-signing-secret-only')
    token = seal(stored_scan())
    api.SCANS.clear()
    async def answer(message, repository, history, scan):
        assert scan.id == 'test-audit' and scan.repository == repository
        return {'message': 'Verified saved report', 'executions': [], 'sources': []}
    monkeypatch.setattr(api.agent, 'chat', answer)
    payload = {'repository': 'pallets/flask', 'scan_id': 'test-audit', 'report_token': token, 'message': 'Explain my scan'}
    response = client.post('/api/chat', json=payload)
    assert response.status_code == 200 and response.json()['message'] == 'Verified saved report'
    payload['repository'] = 'django/django'
    assert client.post('/api/chat', json=payload).status_code == 422


def test_signed_report_rejects_another_signing_key(client, monkeypatch):
    from backend.services.receipts import seal
    monkeypatch.setenv('REPORT_SIGNING_SECRET', 'first-test-signing-key')
    token = seal(stored_scan())
    monkeypatch.setenv('REPORT_SIGNING_SECRET', 'different-test-signing-key')
    assert client.post('/api/reports/export', json={'token': token, 'format': 'html'}).status_code == 422


def test_selected_signed_resource_does_not_replace_another_report(client, monkeypatch):
    import json
    from backend.services.receipts import seal
    from backend.mcp_server.server import REPORTS
    monkeypatch.setenv('REPORT_SIGNING_SECRET','test-signing-key-only')
    selected=stored_scan()
    selected.id='selected-report'
    REPORTS['pallets/flask']={'id':'newer-report','repository':'pallets/flask'}
    response=client.post('/api/mcp/resource',json={'uri':'repoguard://repository/pallets/flask/report','report_token':seal(selected)})
    assert response.status_code==200
    assert 'selected-report' in json.dumps(response.json())
    assert REPORTS['pallets/flask']['id']=='newer-report'
    latest=client.post('/api/mcp/resource',json={'uri':'repoguard://repository/pallets/flask/report'})
    assert 'newer-report' in json.dumps(latest.json())
    REPORTS.pop('pallets/flask',None)
