"""URL convenience must not relax the trusted GitHub provider boundary."""
import httpx
import pytest
from backend.integrations.github import normalize_repository
from backend.integrations import http

@pytest.mark.parametrize('value', [
 'pallets/flask', ' Pallets/Flask ', 'https://github.com/pallets/flask',
 'https://github.com/pallets/flask.git/', 'http://github.com/pallets/flask',
 'github.com/pallets/flask', 'www.github.com/pallets/flask',
 'https://WWW.GITHUB.COM/Pallets/Flask?tab=readme-ov-file#readme',
 'git@github.com:pallets/flask.git',
 'https://github.com/pallets/flask/tree/main/examples/tutorial',
 'https://github.com/pallets/flask/blob/main/README.md',
 'https://github.com/pallets/flask/issues/1',
 'https://github.com/pallets/flask/pull/2',
 'https://github.com/pallets/flask/actions',
 'https://github.com/pallets/flask/releases/tag/3.0',
])
def test_supported_repository_link_forms(value):
    assert normalize_repository(value) == 'pallets/flask'

@pytest.mark.parametrize('value', [
 'https://github.com', 'https://github.com/pallets',
 'https://github.com.evil.example/pallets/flask',
 'https://github.com@evil.example/pallets/flask',
 'https://evil.example@github.com/pallets/flask',
 'https://github.com:443/pallets/flask',
 'https://github.com/pallets/flask/../../evil',
 'https://github.com/pallets/%2e%2e',
 'https://github.com/pallets/flask/settings',
 'https://gist.github.com/pallets/flask',
 'owner/repo?token=secret', 'owner/repo/more',
])
def test_invalid_or_non_repository_links(value):
    with pytest.raises(ValueError):
        normalize_repository(value)

@pytest.fixture
def mock_provider(monkeypatch):
    http._CACHE.clear()
    original = httpx.AsyncClient
    def install(handler):
        monkeypatch.setattr(http.httpx, 'AsyncClient', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    return install

async def test_renamed_repository_redirect_stays_on_trusted_host(mock_provider):
    calls=[]
    def handler(request):
        calls.append(request)
        if request.url.path == '/repos/old/name':
            return httpx.Response(301,headers={'location':'https://api.github.com/repositories/123'})
        return httpx.Response(200,json={'full_name':'new/name','private':False})
    mock_provider(handler)
    result=await http.request_json('https://api.github.com/repos/old/name',headers={'Authorization':'Bearer test-only'})
    assert result['full_name']=='new/name'
    assert len(calls)==2
    assert all(r.url.host=='api.github.com' for r in calls)

async def test_redirect_never_sends_authorization_to_another_host(mock_provider):
    calls=[]
    def handler(request):
        calls.append(request)
        return httpx.Response(301,headers={'location':'https://evil.example/collect'})
    mock_provider(handler)
    with pytest.raises(http.ProviderError,match='unsupported redirect'):
        await http.request_json('https://api.github.com/repos/old/name',headers={'Authorization':'Bearer test-only'})
    assert len(calls)==1

@pytest.mark.parametrize('code,expected',[(404,'make sure the repository is public'),(409,'no commits'),(429,'temporarily limiting')])
async def test_provider_errors_explain_next_step(mock_provider,code,expected):
    mock_provider(lambda request:httpx.Response(code,json={'message':'upstream'}))
    with pytest.raises(http.ProviderError,match=expected):
        await http.request_json('https://api.github.com/repos/owner/repo')

async def test_invalid_json_is_a_safe_provider_error(mock_provider):
    mock_provider(lambda request:httpx.Response(200,text='<html>bad gateway</html>'))
    with pytest.raises(http.ProviderError,match='unreadable response'):
        await http.request_json('https://api.github.com/repos/owner/repo')

async def test_ci_rerun_supersedes_failure_but_other_workflow_still_blocks(monkeypatch):
    from backend.integrations import github
    runs=[
        {'head_sha':'latest','workflow_id':1,'run_number':10,'run_attempt':1,'status':'completed','conclusion':'failure','name':'Tests','html_url':'https://github.com/o/r/actions/runs/1'},
        {'head_sha':'latest','workflow_id':1,'run_number':10,'run_attempt':2,'status':'completed','conclusion':'success','name':'Tests','html_url':'https://github.com/o/r/actions/runs/1'},
    ]
    async def fake(repository,suffix=''):
        if not suffix:return {'private':False,'default_branch':'main'}
        if suffix.startswith('/commits'):return [{'sha':'latest'}]
        return {'workflow_runs':runs}
    monkeypatch.setattr(github,'api',fake)
    assert (await github.ci_status('owner/repo'))['status']=='success'
    runs.append(dict(runs[0],workflow_id=2,name='Build'))
    assert (await github.ci_status('owner/repo'))['status']=='failure'

async def test_tool_timeout_is_explained(monkeypatch):
    from backend.services import analyzer
    async def timeout(*args,**kwargs):
        raise TimeoutError()
    monkeypatch.setattr(analyzer,'execute',timeout)
    result,event=await analyzer.call_tool('get_repository_info',{'repository':'owner/repo'})
    assert result is None
    assert 'took too long' in event['error']

async def test_protocol_error_wrapper_is_hidden_from_user(monkeypatch):
    from backend.services import analyzer
    async def unavailable(*args,**kwargs):
        raise ValueError("Error calling tool 'get_repository_info': GitHub could not find this repository.")
    monkeypatch.setattr(analyzer,'execute',unavailable)
    result,event=await analyzer.call_tool('get_repository_info',{'repository':'owner/repo'})
    assert event['error']=='GitHub could not find this repository.'

async def test_scan_does_not_imply_complete_exploitation_check_without_package_coverage(monkeypatch):
    from backend.services import analyzer
    from backend.schemas import ScanResult
    from backend.services.readiness import evaluate
    async def execute(name,args):
        if name=='get_repository_info':return {'full_name':'owner/repo','archived':False}
        if name=='parse_python_dependencies':return {'dependencies':[],'coverage':'partial','unsupported':['No Python files']}
        if name=='scan_known_vulnerabilities':return {'scanned':0,'findings':[],'coverage':'partial','notes':['No exact versions']}
        if name=='check_known_exploitation':return {'findings':[],'matches':[],'coverage':'complete'}
        if name=='evaluate_release_readiness':return evaluate(args['evidence'])
        raise AssertionError(name)
    monkeypatch.setattr(analyzer,'execute',execute)
    scan=ScanResult(id='coverage-test',repository='owner/repo',created_at='now',modules=['security'])
    await analyzer.run_scan(scan)
    check=next(c for c in scan.checks if c['name']=='CISA known exploitation')
    assert check['status']=='unavailable'
    assert 'incomplete coverage' in check['detail']
    assert scan.readiness['status']=='incomplete'
