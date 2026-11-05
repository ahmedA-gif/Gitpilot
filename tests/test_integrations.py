import pytest
from backend.integrations.dependencies import parse_manifest, parse_requirement
from backend.integrations.github import normalize_repository
from backend.services.readiness import evaluate


def test_manifest_preserves_uncertain_versions_and_markers():
    result=parse_manifest('flask==2.2.0; python_version >= "3.8"\nrequests>=2\n-r base.txt\nfoo==1.*\n','requirements.txt')
    assert result['dependencies'][0]['pinned']
    assert result['dependencies'][0]['version']=='2.2.0'
    assert result['dependencies'][0]['marker']
    assert result['dependencies'][1]['version'] is None
    assert not result['dependencies'][2]['pinned']
    assert result['unsupported']


def test_pyproject_optional_and_dynamic():
    result=parse_manifest('[project]\ndependencies=["flask>=2"]\ndynamic=["dependencies"]\n[project.optional-dependencies]\ntest=["pytest==8.0"]','pyproject.toml')
    assert len(result['dependencies'])==2
    assert result['unsupported']

@pytest.mark.parametrize('value',['https://evil.com/a/b','a/b/../../x','owner/repo?x=1','owner/..','a/b/c'])
def test_repository_restriction(value):
    with pytest.raises(ValueError):
        normalize_repository(value)


def test_repository_url_normalization():
    assert normalize_repository('https://github.com/pallets/flask.git/')=='pallets/flask'


def test_unknown_evidence_never_passes_readiness():
    assert evaluate({})['status']=='incomplete'
    evidence={'repository_info':{'archived':False},'ci':{'status':'success'},'dependencies':{'dependencies':[{'name':'x'}],'coverage':'complete'},'vulnerabilities':{'findings':[],'coverage':'complete'},'exploitation':{'matches':[],'coverage':'complete'}}
    assert evaluate(evidence)['status']=='ready'
    evidence['vulnerabilities']['findings']=[{'severity':'UNKNOWN'}]
    assert evaluate(evidence)['status']=='incomplete'
    evidence['exploitation']['matches']=[{'cveID':'CVE-2020-1234'}]
    assert evaluate(evidence)['status']=='blocked'

@pytest.mark.asyncio
async def test_osv_batch_and_advisory_details(monkeypatch):
    from backend.integrations import osv
    async def fake(url,**kwargs):
        if url.endswith('querybatch'):
            assert kwargs['payload']['queries'][0]['version']=='1.0'
            return {'results':[{'vulns':[{'id':'GHSA-test'}]}]}
        return {'id':'GHSA-test','summary':'Known issue','aliases':['CVE-2020-1234'],'database_specific':{'severity':'HIGH'},'affected':[{'package':{'name':'flask'},'ranges':[{'events':[{'introduced':'0'},{'fixed':'2.0'}]}]}]}
    monkeypatch.setattr(osv,'request_json',fake)
    result=await osv.scan([{'name':'flask','version':'1.0','pinned':True}])
    assert result['findings'][0]['fixed_versions']==['2.0']
    assert result['findings'][0]['severity']=='HIGH'
    assert result['coverage']=='complete'

@pytest.mark.asyncio
async def test_cisa_uses_cve_alias(monkeypatch):
    from backend.integrations import cisa
    async def fake(*args,**kwargs):
        return {'dateReleased':'2026-01-01','vulnerabilities':[{'cveID':'CVE-2020-1234'}]}
    monkeypatch.setattr(cisa,'request_json',fake)
    result=await cisa.check([{'id':'GHSA-abcd','aliases':['CVE-2020-1234']}])
    assert result['findings'][0]['kev'] is True
    assert len(result['matches'])==1

@pytest.mark.asyncio
async def test_private_repository_rejected_before_content_request(monkeypatch):
    from backend.integrations import github
    calls=[]
    async def fake(url,**kwargs):
        calls.append(url)
        return {'private':True}
    monkeypatch.setattr(github,'request_json',fake)
    with pytest.raises(ValueError,match='public'):
        await github.read_file('owner/private','requirements.txt')
    assert calls==['https://api.github.com/repos/owner/private']

@pytest.mark.asyncio
async def test_stale_ci_does_not_pass(monkeypatch):
    from backend.integrations import github
    async def fake(repository,suffix=''):
        if not suffix:
            return {'private':False,'default_branch':'main'}
        if suffix.startswith('/commits'):
            return [{'sha':'latest'}]
        return {'workflow_runs':[{'head_sha':'stale','status':'completed','conclusion':'success','name':'CI','html_url':'https://github.com/o/r/actions/runs/1'}]}
    monkeypatch.setattr(github,'api',fake)
    assert (await github.ci_status('owner/repo'))['status']=='unknown'

@pytest.mark.asyncio
async def test_http_restricts_provider_hosts():
    from backend.integrations.http import request_json, ProviderError
    with pytest.raises(ProviderError):
        await request_json('http://169.254.169.254/latest/meta-data')

async def test_root_manifests_are_not_lost_behind_example_directories(monkeypatch):
    from backend.integrations import github
    async def tree(_):
        paths=[f'examples/{i}/requirements.txt' for i in range(20)]+['requirements.txt','pyproject.toml']
        return {'paths':[{'path':path,'type':'blob'} for path in paths],'truncated':False}
    monkeypatch.setattr(github,'structure',tree)
    result=await github.manifests('owner/repo')
    assert result['manifests'][:2]==['pyproject.toml','requirements.txt']
    assert result['truncated'] is True
