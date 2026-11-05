import pytest
from backend.integrations import osv

@pytest.mark.asyncio
async def test_remediation_does_not_suggest_older_branch_fixes(monkeypatch):
    async def request(url, **kwargs):
        if url.endswith('querybatch'):
            return {'results': [{'vulns': [{'id': 'TEST-1'}]}]}
        return {'id': 'TEST-1', 'summary': 'Example advisory', 'affected': [{'package': {'name': 'example'}, 'ranges': [{'events': [{'introduced': '0'}, {'fixed': '1.5'}, {'introduced': '2.0'}, {'fixed': '2.1'}]}]}]}
    monkeypatch.setattr(osv, 'request_json', request)
    result = await osv.scan([{'name': 'example', 'version': '2.0', 'pinned': True}])
    assert result['findings'][0]['fixed_versions'] == ['2.1']

async def test_duplicate_manifest_versions_only_use_one_query_and_keep_sources(monkeypatch):
    queries=[]
    async def request(url,**kwargs):
        if url.endswith('querybatch'):
            queries.extend(kwargs['payload']['queries'])
            return {'results':[{'vulns':[{'id':'TEST-1'}]}]}
        return {'affected':[{'package':{'name':'my-package','ecosystem':'PyPI'},'ranges':[{'events':[{'fixed':'2.0'},{'fixed':'10.0'}]}]}]}
    monkeypatch.setattr(osv,'request_json',request)
    result=await osv.scan([{'name':'my_package','version':'1.0','pinned':True,'source':'requirements.txt'},{'name':'my.package','version':'1.0','pinned':True,'source':'examples/requirements.txt'}])
    assert len(queries)==1 and queries[0]['package']['name']=='my-package'
    assert result['scanned']==1 and len(result['findings'])==1
    assert result['findings'][0]['sources']==['requirements.txt','examples/requirements.txt']
    assert result['findings'][0]['fixed_versions']==['2.0','10.0']

async def test_unrelated_package_does_not_override_advisory_severity(monkeypatch):
    async def request(url,**kwargs):
        if url.endswith('querybatch'):return {'results':[{'vulns':[{'id':'TEST-1'}]}]}
        return {'database_specific':{'severity':'HIGH'},'affected':[{'package':{'name':'other'},'ecosystem_specific':{'severity':'LOW'}}]}
    monkeypatch.setattr(osv,'request_json',request)
    result=await osv.scan([{'name':'example','version':'1.0','pinned':True}])
    assert result['findings'][0]['severity']=='HIGH'
