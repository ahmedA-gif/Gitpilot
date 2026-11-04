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
