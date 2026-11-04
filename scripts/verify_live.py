"""Live smoke checks. Requires the local server; never supplies fixture findings."""
import asyncio
import json
import time
from pathlib import Path
import httpx

async def main():
    results=[]
    async with httpx.AsyncClient(base_url='http://127.0.0.1:8000',timeout=40) as client:
        for repository in ['https://github.com/pallets/flask/tree/main?tab=readme', 'https://github.com/psf/requests/blob/main/README.md', 'https://github.com/expressjs/express', 'https://github.com/kennethreitz/requests', 'https://github.com/pallets/repoguard-nonexistent-check-20261031']:
            modules=['repository','dependencies','security','ci'] if 'kennethreitz' not in repository else ['repository']
            response=await client.post('/api/scans',json={'repository':repository,'modules':modules})
            response.raise_for_status()
            scan=response.json()
            deadline=time.monotonic()+240
            while scan['status']=='running' and time.monotonic()<deadline:
                await asyncio.sleep(1)
                response=await client.get('/api/scans/'+scan['id'])
                response.raise_for_status()
                scan=response.json()
            assert scan['status']!='running','Scan did not finish within four minutes'
            assert scan['progress']==100
            assert scan['readiness'] is not None
            if 'nonexistent' in repository:
                assert scan['status']=='failed' and scan['repository_info'] is None
            else:
                assert scan['repository_info'] and scan['repository_info'].get('full_name'), 'Live repository metadata unavailable; check provider errors'
            assert not any('Error calling tool' in error for error in scan['errors'])
            for fmt in ['json','html']:
                export=await client.get(f'/api/scans/{scan["id"]}/export?format={fmt}')
                export.raise_for_status()
                assert 'attachment' in export.headers['content-disposition']
                if fmt=='html':
                    assert '<pre>' not in export.text
            item={'input':repository,'repository':scan['repository'],'actual_repository':(scan['repository_info'] or {}).get('full_name'),'status':scan['status'],'dependencies':len(scan['dependencies']),'findings':len(scan['findings']),'readiness':scan['readiness']['status'],'checks':scan['checks'],'errors':scan['errors'],'exports':'JSON and HTML passed'}
            results.append(item)
            print(json.dumps(item),flush=True)
        invalid=await client.post('/api/scans',json={'repository':'https://github.com.evil.example/owner/repo'})
        assert invalid.status_code==422
        catalog=(await client.get('/api/mcp/discover')).json()
        assert len(catalog['tools'])==13 and len(catalog['resources'])+len(catalog['templates'])==5 and len(catalog['prompts'])==3
    Path('/tmp/repoguard-live-verification.json').write_text(json.dumps(results,indent=2))
    print('Live checks and both report formats complete. Results: /tmp/repoguard-live-verification.json',flush=True)

asyncio.run(main())
