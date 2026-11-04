"""Verify the latest live scan's expanded profile and both report formats."""
import asyncio
import httpx

async def main():
    async with httpx.AsyncClient(base_url='http://127.0.0.1:8000', timeout=40) as client:
        scans=(await client.get('/api/scans')).json()
        if not scans:
            raise SystemExit('Start a repository scan in the browser first.')
        scan=scans[0]
        for _ in range(180):
            if scan['status']!='running':break
            await asyncio.sleep(1)
            scan=(await client.get('/api/scans/'+scan['id'])).json()
        assert scan['repository_info'], scan['errors']
        overview=scan['overview']
        assert overview and len(overview['sections'])==7
        for name,section in overview['sections'].items():
            if section['status']=='available':
                value=section['data']
                count=len(value) if isinstance(value,list) else len(value.get('paths',[])) if name=='files' else len(value.get('text','')) if name=='readme' else len(value.get('files',{}))
                print(f'{name}: available ({count} entries/characters)',flush=True)
            else:
                print(f'{name}: unavailable — {section["message"]}',flush=True)
        catalog=(await client.get('/api/mcp/discover')).json()
        assert len(catalog['tools'])==13
        resource=await client.post('/api/mcp/resource',json={'uri':f'repoguard://repository/{scan["repository"]}/overview'})
        resource.raise_for_status()
        for fmt in ['html','json']:
            response=await client.get(f'/api/scans/{scan["id"]}/export?format={fmt}')
            response.raise_for_status()
            assert 'attachment' in response.headers['content-disposition']
            if fmt=='html':
                assert 'Repository profile' in response.text
                assert 'Contributors' in response.text and 'Readme' in response.text
            else:assert response.json()['overview']==overview
            print(fmt+' report: passed',flush=True)
        assert scan['progress']==100
        print(f'Live scan: {scan["repository"]}, status={scan["status"]}; 13 MCP tools discovered.',flush=True)

asyncio.run(main())
