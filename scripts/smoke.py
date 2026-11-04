"""Live full-stack smoke test. Providers are real; errors remain explicit."""
import argparse
import json
import time
import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', default='http://127.0.0.1:8000')
    parser.add_argument('--repository', default='pallets/flask')
    parser.add_argument('--ai', action='store_true', help='Also use NVIDIA credits to verify a real MCP tool-calling response')
    args = parser.parse_args()
    with httpx.Client(base_url=args.base_url, timeout=260) as client:
        def request(method, path, **kwargs):
            response = client.request(method, path, **kwargs)
            response.raise_for_status()
            return response
        health = request('GET', '/api/health').json()
        assert health['status'] == 'ok'
        catalog = request('GET', '/api/mcp/discover').json()
        assert len(catalog['tools']) == 13
        assert len(catalog['resources']) == 2 and len(catalog['templates']) == 3 and len(catalog['prompts']) == 3
        request('POST', '/api/mcp/resource', json={'uri': 'repoguard://about'})
        request('POST', '/api/mcp/prompt', json={'name': 'analyze_repository', 'arguments': {'repository': args.repository}})
        scan = request('POST', '/api/scans', json={'repository': args.repository, 'modules': ['repository', 'dependencies', 'security', 'ci']}).json()
        deadline = time.monotonic() + 600
        while scan['status'] == 'running' and time.monotonic() < deadline:
            time.sleep(2)
            scan = request('GET', f"/api/scans/{scan['id']}").json()
        assert scan['status'] != 'running', 'Audit did not finish within ten minutes'
        assert scan['repository_info'], 'Live GitHub metadata was unavailable'
        for format in ('json', 'html'):
            response = request('GET', f"/api/scans/{scan['id']}/export?format={format}")
            assert 'attachment' in response.headers['content-disposition']
            if format == 'json':
                assert response.json()['id'] == scan['id']
            else:
                assert '<!doctype html>' in response.text.lower()
        result = {'scan_id': scan['id'], 'status': scan['status'], 'dependencies': len(scan['dependencies']), 'findings': len(scan['findings']), 'errors': scan['errors']}
        if args.ai:
            assert health['ai_configured'], 'NVIDIA key is not configured'
            answer = request('POST', '/api/chat', json={'repository': args.repository, 'scan_id': scan['id'], 'message': 'Call get_repository_info for this repository now, then summarize its primary language and description using that result.', 'history': []}).json()
            assert any(e['status'] == 'completed' for e in answer['executions']), 'NVIDIA did not execute an MCP tool'
            result['ai_tool_calls'] = len(answer['executions'])
        print(json.dumps(result, indent=2))
        if scan['errors']:
            raise SystemExit('Smoke completed with unavailable provider evidence; inspect reported errors.')

if __name__ == '__main__':
    main()
