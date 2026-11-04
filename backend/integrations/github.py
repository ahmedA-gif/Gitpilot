import base64
import os
import re
from urllib.parse import quote, urlsplit
from .http import request_json, ProviderError

_REPO = re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$')

def normalize_repository(repository: str) -> str:
    value = repository.strip().rstrip('/')
    if value.startswith('git@github.com:'):
        value = value[len('git@github.com:'):]
    elif value.lower().startswith(('github.com/', 'www.github.com/')):
        value = 'https://' + value
    if '://' in value:
        url = urlsplit(value)
        if url.scheme not in {'http', 'https'} or url.netloc.lower() not in {'github.com', 'www.github.com'}:
            raise ValueError('Use a public repository link from github.com, or enter owner/repository.')
        parts = url.path.strip('/').split('/')
        if len(parts) < 2 or (len(parts) > 2 and parts[2] not in {'tree','blob','issues','pull','pulls','actions','releases','commit','commits','discussions','wiki','tags','branches','compare'}):
            raise ValueError('Paste a repository link, such as https://github.com/owner/repository. Profile and organization pages cannot be scanned.')
        value = '/'.join(parts[:2])
    if value.endswith('.git'):
        value = value[:-4]
    if not _REPO.fullmatch(value) or value.split('/')[1] in {'.', '..'}:
        raise ValueError('Enter a public GitHub repository as owner/repository or https://github.com/owner/repository.')
    return value.lower()

async def api(repository: str, suffix: str = ''):
    repository = normalize_repository(repository)
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
    if os.getenv('GITHUB_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
    base = f'https://api.github.com/repos/{repository}'
    metadata = await request_json(base, headers=headers)
    if metadata.get('private'):
        raise ValueError('Only public repositories are supported')
    return await request_json(base+suffix, headers=headers) if suffix else metadata

async def repository_info(repository: str) -> dict:
    data = await api(repository)
    if data.get('private'):
        raise ValueError('Only public repositories are supported')
    keys = ['full_name','description','html_url','default_branch','language','stargazers_count','forks_count','open_issues_count','archived','disabled','pushed_at','updated_at','topics','license','size','created_at','homepage','visibility','fork','subscribers_count','has_issues','has_wiki','has_discussions','has_projects','allow_forking']
    return {key: data.get(key) for key in keys} | {'owner': {key: (data.get('owner') or {}).get(key) for key in ('login', 'type', 'html_url')}}

async def structure(repository: str) -> dict:
    info = await repository_info(repository)
    data = await api(repository, '/git/trees/' + quote(info['default_branch'], safe='') + '?recursive=1')
    tree = data.get('tree', [])
    return {'repository': normalize_repository(repository), 'branch': info['default_branch'], 'paths': [{'path': item['path'], 'type': item['type'], 'size': item.get('size')} for item in tree[:5000]], 'truncated': data.get('truncated', False) or len(tree)>5000}

async def commits(repository: str) -> dict:
    data = await api(repository, '/commits?per_page=10')
    return {'commits': [{'sha': x['sha'], 'message': x['commit']['message'], 'date': x['commit']['committer']['date'], 'url': x['html_url']} for x in data], 'limit': 10}

async def issues(repository: str) -> dict:
    data = await api(repository, '/issues?state=open&per_page=30')
    return {'issues': [{'number':x['number'],'title':x['title'],'url':x['html_url'],'labels':[y['name'] for y in x.get('labels',[])]} for x in data if 'pull_request' not in x], 'limit':30, 'coverage':'First page only; GitHub issues endpoint includes PRs'}

async def pull_requests(repository: str) -> dict:
    data = await api(repository, '/pulls?state=open&per_page=20')
    return {'pull_requests':[{'number':x['number'],'title':x['title'],'url':x['html_url'],'draft':x.get('draft',False)} for x in data], 'limit':20}

async def ci_status(repository: str) -> dict:
    info = await repository_info(repository)
    branch = quote(info['default_branch'],safe='')
    data = await api(repository, '/actions/runs?per_page=20&branch='+branch)
    latest = await api(repository, '/commits?per_page=1')
    branch_sha = latest[0]['sha'] if latest else None
    runs = data.get('workflow_runs', [])
    # Only the newest commit's runs represent the current branch evidence.
    sha = branch_sha
    runs = [x for x in runs if x['head_sha']==sha]
    # A successful rerun supersedes an older failure of the same workflow.
    latest_runs = {}
    for run in sorted(runs, key=lambda x: (x.get('run_number', 0), x.get('run_attempt', 1), x.get('updated_at', '')), reverse=True):
        latest_runs.setdefault(run.get('workflow_id', run['name']), run)
    runs = list(latest_runs.values())
    conclusions = [x.get('conclusion') for x in runs]
    if not runs:
        status='unknown'
    elif any(x in {'failure','timed_out','action_required','cancelled','startup_failure'} for x in conclusions):
        status='failure'
    elif any(x.get('status')!='completed' for x in runs):
        status='pending'
    elif all(x in {'success','neutral','skipped'} for x in conclusions) and 'success' in conclusions:
        status='success'
    else:
        status='unknown'
    return {'status':status,'sha':sha,'runs':[{'name':x['name'],'status':x['status'],'conclusion':x.get('conclusion'),'url':x['html_url']} for x in runs], 'coverage':'Public GitHub Actions runs on the default branch; other CI providers are not covered'}

async def manifests(repository: str) -> dict:
    data = await structure(repository)
    paths = [x['path'] for x in data['paths'] if x['type']=='blob' and (x['path'].split('/')[-1]=='pyproject.toml' or re.search(r'(^|/)requirements[^/]*\.txt$', x['path']) or '/requirements/' in '/'+x['path'] and x['path'].endswith('.txt'))]
    return {'manifests': paths[:15], 'truncated': data['truncated'] or len(paths)>15, 'limit':15}

async def read_file(repository: str, path: str) -> str:
    if not path or path.startswith('/') or '..' in path.split('/') or len(path)>500:
        raise ValueError('Invalid manifest path')
    data = await api(repository, '/contents/'+quote(path,safe='/'))
    if data.get('encoding')!='base64' or data.get('size',0)>200_000:
        raise ProviderError('Manifest is too large or unavailable')
    return base64.b64decode(data['content']).decode('utf-8')

async def repository_overview(repository: str) -> dict:
    """Bounded public profile; failure of one section never erases other evidence."""
    import asyncio
    from datetime import datetime, timezone
    info = await repository_info(repository)
    sections = {}
    async def section(name, suffix, transform):
        try:
            data = await api(repository, suffix)
            sections[name] = {'status': 'available', 'data': transform(data)}
        except Exception as exc:
            message = str(exc)[:300]
            if 'could not find' in message and name in {'readme', 'community'}:
                sections[name] = {'status': 'unavailable', 'message': 'GitHub did not provide this information for this repository.'}
            else:
                sections[name] = {'status': 'unavailable', 'message': message or 'This information could not be retrieved.'}
    def readme(data):
        if data.get('encoding') != 'base64' or data.get('size', 0) > 200_000:
            raise ProviderError('README preview exceeds the supported size. Open it on GitHub.')
        content = base64.b64decode(data.get('content', ''), validate=False).decode('utf-8', errors='replace')
        return {'name': data.get('name'), 'path': data.get('path'), 'url': data.get('html_url'), 'text': content[:16000], 'truncated': len(content) > 16000}
    def languages(data):
        total = sum(data.values())
        return [{'name': name, 'bytes': size, 'percentage': round(size / total * 100, 1) if total else 0} for name, size in sorted(data.items(), key=lambda item: item[1], reverse=True)]
    await asyncio.gather(
        section('languages', '/languages', languages),
        section('readme', '/readme', readme),
        section('releases', '/releases?per_page=10', lambda data: [{'name': x.get('name') or x.get('tag_name'), 'tag': x.get('tag_name'), 'url': x.get('html_url'), 'published_at': x.get('published_at'), 'prerelease': x.get('prerelease'), 'notes': (x.get('body') or '')[:2000]} for x in data]),
        section('branches', '/branches?per_page=30', lambda data: [{'name': x['name'], 'protected': x.get('protected'), 'sha': x.get('commit', {}).get('sha')} for x in data]),
        section('contributors', '/contributors?per_page=20', lambda data: [{'name': x.get('login'), 'url': x.get('html_url'), 'contributions': x.get('contributions')} for x in data]),
        section('community', '/community/profile', lambda data: {'health_percentage': data.get('health_percentage'), 'files': {name: {'present': bool(value), 'url': value.get('html_url') if isinstance(value, dict) else None} for name, value in data.get('files', {}).items()}}),
    )
    try:
        sections['files'] = {'status': 'available', 'data': await structure(repository)}
    except Exception as exc:
        sections['files'] = {'status': 'unavailable', 'message': str(exc)[:300]}
    notes = ['Default branch only. Recent activity and lists are bounded snapshots, not the complete repository history.', 'Up to 10 releases, 30 branches, 20 contributors, 5,000 file paths and 16,000 README characters. Provider results may be cached for up to five minutes.', 'Language percentages describe source-code bytes reported by GitHub, not security coverage. Community-file presence is not a security score.']
    gaps = [name for name, value in sections.items() if value['status'] != 'available']
    if gaps:
        notes.append('Unavailable sections: ' + ', '.join(gaps))
    return {'repository': info.get('full_name') or normalize_repository(repository), 'fetched_at': datetime.now(timezone.utc).isoformat(), 'sections': sections, 'coverage': 'partial' if gaps else 'complete', 'notes': notes, 'source_url': info.get('html_url')}
