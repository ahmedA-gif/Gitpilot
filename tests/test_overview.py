"""A richer profile must retain honest per-section coverage and safe output."""
import base64
import pytest
from backend.integrations import github
from backend.schemas import ScanResult
from backend.services.reports import render_html

@pytest.fixture
def provider(monkeypatch):
    async def fake(repository, suffix=''):
        if not suffix:
            return {'full_name':'owner/repo','html_url':'https://github.com/owner/repo','private':False,'default_branch':'main','owner':{'login':'owner'},'created_at':'2020-01-01','homepage':'https://example.com'}
        if suffix=='/languages':return {'Python':75,'HTML':25}
        if suffix=='/readme':return {'name':'README.md','html_url':'https://github.com/owner/repo/blob/main/README.md','encoding':'base64','content':base64.b64encode(b'# Hello\n<script>alert(1)</script>').decode()}
        if suffix.startswith('/releases'):return [{'name':'First release','tag_name':'v1','html_url':'https://github.com/owner/repo/releases/v1','body':'Fixes'}]
        if suffix.startswith('/branches'):return [{'name':'main','protected':True,'commit':{'sha':'a'}}]
        if suffix.startswith('/contributors'):return [{'login':'alice','contributions':15,'html_url':'https://github.com/alice'}]
        if suffix=='/community/profile':return {'health_percentage':50,'files':{'readme':{'html_url':'https://github.com/owner/repo/blob/main/README.md'},'contributing':None}}
        if suffix.startswith('/git/trees'):return {'tree':[{'type':'blob','path':'README.md'}],'truncated':False}
        raise AssertionError(suffix)
    monkeypatch.setattr(github,'api',fake)
    return fake

async def test_full_public_overview(provider):
    result=await github.repository_overview('owner/repo')
    assert result['coverage']=='complete'
    assert len(result['sections'])==7
    data=lambda name:result['sections'][name]['data']
    assert data('languages')[0]['percentage']==75
    assert data('readme')['text'].startswith('# Hello')
    assert data('community')['files']['contributing']['present'] is False
    assert data('branches')[0]['protected'] is True
    assert data('files')['paths'][0]['path']=='README.md'
    assert data('contributors')[0]['name']=='alice'
    assert result['fetched_at']

async def test_optional_provider_failure_preserves_other_sections(provider,monkeypatch):
    async def partial(repository,suffix=''):
        if suffix=='/readme':raise github.ProviderError('GitHub could not find this repository or resource.')
        if suffix.startswith('/contributors'):raise github.ProviderError('GitHub is temporarily limiting requests.')
        return await provider(repository,suffix)
    monkeypatch.setattr(github,'api',partial)
    result=await github.repository_overview('owner/repo')
    assert result['coverage']=='partial'
    assert result['sections']['readme']['status']=='unavailable'
    assert 'did not provide' in result['sections']['readme']['message']
    assert result['sections']['releases']['status']=='available'
    assert 'limiting' in result['sections']['contributors']['message']

async def test_readme_preview_is_bounded(provider,monkeypatch):
    async def long_readme(repository,suffix=''):
        if suffix=='/readme':return {'encoding':'base64','size':17000,'content':base64.b64encode(b'x'*17000).decode()}
        return await provider(repository,suffix)
    monkeypatch.setattr(github,'api',long_readme)
    readme=(await github.repository_overview('owner/repo'))['sections']['readme']['data']
    assert len(readme['text'])==16000 and readme['truncated']

async def test_reports_include_profile_and_escape_readme(provider):
    overview=await github.repository_overview('owner/repo')
    scan=ScanResult(id='test',repository='owner/repo',created_at='now',status='completed',overview=overview,repository_info=await github.repository_info('owner/repo'))
    html=render_html(scan.model_dump())
    assert '<script>alert(1)</script>' not in html
    assert '&lt;script&gt;' in html
    assert 'First release' in html and 'alice' in html
    assert 'Repository profile' in html
