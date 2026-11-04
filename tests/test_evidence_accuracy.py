from backend.integrations.osv import merge_aliases
from backend.services.readiness import evaluate
from backend.services.reports import render_html
from backend.schemas import ScanResult


def test_advisory_aliases_merge_only_for_same_package_and_version():
    base = {'package':'flask', 'version':'2.0', 'source':'requirements.txt', 'summary':'Issue', 'fixed_versions':['2.1'], 'references':[], 'kev':False}
    records = [dict(base, id='GHSA-1', aliases=['CVE-2024-1111'], severity='HIGH'),
               dict(base, id='PYSEC-1', aliases=['CVE-2024-1111'], severity='UNKNOWN'),
               dict(base, id='GHSA-2', aliases=['CVE-2024-2222'], severity='LOW'),
               dict(base, id='OTHER', package='other', aliases=['CVE-2024-1111'], severity='LOW')]
    result = merge_aliases(records)
    assert len(result) == 3
    assert {'PYSEC-1', 'CVE-2024-1111'} <= set(result[0]['aliases'])
    assert result[0]['severity'] == 'HIGH'


def test_no_exploitation_match_is_unknown_when_vulnerability_scan_is_incomplete():
    evidence = {'vulnerabilities':{'coverage':'partial','findings':[]}, 'exploitation':{'coverage':'complete','matches':[]}}
    check = next(c for c in evaluate(evidence)['checks'] if c['name'] == 'Known exploitation')
    assert check['status'] == 'unknown'
    assert 'incomplete' in check['detail']


def test_html_report_contains_readable_evidence_without_json_dump():
    scan = ScanResult(id='1',repository='owner/repo',created_at='now',status='completed',dependencies=[{'name':'example','version':'1.0','source':'requirements.txt','pinned':True}])
    rendered = render_html(scan.model_dump())
    assert 'requirements.txt' in rendered and 'example' in rendered
    assert '<pre>' not in rendered and '"repository":' not in rendered


def test_alias_merging_retains_all_manifest_sources():
    base = {'package':'flask', 'version':'2.0', 'summary':'Issue', 'fixed_versions':[], 'references':[], 'kev':False, 'severity':'HIGH'}
    findings = [dict(base, id='GHSA-1', aliases=['CVE-2024-1111'], source='requirements.txt', sources=['requirements.txt']),
                dict(base, id='PYSEC-1', aliases=['CVE-2024-1111'], source='examples/requirements.txt', sources=['examples/requirements.txt'])]
    merged = merge_aliases(findings)
    assert len(merged) == 1
    assert merged[0]['sources'] == ['requirements.txt', 'examples/requirements.txt']


async def test_failed_ci_is_a_failed_check_not_a_pass(monkeypatch):
    from backend.services import analyzer
    from backend.services.readiness import evaluate
    async def fake_execute(name, arguments):
        if name == 'get_repository_info':
            return {'full_name':'owner/repo', 'archived':False, 'disabled':False}
        if name == 'inspect_ci_status':
            return {'status':'failure'}
        if name == 'evaluate_release_readiness':
            return evaluate(arguments['evidence'])
        raise AssertionError(name)
    monkeypatch.setattr(analyzer, 'execute', fake_execute)
    scan = ScanResult(id='ci-test',repository='owner/repo',created_at='now',modules=['ci'])
    await analyzer.run_scan(scan)
    assert next(c for c in scan.checks if c['name']=='CI workflows')['status'] == 'failed'
    assert scan.readiness['status'] == 'blocked'


async def test_dependency_inventory_preserves_each_manifest_source(monkeypatch):
    from backend.integrations import dependencies
    async def manifests(_):
        return {'manifests':['requirements.txt','examples/requirements.txt'], 'truncated':False}
    async def read_file(_, path):
        return 'example==1.0\n'
    monkeypatch.setattr(dependencies.github,'manifests',manifests)
    monkeypatch.setattr(dependencies.github,'read_file',read_file)
    result = await dependencies.parse_repository('owner/repo')
    assert {item['source'] for item in result['dependencies']} == {'requirements.txt','examples/requirements.txt'}
