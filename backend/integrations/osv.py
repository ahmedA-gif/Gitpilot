import asyncio
import re
from .http import request_json
from packaging.version import Version, InvalidVersion
from packaging.utils import canonicalize_name
from ..schemas import SecurityFinding, DependencyFinding

async def scan(dependencies: list[dict]) -> dict:
    if len(dependencies)>150:
        raise ValueError('Maximum 150 dependencies per scan')
    dependencies=[DependencyFinding.model_validate(x).model_dump() for x in dependencies]
    pinned=[x for x in dependencies if x['pinned'] and x['version']]
    skipped=[x for x in dependencies if not x['pinned'] or not x['version']]
    for dep in pinned:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}',dep['name']) or len(dep['version'])>100:
            raise ValueError('Invalid package name or version')
        try:
            Version(dep['version'])
        except InvalidVersion:
            raise ValueError('Enter an exact Python package version, such as 2.1.0.') from None
    # Query each package/version once while retaining every declaring manifest.
    unique = {}
    for dep in pinned:
        key = (canonicalize_name(dep['name']), Version(dep['version']))
        if key not in unique:
            unique[key] = dep | {'sources': []}
        if dep['source'] and dep['source'] not in unique[key]['sources']:
            unique[key]['sources'].append(dep['source'])
    pinned = list(unique.values())
    if not pinned:
        return {'findings':[],'scanned':0,'skipped':skipped,'coverage':'unknown','notes':['No exact pinned package versions available; absence of findings does not indicate safety.']}
    batch=await request_json('https://api.osv.dev/v1/querybatch',method='POST',payload={'queries':[{'package':{'name':canonicalize_name(x['name']),'ecosystem':'PyPI'},'version':x['version']} for x in pinned]})
    findings=[]
    errors=[]
    pending=[]
    for dep,result in zip(pinned,batch['results'],strict=True):
        if result.get('next_page_token'):
            errors.append('OSV results paginated for '+dep['name']+'; further pages not fetched')
        for vuln in result.get('vulns',[]):
            pending.append((dep,vuln['id']))
    if len(pending)>60:
        errors.append('Advisory detail limit reached (60)')
    for dep,identifier in pending[:60]:
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,150}',identifier):
            errors.append('Invalid upstream advisory identifier')
            continue
        try:
            advisory=await request_json('https://api.osv.dev/v1/vulns/'+identifier,ttl=1800)
            if advisory.get('withdrawn'):
                continue
            fixed=[]
            for affected in advisory.get('affected',[]):
                package = affected.get('package', {})
                if canonicalize_name(package.get('name','')) != canonicalize_name(dep['name']) or package.get('ecosystem', 'PyPI') != 'PyPI':
                    continue
                for ranges in affected.get('ranges',[]):
                    fixed.extend(event['fixed'] for event in ranges.get('events',[]) if 'fixed' in event)
            # Never recommend an older branch fix as an upgrade for this installed version.
            upgrades=[]
            for version in fixed:
                try:
                    if Version(version) > Version(dep['version']):
                        upgrades.append(version)
                except InvalidVersion:
                    pass
            fixed=sorted(set(upgrades), key=Version)
            severity=advisory.get('database_specific',{}).get('severity','UNKNOWN')
            for affected in advisory.get('affected',[]):
                package = affected.get('package', {})
                if canonicalize_name(package.get('name','')) == canonicalize_name(dep['name']) and package.get('ecosystem', 'PyPI') == 'PyPI':
                    severity=affected.get('ecosystem_specific',{}).get('severity',severity)
            findings.append(SecurityFinding(id=identifier,package=dep['name'],version=dep['version'],source=dep['source'],sources=dep['sources'],summary=advisory.get('summary') or advisory.get('details','')[:350],severity=str(severity).upper(),aliases=advisory.get('aliases',[]),fixed_versions=fixed,references=[x['url'] for x in advisory.get('references',[])][:5]).model_dump())
        except Exception as exc:
            errors.append(f'{identifier}: {exc}')
    findings = merge_aliases(findings)
    return {'findings':findings,'scanned':len(pinned),'skipped':skipped,'coverage':'partial' if skipped or errors else 'complete','errors':errors,'notes':['Only exact pinned declared dependencies are queried; transitive dependencies are not resolved.']}


def merge_aliases(findings: list[dict]) -> list[dict]:
    """Combine OSV records only when they share a published identifier for the same declared package version."""
    merged = []
    priority = {'UNKNOWN': 0, 'LOW': 1, 'MODERATE': 2, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    for original in findings:
        item = dict(original)
        identities = set([item['id'], *item.get('aliases', [])])
        matches = [existing for existing in merged if canonicalize_name(existing['package']) == canonicalize_name(item['package']) and existing['version'] == item['version'] and identities.intersection([existing['id'], *existing.get('aliases', [])])]
        if not matches:
            merged.append(item)
            continue
        primary = matches[0]
        for other in [*matches[1:], item]:
            primary['aliases'] = sorted((set(primary.get('aliases', [])) | {other['id']} | set(other.get('aliases', []))) - {primary['id']})
            primary['references'] = list(dict.fromkeys(primary.get('references', []) + other.get('references', [])))
            primary['sources'] = list(dict.fromkeys(primary.get('sources', []) + other.get('sources', [])))
            primary['fixed_versions'] = sorted(set(primary.get('fixed_versions', []) + other.get('fixed_versions', [])), key=Version)
            if priority.get(other.get('severity', 'UNKNOWN'), 0) > priority.get(primary.get('severity', 'UNKNOWN'), 0):
                primary['severity'] = other['severity']
            if other is not item:
                merged.remove(other)
    return merged
