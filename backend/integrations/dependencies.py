import asyncio
import re
import tomllib
from packaging.requirements import Requirement, InvalidRequirement
from . import github
from ..schemas import DependencyFinding


def parse_requirement(value: str, source: str) -> dict:
    req = Requirement(value)
    specs = list(req.specifier)
    pinned = len(specs)==1 and specs[0].operator=='==' and '*' not in specs[0].version and not req.url
    return DependencyFinding(name=req.name, specifier=str(req.specifier), version=specs[0].version if pinned else None, source=source, pinned=pinned).model_dump() | {'marker': str(req.marker) if req.marker else None, 'extras': sorted(req.extras)}


def parse_manifest(text: str, path: str) -> dict:
    unsupported=[]
    deps=[]
    if path.endswith('pyproject.toml'):
        data=tomllib.loads(text)
        project=data.get('project',{})
        values=list(project.get('dependencies',[]))
        for group, requirements in project.get('optional-dependencies',{}).items():
            values.extend(requirements)
        if 'dependencies' in project.get('dynamic',[]):
            unsupported.append(f'{path}: dynamic dependencies require build execution and were not resolved')
        if data.get('tool',{}).get('poetry',{}).get('dependencies'):
            unsupported.append(f'{path}: Poetry dependency tables are not supported')
    else:
        values=[]
        for line in text.splitlines():
            value=re.split(r'\s+#',line, maxsplit=1)[0].strip()
            if not value or value.startswith('#'):
                continue
            if value.startswith(('-', 'git+', 'https://')) or '\\' in value:
                unsupported.append(f'{path}: unsupported requirement directive or URL: {value[:100]}')
                continue
            values.append(value)
    for value in values:
        try:
            deps.append(parse_requirement(value,path))
        except (InvalidRequirement,TypeError):
            unsupported.append(f'{path}: invalid requirement: {str(value)[:100]}')
    return {'dependencies':deps,'unsupported':unsupported}

async def parse_repository(repository: str) -> dict:
    discovery=await github.manifests(repository)
    deps=[]
    unsupported=[]
    for path in discovery['manifests']:
        try:
            parsed=parse_manifest(await github.read_file(repository,path),path)
            deps.extend(parsed['dependencies'])
            unsupported.extend(parsed['unsupported'])
        except Exception as exc:
            unsupported.append(f'{path}: {exc}')
    unique={ (x['name'].lower().replace('_','-'),x['version'],x['specifier'],x.get('marker'),x['source']):x for x in deps }
    if discovery['truncated']:
        unsupported.append('Manifest discovery was truncated')
    if not discovery['manifests']:
        unsupported.append('No supported Python dependency manifests found')
    return {'dependencies':list(unique.values())[:150], 'manifests':discovery['manifests'], 'unsupported':unsupported, 'coverage':'partial' if unsupported or len(unique)>150 else 'complete', 'notes':['Declared dependencies only; transitive dependencies are not resolved. Markers are included conservatively across all target environments.'], 'truncated':len(unique)>150}
