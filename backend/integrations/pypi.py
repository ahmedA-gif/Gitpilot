import re
from urllib.parse import quote
from .http import request_json

async def release_info(package: str) -> dict:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}',package):
        raise ValueError('Invalid Python package name')
    data=await request_json('https://pypi.org/pypi/'+quote(package,safe='')+'/json')
    info=data['info']
    return {'name':info['name'],'latest_version':info['version'],'summary':info.get('summary'),'requires_python':info.get('requires_python'),'project_url':info.get('package_url'),'license':info.get('license'), 'released_at':next(iter(data.get('releases',{}).get(info['version'],[])),{}).get('upload_time_iso_8601')}
