from .http import request_json

async def check(findings: list[dict]) -> dict:
    if len(findings)>150:
        raise ValueError('Maximum 150 findings per lookup')
    catalog=await request_json('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',ttl=3600)
    records={x['cveID']:x for x in catalog['vulnerabilities']}
    updated=[]
    matches=[]
    for finding in findings:
        result=dict(finding)
        ids=set(finding.get('aliases',[])+[finding.get('id','')])
        matched=[records[x] for x in ids if x in records]
        result['kev']=bool(matched)
        if matched:
            result['kev_details']=matched
            matches.extend(matched)
        updated.append(result)
    return {'findings':updated,'matches':matches,'catalog_date':catalog.get('dateReleased'),'catalog_version':catalog.get('catalogVersion'),'coverage':'complete','notes':['A KEV non-match does not imply that exploitation is impossible.']}
