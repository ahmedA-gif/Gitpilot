"""Deterministic evidence rules; unknown coverage can never produce a ready verdict."""
def evaluate(evidence: dict) -> dict:
    info=evidence.get('repository_info') or {}
    ci=evidence.get('ci') or {}
    dependencies=evidence.get('dependencies') or {}
    vulnerabilities=evidence.get('vulnerabilities') or {}
    exploitation=evidence.get('exploitation') or {}
    if isinstance(dependencies,list):
        dependencies={'dependencies':dependencies,'coverage':'unknown'}
    findings=vulnerabilities.get('findings',evidence.get('findings',[]))
    checks=[]
    def add(name,status,detail):
        checks.append({'name':name,'status':status,'detail':detail})
    add('Repository active','fail' if info.get('archived') or info.get('disabled') else 'pass' if info else 'unknown','Repository must be public, active, and available.')
    add('CI on default branch',{'success':'pass','failure':'fail'}.get(ci.get('status'),'unknown'),'Latest public GitHub Actions evidence: '+ci.get('status','unavailable'))
    dep_values=dependencies.get('dependencies',[])
    complete=dependencies.get('coverage')=='complete' and vulnerabilities.get('coverage')=='complete' and bool(dep_values)
    add('Dependency coverage','pass' if complete else 'unknown','Exact pins in supported manifests only; no transitive dependency resolution.')
    severe=[x for x in findings if x.get('severity','').upper() in {'HIGH','CRITICAL'}]
    unknown=[x for x in findings if x.get('severity','UNKNOWN').upper() not in {'LOW','MODERATE','MEDIUM','HIGH','CRITICAL'}]
    add('Known vulnerabilities','fail' if severe else 'unknown' if unknown or not vulnerabilities or vulnerabilities.get('coverage')!='complete' else 'warn' if findings else 'pass',f'{len(findings)} advisories; {len(severe)} high/critical; {len(unknown)} with unknown severity.')
    matches=exploitation.get('matches',[])
    add('Known exploitation','fail' if matches else 'pass' if exploitation.get('coverage')=='complete' and vulnerabilities.get('coverage')=='complete' else 'unknown',(f'{len(matches)} CISA KEV matches among returned advisories.' if vulnerabilities.get('coverage')=='complete' else f'{len(matches)} CISA KEV matches among returned advisories; vulnerability coverage is incomplete.') if exploitation else 'CISA evidence unavailable.')
    if evidence.get('errors'):
        add('Upstream evidence','unknown','One or more checks failed or could not be completed.')
    statuses=[x['status'] for x in checks]
    status='blocked' if 'fail' in statuses else 'incomplete' if 'unknown' in statuses else 'review' if 'warn' in statuses else 'ready'
    score=round(sum({'pass':1,'warn':0.5}.get(x,0) for x in statuses)/len(statuses)*100)
    return {'status':status,'score':score,'checks':checks,'summary':{'blocked':'Resolve blocking findings before release.','incomplete':'More evidence is required before release readiness can be determined.','review':'Review the reported advisories before release.','ready':'All supported release checks passed; this is not a comprehensive security certification.'}[status]}
