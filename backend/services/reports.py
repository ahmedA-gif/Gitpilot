"""Readable HTML reports; the separate JSON export retains the full evidence."""
import html


def readable(value):
    esc = lambda item: html.escape(str(item))
    if value is None:
        return 'Not reported'
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    if isinstance(value, dict):
        return '<dl>' + ''.join(f'<dt><b>{esc(key.replace("_", " ").capitalize())}</b></dt><dd>{readable(item)}</dd>' for key, item in value.items() if key not in {'sha', 'bytes'} and item is not None) + '</dl>'
    if isinstance(value, list):
        if not value:
            return 'None returned'
        return '<ul>' + ''.join('<li>' + readable(item) + '</li>' for item in value[:100]) + '</ul>' + ('<p>Showing the first 100 entries. The JSON export retains all retrieved entries.</p>' if len(value) > 100 else '')
    if isinstance(value, str) and value.startswith('https://'):
        return f'<a href="{esc(value)}" rel="noreferrer">{esc(value)}</a>'
    return '<span style="white-space:pre-wrap;overflow-wrap:anywhere">' + esc(value) + '</span>'


def render_html(report: dict) -> str:
    esc = lambda x: html.escape(str(x))
    readiness = report.get('readiness') or {}
    profile = '<h2>Repository profile</h2>' + readable(report.get('repository_info') or {})
    overview = report.get('overview') or {}
    profile += ''.join('<details><summary>' + esc(name.replace('_', ' ').capitalize()) + '</summary>' + readable(value) + '</details>' for name, value in overview.get('sections', {}).items())
    profile += readable(overview.get('notes', []))
    for event in report.get('executions', []):
        if event.get('tool') in {'get_recent_commits','get_open_issues','get_pull_requests'} and event.get('status') == 'completed':
            profile += '<details><summary>' + esc(event['tool'].replace('_', ' ').capitalize()) + '</summary>' + readable(event.get('result')) + '</details>'
    findings = report.get('findings', [])
    dependencies = report.get('dependencies', [])
    checks = ''.join(f"<li><b>{esc(c['name'])}</b> <span class='status'>{esc(c['status'])}</span><p>{esc(c.get('detail',''))}</p></li>" for c in report.get('checks', []))
    rows = ''.join(f"<tr><td>{esc(f['package'])}<small>{esc(', '.join(f.get('sources') or []) or f.get('source') or 'Source unavailable')}</small></td><td>{esc(f['id'])}</td><td>{esc(f.get('severity','UNKNOWN'))}</td><td>{esc(f.get('version','Unavailable'))}</td><td>{esc(f.get('summary',''))}</td></tr>" for f in findings)
    dep_rows = ''.join(f"<tr><td>{esc(d.get('name','Unavailable'))}</td><td>{esc(d.get('specifier') or d.get('version') or 'Not specified')}</td><td>{esc(d.get('source') or 'Unavailable')}</td><td>{'Exact version' if d.get('pinned') else 'Not checked by OSV'}</td></tr>" for d in dependencies)
    trace = ''.join(f"<li><b>{esc(e.get('tool','').replace('_',' '))}</b> <span class='status'>{esc(e.get('status','unknown'))}</span><p>{esc(e.get('error') or 'Evidence retrieved')} · {esc(e.get('duration_ms',0))} ms</p></li>" for e in report.get('executions', []))
    if not rows:
        rows = '<tr><td colspan="5">No advisory details are available. Check audit coverage before drawing conclusions.</td></tr>'
    if not dep_rows:
        dep_rows = '<tr><td colspan="4">No dependency details are available.</td></tr>'
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Gitpilot audit — {esc(report['repository'])}</title><style>body{{font:15px system-ui;max-width:1050px;margin:60px auto;padding:24px;color:#18252a;background:#f6f8f7}}h1{{font-size:42px}}small{{display:block;color:#566;margin-top:6px}}table{{width:100%;border-collapse:collapse;background:white}}td,th{{padding:14px;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}}li{{margin:12px 0}}li p{{margin:4px 0;color:#566}}.status{{font-size:12px;text-transform:uppercase;color:#53684c;margin-left:8px}}</style><small>REPOGUARD / EVIDENCE REPORT</small><h1>{esc(report['repository'])}</h1><p>Generated {esc(report.get('completed_at') or 'Unavailable')} · {esc(report['status'])}</p><h2>Release readiness: {esc(readiness.get('status','unavailable'))}</h2><p>{esc(readiness.get('summary','No assessment available'))}</p><p>Read-only public repository assessment. Only declared exact Python versions are checked; unavailable or skipped checks do not establish safety.</p>{profile}<h2>Audit coverage</h2><ul>{checks or '<li>No checks available.</li>'}</ul><h2>Known vulnerability findings</h2><table><tr><th>Package and source</th><th>Advisory</th><th>Severity</th><th>Declared version</th><th>Summary</th></tr>{rows}</table><h2>Declared dependencies</h2><table><tr><th>Package</th><th>Requirement</th><th>Source</th><th>Coverage</th></tr>{dep_rows}</table><h2>Tool activity</h2><ul>{trace or '<li>No tool activity available.</li>'}</ul><p>The JSON export contains the complete machine-readable evidence.</p></html>'''
