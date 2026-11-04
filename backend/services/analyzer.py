"""Bounded audit controller; all evidence crosses the MCP client boundary."""
import asyncio
import re
from collections import OrderedDict
from datetime import datetime, timezone
from time import monotonic
from uuid import uuid4
from backend.schemas import ScanResult, ToolExecution
from backend.mcp_client import execute

SCANS: OrderedDict[str, ScanResult] = OrderedDict()
ACTIVITY: list[dict] = []
SCAN_LOCK = asyncio.Semaphore(2)

def now():
    return datetime.now(timezone.utc).isoformat()

async def call_tool(name: str, arguments: dict):
    start = monotonic()
    event = ToolExecution(id=uuid4().hex, tool=name, arguments=arguments, status='running', timestamp=now())
    try:
        result = await asyncio.wait_for(execute(name, arguments), timeout=90)
        event.status, event.result = 'completed', result
        event.duration_ms = int((monotonic() - start) * 1000)
        return result, event.model_dump()
    except Exception as exc:
        # Provider adapters return safe errors; do not include request headers or secrets.
        event.status = 'failed'
        event.error = 'This check took too long. Try scanning again in a moment.' if isinstance(exc, TimeoutError) else str(exc)[:700] or 'This check could not finish. Please try again.'
        event.error = re.sub(r"^Error calling tool '[^']+':\s*", '', event.error)
        event.duration_ms = int((monotonic() - start) * 1000)
        return None, event.model_dump()
    finally:
        event.duration_ms = int((monotonic() - start) * 1000)
        ACTIVITY.append(event.model_dump())
        del ACTIVITY[:-200]

async def run_scan(scan: ScanResult):
    async with SCAN_LOCK:
        evidence = {}
        async def step(name, args, label):
            result, event = await call_tool(name, args)
            # Set duration from the finalized activity event.
            if ACTIVITY and ACTIVITY[-1]['id'] == event['id']:
                event = ACTIVITY[-1].copy()
            scan.executions.append(event)
            ok = result is not None
            coverage = result.get('coverage') if isinstance(result, dict) else None
            tool_status = result.get('status') if isinstance(result, dict) else None
            unavailable = coverage in ('partial', 'unknown') or (name == 'inspect_ci_status' and tool_status in ('unknown', 'pending'))
            failed = name == 'inspect_ci_status' and tool_status == 'failure'
            detail = event.get('error') or ('CI workflow failed on the default branch.' if failed else 'CI has not completed or is unavailable.' if name == 'inspect_ci_status' and unavailable else 'Incomplete coverage: ' + '; '.join(str(x) for x in result.get('unsupported', result.get('notes', [])))[:600] if unavailable else 'Evidence retrieved through MCP')
            if name == 'check_known_exploitation' and (evidence.get('vulnerabilities') or {}).get('coverage') != 'complete':
                unavailable = True
                detail = event.get('error') or 'Only returned advisories were checked for known exploitation. The package scan has incomplete coverage.'
            scan.checks.append({'name': label, 'status': 'failed' if failed else 'unavailable' if not ok or unavailable else 'passed', 'detail': detail})
            if not ok:
                scan.errors.append(f"{label}: {event.get('error', 'Unavailable')}")
            scan.progress = min(94, scan.progress + 12)
            return result
        try:
            evidence['repository_info'] = await step('get_repository_info', {'repository': scan.repository}, 'Repository metadata')
            scan.repository_info = evidence['repository_info']
            if scan.repository_info is None:
                evidence['errors'] = scan.errors
                scan.readiness = await step('evaluate_release_readiness', {'evidence': evidence}, 'Release readiness')
                scan.status = 'failed'
                return
            if 'repository' in scan.modules:
                scan.overview = await step('get_repository_overview', {'repository': scan.repository}, 'Repository overview')
                await step('get_recent_commits', {'repository': scan.repository}, 'Recent commits')
                await step('get_pull_requests', {'repository': scan.repository}, 'Pull requests')
                await step('get_open_issues', {'repository': scan.repository}, 'Open issues')
            if 'ci' in scan.modules:
                evidence['ci'] = await step('inspect_ci_status', {'repository': scan.repository}, 'CI workflows')
            if 'dependencies' in scan.modules or 'security' in scan.modules:
                evidence['dependencies'] = await step('parse_python_dependencies', {'repository': scan.repository}, 'Python dependencies')
                scan.dependencies = (evidence['dependencies'] or {}).get('dependencies', [])
            if 'security' in scan.modules and evidence.get('dependencies') is not None:
                evidence['vulnerabilities'] = await step('scan_known_vulnerabilities', {'dependencies': scan.dependencies}, 'OSV vulnerabilities')
                scan.findings = (evidence['vulnerabilities'] or {}).get('findings', [])
                if evidence['vulnerabilities'] is not None:
                    evidence['exploitation'] = await step('check_known_exploitation', {'findings': scan.findings}, 'CISA known exploitation')
                    if evidence['exploitation']:
                        scan.findings = evidence['exploitation'].get('findings', scan.findings)
            evidence['errors'] = scan.errors
            scan.readiness = await step('evaluate_release_readiness', {'evidence': evidence}, 'Release readiness')
            scan.status = 'partial' if scan.errors or any(c['status'] == 'unavailable' for c in scan.checks) else 'completed'
        except Exception:
            scan.errors.append('Audit controller could not finish. See completed tool executions for evidence.')
            scan.status = 'failed'
        finally:
            scan.progress, scan.completed_at = 100, now()
            from backend.mcp_server.server import REPORTS
            REPORTS[scan.repository] = scan.model_dump()
            if len(REPORTS) > 40:
                REPORTS.pop(next(iter(REPORTS)))
