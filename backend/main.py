from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[1] / '.env')

import asyncio
import os
from urllib.parse import urlsplit
import json
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from time import monotonic
from uuid import uuid4
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field
from backend import agent
from backend.mcp_client import discover
from backend.mcp_server.server import mcp
from backend.services.analyzer import SCANS, ACTIVITY, now, run_scan, call_tool
from backend.schemas import ScanResult
from backend.services.reports import render_html
from backend.integrations.github import normalize_repository

HOSTED = os.getenv('VERCEL') == '1'
from backend.services.receipts import seal, unseal

mcp_app = mcp.http_app(path='/', stateless_http=True)

TASKS: set[asyncio.Task] = set()
@asynccontextmanager
async def lifespan(app):
    async with mcp_app.lifespan(app):
        yield
    for task in TASKS:
        task.cancel()
    await asyncio.gather(*TASKS, return_exceptions=True)

app = FastAPI(title='Gitpilot MCP', version='2.0.0', lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1', '[::1]', 'testserver'] + (['*.vercel.app'] if HOSTED else []))
LIMITS = defaultdict(deque)

@app.middleware('http')
async def boundaries(request: Request, call_next):
    origin = request.headers.get('origin')
    same_host = bool(origin and urlsplit(origin).netloc == request.headers.get('host') and urlsplit(origin).scheme == 'https')
    if origin and not same_host and origin not in ('http://localhost:5173','http://127.0.0.1:5173','http://localhost:8000','http://127.0.0.1:8000'):
        return JSONResponse({'detail': 'Origin is not allowed'}, status_code=403)
    try:
        declared_length = int(request.headers.get('content-length', '0'))
        if declared_length < 0:
            raise ValueError
    except ValueError:
        return JSONResponse({'detail': 'Invalid Content-Length'}, status_code=400)
    body_limit = 4_000_000 if request.url.path in {'/api/reports/export','/api/chat','/api/mcp/resource'} else 200000
    if declared_length > body_limit:
        return JSONResponse({'detail': 'Request too large'}, status_code=413)
    if request.method == 'POST':
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > body_limit:
                return JSONResponse({'detail': 'Request too large'}, status_code=413)
        request._body = bytes(body)
    path = request.url.path
    if request.method == 'POST':
        category, limit = ('chat', 6) if path == '/api/chat' else ('scan', 10) if path == '/api/scans' else ('tool', 40)
        key = ((request.client.host if request.client else 'local'), category)
        queue, current = LIMITS[key], monotonic()
        while queue and current - queue[0] > 300:
            queue.popleft()
        if len(queue) >= limit:
            return JSONResponse({'detail': 'Request budget reached. Try again in five minutes.'}, status_code=429, headers={'Retry-After': '300'})
        queue.append(current)
    return await call_next(request)

class ScanRequest(BaseModel):
    repository: str = Field(min_length=3, max_length=2048)
    modules: list[str] = Field(default_factory=lambda: ['repository','dependencies','security','ci'], max_length=4)
class ToolRequest(BaseModel):
    name: str = Field(max_length=100)
    arguments: dict = Field(default_factory=dict)
class ResourceRequest(BaseModel):
    uri: str = Field(max_length=400)
    report_token: str | None = Field(default=None, max_length=4_000_000)
class HistoryMessage(BaseModel):
    role: str = Field(pattern='^(user|assistant)$')
    content: str = Field(max_length=6000)
class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=6000)
    repository: str = Field(max_length=2048)
    scan_id: str | None = None
    report_token: str | None = Field(default=None, max_length=4_000_000)
    history: list[HistoryMessage] = Field(default_factory=list, max_length=12)

def repository_id(value):
    try:
        return normalize_repository(value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

def get_scan(scan_id):
    if scan_id not in SCANS:
        raise HTTPException(404, 'Audit not found. In-memory audits expire after restart or after 40 newer scans.')
    return SCANS[scan_id]

@app.get('/api/health')
async def health():
    import os
    return {'status': 'ok', 'ai_configured': bool(os.getenv('NVIDIA_API_KEY')), 'model': agent.MODEL, 'hosting_mode': 'stateless' if HOSTED else 'local'}

@app.get('/api/scans')
async def scans():
    return [] if HOSTED else list(reversed(list(SCANS.values())))

@app.post('/api/scans', status_code=202)
async def create_scan(body: ScanRequest):
    repository = repository_id(body.repository)
    if not body.modules or set(body.modules) - {'repository','dependencies','security','ci'}:
        raise HTTPException(422, 'Select valid audit modules')
    if sum(s.status == 'running' for s in SCANS.values()) >= 4:
        raise HTTPException(429, 'Four audits are already queued. Wait for completion.')
    scan = ScanResult(id=uuid4().hex, repository=repository, created_at=now(), modules=body.modules)
    SCANS[scan.id] = scan
    if len(SCANS) > 40:
        for sid, old in list(SCANS.items()):
            if old.status != 'running':
                del SCANS[sid]
                break
    if HOSTED:
        try:
            await asyncio.wait_for(run_scan(scan), timeout=230)
        except asyncio.TimeoutError:
            scan.status = 'partial'
            scan.progress = 100
            scan.completed_at = now()
            scan.errors.append('Some checks exceeded the hosted scan time limit. Try fewer scan options.')
        try:
            scan.report_token = seal(scan)
        except ValueError as exc:
            raise HTTPException(503, str(exc)) from exc
        return scan
    task = asyncio.create_task(run_scan(scan))
    TASKS.add(task)
    task.add_done_callback(TASKS.discard)
    return scan

@app.get('/api/scans/{scan_id}')
async def scan_detail(scan_id: str):
    return get_scan(scan_id)

@app.get('/api/scans/{scan_id}/export')
async def export(scan_id: str, format: str = 'json'):
    return export_response(get_scan(scan_id), format)

def export_response(scan, format):
    if format not in ('json', 'html'):
        raise HTTPException(422, 'Choose json or html')
    if scan.status == 'running':
        raise HTTPException(409, 'Wait for the audit to finish before exporting')
    report = scan.model_dump(exclude={'report_token'})
    data = json.dumps(report, indent=2) if format == 'json' else render_html(report)
    headers = {'Content-Disposition': f'attachment; filename="repoguard-{scan.id[:8]}.{format}"'}
    if format == 'html':
        headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    return Response(data, media_type='application/json' if format == 'json' else 'text/html', headers=headers)

class ReportExportRequest(BaseModel):
    token: str = Field(max_length=4_000_000)
    format: str = Field(pattern='^(json|html)$')

def saved_report(token):
    try:
        return unseal(token)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

@app.post('/api/reports/export')
async def portable_export(body: ReportExportRequest):
    return export_response(saved_report(body.token), body.format)

@app.get('/api/activity')
async def activity():
    return [] if HOSTED else list(reversed(ACTIVITY))

@app.get('/api/mcp/discover')
async def discovery():
    return await discover()

@app.post('/api/mcp/call')
async def tool_call(body: ToolRequest):
    catalog = await discover()
    if body.name not in {t['name'] for t in catalog['tools']}:
        raise HTTPException(422, 'Tool is not allowed')
    result, execution = await call_tool(body.name, body.arguments)
    return {'result': result, 'execution': execution}

@app.post('/api/mcp/resource')
async def resource(body: ResourceRequest):
    from fastmcp import Client
    from backend.mcp_server.server import REPORT_CONTEXT
    context_token = None
    if body.report_token:
        scan = saved_report(body.report_token)
        if body.uri == f'repoguard://repository/{scan.repository}/report':
            context_token = REPORT_CONTEXT.set(scan.model_dump(exclude={'report_token'}))
    try:
        async with Client(mcp) as client:
            blocks = await client.read_resource(body.uri)
            return {'result': [b.model_dump(mode='json') for b in blocks]}
    except Exception as exc:
        raise HTTPException(422, str(exc)[:500]) from exc
    finally:
        if context_token is not None:
            REPORT_CONTEXT.reset(context_token)

@app.post('/api/mcp/prompt')
async def prompt(body: ToolRequest):
    from fastmcp import Client
    try:
        async with Client(mcp) as client:
            result = await client.get_prompt(body.name, body.arguments)
            return {'result': result.model_dump(mode='json')}
    except Exception as exc:
        raise HTTPException(422, str(exc)[:500]) from exc

CHAT_LOCK = asyncio.Semaphore(1)
@app.post('/api/chat')
async def chat(body: ChatRequest):
    repository = repository_id(body.repository)
    scan = saved_report(body.report_token) if body.report_token else get_scan(body.scan_id) if body.scan_id else None
    if scan and scan.repository != repository:
        raise HTTPException(422, 'Audit repository does not match the conversation repository')
    if CHAT_LOCK.locked():
        raise HTTPException(429, 'An assistant request is already running')
    try:
        async with CHAT_LOCK:
            return await asyncio.wait_for(agent.chat(body.message, repository, body.history, scan), timeout=240)
    except (ValueError, httpx.HTTPError) as exc:
        raise HTTPException(503, str(exc)[:300] if isinstance(exc, ValueError) else 'NVIDIA service is temporarily unavailable') from exc
    except asyncio.TimeoutError as exc:
        raise HTTPException(504, 'Assistant timed out. Try a narrower question.') from exc

import httpx
@app.api_route('/mcp', methods=['GET', 'POST', 'DELETE'], include_in_schema=False)
async def mcp_without_slash():
    return RedirectResponse('/mcp/', status_code=307)

app.mount('/mcp', mcp_app)
dist = Path(__file__).resolve().parents[1] / 'frontend' / 'dist'
if dist.exists():
    app.mount('/', StaticFiles(directory=dist, html=True), name='frontend')
