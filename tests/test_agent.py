"""Verify agent tool orchestration without spending provider credits."""
import json
from types import SimpleNamespace
import pytest
from backend import agent

@pytest.mark.asyncio
async def test_agent_uses_real_discovered_schema_and_repository_scope(monkeypatch):
    monkeypatch.setenv('NVIDIA_API_KEY', 'test-credential')
    async def discover():
        return {'tools': [{'name': 'get_repository_info', 'description': 'Metadata', 'inputSchema': {'type': 'object', 'properties': {'repository': {'type': 'string'}}}}]}
    calls, payloads = [], []
    async def call_tool(name, args):
        calls.append((name, args))
        return {'full_name': args['repository']}, {'tool': name, 'status': 'completed'}
    responses = [
        {'role': 'assistant', 'content': None, 'tool_calls': [{'id': 'call_1', 'type': 'function', 'function': {'name': 'get_repository_info', 'arguments': json.dumps({'repository': 'other/repo'})}}]},
        {'role': 'assistant', 'content': 'Metadata retrieved using get_repository_info.'},
    ]
    class FakeClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def post(self, url, headers, json):
            payloads.append(json)
            assert url == 'https://integrate.api.nvidia.com/v1/chat/completions'
            return SimpleNamespace(status_code=200, json=lambda: {'choices': [{'message': responses.pop(0)}]})
    monkeypatch.setattr(agent, 'discover', discover)
    monkeypatch.setattr(agent, 'call_tool', call_tool)
    monkeypatch.setattr(agent.httpx, 'AsyncClient', FakeClient)
    result = await agent.chat('Analyze', 'pallets/flask', [])
    assert calls == [('get_repository_info', {'repository': 'pallets/flask'})]
    assert result['sources'] == ['get_repository_info']
    assert payloads[0]['tools'][0]['function']['parameters']['type'] == 'object'
    assert any(m['role'] == 'tool' for m in payloads[1]['messages'])

@pytest.mark.asyncio
async def test_agent_total_tool_budget(monkeypatch):
    monkeypatch.setenv('NVIDIA_API_KEY', 'test-credential')
    async def discover():
        return {'tools': [{'name': 'inspect_ci_status', 'description': '', 'inputSchema': {'type': 'object'}}]}
    count = 0
    async def call_tool(name, args):
        nonlocal count
        count += 1
        return {'status': 'unknown'}, {'tool': name}
    class FakeClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def post(self, url, headers, json):
            if 'tools' not in json:
                msg = {'role': 'assistant', 'content': 'Budget exhausted; evidence is incomplete.'}
            else:
                msg = {'role': 'assistant', 'content': None, 'tool_calls': [{'id': str(i), 'type': 'function', 'function': {'name': 'inspect_ci_status', 'arguments': '{}'}} for i in range(20)]}
            return SimpleNamespace(status_code=200, json=lambda: {'choices': [{'message': msg}]})
    monkeypatch.setattr(agent, 'discover', discover)
    monkeypatch.setattr(agent, 'call_tool', call_tool)
    monkeypatch.setattr(agent.httpx, 'AsyncClient', FakeClient)
    result = await agent.chat('Check CI', 'pallets/flask', [])
    assert count == 12
    assert len(result['executions']) == 12

@pytest.mark.parametrize('payload',[{}, {'choices':[]}, {'choices':[{'message':{'content':42}}]}, {'choices':[{'message':{'tool_calls':[{}]}}]}])
async def test_malformed_ai_responses_return_clear_errors(monkeypatch,payload):
    monkeypatch.setenv('NVIDIA_API_KEY','test-only')
    async def discover():return {'tools':[]}
    class FakeClient:
        def __init__(self,**kwargs):pass
        async def __aenter__(self):return self
        async def __aexit__(self,*args):pass
        async def post(self,*args,**kwargs):return SimpleNamespace(status_code=200,json=lambda:payload)
    monkeypatch.setattr(agent,'discover',discover)
    monkeypatch.setattr(agent.httpx,'AsyncClient',FakeClient)
    with pytest.raises(ValueError,match='unreadable response'):
        await agent.chat('Question','owner/repo',[])
