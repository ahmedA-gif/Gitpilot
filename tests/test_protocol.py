import pytest
from backend.mcp_client import discover, execute, read_resource, get_prompt

@pytest.mark.asyncio
async def test_protocol_discovery_resources_prompts_and_execution():
    catalog=await discover()
    assert len(catalog['tools'])==13
    from backend.mcp_client import ALLOWED_TOOLS
    assert {tool['name'] for tool in catalog['tools']} == ALLOWED_TOOLS
    assert len(catalog['resources'])==2
    assert len(catalog['templates'])==3
    assert len(catalog['prompts'])==3
    assert all(x['inputSchema']['type']=='object' for x in catalog['tools'])
    assert await read_resource('repoguard://about')
    assert await get_prompt('analyze_repository',{'repository':'pallets/flask'})
    result=await execute('evaluate_release_readiness',{'evidence':{}})
    assert result['status']=='incomplete'
    with pytest.raises(ValueError):
        await execute('delete_repository',{})
