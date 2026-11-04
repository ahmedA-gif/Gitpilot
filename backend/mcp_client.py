"""Independent MCP protocol client used by scans, explorer, and NVIDIA agent."""
import asyncio
import json
from fastmcp import Client
from backend.mcp_server.server import mcp

ALLOWED_TOOLS={'get_repository_info','get_repository_overview','get_repository_structure','get_recent_commits','get_open_issues','get_pull_requests','inspect_ci_status','find_dependency_manifests','parse_python_dependencies','get_package_release_info','scan_known_vulnerabilities','check_known_exploitation','evaluate_release_readiness'}

def plain(value):
    if hasattr(value,'model_dump'):
        return value.model_dump(mode='json',by_alias=True)
    if isinstance(value,list):
        return [plain(x) for x in value]
    if isinstance(value,dict):
        return {str(k):plain(v) for k,v in value.items()}
    return value

async def discover() -> dict:
    async with Client(mcp) as client:
        tools=await client.list_tools()
        resources=await client.list_resources()
        templates=await client.list_resource_templates()
        prompts=await client.list_prompts()
        return {'tools':[{'name':x.name,'description':x.description,'inputSchema':x.inputSchema} for x in tools], 'resources':plain(resources),'templates':plain(templates),'prompts':plain(prompts)}

async def execute(name: str, arguments: dict) -> dict:
    if name not in ALLOWED_TOOLS:
        raise ValueError('Tool is not allowed')
    async with Client(mcp) as client:
        async with asyncio.timeout(180):
            result=await client.call_tool(name,arguments)
        if result.is_error:
            raise ValueError('MCP tool execution failed')
        return plain(result.data)

async def read_resource(uri: str):
    if not uri.startswith('repoguard://') or len(uri)>500:
        raise ValueError('Resource URI is not allowed')
    async with Client(mcp) as client:
        return plain(await client.read_resource(uri))

async def get_prompt(name: str, arguments: dict):
    if name not in {'analyze_repository','explain_security_finding','prepare_release_checklist'}:
        raise ValueError('Prompt is not allowed')
    async with Client(mcp) as client:
        return plain(await client.get_prompt(name,arguments))

async def main():
    import argparse
    parser=argparse.ArgumentParser(description='Independent RepoGuard MCP client')
    parser.add_argument('tool',nargs='?')
    parser.add_argument('--arguments',default='{}')
    args=parser.parse_args()
    print(json.dumps(await execute(args.tool,json.loads(args.arguments)) if args.tool else await discover(),indent=2))

if __name__=='__main__':
    asyncio.run(main())
