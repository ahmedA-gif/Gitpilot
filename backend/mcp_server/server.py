"""Gitpilot MCP server: tools, resources, templates, and prompts."""
from contextvars import ContextVar
from fastmcp import FastMCP
from backend.integrations import github, dependencies, pypi, osv, cisa
from backend.services.readiness import evaluate

mcp=FastMCP('Gitpilot MCP 2.0', instructions='Read-only evidence-based analysis of public Python repositories. Missing evidence must be reported as unknown.')
REPORTS: dict[str, dict] = {}
REPORT_CONTEXT: ContextVar[dict | None] = ContextVar('selected_report', default=None)

@mcp.tool()
async def get_repository_info(repository: str) -> dict:
    """Retrieve public GitHub repository metadata and default branch."""
    return await github.repository_info(repository)

@mcp.tool()
async def get_repository_overview(repository: str) -> dict:
    """Retrieve README, languages, releases, branches, contributors, community files and file paths with explicit section coverage."""
    return await github.repository_overview(repository)

@mcp.tool()
async def get_repository_structure(repository: str) -> dict:
    """List the bounded public repository file tree; reports truncation."""
    return await github.structure(repository)

@mcp.tool()
async def get_recent_commits(repository: str) -> dict:
    """Get the ten most recent commits on the default branch."""
    return await github.commits(repository)

@mcp.tool()
async def get_open_issues(repository: str) -> dict:
    """Get a bounded first page of open issues, excluding pull requests."""
    return await github.issues(repository)

@mcp.tool()
async def get_pull_requests(repository: str) -> dict:
    """Get a bounded first page of open pull requests."""
    return await github.pull_requests(repository)

@mcp.tool()
async def inspect_ci_status(repository: str) -> dict:
    """Assess available public GitHub Actions evidence on the default branch."""
    return await github.ci_status(repository)

@mcp.tool()
async def find_dependency_manifests(repository: str) -> dict:
    """Discover up to fifteen requirements text files and pyproject.toml manifests."""
    return await github.manifests(repository)

@mcp.tool()
async def parse_python_dependencies(repository: str) -> dict:
    """Read and parse supported public Python manifests without executing code."""
    return await dependencies.parse_repository(repository)

@mcp.tool()
async def get_package_release_info(package: str) -> dict:
    """Retrieve latest package release metadata directly from PyPI."""
    return await pypi.release_info(package)

@mcp.tool()
async def scan_known_vulnerabilities(dependencies: list[dict]) -> dict:
    """Query OSV for known advisories affecting exact pinned Python packages."""
    return await osv.scan(dependencies)

@mcp.tool()
async def check_known_exploitation(findings: list[dict]) -> dict:
    """Match advisory CVE aliases against the live cached CISA KEV catalog."""
    return await cisa.check(findings)

@mcp.tool()
async def evaluate_release_readiness(evidence: dict) -> dict:
    """Apply deterministic release rules to supplied evidence and explicit coverage."""
    return evaluate(evidence)

@mcp.resource('repoguard://about')
def about() -> dict:
    return {'name':'Gitpilot MCP','version':'2.0','tools':13,'scope':'Read-only public GitHub repositories; Python package security checks','providers':['GitHub','PyPI','OSV','CISA KEV'],'storage':'Local process memory; signed browser-session reports when hosted'}

@mcp.resource('repoguard://audit-policy')
def audit_policy() -> dict:
    return {'policy':'Unknown evidence never passes readiness. Exact pinned versions only for OSV. No transitive resolution. No repository code execution. No authentication or persistent database.','limits':{'manifests':15,'dependencies':150,'advisory_details':60,'ai_rounds':5,'ai_tool_calls':12}}

@mcp.resource('repoguard://repository/{owner}/{repo}/overview')
async def overview(owner: str, repo: str) -> dict:
    return await github.repository_overview(owner+'/'+repo)

@mcp.resource('repoguard://repository/{owner}/{repo}/dependencies')
async def repository_dependencies(owner: str, repo: str) -> dict:
    return await dependencies.parse_repository(owner+'/'+repo)

@mcp.resource('repoguard://repository/{owner}/{repo}/report')
def latest_report(owner: str, repo: str) -> dict:
    repository=github.normalize_repository(owner+'/'+repo)
    selected = REPORT_CONTEXT.get()
    if selected and selected.get('repository') == repository:
        return selected
    if repository not in REPORTS:
        return {'repository':repository,'status':'unavailable','detail':'No report exists in this process session.'}
    return REPORTS[repository]

@mcp.prompt()
def analyze_repository(repository: str) -> str:
    github.normalize_repository(repository)
    return f'Analyze public repository {repository} using Gitpilot MCP tools. Cite tool evidence, explain coverage gaps, and distinguish unknown checks from passing checks. Do not execute repository code.'

@mcp.prompt()
def explain_security_finding(advisory_id: str, package: str) -> str:
    return f'Explain advisory {advisory_id[:150]} affecting package {package[:100]}. Use real OSV and CISA tool evidence; describe affected versions, known fixes, exploitation evidence, and uncertainty. Do not invent a patch version.'

@mcp.prompt()
def prepare_release_checklist(repository: str) -> str:
    github.normalize_repository(repository)
    return f'Prepare a release checklist for {repository} using repository metadata, public CI, dependency coverage, OSV advisories, CISA evidence, and evaluate_release_readiness. List blocking and incomplete evidence explicitly.'

if __name__=='__main__':
    mcp.run(transport='stdio')
