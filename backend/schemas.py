"""Shared wire contracts; nullable evidence is never treated as a passing check."""
from typing import Any, Literal
from pydantic import BaseModel, Field

class DependencyFinding(BaseModel):
    name: str
    specifier: str = ''
    version: str | None = None
    source: str = ''
    pinned: bool = False

class SecurityFinding(BaseModel):
    id: str
    package: str
    version: str
    source: str = ''
    sources: list[str] = Field(default_factory=list)
    summary: str = ''
    severity: str = 'UNKNOWN'
    aliases: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    kev: bool = False

class ToolExecution(BaseModel):
    id: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: str
    duration_ms: int = 0
    timestamp: str
    result: Any = None
    error: str | None = None

class ReadinessResult(BaseModel):
    status: str
    score: int
    checks: list[dict[str, Any]]
    summary: str

class ScanResult(BaseModel):
    id: str
    repository: str
    status: str = 'running'
    created_at: str
    completed_at: str | None = None
    modules: list[str] = Field(default_factory=list)
    repository_info: dict[str, Any] | None = None
    overview: dict[str, Any] | None = None
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    readiness: dict[str, Any] | None = None
    checks: list[dict[str, Any]] = Field(default_factory=list)
    executions: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    report_token: str | None = None
    progress: int = 0
