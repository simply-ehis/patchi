"""
Tools API — execute tools via the unified tool executor.

POST /api/v2/tools/execute  — execute a tool by name with parameters
GET  /api/v2/tools/list     — list available tools
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from patchi.core.ai.tools.executor import ToolExecutor

router = APIRouter(prefix="/api/v2/tools", tags=["tools"])


class ToolExecuteRequest(BaseModel):
    tool: str
    parameters: dict = {}


class ToolExecuteResponse(BaseModel):
    success: bool
    result: dict | None = None
    error: str | None = None
    invocation_id: str = ""
    duration_ms: int = 0


@router.post("/execute", response_model=ToolExecuteResponse)
async def execute_tool(request: Request, payload: ToolExecuteRequest):
    """Execute a tool via the unified tool executor."""
    root = request.app.state.root
    executor = ToolExecutor(root)

    try:
        result = await executor.execute(
            tool_name=payload.tool,
            parameters=payload.parameters,
            invoked_by="api",
        )
        return ToolExecuteResponse(
            success=result.success,
            result=result.result,
            error=result.error,
            invocation_id=result.invocation_id,
            duration_ms=result.duration_ms,
        )
    except Exception as e:
        return ToolExecuteResponse(
            success=False,
            error=str(e),
        )


@router.get("/list")
async def list_tools(request: Request):
    """List all available tools with their schemas."""
    from patchi.core.ai.tools.registry import get_tool_registry

    registry = get_tool_registry()
    tools = registry.list_tools()

    return {
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "requires_confirmation": t.requires_confirmation,
                "side_effects": t.side_effects,
                "parameters": [
                    {
                        "name": p.name,
                        "type": p.type,
                        "required": p.required,
                        "description": p.description,
                    }
                    for p in t.parameters
                ],
            }
            for t in tools
        ]
    }
