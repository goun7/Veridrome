"""
Veridrome Core: Model Context Protocol (MCP) Sandbox & Test Runner
Ajanların araç çağırma (tool-calling), kaynak okuma ve prompt şablonu yürütmelerini
izole TEE ortamında denetleyen referans sunucu.
"""

from __future__ import annotations
import json
from typing import Any, Callable, Dict, List, Optional


class MCPSandboxServer:
    """
    Model Context Protocol (MCP) uyumlu mock ve denetim sunucusu.
    Ajanın çağırdığı araçları, parametreleri ve sırayı W1a değişmezleri için kaydeder.
    """

    def __init__(self, server_name: str = "veridrome-mcp-sandbox", version: str = "1.0.0"):
        self.server_name = server_name
        self.version = version
        self.tools: Dict[str, Dict[str, Any]] = {}
        self.handlers: Dict[str, Callable[..., Any]] = {}
        self.audit_log: List[Dict[str, Any]] = []

    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[..., Any],
    ) -> None:
        """Sunucuya yeni bir MCP aracı kaydeder."""
        self.tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        }
        self.handlers[name] = handler

    def list_tools(self) -> List[Dict[str, Any]]:
        """Kayıtlı tüm araçların manifestosunu listeler."""
        return list(self.tools.values())

    def handle_jsonrpc(self, request_payload: str) -> str:
        """Gelen JSON-RPC 2.0 MCP isteğini işler."""
        try:
            req = json.loads(request_payload)
        except Exception as e:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
            })

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "tools/list":
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.list_tools()},
            })

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            result = self.call_tool(tool_name, args)
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            })

        else:
            return json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            })

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Aracı doğrudan çağırır ve audit loguna ekler."""
        self.audit_log.append({
            "tool": tool_name,
            "arguments": arguments,
        })

        if tool_name not in self.handlers:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Kayıtsız araç çağrısı: '{tool_name}'"}],
            }

        try:
            handler = self.handlers[tool_name]
            output = handler(**arguments)
            return {
                "isError": False,
                "content": [{"type": "text", "text": json.dumps(output) if isinstance(output, (dict, list)) else str(output)}],
            }
        except Exception as e:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Araç yürütme hatası: {str(e)}"}],
            }

    def verify_called_sequence(self, expected_tools: List[str]) -> bool:
        """Ajanın tam olarak beklenen araçları sırasıyla çağırıp çağırmadığını doğrular."""
        actual = [log["tool"] for log in self.audit_log]
        return actual == expected_tools

    def get_tool_call_arguments(self, tool_name: str) -> List[Dict[str, Any]]:
        """Belirtilen aracın tüm çağrılarındaki argümanları döndürür."""
        return [log["arguments"] for log in self.audit_log if log["tool"] == tool_name]
