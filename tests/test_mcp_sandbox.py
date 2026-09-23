import json
import pytest
from veridrome.core.mcp_sandbox import MCPSandboxServer


def test_mcp_sandbox_tool_registration_and_execution():
    server = MCPSandboxServer()

    def add_numbers(a: int, b: int) -> int:
        return a + b

    server.register_tool(
        name="add",
        description="İki sayıyı toplar",
        input_schema={"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}}},
        handler=add_numbers,
    )

    tools = server.list_tools()
    assert len(tools) == 1
    assert tools[0]["name"] == "add"

    # JSON-RPC tools/call çağrısı
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "tools/call",
        "params": {"name": "add", "arguments": {"a": 15, "b": 27}},
    })

    resp = json.loads(server.handle_jsonrpc(req))
    assert resp["id"] == "1"
    assert resp["result"]["isError"] is False
    assert resp["result"]["content"][0]["text"] == "42"

    # Audit log denetimi
    assert server.verify_called_sequence(["add"]) is True
    args = server.get_tool_call_arguments("add")
    assert args == [{"a": 15, "b": 27}]


def test_mcp_sandbox_unknown_tool_error():
    server = MCPSandboxServer()
    req = json.dumps({
        "jsonrpc": "2.0",
        "id": "2",
        "method": "tools/call",
        "params": {"name": "unregistered_tool", "arguments": {}},
    })

    resp = json.loads(server.handle_jsonrpc(req))
    assert resp["result"]["isError"] is True
    assert "Kayıtsız araç" in resp["result"]["content"][0]["text"]
