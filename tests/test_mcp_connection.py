
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


PROJECT_ROOT = Path(__file__).resolve().parents[1]


async def main():
    server_parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "app.mcp_server.local_server"],
        cwd=str(PROJECT_ROOT),
    )

    async with stdio_client(server_parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            print("Connected to MCP server.")

            tools = await session.list_tools()
            print("Available tools:", [tool.name for tool in tools.tools])

            # Test 1: An approved calculation should succeed.
            print("\nTEST 1: Approved calculation")
            allowed = await session.call_tool(
                "calculate_total",
                arguments={"numbers": [10, 20, 30]},
            )

            print("Result:", allowed.structured_content)
            print("MCP reported error:", allowed.is_error)

            assert not allowed.is_error, "Approved calculation unexpectedly failed"
            assert allowed.structured_content["result"] == 60.0

            print("PASS: Approved request succeeded.")

            # Test 2: An unapproved filename should be blocked.
            print("\nTEST 2: Unauthorized report access")
            blocked = await session.call_tool(
                "read_report",
                arguments={"filename": "secret.txt"},
            )

            print("MCP reported error:", blocked.is_error)
            print("Response:", blocked.content)

            assert blocked.is_error, "Unauthorized report access was not blocked"

            print("PASS: Unauthorized request was rejected.")

            print("\nBoth MCP security integration checks passed.")


if __name__ == "__main__":
    asyncio.run(main())
