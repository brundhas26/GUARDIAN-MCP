
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "app.mcp_server.local_server"],
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools_result = await session.list_tools()
            tool_names = [tool.name for tool in tools_result.tools]

            print("Available MCP tools:", tool_names)
            assert "read_report" in tool_names
            assert "send_external" in tool_names

            print("\nTEST 1: Read an approved public report")
            read_result = await session.call_tool(
                "read_report",
                {"filename": "public.txt"},
            )

            print("MCP reported error:", read_result.is_error)
            assert not read_result.is_error, (
                "The approved public report should be readable."
            )
            print("PASS: Approved report read succeeded.")

            print("\nTEST 2: Attempt an external send after reading")
            send_result = await session.call_tool(
                "send_external",
                {"content": "Harmless security test message"},
            )

            print("MCP reported error:", send_result.is_error)
            assert send_result.is_error, (
                "GUARDIAN should block the external send."
            )
            print("PASS: External send was blocked.")

            print("\nSUCCESS: MCP sequence security test passed.")
            print("No external transmission was implemented.")


if __name__ == "__main__":
    asyncio.run(main())
