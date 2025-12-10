#!/usr/bin/env python3
"""
MCP Server for PCILeech

Provides Model Context Protocol interface for PCILeech memory operations.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import AnyUrl

from pcileech_wrapper import PCILeechWrapper, PCILeechError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-server-pcileech")

# Initialize PCILeech wrapper (lazy initialization)
pcileech = None

# Initialize MCP server
server = Server("mcp-server-pcileech")


def get_pcileech():
    """Get or initialize PCILeech wrapper."""
    global pcileech
    if pcileech is None:
        try:
            pcileech = PCILeechWrapper()
        except Exception as e:
            logger.error(f"Failed to initialize PCILeech: {e}")
            raise
    return pcileech


def format_memory_dump(data: bytes, address: str, show_ascii: bool = True) -> str:
    """
    Format memory data as hex dump (similar to hexdump -C).

    Args:
        data: Raw memory bytes
        address: Starting address (hex string)
        show_ascii: Whether to show ASCII column

    Returns:
        Formatted hex dump string
    """
    lines = []
    addr_int = int(address.replace('0x', ''), 16)

    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]

        # Format address
        line_addr = f"0x{addr_int + i:016x}"

        # Format hex bytes
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        # Pad if less than 16 bytes
        hex_part = hex_part.ljust(47)  # 16 bytes * 2 chars + 15 spaces

        # Format ASCII
        if show_ascii:
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            line = f"{line_addr}: {hex_part}  |{ascii_part}|"
        else:
            line = f"{line_addr}: {hex_part}"

        lines.append(line)

    return '\n'.join(lines)


def format_byte_array(data: bytes) -> str:
    """Format memory as byte array (decimal)."""
    return str(list(data))


def format_dword_array(data: bytes) -> str:
    """Format memory as DWORD array (little-endian uint32)."""
    dwords = []
    for i in range(0, len(data), 4):
        if i + 4 <= len(data):
            dword = int.from_bytes(data[i:i+4], byteorder='little', signed=False)
            dwords.append(f"0x{dword:08x}")
    return str(dwords)


def format_ascii_view(data: bytes) -> str:
    """Format memory as ASCII text (non-printable as dots)."""
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)


@server.list_tools()
async def list_tools() -> list[Tool]:
    """
    List available MCP tools.

    Returns three tools for memory operations:
    - memory_read: Read memory from address
    - memory_write: Write data to memory address
    - memory_format: Read and format memory in multiple views
    """
    return [
        Tool(
            name="memory_read",
            description="Read memory from specified address using PCILeech DMA",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address in hex format (e.g., '0x1000' or '1000')"
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to read",
                        "minimum": 1,
                        "maximum": 1048576  # 1MB max
                    }
                },
                "required": ["address", "length"]
            }
        ),
        Tool(
            name="memory_write",
            description="Write data to memory at specified address using PCILeech DMA",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address in hex format (e.g., '0x1000' or '1000')"
                    },
                    "data": {
                        "type": "string",
                        "description": "Hex string of data to write (e.g., '48656c6c6f')"
                    }
                },
                "required": ["address", "data"]
            }
        ),
        Tool(
            name="memory_format",
            description="Read memory and format in multiple views (hex dump, ASCII, byte array, DWORD array) for AI analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address in hex format (e.g., '0x1000' or '1000')"
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to read",
                        "minimum": 1,
                        "maximum": 4096  # 4KB max for formatted output
                    },
                    "formats": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["hexdump", "ascii", "bytes", "dwords", "raw"]
                        },
                        "description": "Output formats to include (default: all)",
                        "default": ["hexdump", "ascii", "bytes", "dwords", "raw"]
                    }
                },
                "required": ["address", "length"]
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """
    Handle tool calls from MCP client.

    Args:
        name: Tool name
        arguments: Tool arguments

    Returns:
        List of text content results
    """
    try:
        if name == "memory_read":
            return await handle_memory_read(arguments)
        elif name == "memory_write":
            return await handle_memory_write(arguments)
        elif name == "memory_format":
            return await handle_memory_format(arguments)
        else:
            return [TextContent(
                type="text",
                text=f"Unknown tool: {name}"
            )]
    except PCILeechError as e:
        logger.error(f"PCILeech error in {name}: {e}")
        return [TextContent(
            type="text",
            text=f"PCILeech error: {str(e)}"
        )]
    except Exception as e:
        logger.error(f"Unexpected error in {name}: {e}", exc_info=True)
        return [TextContent(
            type="text",
            text=f"Internal error: {str(e)}"
        )]


async def handle_memory_read(args: dict[str, Any]) -> list[TextContent]:
    """Handle memory_read tool."""
    address = args["address"]
    length = args["length"]

    logger.info(f"Reading {length} bytes from {address}")

    # Read memory
    pcileech = get_pcileech()
    data = pcileech.read_memory(address, length)

    # Format result
    result = {
        "address": address,
        "length": length,
        "bytes_read": len(data),
        "data_hex": data.hex(),
        "timestamp": datetime.now().isoformat()
    }

    return [TextContent(
        type="text",
        text=f"Successfully read {len(data)} bytes from {address}\n\n" +
             f"Hex data: {data.hex()}\n\n" +
             f"Result: {result}"
    )]


async def handle_memory_write(args: dict[str, Any]) -> list[TextContent]:
    """Handle memory_write tool."""
    address = args["address"]
    data_hex = args["data"]

    # Validate hex string
    try:
        data = bytes.fromhex(data_hex)
    except ValueError as e:
        return [TextContent(
            type="text",
            text=f"Invalid hex data: {str(e)}"
        )]

    logger.info(f"Writing {len(data)} bytes to {address}")

    # Write memory
    pcileech = get_pcileech()
    success = pcileech.write_memory(address, data)

    result = {
        "address": address,
        "bytes_written": len(data),
        "success": success,
        "timestamp": datetime.now().isoformat()
    }

    return [TextContent(
        type="text",
        text=f"Successfully wrote {len(data)} bytes to {address}\n\n" +
             f"Data: {data_hex}\n\n" +
             f"Result: {result}"
    )]


async def handle_memory_format(args: dict[str, Any]) -> list[TextContent]:
    """Handle memory_format tool."""
    address = args["address"]
    length = args["length"]
    formats = args.get("formats", ["hexdump", "ascii", "bytes", "dwords", "raw"])

    logger.info(f"Reading and formatting {length} bytes from {address}")

    # Read memory
    pcileech = get_pcileech()
    data = pcileech.read_memory(address, length)

    # Build formatted output
    output_parts = [
        f"Memory at {address} ({length} bytes)\n",
        "=" * 80,
        ""
    ]

    if "hexdump" in formats:
        output_parts.extend([
            "## Hex Dump (with ASCII):",
            format_memory_dump(data, address),
            ""
        ])

    if "ascii" in formats:
        output_parts.extend([
            "## ASCII View:",
            format_ascii_view(data),
            ""
        ])

    if "bytes" in formats:
        output_parts.extend([
            "## Byte Array (decimal):",
            format_byte_array(data),
            ""
        ])

    if "dwords" in formats:
        output_parts.extend([
            "## DWORD Array (little-endian uint32):",
            format_dword_array(data),
            ""
        ])

    if "raw" in formats:
        output_parts.extend([
            "## Raw Hex:",
            data.hex(),
            ""
        ])

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def main():
    """Run the MCP server."""
    logger.info("Starting MCP Server for PCILeech")

    # Don't verify connection during startup - it will be verified on first use
    # This prevents startup failures if hardware is temporarily unavailable

    # Run server using stdio transport
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        logger.info("Server running on stdio")
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
