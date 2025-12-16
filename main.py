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

from pcileech_wrapper import (
    PCILeechWrapper, PCILeechError, DeviceNotFoundError,
    MemoryAccessError, SignatureNotFoundError, ProbeNotSupportedError, KMDError
)

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


def validate_mutually_exclusive(args: dict, *param_names: str) -> str | None:
    """
    Validate that only one of the specified parameters is provided.

    Returns:
        Error message if validation fails, None otherwise.
    """
    provided = [name for name in param_names if args.get(name) is not None]
    if len(provided) > 1:
        return f"Parameters {', '.join(provided)} are mutually exclusive - only one can be specified"
    return None


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
            description="Read memory from specified address using PCILeech DMA. Supports both physical addresses and process virtual addresses.",
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
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID for virtual address mode (optional)"
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name for virtual address mode (optional, alternative to pid)"
                    }
                },
                "required": ["address", "length"]
            }
        ),
        Tool(
            name="memory_write",
            description="Write data to memory at specified address using PCILeech DMA. Supports both physical addresses and process virtual addresses.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address in hex format (e.g., '0x1000' or '1000')"
                    },
                    "data": {
                        "type": "string",
                        "description": "Hex string of data to write (e.g., '48656c6c6f')",
                        "maxLength": 2097152  # 1MB in hex = 2M chars
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID for virtual address mode (optional)"
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name for virtual address mode (optional, alternative to pid)"
                    }
                },
                "required": ["address", "data"]
            }
        ),
        Tool(
            name="memory_format",
            description="Read memory and format in multiple views (hex dump, ASCII, byte array, DWORD array) for AI analysis. Supports both physical addresses and process virtual addresses.",
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
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID for virtual address mode (optional)"
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name for virtual address mode (optional, alternative to pid)"
                    }
                },
                "required": ["address", "length"]
            }
        ),
        # ==================== Phase 1: Core Tools ====================
        Tool(
            name="system_info",
            description="Get target system and PCILeech device information",
            inputSchema={
                "type": "object",
                "properties": {
                    "verbose": {
                        "type": "boolean",
                        "description": "Include detailed information",
                        "default": False
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="memory_probe",
            description="Probe target memory to find readable regions (FPGA only)",
            inputSchema={
                "type": "object",
                "properties": {
                    "min_address": {
                        "type": "string",
                        "description": "Starting address in hex (default: 0x0)",
                        "default": "0x0"
                    },
                    "max_address": {
                        "type": "string",
                        "description": "Ending address in hex (default: auto-detect)"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="memory_dump",
            description="Dump memory range to file for offline analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "min_address": {
                        "type": "string",
                        "description": "Starting address in hex"
                    },
                    "max_address": {
                        "type": "string",
                        "description": "Ending address in hex"
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output file path (auto-generated if not specified)"
                    },
                    "force": {
                        "type": "boolean",
                        "description": "Force read even if marked inaccessible",
                        "default": False
                    }
                },
                "required": ["min_address", "max_address"]
            }
        ),
        Tool(
            name="memory_search",
            description="Search memory for byte pattern or signature",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Hex pattern to search (e.g., '4D5A9000' for MZ header)"
                    },
                    "signature": {
                        "type": "string",
                        "description": "Signature file name without .sig extension"
                    },
                    "min_address": {
                        "type": "string",
                        "description": "Start address in hex"
                    },
                    "max_address": {
                        "type": "string",
                        "description": "End address in hex"
                    },
                    "find_all": {
                        "type": "boolean",
                        "description": "Find all matches instead of just first",
                        "default": False
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="memory_patch",
            description="Search and patch memory using signature file",
            inputSchema={
                "type": "object",
                "properties": {
                    "signature": {
                        "type": "string",
                        "description": "Signature file name without .sig extension"
                    },
                    "min_address": {
                        "type": "string",
                        "description": "Start address in hex"
                    },
                    "max_address": {
                        "type": "string",
                        "description": "End address in hex"
                    },
                    "patch_all": {
                        "type": "boolean",
                        "description": "Patch all matches instead of just first",
                        "default": False
                    }
                },
                "required": ["signature"]
            }
        ),
        Tool(
            name="process_list",
            description="List processes on target Windows system",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        # ==================== Phase 2: Address Translation ====================
        Tool(
            name="translate_phys2virt",
            description="Translate physical address to virtual address using page table",
            inputSchema={
                "type": "object",
                "properties": {
                    "physical_address": {
                        "type": "string",
                        "description": "Physical address in hex format"
                    },
                    "cr3": {
                        "type": "string",
                        "description": "Page table base address (CR3 register value) in hex"
                    }
                },
                "required": ["physical_address", "cr3"]
            }
        ),
        Tool(
            name="translate_virt2phys",
            description="Translate virtual address to physical address using page table",
            inputSchema={
                "type": "object",
                "properties": {
                    "virtual_address": {
                        "type": "string",
                        "description": "Virtual address in hex format"
                    },
                    "cr3": {
                        "type": "string",
                        "description": "Page table base address (CR3 register value) in hex"
                    }
                },
                "required": ["virtual_address", "cr3"]
            }
        ),
        Tool(
            name="process_virt2phys",
            description="Translate process virtual address to physical address",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID"
                    },
                    "virtual_address": {
                        "type": "string",
                        "description": "Virtual address in hex format"
                    }
                },
                "required": ["pid", "virtual_address"]
            }
        ),
        # ==================== Phase 3: Kernel Module (KMD) ====================
        Tool(
            name="kmd_load",
            description="Load kernel module (KMD) to target system for enhanced memory access",
            inputSchema={
                "type": "object",
                "properties": {
                    "kmd_type": {
                        "type": "string",
                        "enum": [
                            "WIN10_X64", "WIN10_X64_2", "WIN10_X64_3", "WIN11_X64",
                            "LINUX_X64_46", "LINUX_X64_48", "LINUX_X64_MAP", "LINUX_X64_EFI",
                            "FREEBSD_X64", "MACOS",
                            "UEFI_EXIT_BOOT_SERVICES", "UEFI_SIGNAL_EVENT"
                        ],
                        "description": "Kernel module type for target OS"
                    },
                    "use_page_table": {
                        "type": "boolean",
                        "description": "Use page table hijacking method",
                        "default": False
                    },
                    "cr3": {
                        "type": "string",
                        "description": "Page table base address (optional)"
                    },
                    "sysmap": {
                        "type": "string",
                        "description": "Linux System.map file path (for LINUX_X64_MAP)"
                    }
                },
                "required": ["kmd_type"]
            }
        ),
        Tool(
            name="kmd_exit",
            description="Unload kernel module (KMD) from target system",
            inputSchema={
                "type": "object",
                "properties": {
                    "kmd_address": {
                        "type": "string",
                        "description": "KMD address in hex (uses cached address if not provided)"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="kmd_execute",
            description="Execute kernel script (.ksh) on target system via loaded KMD",
            inputSchema={
                "type": "object",
                "properties": {
                    "script_name": {
                        "type": "string",
                        "description": "Script name without .ksh extension (e.g., 'wx64_pslist')"
                    },
                    "kmd_address": {
                        "type": "string",
                        "description": "KMD address (uses cached address if not provided)"
                    },
                    "input_file": {
                        "type": "string",
                        "description": "Input file path"
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output file path"
                    },
                    "string_param": {
                        "type": "string",
                        "description": "String parameter (-s)"
                    },
                    "param_0": {"type": "string", "description": "Numeric param -0"},
                    "param_1": {"type": "string", "description": "Numeric param -1"},
                    "param_2": {"type": "string", "description": "Numeric param -2"},
                    "param_3": {"type": "string", "description": "Numeric param -3"}
                },
                "required": ["script_name"]
            }
        ),
        Tool(
            name="kmd_list_scripts",
            description="List available kernel scripts (.ksh files)",
            inputSchema={
                "type": "object",
                "properties": {
                    "platform": {
                        "type": "string",
                        "enum": ["all", "windows", "linux", "macos", "freebsd", "uefi"],
                        "description": "Filter by target platform",
                        "default": "all"
                    }
                },
                "required": []
            }
        ),
        # ==================== Phase 4: Advanced/FPGA ====================
        Tool(
            name="benchmark",
            description="Run memory read/write performance benchmark",
            inputSchema={
                "type": "object",
                "properties": {
                    "test_type": {
                        "type": "string",
                        "enum": ["read", "readwrite", "full"],
                        "description": "Type of benchmark test",
                        "default": "read"
                    },
                    "address": {
                        "type": "string",
                        "description": "Test address in hex",
                        "default": "0x1000"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="tlp_send",
            description="Send/receive PCIe TLP packets (FPGA only)",
            inputSchema={
                "type": "object",
                "properties": {
                    "tlp_data": {
                        "type": "string",
                        "description": "TLP packet data in hex (optional, omit to just listen)"
                    },
                    "wait_seconds": {
                        "type": "number",
                        "description": "Time to wait for TLP responses",
                        "default": 0.5,
                        "minimum": 0.1,
                        "maximum": 60
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Show detailed TLP info",
                        "default": True
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="fpga_config",
            description="Read/write FPGA PCIe configuration space",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "write"],
                        "description": "Read or write configuration",
                        "default": "read"
                    },
                    "address": {
                        "type": "string",
                        "description": "Configuration space address in hex"
                    },
                    "data": {
                        "type": "string",
                        "description": "Data to write in hex (for write action)"
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output file path"
                    }
                },
                "required": []
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
        # Phase 1: Core Tools
        elif name == "system_info":
            return await handle_system_info(arguments)
        elif name == "memory_probe":
            return await handle_memory_probe(arguments)
        elif name == "memory_dump":
            return await handle_memory_dump(arguments)
        elif name == "memory_search":
            return await handle_memory_search(arguments)
        elif name == "memory_patch":
            return await handle_memory_patch(arguments)
        elif name == "process_list":
            return await handle_process_list(arguments)
        # Phase 2: Address Translation
        elif name == "translate_phys2virt":
            return await handle_translate_phys2virt(arguments)
        elif name == "translate_virt2phys":
            return await handle_translate_virt2phys(arguments)
        elif name == "process_virt2phys":
            return await handle_process_virt2phys(arguments)
        # Phase 3: KMD Tools
        elif name == "kmd_load":
            return await handle_kmd_load(arguments)
        elif name == "kmd_exit":
            return await handle_kmd_exit(arguments)
        elif name == "kmd_execute":
            return await handle_kmd_execute(arguments)
        elif name == "kmd_list_scripts":
            return await handle_kmd_list_scripts(arguments)
        # Phase 4: Advanced/FPGA
        elif name == "benchmark":
            return await handle_benchmark(arguments)
        elif name == "tlp_send":
            return await handle_tlp_send(arguments)
        elif name == "fpga_config":
            return await handle_fpga_config(arguments)
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
    pid = args.get("pid")
    process_name = args.get("process_name")

    # Validate mutually exclusive parameters
    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    mode = "physical"
    if pid is not None:
        mode = f"virtual (PID: {pid})"
    elif process_name is not None:
        mode = f"virtual (Process: {process_name})"

    logger.info(f"Reading {length} bytes from {address} ({mode})")

    # Read memory (use asyncio.to_thread to avoid blocking event loop)
    wrapper = get_pcileech()
    data = await asyncio.to_thread(
        wrapper.read_memory, address, length, pid=pid, process_name=process_name
    )

    # Format result
    result = {
        "address": address,
        "length": length,
        "mode": mode,
        "bytes_read": len(data),
        "data_hex": data.hex(),
        "timestamp": datetime.now().isoformat()
    }

    return [TextContent(
        type="text",
        text=f"Successfully read {len(data)} bytes from {address} ({mode})\n\n" +
             f"Hex data: {data.hex()}\n\n" +
             f"Result: {result}"
    )]


async def handle_memory_write(args: dict[str, Any]) -> list[TextContent]:
    """Handle memory_write tool."""
    address = args["address"]
    data_hex = args["data"]
    pid = args.get("pid")
    process_name = args.get("process_name")

    # Validate mutually exclusive parameters
    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    # Validate hex string length (max 1MB = 2MB hex chars)
    MAX_HEX_LENGTH = 2 * 1024 * 1024  # 1MB in hex = 2M chars
    if len(data_hex) > MAX_HEX_LENGTH:
        return [TextContent(
            type="text",
            text=f"Data too large: {len(data_hex)//2} bytes exceeds maximum 1MB"
        )]

    # Validate hex string
    try:
        data = bytes.fromhex(data_hex)
    except ValueError as e:
        return [TextContent(
            type="text",
            text=f"Invalid hex data: {str(e)}"
        )]

    mode = "physical"
    if pid is not None:
        mode = f"virtual (PID: {pid})"
    elif process_name is not None:
        mode = f"virtual (Process: {process_name})"

    logger.info(f"Writing {len(data)} bytes to {address} ({mode})")

    # Write memory (use asyncio.to_thread to avoid blocking event loop)
    wrapper = get_pcileech()
    success = await asyncio.to_thread(
        wrapper.write_memory, address, data, pid=pid, process_name=process_name
    )

    result = {
        "address": address,
        "mode": mode,
        "bytes_written": len(data),
        "success": success,
        "timestamp": datetime.now().isoformat()
    }

    return [TextContent(
        type="text",
        text=f"Successfully wrote {len(data)} bytes to {address} ({mode})\n\n" +
             f"Data: {data_hex}\n\n" +
             f"Result: {result}"
    )]


async def handle_memory_format(args: dict[str, Any]) -> list[TextContent]:
    """Handle memory_format tool."""
    address = args["address"]
    length = args["length"]
    formats = args.get("formats", ["hexdump", "ascii", "bytes", "dwords", "raw"])
    pid = args.get("pid")
    process_name = args.get("process_name")

    # Validate mutually exclusive parameters
    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    mode = "physical"
    if pid is not None:
        mode = f"virtual (PID: {pid})"
    elif process_name is not None:
        mode = f"virtual (Process: {process_name})"

    logger.info(f"Reading and formatting {length} bytes from {address} ({mode})")

    # Read memory (use asyncio.to_thread to avoid blocking event loop)
    wrapper = get_pcileech()
    data = await asyncio.to_thread(
        wrapper.read_memory, address, length, pid=pid, process_name=process_name
    )

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


# ==================== Phase 1: Core Tool Handlers ====================

async def handle_system_info(args: dict[str, Any]) -> list[TextContent]:
    """Handle system_info tool."""
    verbose = args.get("verbose", False)

    logger.info(f"Getting system info (verbose={verbose})")

    wrapper = get_pcileech()
    info = await asyncio.to_thread(wrapper.get_system_info, verbose)

    # Format output
    output_parts = [
        "## PCILeech System Information",
        "=" * 50,
        ""
    ]

    if info.get('device'):
        output_parts.append(f"**Device:** {info['device']}")
    if info.get('fpga'):
        output_parts.append("**Type:** FPGA-based device")
    if info.get('memory_max'):
        output_parts.append(f"**Max Memory:** {info['memory_max']}")

    output_parts.extend([
        "",
        "### Raw Output:",
        "```",
        info.get('raw_output', 'No output'),
        "```"
    ])

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_memory_probe(args: dict[str, Any]) -> list[TextContent]:
    """Handle memory_probe tool."""
    min_addr = args.get("min_address", "0x0")
    max_addr = args.get("max_address")

    logger.info(f"Probing memory from {min_addr} to {max_addr or 'auto'}")

    wrapper = get_pcileech()
    regions = await asyncio.to_thread(wrapper.probe_memory, min_addr, max_addr)

    # Format output
    output_parts = [
        "## Memory Probe Results",
        "=" * 50,
        ""
    ]

    if not regions:
        output_parts.append("No readable memory regions found.")
    else:
        output_parts.append(f"Found {len(regions)} memory region(s):\n")
        for i, region in enumerate(regions, 1):
            output_parts.append(
                f"{i}. **{region['start']}** - **{region['end']}** "
                f"({region['size_mb']:.2f} MB) - {region['status']}"
            )

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_memory_dump(args: dict[str, Any]) -> list[TextContent]:
    """Handle memory_dump tool."""
    min_addr = args["min_address"]
    max_addr = args["max_address"]
    output_file = args.get("output_file")
    force = args.get("force", False)

    logger.info(f"Dumping memory {min_addr} to {max_addr}")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(
        wrapper.dump_memory, min_addr, max_addr, output_file, force
    )

    # Format output
    output_parts = [
        "## Memory Dump Result",
        "=" * 50,
        "",
        f"**Range:** {result['min_address']} - {result['max_address']}",
        f"**Success:** {result['success']}"
    ]

    if result.get('file'):
        output_parts.append(f"**Output File:** {result['file']}")

    output_parts.extend([
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ])

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_memory_search(args: dict[str, Any]) -> list[TextContent]:
    """Handle memory_search tool."""
    pattern = args.get("pattern")
    signature = args.get("signature")
    min_addr = args.get("min_address")
    max_addr = args.get("max_address")
    find_all = args.get("find_all", False)

    # Validate mutually exclusive parameters
    error = validate_mutually_exclusive(args, "pattern", "signature")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    if not pattern and not signature:
        return [TextContent(
            type="text",
            text="Error: Either 'pattern' or 'signature' must be provided"
        )]

    search_term = pattern if pattern else f"signature:{signature}"
    logger.info(f"Searching memory for {search_term}")

    wrapper = get_pcileech()
    matches = await asyncio.to_thread(
        wrapper.search_memory, pattern, signature, min_addr, max_addr, find_all
    )

    # Format output
    output_parts = [
        "## Memory Search Results",
        "=" * 50,
        "",
        f"**Search:** {search_term}",
        f"**Range:** {min_addr or '0x0'} - {max_addr or 'max'}",
        ""
    ]

    if not matches:
        output_parts.append("**No matches found.**")
    else:
        output_parts.append(f"**Found {len(matches)} match(es):**\n")
        for i, match in enumerate(matches, 1):
            output_parts.append(f"{i}. Address: **{match['address']}**")
            if match.get('line'):
                output_parts.append(f"   Context: {match['line']}")

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_memory_patch(args: dict[str, Any]) -> list[TextContent]:
    """Handle memory_patch tool."""
    signature = args["signature"]
    min_addr = args.get("min_address")
    max_addr = args.get("max_address")
    patch_all = args.get("patch_all", False)

    logger.info(f"Patching memory with signature {signature}")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(
        wrapper.patch_memory, signature, min_addr, max_addr, patch_all
    )

    # Format output
    output_parts = [
        "## Memory Patch Result",
        "=" * 50,
        "",
        f"**Signature:** {result['signature']}",
        f"**Success:** {result['success']}",
        f"**Matches Found:** {result['matches_found']}",
        f"**Patches Applied:** {result['patches_applied']}",
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ]

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_process_list(args: dict[str, Any]) -> list[TextContent]:
    """Handle process_list tool."""
    logger.info("Listing processes on target system")

    wrapper = get_pcileech()
    processes = await asyncio.to_thread(wrapper.list_processes)

    # Format output
    output_parts = [
        "## Process List",
        "=" * 50,
        ""
    ]

    if not processes:
        output_parts.append("No processes found or unable to enumerate.")
    else:
        output_parts.append(f"Found {len(processes)} process(es):\n")
        output_parts.append("| PID | PPID | Name |")
        output_parts.append("|-----|------|------|")
        for proc in processes:
            ppid = proc.get('ppid', '-')
            output_parts.append(f"| {proc['pid']} | {ppid} | {proc.get('name', 'Unknown')} |")

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


# ==================== Phase 2: Address Translation Handlers ====================

async def handle_translate_phys2virt(args: dict[str, Any]) -> list[TextContent]:
    """Handle translate_phys2virt tool."""
    phys_addr = args["physical_address"]
    cr3 = args["cr3"]

    logger.info(f"Translating physical {phys_addr} to virtual (CR3: {cr3})")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(wrapper.translate_phys2virt, phys_addr, cr3)

    # Format output
    output_parts = [
        "## Physical to Virtual Address Translation",
        "=" * 50,
        "",
        f"**Physical Address:** {result['physical']}",
        f"**CR3 (Page Table Base):** {result['cr3']}",
        f"**Virtual Address:** {result['virtual'] or 'Not found'}",
        f"**Success:** {result['success']}",
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ]

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_translate_virt2phys(args: dict[str, Any]) -> list[TextContent]:
    """Handle translate_virt2phys tool."""
    virt_addr = args["virtual_address"]
    cr3 = args["cr3"]

    logger.info(f"Translating virtual {virt_addr} to physical (CR3: {cr3})")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(wrapper.translate_virt2phys, virt_addr, cr3)

    # Format output
    output_parts = [
        "## Virtual to Physical Address Translation",
        "=" * 50,
        "",
        f"**Virtual Address:** {result['virtual']}",
        f"**CR3 (Page Table Base):** {result['cr3']}",
        f"**Physical Address:** {result['physical'] or 'Not found'}",
        f"**Success:** {result['success']}",
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ]

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_process_virt2phys(args: dict[str, Any]) -> list[TextContent]:
    """Handle process_virt2phys tool."""
    pid = args["pid"]
    virt_addr = args["virtual_address"]

    logger.info(f"Translating PID {pid} virtual {virt_addr} to physical")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(wrapper.process_virt2phys, pid, virt_addr)

    # Format output
    output_parts = [
        "## Process Virtual to Physical Address Translation",
        "=" * 50,
        "",
        f"**Process ID:** {result['pid']}",
        f"**Virtual Address:** {result['virtual']}",
        f"**Physical Address:** {result['physical'] or 'Not found'}",
        f"**Success:** {result['success']}",
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ]

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


# ==================== Phase 3: KMD Handlers ====================

async def handle_kmd_load(args: dict[str, Any]) -> list[TextContent]:
    """Handle kmd_load tool."""
    kmd_type = args["kmd_type"]
    use_pt = args.get("use_page_table", False)
    cr3 = args.get("cr3")
    sysmap = args.get("sysmap")

    logger.info(f"Loading KMD type {kmd_type} (PT: {use_pt})")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(wrapper.load_kmd, kmd_type, use_pt, cr3, sysmap)

    # Format output
    output_parts = [
        "## Kernel Module Load Result",
        "=" * 50,
        "",
        f"**KMD Type:** {result['kmd_type']}",
        f"**Success:** {result['success']}",
        f"**KMD Address:** {result['kmd_address'] or 'Unknown'}",
        "",
        "[!] **WARNING:** KMD is now loaded in target kernel memory!",
        "Remember to unload with `kmd_exit` when done.",
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ]

    if result.get('error'):
        output_parts.extend([
            "",
            "### Error:",
            result['error']
        ])

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_kmd_exit(args: dict[str, Any]) -> list[TextContent]:
    """Handle kmd_exit tool."""
    kmd_address = args.get("kmd_address")

    wrapper = get_pcileech()

    if not kmd_address and not wrapper.kmd_loaded:
        return [TextContent(
            type="text",
            text="Error: No KMD address provided and no KMD currently loaded"
        )]

    logger.info(f"Unloading KMD at {kmd_address or wrapper.kmd_address}")

    result = await asyncio.to_thread(wrapper.unload_kmd, kmd_address)

    # Format output
    output_parts = [
        "## Kernel Module Unload Result",
        "=" * 50,
        "",
        f"**KMD Address:** {result['kmd_address']}",
        f"**Success:** {result['success']}",
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ]

    if result['success']:
        output_parts.insert(5, "[OK] KMD successfully unloaded from target system.")
    elif result.get('error'):
        output_parts.extend([
            "",
            "### Error:",
            "```",
            result['error'],
            "```"
        ])

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_kmd_execute(args: dict[str, Any]) -> list[TextContent]:
    """Handle kmd_execute tool."""
    script_name = args["script_name"]
    kmd_address = args.get("kmd_address")
    input_file = args.get("input_file")
    output_file = args.get("output_file")
    string_param = args.get("string_param")

    # Collect numeric params
    numeric_params = {}
    for i in range(4):
        val = args.get(f"param_{i}")
        if val is not None:
            numeric_params[i] = val

    logger.info(f"Executing KSH script: {script_name}")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(
        wrapper.execute_ksh,
        script_name, kmd_address, input_file, output_file,
        string_param, numeric_params if numeric_params else None
    )

    # Format output
    output_parts = [
        "## Kernel Script Execution Result",
        "=" * 50,
        "",
        f"**Script:** {result['script']}",
        f"**KMD Address:** {result['kmd_address']}",
        f"**Success:** {result['success']}",
        "",
        "### Script Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ]

    if result.get('error'):
        output_parts.extend([
            "",
            "### Error:",
            result['error']
        ])

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_kmd_list_scripts(args: dict[str, Any]) -> list[TextContent]:
    """Handle kmd_list_scripts tool."""
    platform = args.get("platform", "all")

    logger.info(f"Listing KSH scripts for platform: {platform}")

    wrapper = get_pcileech()
    scripts = await asyncio.to_thread(wrapper.list_available_scripts, platform)

    # Format output
    output_parts = [
        "## Available Kernel Scripts (.ksh)",
        "=" * 50,
        "",
        f"**Platform Filter:** {platform}",
        f"**Total Scripts:** {len(scripts)}",
        ""
    ]

    if not scripts:
        output_parts.append("No scripts found for the specified platform.")
    else:
        # Group by platform
        current_platform = None
        for script in scripts:
            if script['platform'] != current_platform:
                current_platform = script['platform']
                output_parts.append(f"\n### {current_platform.upper()}")
                output_parts.append("")

            output_parts.append(f"- `{script['name']}`")

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


# ==================== Phase 4: Advanced/FPGA Handlers ====================

async def handle_benchmark(args: dict[str, Any]) -> list[TextContent]:
    """Handle benchmark tool."""
    test_type = args.get("test_type", "read")
    address = args.get("address", "0x1000")

    logger.info(f"Running {test_type} benchmark at {address}")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(wrapper.run_benchmark, test_type, address)

    # Format output
    output_parts = [
        "## Memory Benchmark Result",
        "=" * 50,
        "",
        f"**Test Type:** {result['test_type']}",
        f"**Address:** {result['address']}",
        f"**Success:** {result['success']}"
    ]

    if result['speed_mbps']:
        output_parts.append(f"**Speed:** {result['speed_mbps']:.2f} MB/s")

    output_parts.extend([
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ])

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_tlp_send(args: dict[str, Any]) -> list[TextContent]:
    """Handle tlp_send tool."""
    tlp_data = args.get("tlp_data")
    wait_seconds = args.get("wait_seconds", 0.5)
    verbose = args.get("verbose", True)

    action = "Sending TLP" if tlp_data else "Listening for TLP"
    logger.info(f"{action} (wait: {wait_seconds}s)")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(wrapper.send_tlp, tlp_data, wait_seconds, verbose)

    # Format output
    output_parts = [
        "## PCIe TLP Operation Result",
        "=" * 50,
        "",
        f"**Action:** {action}",
        f"**Wait Time:** {result['wait_seconds']}s",
        f"**Success:** {result['success']}"
    ]

    if tlp_data:
        output_parts.append(f"**TLP Sent:** {tlp_data}")

    if result['tlp_received']:
        output_parts.append(f"\n**TLP Received ({len(result['tlp_received'])}):**")
        for i, tlp in enumerate(result['tlp_received'], 1):
            output_parts.append(f"  {i}. {tlp}")

    output_parts.extend([
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
    ])

    return [TextContent(
        type="text",
        text="\n".join(output_parts)
    )]


async def handle_fpga_config(args: dict[str, Any]) -> list[TextContent]:
    """Handle fpga_config tool."""
    action = args.get("action", "read")
    address = args.get("address")
    data = args.get("data")
    output_file = args.get("output_file")

    logger.info(f"FPGA config {action} at {address}")

    wrapper = get_pcileech()
    result = await asyncio.to_thread(wrapper.fpga_config, action, address, data, output_file)

    # Format output
    output_parts = [
        "## FPGA Configuration Space Result",
        "=" * 50,
        "",
        f"**Action:** {result['action']}",
        f"**Address:** {result['address'] or 'Default'}",
        f"**Success:** {result['success']}"
    ]

    if result['data']:
        output_parts.append(f"\n**Data Read:**\n```\n{result['data']}\n```")

    output_parts.extend([
        "",
        "### Command Output:",
        "```",
        result.get('output', 'No output'),
        "```"
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
