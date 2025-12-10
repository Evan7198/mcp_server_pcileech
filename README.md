# MCP Server for PCILeec

[English](#english) | [中文](README_CN.md)

## English

A Model Context Protocol (MCP) server that provides a standardized interface to PCILeech for DMA-based memory operations. This server enables AI assistants like Claude to perform memory debugging through natural language commands.

**Authors:** EVAN & MOER
**Support:** [Join our Discord](https://discord.gg/PwAXYPMkkF)

## Features

- **Three MCP Tools**:
  - `memory_read`: Read memory from any address
  - `memory_write`: Write data to memory
  - `memory_format`: Multi-view memory formatting (hex dump, ASCII, byte array, DWORD)

- **Low Latency**: Direct subprocess calls to PCILeech binary
- **AI-Friendly**: Natural language interface through MCP protocol
- **Simple Configuration**: Minimal dependencies, easy setup
- **Multiple Formats**: View memory in hex, ASCII, byte arrays, and DWORD arrays

## Prerequisites

- **Windows 10/11** (x64)
- **Python 3.10+**
- **PCILeech hardware** properly configured and working
- **PCILeech binary** (included in `pcileech/` directory)

## Quick Start

### 1. Clone Repository

```bash
git clone <repository-url>
cd mcp_server_pcileech
```

### 2. Install Dependencies

Create and activate virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Verify PCILeech

Test that PCILeech hardware is working:

```bash
cd pcileech
pcileech.exe probe
```

You should see hardware detection output.

### 4. Configure for Claude Code

Add this configuration to your Claude Code MCP settings:

```json
"mcpServers": {
  "pcileech": {
    "command": "C:\\path\\to\\mcp_server_pcileech\\.venv\\Scripts\\python.exe",
    "args": [
      "C:\\path\\to\\mcp_server_pcileech\\main.py"
    ],
    "cwd": "C:\\path\\to\\mcp_server_pcileech",
    "env": {}
  }
}
```

**Important:** Replace `C:\\path\\to\\mcp_server_pcileech` with your actual project path.

### 5. Restart Claude Code

After adding the configuration, restart Claude Code to load the MCP server.

## Configuration

The server uses `config.json` for configuration:

```json
{
  "pcileech": {
    "executable_path": "pcileech\\pcileech.exe",
    "timeout_seconds": 30
  },
  "server": {
    "name": "mcp-server-pcileech",
    "version": "0.1.0"
  }
}
```

Adjust `executable_path` and `timeout_seconds` if needed for your setup.

## Usage Examples

Once configured in Claude Code, you can use natural language commands:

### Reading Memory

```
Read 256 bytes from address 0x1000
```

### Writing Memory

```
Write the hex data 48656c6c6f to address 0x2000
```

### Formatted Memory View

```
Show me a formatted view of 64 bytes at address 0x1000
```

This will display:
- Hex dump with ASCII sidebar
- Pure ASCII view
- Byte array (decimal)
- DWORD array (little-endian)
- Raw hex string

## MCP Tools Reference

### memory_read

Read raw memory from specified address.

**Parameters:**
- `address` (string): Memory address in hex format (e.g., "0x1000" or "1000")
- `length` (integer): Number of bytes to read (1-1048576, max 1MB)

**Returns:** Hex string of memory data with metadata

### memory_write

Write data to memory at specified address.

**Parameters:**
- `address` (string): Memory address in hex format
- `data` (string): Hex string of data to write (e.g., "48656c6c6f")

**Returns:** Success status with confirmation

### memory_format

Read memory and format in multiple views for AI analysis.

**Parameters:**
- `address` (string): Memory address in hex format
- `length` (integer): Number of bytes to read (1-4096, max 4KB)
- `formats` (array, optional): Format types to include - ["hexdump", "ascii", "bytes", "dwords", "raw"]

**Returns:** Multi-format memory view

## Architecture

### Two-Layer Design

1. **MCP Server Layer** (`main.py`)
   - Handles MCP protocol communication via stdio transport
   - Defines tool schemas and parameter validation
   - Formats output for AI analysis
   - Async tool handlers: `handle_memory_read`, `handle_memory_write`, `handle_memory_format`

2. **PCILeech Wrapper Layer** (`pcileech_wrapper.py`)
   - Manages PCILeech executable subprocess calls
   - Handles address alignment and chunked reads (256-byte blocks, 16-byte alignment)
   - Parses PCILeech output format
   - Timeout and error handling

### Key Implementation Details

**Memory Read Alignment:**
- PCILeech `display` command always returns 256 bytes aligned to 16-byte boundaries
- `read_memory()` automatically handles:
  - Calculating aligned addresses
  - Chunked reading of 256-byte blocks
  - Extracting and concatenating requested byte ranges
  - Supporting arbitrary addresses and lengths

## Troubleshooting

### PCILeech Not Found

**Error:** `PCILeech executable not found`

**Solution:** Verify the path in `config.json` points to the correct location of `pcileech.exe`

### Hardware Not Connected

**Warning:** `PCILeech connection verification failed`

**Solution:**
- Ensure PCILeech hardware is properly connected
- Test with `pcileech.exe probe` directly
- Check hardware drivers are installed

### Memory Read/Write Fails

**Error:** `Memory read/write failed`

**Possible causes:**
- Invalid memory address
- Hardware access denied
- Target system not accessible
- Insufficient permissions

**Solution:** Verify the target address is valid and accessible by testing with PCILeech CLI first.

### Timeout Errors

**Error:** `PCILeech command timed out`

**Solution:** Increase `timeout_seconds` in `config.json` if operations are legitimately slow.

## Project Structure

```
mcp_server_pcileech/
├── main.py                 # MCP server entry point
├── pcileech_wrapper.py     # PCILeech integration layer
├── config.json             # Configuration file
├── requirements.txt        # Python dependencies
├── pyproject.toml          # Project metadata
├── README.md               # This file (English)
├── README_CN.md            # Chinese version
├── CLAUDE.md               # Claude Code guidance
├── docs/
│   └── brief.md            # Project brief
└── pcileech/               # PCILeech binary and dependencies
    └── pcileech.exe
```

## Development

### Code Formatting

```bash
black main.py pcileech_wrapper.py
```

### Type Checking

```bash
mypy main.py pcileech_wrapper.py
```

### Running Tests

```bash
pytest
```

## Performance

- **MCP Server overhead:** < 100ms per operation
- **PCILeech native performance:** Maintained (no additional overhead)
- **End-to-end latency:** < 5 seconds (including AI processing)

## Limitations

- **Windows only:** PCILeech is Windows-specific
- **Hardware dependent:** Requires PCILeech hardware connection
- **Read size limits:**
  - `memory_read`: Maximum 1MB
  - `memory_format`: Maximum 4KB (for readable output)
- **Synchronous PCILeech calls:** Wrapper uses subprocess.run (blocking), called in async context
- **No concurrent memory operations:** Each PCILeech command executes sequentially

## Security & Legal

**IMPORTANT DISCLAIMER**

This tool is designed for:
- Authorized hardware debugging
- Security research with proper authorization
- Educational purposes
- Personal hardware development

**DO NOT use for:**
- Unauthorized access to systems
- Malicious activities
- Circumventing security measures without permission

Users are responsible for ensuring their use complies with all applicable laws and regulations.

## License

This project wraps PCILeech which has its own license. See `pcileech/LICENSE.txt` for PCILeech licensing.

## Credits

- **PCILeech:** [Ulf Frisk](https://github.com/ufrisk/pcileech)
- **Model Context Protocol:** [Anthropic](https://modelcontextprotocol.io/)
- **Authors:** EVAN & MOER

## Version

**v0.1.0** - Initial MVP Release

## Support

- **Discord Community:** [Join our Discord](https://discord.gg/PwAXYPMkkF)
- **Issues:** Open an issue in this repository
- **PCILeech Documentation:** [PCILeech GitHub](https://github.com/ufrisk/pcileech)
- **MCP Protocol:** [MCP Documentation](https://modelcontextprotocol.io/)

## Changelog

### v0.1.0 (2025-12-10)
- Initial release
- Three MCP tools: memory_read, memory_write, memory_format
- PCILeech subprocess integration
- Basic error handling and timeout support
- Claude Code integration support
- Multi-format memory visualization
