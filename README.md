# MCP Server for PCILeech 

[English](#english) | [中文](README_CN.md)

## English

A Model Context Protocol (MCP) server that provides a standardized interface to PCILeech for DMA-based memory operations. This enables MCP clients (e.g., Claude Code) to perform memory/debug workflows through tool calls.

**Authors:** EVAN & MOER  
**Support:** [Join our Discord](https://discord.gg/PwAXYPMkkF)

## Features

- **19 MCP tools** grouped by capability:
  - **Core Memory:** `memory_read`, `memory_write`, `memory_format`
  - **System:** `system_info`, `memory_probe`, `memory_dump`, `memory_search`, `memory_patch`, `process_list`
  - **Address Translation:** `translate_phys2virt`, `translate_virt2phys`, `process_virt2phys`
  - **Kernel Module (KMD):** `kmd_load`, `kmd_exit`, `kmd_execute`, `kmd_list_scripts`
  - **Advanced/FPGA:** `benchmark`, `tlp_send`, `fpga_config`
- **Virtual address mode:** memory tools support `pid` or `process_name` (mutually exclusive)
- **Non-blocking server:** PCILeech calls are executed via `asyncio.to_thread`
- **Output helpers:** hexdump + ASCII + byte/DWORD views for analysis

## Prerequisites

- **Windows 10/11** (x64)
- **Python 3.10+**
- **PCILeech hardware** properly configured and working
- **PCILeech binaries** (bundled under `pcileech/`)

## Quick Start

### 1. Clone

```bash
git clone https://github.com/Evan7198/mcp_server_pcileech
cd mcp_server_pcileech
```

### 2. Install dependencies

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

If you hit MCP import/version issues, install from `pyproject.toml` instead:

```bash
pip install -e .
```

### 3. Verify PCILeech

```bash
cd pcileech
pcileech.exe probe
```

### 4. Configure Claude Code (MCP)

Add a server entry (adjust paths):

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

Restart Claude Code after editing the MCP config.

## Configuration

`config.json` controls the PCILeech executable path and timeouts:

```json
{
  "pcileech": {
    "executable_path": "pcileech\\pcileech.exe",
    "timeout_seconds": 30
  },
  "server": {
    "name": "mcp-server-pcileech",
    "version": "1.0.0"
  }
}
```

## Usage Examples

Once configured, you can request actions in natural language; the client will translate them into tool calls:

```
Read 256 bytes from address 0x1000
```

```
Write the hex data 48656c6c6f to address 0x2000
```

```
Show me a formatted view of 64 bytes at address 0x1000
```

## MCP Tools (Overview)

Notes:
- **Virtual memory mode:** for memory tools, use `pid` *or* `process_name` (not both).
- **FPGA-only:** some operations require an FPGA-backed device (e.g., `memory_probe`, `tlp_send`).

### Core Memory

- `memory_read(address, length, pid?, process_name?)` → hex data + metadata
- `memory_write(address, data, pid?, process_name?)` → success/confirmation
- `memory_format(address, length, formats?, pid?, process_name?)` → hexdump/ASCII/arrays/raw

### System

- `system_info(verbose?)` → target system + device info
- `memory_probe(min_address?, max_address?)` → readable regions (**FPGA only**)
- `memory_dump(min_address, max_address, output_file?, force?)` → dump file path/result
- `memory_search(pattern? | signature?, min_address?, max_address?, find_all?)` → matches
- `memory_patch(signature, min_address?, max_address?, patch_all?)` → patch result
- `process_list()` → PID/PPID/name list

### Address Translation

- `translate_phys2virt(physical_address, cr3)` → translation details
- `translate_virt2phys(virtual_address, cr3)` → translation details
- `process_virt2phys(pid, virtual_address)` → translation details

### Kernel Module (KMD)

- `kmd_load(kmd_type, use_pt?, cr3?)` → load result (+ caches KMD address)
- `kmd_exit(kmd_address?)` → unload result (uses cached address if omitted)
- `kmd_execute(script_name, kmd_address?, input_file?, output_file?, parameter_string?, parameter_int0?, parameter_int1?)`
- `kmd_list_scripts(platform?)` → available `.ksh` scripts grouped by platform

### Advanced / FPGA

- `benchmark(test_type?, address?)` → MB/s results (depends on hardware)
- `tlp_send(tlp_data?, wait_seconds?, verbose?)` → sent/received TLPs (**FPGA only**)
- `fpga_config(action?, address?, data?, output_file?)` → config read/write (**FPGA only**)

## Architecture

### Two-Layer Design

1. **MCP server layer** (`main.py`)
   - Stdio transport, tool schemas, validation, formatting
   - Uses `asyncio.to_thread()` to avoid blocking the event loop
2. **PCILeech wrapper** (`pcileech_wrapper.py`)
   - Subprocess calls into `pcileech.exe`
   - Address alignment + 256-byte chunking (PCILeech `display` behavior)
   - Output parsing, timeouts, and error mapping

## Troubleshooting

### PCILeech not found

**Error:** `PCILeech executable not found`  
**Fix:** verify `config.json` → `pcileech.executable_path`

### Hardware not connected

**Warning:** `PCILeech connection verification failed`  
**Fix:** run `pcileech\\pcileech.exe probe` and validate drivers/cabling

### Memory access fails

**Error:** `Memory read/write failed`  
**Fix:** validate address/range on the CLI first, then retry via MCP

### Timeout

**Error:** `PCILeech command timed out`  
**Fix:** increase `pcileech.timeout_seconds` in `config.json`

## Project Structure

```
mcp_server_pcileech/
├── main.py
├── pcileech_wrapper.py
├── config.json
├── pyproject.toml
├── requirements.txt
├── README.md
├── README_CN.md
└── pcileech/
    ├── pcileech.exe
    └── LICENSE.txt
```

## Limitations

- Windows only (PCILeech is Windows-focused in this repo)
- Requires compatible PCILeech hardware for real memory operations
- Read size limits:
  - `memory_read`: up to 1MB
  - `memory_format`: up to 4KB (readable output)
- Some tools are **FPGA-only** (probe/TLP/config)
- PCILeech commands run sequentially (per subprocess call)

## Security & Legal

This tool is intended for authorized debugging/security research/education. Do not use it for unauthorized access or malicious activity. You are responsible for complying with applicable laws and regulations.

## License

This project wraps PCILeech, which has its own license. See `pcileech/LICENSE.txt`.

## Credits

- **PCILeech:** [Ulf Frisk](https://github.com/ufrisk/pcileech)
- **Model Context Protocol:** [Anthropic](https://modelcontextprotocol.io/)
- **Authors:** EVAN & MOER

## Version

The toolset in this repository currently includes the 19-tool extended set. For the package/config version, refer to:
- `pyproject.toml` (`[project].version`)
- `config.json` (`server.version`)

## Support

- Discord: [Join our Discord](https://discord.gg/PwAXYPMkkF)
- Issues: open an issue in this repository
- PCILeech docs: [PCILeech GitHub](https://github.com/ufrisk/pcileech)
- MCP docs: [MCP Documentation](https://modelcontextprotocol.io/)

## Changelog

### v1.0.0 (2025-12-16)
- Extended to 19 MCP tools covering full PCILeech functionality
- Added virtual address mode (`pid` / `process_name`) to memory tools
- Added address translation, KMD, and FPGA/advanced tools
- Added broader validation and error handling; non-blocking server execution

### v0.1.0 (2025-12-10)
- Initial release
- Three MCP tools: `memory_read`, `memory_write`, `memory_format`
