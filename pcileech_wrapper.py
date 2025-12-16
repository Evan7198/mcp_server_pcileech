"""
PCILeech wrapper for memory operations.

This module provides a Python interface to PCILeech command-line tool
for DMA-based memory read/write operations.
"""

import subprocess
import os
import json
import re
import threading
from typing import Optional, Tuple
from pathlib import Path


# ==================== Constants ====================
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
# Valid process name pattern (alphanumeric, dot, underscore, hyphen, space)
_PROCESS_NAME_PATTERN = re.compile(r"^[\w\.\-\s]+$")

# Patterns to detect PCILeech command failures (returncode may still be 0)
_FAIL_PATTERNS = [
    re.compile(r"Failed reading memory at address:\s*(0x[0-9a-fA-F]+)?", re.IGNORECASE),
    re.compile(r"Failed translating address", re.IGNORECASE),
    re.compile(r"UMD:\s*Failed", re.IGNORECASE),
    re.compile(r"Memory Display:\s*Failed", re.IGNORECASE),
    re.compile(r"\bSYNTAX:\b", re.IGNORECASE),
    re.compile(r"Failed retrieving information", re.IGNORECASE),
]


# ==================== Helper Functions ====================
def _detect_failure(stdout: str, stderr: str) -> str | None:
    """
    Detect PCILeech business failures from stdout/stderr.

    PCILeech may return returncode=0 but output contains failure messages.
    This function scans output for known failure patterns.

    Returns:
        str: Failure message if detected, None otherwise
    """
    combined = "\n".join([stdout or "", stderr or ""])

    # Check known failure patterns
    for pattern in _FAIL_PATTERNS:
        match = pattern.search(combined)
        if match:
            return match.group(0).strip()

    # Fallback: check for "failed" keyword in output
    for line in combined.splitlines():
        line_lower = line.lower()
        if "failed" in line_lower and "success" not in line_lower:
            return line.strip()

    return None


def _parse_hex_address(value: str, name: str = "address") -> int:
    """
    Parse and validate a hex address string.

    Args:
        value: Hex string like "0x1000" or "1000"
        name: Parameter name for error messages

    Returns:
        int: Parsed address value

    Raises:
        PCILeechError: If address format is invalid or out of range
    """
    if not isinstance(value, str):
        raise PCILeechError(f"{name} must be a hex string, got {type(value).__name__}")

    s = value.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if s.startswith("-"):
        raise PCILeechError(f"{name} cannot be negative: {value}")
    if not s or not _HEX_PATTERN.fullmatch(s):
        raise PCILeechError(f"Invalid {name} format '{value}' (expected hex like 0x1000)")

    try:
        n = int(s, 16)
    except ValueError as e:
        raise PCILeechError(f"Invalid {name} format '{value}': {e}")

    if n > _U64_MAX:
        raise PCILeechError(f"{name} exceeds 64-bit range: {value}")

    return n


def _validate_length(length: int, min_val: int = 1, max_val: int | None = None) -> None:
    """
    Validate length parameter.

    Args:
        length: Length value to validate
        min_val: Minimum allowed value (default: 1)
        max_val: Maximum allowed value (optional)

    Raises:
        PCILeechError: If length is invalid
    """
    if not isinstance(length, int):
        raise PCILeechError(f"length must be int, got {type(length).__name__}")
    if length < min_val:
        raise PCILeechError(f"length must be >= {min_val}, got {length}")
    if max_val is not None and length > max_val:
        raise PCILeechError(f"length must be <= {max_val}, got {length}")


def _sanitize_path_component(name: str, param_name: str = "name") -> str:
    """
    Sanitize a path component to prevent path traversal attacks.

    Args:
        name: The name to sanitize (e.g., signature name, script name)
        param_name: Parameter name for error messages

    Returns:
        str: Sanitized name

    Raises:
        PCILeechError: If name contains path traversal characters
    """
    if not name or not name.strip():
        raise PCILeechError(f"{param_name} cannot be empty")

    name = name.strip()

    # Reject path traversal attempts
    if ".." in name or "/" in name or "\\" in name:
        raise PCILeechError(f"{param_name} cannot contain path separators or '..': {name}")

    # Reject absolute paths
    if os.path.isabs(name):
        raise PCILeechError(f"{param_name} cannot be an absolute path: {name}")

    return name


def _validate_hex_data(hex_string: str, param_name: str = "data") -> bytes:
    """
    Validate and convert hex string to bytes.

    Args:
        hex_string: Hex string to validate
        param_name: Parameter name for error messages

    Returns:
        bytes: Converted data

    Raises:
        PCILeechError: If hex string is invalid
    """
    if not hex_string:
        raise PCILeechError(f"{param_name} cannot be empty")

    # Check for odd length (invalid hex)
    if len(hex_string) % 2 != 0:
        raise PCILeechError(
            f"{param_name} has odd length ({len(hex_string)}). "
            f"Hex strings must have even length (2 chars per byte)"
        )

    # Check for valid hex characters
    if not _HEX_PATTERN.fullmatch(hex_string):
        raise PCILeechError(f"{param_name} contains invalid hex characters")

    try:
        return bytes.fromhex(hex_string)
    except ValueError as e:
        raise PCILeechError(f"Invalid {param_name}: {e}")


def _validate_process_name(name: str) -> str:
    """
    Validate process name for safety.

    Args:
        name: Process name to validate

    Returns:
        str: Validated process name

    Raises:
        PCILeechError: If process name is invalid or contains dangerous characters
    """
    if not name or not name.strip():
        raise PCILeechError("process_name cannot be empty")

    name = name.strip()

    # Check length (Windows process names max ~260 chars, but practical limit is shorter)
    if len(name) > 260:
        raise PCILeechError(f"process_name too long: {len(name)} chars (max 260)")

    # Check for valid characters only
    if not _PROCESS_NAME_PATTERN.fullmatch(name):
        raise PCILeechError(
            f"process_name contains invalid characters: '{name}'. "
            f"Only alphanumeric, dot, underscore, hyphen, and space allowed"
        )

    return name


def _validate_address_range(address: int, length: int, param_prefix: str = "") -> None:
    """
    Validate that address + length doesn't overflow 64-bit range.

    Args:
        address: Start address
        length: Length in bytes
        param_prefix: Prefix for error messages

    Raises:
        PCILeechError: If range overflows
    """
    if length <= 0:
        raise PCILeechError(f"{param_prefix}length must be positive, got {length}")

    end_address = address + length - 1
    if end_address > _U64_MAX:
        raise PCILeechError(
            f"Address range overflow: 0x{address:x} + {length} bytes "
            f"exceeds 64-bit address space"
        )


class PCILeechError(Exception):
    """Base exception for PCILeech operations."""
    pass


class DeviceNotFoundError(PCILeechError):
    """Raised when PCILeech hardware device is not found."""
    pass


class MemoryAccessError(PCILeechError):
    """Raised when memory access fails."""
    pass


class SignatureNotFoundError(PCILeechError):
    """Raised when signature file is not found."""
    pass


class ProbeNotSupportedError(PCILeechError):
    """Raised when probe command is not supported (non-FPGA device)."""
    pass


class KMDError(PCILeechError):
    """Raised when kernel module operation fails."""
    pass


class PCILeechWrapper:
    """Wrapper for PCILeech command-line tool."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize PCILeech wrapper with configuration."""
        # Default to config.json in the same directory as this script
        if config_path is None:
            script_dir = Path(__file__).parent
            config_path = script_dir / "config.json"

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise PCILeechError(f"Configuration file not found: {config_path}")
        except json.JSONDecodeError as e:
            raise PCILeechError(f"Invalid JSON in configuration file: {e}")

        try:
            # Make executable path absolute relative to config file location
            exe_path = config['pcileech']['executable_path']
            self.timeout = config['pcileech']['timeout_seconds']
        except KeyError as e:
            raise PCILeechError(f"Missing required configuration key: {e}")

        if not os.path.isabs(exe_path):
            config_dir = Path(config_path).parent
            exe_path = str(config_dir / exe_path)

        self.executable = exe_path

        # Verify PCILeech executable exists
        if not os.path.exists(self.executable):
            raise PCILeechError(f"PCILeech executable not found at: {self.executable}")

        # KMD state management
        self._kmd_address = None  # Current loaded KMD address
        self._kmd_type = None     # Current loaded KMD type

    @property
    def kmd_loaded(self) -> bool:
        """Check if a kernel module is currently loaded."""
        return self._kmd_address is not None

    @property
    def kmd_address(self) -> Optional[str]:
        """Get the current KMD address."""
        return self._kmd_address

    @property
    def kmd_type(self) -> Optional[str]:
        """Get the current KMD type."""
        return self._kmd_type

    def _run_command(self, args: list[str]) -> Tuple[str, str, int]:
        """
        Execute PCILeech command and return output.

        Args:
            args: Command-line arguments for PCILeech

        Returns:
            Tuple of (stdout, stderr, returncode)

        Raises:
            PCILeechError: If command execution fails
        """
        try:
            result = subprocess.run(
                [self.executable] + args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=os.path.dirname(self.executable)
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            raise PCILeechError(f"PCILeech command timed out after {self.timeout} seconds")
        except Exception as e:
            raise PCILeechError(f"Failed to execute PCILeech: {str(e)}")

    def read_memory(self, address: str, length: int,
                    pid: int | None = None, process_name: str | None = None) -> bytes:
        """
        Read memory from specified address.

        Uses PCILeech 'display' command which always returns 256 bytes aligned to
        16-byte boundaries. This method handles alignment and extraction of the
        requested data range.

        Args:
            address: Memory address in hex format (e.g., "0x1000" or "1000")
            length: Number of bytes to read
            pid: Process ID for virtual address mode (optional)
            process_name: Process name for virtual address mode (optional)

        Returns:
            bytes: Memory content

        Raises:
            PCILeechError: If read operation fails
        """
        # Validate length using helper
        _validate_length(length, min_val=1)

        # Validate mutually exclusive parameters
        if pid is not None and process_name is not None:
            raise PCILeechError("pid and process_name are mutually exclusive")

        # Validate pid value
        if pid is not None and pid <= 0:
            raise PCILeechError(f"pid must be positive, got {pid}")

        # Validate process_name (check for dangerous characters)
        if process_name is not None:
            process_name = _validate_process_name(process_name)

        # Parse and validate address using helper
        target_addr = _parse_hex_address(address, "address")

        # Validate address + length doesn't overflow
        _validate_address_range(target_addr, length)

        # Display command returns 256 bytes aligned to 16-byte boundaries
        # We need to read in 256-byte chunks and extract what we need
        DISPLAY_SIZE = 256  # Display always returns 256 bytes
        ALIGN_SIZE = 16     # Display aligns to 16-byte boundaries

        all_data = bytearray()
        bytes_remaining = length
        current_addr = target_addr

        while bytes_remaining > 0:
            # Calculate aligned address (16-byte boundary)
            aligned_addr = (current_addr // ALIGN_SIZE) * ALIGN_SIZE

            # Build command: virtual address mode uses -vamin, physical mode uses -min
            # PCILeech expects: display -pid/-psname <value> -vamin <addr> (VA mode)
            #                   display -min <addr> (physical mode)
            args = ['display']
            if pid is not None:
                args.extend(['-pid', str(pid), '-vamin', f'0x{aligned_addr:x}'])
            elif process_name is not None:
                args.extend(['-psname', process_name, '-vamin', f'0x{aligned_addr:x}'])
            else:
                args.extend(['-min', f'0x{aligned_addr:x}'])

            stdout, stderr, returncode = self._run_command(args)

            # Check for business-level failures FIRST (PCILeech may return 0 on failure)
            failure = _detect_failure(stdout, stderr)
            if failure:
                raise MemoryAccessError(f"Memory read failed at 0x{aligned_addr:x}: {failure}")

            if returncode != 0:
                msg = (stderr or stdout).strip() or f"returncode={returncode}"
                raise MemoryAccessError(f"Memory read failed: {msg}")

            # Parse the 256-byte chunk
            chunk_hex = self._parse_display_output(stdout)
            if not chunk_hex:
                # Provide context about what went wrong
                preview_lines = (stdout or stderr or "").strip().splitlines()[:5]
                preview = "\n".join(preview_lines) if preview_lines else "(empty output)"
                raise MemoryAccessError(
                    f"No hex data returned for address 0x{aligned_addr:x}. "
                    f"PCILeech output:\n{preview}"
                )

            chunk_data = bytes.fromhex(chunk_hex)

            # Verify we got 256 bytes
            if len(chunk_data) != DISPLAY_SIZE:
                raise MemoryAccessError(f"Expected {DISPLAY_SIZE} bytes, got {len(chunk_data)}")

            # Calculate offset within this chunk
            offset_in_chunk = current_addr - aligned_addr

            # Calculate how many bytes to extract from this chunk
            bytes_from_chunk = min(DISPLAY_SIZE - offset_in_chunk, bytes_remaining)

            # Extract the needed portion
            extracted = chunk_data[offset_in_chunk : offset_in_chunk + bytes_from_chunk]
            all_data.extend(extracted)

            # Update counters
            bytes_remaining -= bytes_from_chunk
            current_addr += bytes_from_chunk

        return bytes(all_data)

    def write_memory(self, address: str, data: bytes,
                     pid: int | None = None, process_name: str | None = None) -> bool:
        """
        Write data to memory at specified address.

        Args:
            address: Memory address in hex format
            data: Data to write
            pid: Process ID for virtual address mode (optional)
            process_name: Process name for virtual address mode (optional)

        Returns:
            bool: True if write succeeded

        Raises:
            PCILeechError: If write operation fails
        """
        # Validate data is not empty
        if not data:
            raise PCILeechError("data cannot be empty")

        # Validate mutually exclusive parameters
        if pid is not None and process_name is not None:
            raise PCILeechError("pid and process_name are mutually exclusive")

        # Validate pid value
        if pid is not None and pid <= 0:
            raise PCILeechError(f"pid must be positive, got {pid}")

        # Validate process_name (check for dangerous characters)
        if process_name is not None:
            process_name = _validate_process_name(process_name)

        # Parse and validate address
        target_addr = _parse_hex_address(address, "address")

        # Validate address + data length doesn't overflow
        _validate_address_range(target_addr, len(data))

        # Normalize address for command
        addr = f"{target_addr:x}"

        # Convert data to hex string
        hex_data = data.hex()

        # Build command: virtual address mode uses -vamin, physical mode uses -min
        # PCILeech expects: write -pid/-psname <value> -vamin <addr> -in <data> (VA mode)
        #                   write -min <addr> -in <data> (physical mode)
        args = ['write']
        if pid is not None:
            args.extend(['-pid', str(pid), '-vamin', f'0x{addr}', '-in', hex_data])
        elif process_name is not None:
            args.extend(['-psname', process_name, '-vamin', f'0x{addr}', '-in', hex_data])
        else:
            args.extend(['-min', f'0x{addr}', '-in', hex_data])

        stdout, stderr, returncode = self._run_command(args)

        # Check for business-level failures FIRST (PCILeech may return 0 on failure)
        failure = _detect_failure(stdout, stderr)
        if failure:
            raise MemoryAccessError(f"Memory write failed at 0x{addr}: {failure}")

        if returncode != 0:
            msg = (stderr or stdout).strip() or f"returncode={returncode}"
            raise MemoryAccessError(f"Memory write failed: {msg}")

        return True

    def _parse_display_output(self, output: str) -> str:
        """
        Parse PCILeech display output to extract hex data.

        Format example:
        0000    e9 4d 06 00 01 00 00 00  01 00 00 00 3f 00 18 10   .M..........?...
                ^offset  ^8 hex bytes       ^8 hex bytes          ^ASCII

        The format is fixed:
        - 4 char hex offset
        - 4 spaces
        - 47 chars of hex data (16 bytes as "xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx")
        - 3 spaces
        - 16 chars ASCII representation

        Args:
            output: Raw PCILeech display output

        Returns:
            str: Concatenated hex data (without spaces)
        """
        hex_data = []

        for line in output.splitlines():
            # Skip headers and empty lines
            if not line or 'Memory Display:' in line or 'Contents for address:' in line:
                continue

            line = line.rstrip()  # Only strip trailing whitespace

            # Match lines starting with 4-digit hex offset
            if re.match(r'^[0-9a-fA-F]{4}\s+', line):
                # More robust method: extract all hex byte pairs using regex
                # This finds all 2-character hex sequences that are word-bounded
                # Skip the first match which is the offset

                # First, try to extract hex data from fixed positions
                # Format: "0060    xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx   ASCII"
                # Position: 0-3=offset, 4-7=spaces, 8-54=hex data (47 chars), 55-57=spaces, 58+=ASCII

                if len(line) >= 56:
                    # Extract the hex portion (positions 8-55, which is 48 chars)
                    # Format: "xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx"
                    # = 8*3-1 + 2 + 8*3-1 = 23 + 2 + 23 = 48 chars
                    hex_portion = line[8:56]
                else:
                    # Fallback for shorter lines
                    hex_portion = line[4:].lstrip()
                    # Try to find where ASCII starts (after 3+ spaces following hex data)
                    ascii_match = re.search(r'\s{3,}[^\s]', hex_portion)
                    if ascii_match:
                        hex_portion = hex_portion[:ascii_match.start()]

                # Extract all hex byte pairs (2 consecutive hex chars)
                hex_bytes = re.findall(r'[0-9a-fA-F]{2}', hex_portion)

                # Validate we got reasonable number of bytes (should be 16 per line)
                if hex_bytes:
                    hex_data.append(''.join(hex_bytes))

        return ''.join(hex_data)

    def verify_connection(self) -> bool:
        """
        Verify PCILeech is working and hardware is connected.

        Returns:
            bool: True if connection is valid
        """
        try:
            # Use 'info' command which works for all device types
            stdout, stderr, returncode = self._run_command(['info'])
            return returncode == 0
        except Exception:
            return False

    # ==================== Phase 1: Core Functions ====================

    def get_system_info(self, verbose: bool = False) -> dict:
        """
        Get system and device information.

        Args:
            verbose: Include detailed information

        Returns:
            dict: System information with keys like 'device', 'memory_size', etc.
        """
        args = ['info']
        if verbose:
            args.append('-v')

        stdout, stderr, returncode = self._run_command(args)

        if returncode != 0:
            if 'device' in stderr.lower() or 'fpga' in stderr.lower():
                raise DeviceNotFoundError(f"Device not found: {stderr}")
            raise PCILeechError(f"Info command failed: {stderr}")

        return self._parse_info_output(stdout)

    def probe_memory(self, min_addr: str = "0x0", max_addr: str | None = None) -> list[dict]:
        """
        Probe memory to find readable regions (FPGA only).

        Args:
            min_addr: Starting address in hex
            max_addr: Ending address in hex (default: auto-detect)

        Returns:
            list[dict]: List of memory regions with 'start', 'end', 'size'
        """
        args = ['probe']

        # Normalize addresses
        min_normalized = min_addr.lower().replace('0x', '')
        args.extend(['-min', f'0x{min_normalized}'])

        if max_addr:
            max_normalized = max_addr.lower().replace('0x', '')
            args.extend(['-max', f'0x{max_normalized}'])

        stdout, stderr, returncode = self._run_command(args)

        if returncode != 0:
            if 'not supported' in stderr.lower() or 'fpga' in stderr.lower():
                raise ProbeNotSupportedError("Probe is only supported on FPGA devices")
            raise PCILeechError(f"Probe failed: {stderr}")

        return self._parse_probe_output(stdout)

    def dump_memory(self, min_addr: str, max_addr: str,
                    output_file: str | None = None, force: bool = False) -> dict:
        """
        Dump memory range to file.

        Args:
            min_addr: Starting address
            max_addr: Ending address
            output_file: Output file path (auto-generated if not specified)
            force: Force read even if marked inaccessible

        Returns:
            dict: Dump result with 'file', 'size', 'success'
        """
        args = ['dump']

        # Normalize addresses
        min_normalized = min_addr.lower().replace('0x', '')
        max_normalized = max_addr.lower().replace('0x', '')

        args.extend(['-min', f'0x{min_normalized}'])
        args.extend(['-max', f'0x{max_normalized}'])

        if output_file:
            args.extend(['-out', output_file])

        if force:
            args.append('-force')

        stdout, stderr, returncode = self._run_command(args)

        if returncode != 0:
            raise MemoryAccessError(f"Memory dump failed: {stderr}")

        # Parse output to find the created file
        result = {
            'min_address': f'0x{min_normalized}',
            'max_address': f'0x{max_normalized}',
            'success': True,
            'output': stdout
        }

        # Try to extract file path from output
        for line in stdout.splitlines():
            if 'file:' in line.lower() or '.raw' in line.lower() or '.dmp' in line.lower():
                result['file'] = line.strip()
                break

        return result

    def search_memory(self, pattern: str | None = None, signature: str | None = None,
                      min_addr: str | None = None, max_addr: str | None = None,
                      find_all: bool = False) -> list[dict]:
        """
        Search memory for pattern or signature.

        Args:
            pattern: Hex pattern to search (e.g., "4D5A9000")
            signature: Signature file name (without .sig extension)
            min_addr: Start address
            max_addr: End address
            find_all: Find all matches (not just first)

        Returns:
            list[dict]: List of matches with 'address', 'offset' info

        Raises:
            PCILeechError: If neither or both pattern/signature provided
        """
        if pattern and signature:
            raise PCILeechError("pattern and signature are mutually exclusive")
        if not pattern and not signature:
            raise PCILeechError("Either pattern or signature must be provided")

        args = ['search']

        if pattern:
            args.extend(['-in', pattern])
        elif signature:
            # Sanitize signature name to prevent path traversal
            safe_sig = _sanitize_path_component(signature, "signature")
            # Check if signature file exists
            sig_file = os.path.join(os.path.dirname(self.executable), f"{safe_sig}.sig")
            if not os.path.exists(sig_file):
                raise SignatureNotFoundError(f"Signature file not found: {sig_file}")
            args.extend(['-sig', safe_sig])

        if min_addr:
            min_normalized = min_addr.lower().replace('0x', '')
            args.extend(['-min', f'0x{min_normalized}'])

        if max_addr:
            max_normalized = max_addr.lower().replace('0x', '')
            args.extend(['-max', f'0x{max_normalized}'])

        if find_all:
            args.append('-all')

        stdout, stderr, returncode = self._run_command(args)

        if returncode != 0:
            if 'not found' in stderr.lower():
                return []  # No matches found is not an error
            raise PCILeechError(f"Search failed: {stderr}")

        return self._parse_search_output(stdout)

    def patch_memory(self, signature: str, min_addr: str | None = None,
                     max_addr: str | None = None, patch_all: bool = False) -> dict:
        """
        Search and patch memory using signature.

        Args:
            signature: Signature file name (without .sig extension)
            min_addr: Start address
            max_addr: End address
            patch_all: Patch all matches

        Returns:
            dict: Patch result with 'matches', 'patched', 'success'
        """
        # Sanitize signature name to prevent path traversal
        safe_sig = _sanitize_path_component(signature, "signature")
        # Check if signature file exists
        sig_file = os.path.join(os.path.dirname(self.executable), f"{safe_sig}.sig")
        if not os.path.exists(sig_file):
            raise SignatureNotFoundError(f"Signature file not found: {sig_file}")

        args = ['patch', '-sig', safe_sig]

        if min_addr:
            min_normalized = min_addr.lower().replace('0x', '')
            args.extend(['-min', f'0x{min_normalized}'])

        if max_addr:
            max_normalized = max_addr.lower().replace('0x', '')
            args.extend(['-max', f'0x{max_normalized}'])

        if patch_all:
            args.append('-all')

        stdout, stderr, returncode = self._run_command(args)

        if returncode != 0:
            raise MemoryAccessError(f"Patch failed: {stderr}")

        # Parse output
        result = {
            'signature': signature,
            'success': True,
            'output': stdout,
            'matches_found': 0,
            'patches_applied': 0
        }

        # Try to extract patch counts from output
        for line in stdout.splitlines():
            line_lower = line.lower()
            if 'match' in line_lower or 'found' in line_lower:
                # Extract number (re already imported at module level)
                nums = re.findall(r'\d+', line)
                if nums:
                    result['matches_found'] = int(nums[0])
            if 'patch' in line_lower or 'applied' in line_lower:
                nums = re.findall(r'\d+', line)
                if nums:
                    result['patches_applied'] = int(nums[0])

        return result

    def list_processes(self) -> list[dict]:
        """
        List processes on target Windows system.

        Returns:
            list[dict]: List of processes with 'pid', 'name', 'ppid', etc.
        """
        args = ['pslist']

        stdout, stderr, returncode = self._run_command(args)

        if returncode != 0:
            raise PCILeechError(f"Process list failed: {stderr}")

        return self._parse_pslist_output(stdout)

    # ==================== Phase 2: Address Translation ====================

    def translate_phys2virt(self, phys_addr: str, cr3: str) -> dict:
        """
        Translate physical address to virtual address.

        Args:
            phys_addr: Physical address in hex
            cr3: Page table base address (CR3 register value)

        Returns:
            dict: Translation result with 'physical', 'virtual', 'success', 'error'
        """
        # Validate and normalize addresses
        phys_int = _parse_hex_address(phys_addr, "physical_address")
        cr3_int = _parse_hex_address(cr3, "cr3")
        phys_normalized = f"{phys_int:x}"
        cr3_normalized = f"{cr3_int:x}"

        args = ['pt_phys2virt', '-cr3', f'0x{cr3_normalized}', '-0', f'0x{phys_normalized}']

        stdout, stderr, returncode = self._run_command(args)

        # Detect business-level failures (PCILeech may return 0 on failure)
        failure = _detect_failure(stdout, stderr)
        is_success = (returncode == 0) and (failure is None)

        result = {
            'physical': f'0x{phys_normalized}',
            'cr3': f'0x{cr3_normalized}',
            'virtual': None,
            'success': is_success,
            'output': stdout,
            'error': failure or (stderr.strip() if returncode != 0 else None)
        }

        if is_success:
            # Try to extract virtual address from output
            virt_match = re.search(r'virtual[:\s]*(0x[0-9a-fA-F]+)', stdout, re.IGNORECASE)
            if virt_match:
                result['virtual'] = virt_match.group(1)
            else:
                # Try to find any hex address in output that's not the input
                for match in re.finditer(r'0x[0-9a-fA-F]+', stdout):
                    addr = match.group()
                    if addr.lower() != f'0x{phys_normalized}' and addr.lower() != f'0x{cr3_normalized}':
                        result['virtual'] = addr
                        break

        return result

    def translate_virt2phys(self, virt_addr: str, cr3: str) -> dict:
        """
        Translate virtual address to physical address.

        Args:
            virt_addr: Virtual address in hex
            cr3: Page table base address (CR3 register value)

        Returns:
            dict: Translation result with 'virtual', 'physical', 'success', 'error'
        """
        # Validate and normalize addresses
        virt_int = _parse_hex_address(virt_addr, "virtual_address")
        cr3_int = _parse_hex_address(cr3, "cr3")
        virt_normalized = f"{virt_int:x}"
        cr3_normalized = f"{cr3_int:x}"

        args = ['pt_virt2phys', '-cr3', f'0x{cr3_normalized}', '-0', f'0x{virt_normalized}']

        stdout, stderr, returncode = self._run_command(args)

        # Detect business-level failures (PCILeech may return 0 on failure)
        failure = _detect_failure(stdout, stderr)
        is_success = (returncode == 0) and (failure is None)

        result = {
            'virtual': f'0x{virt_normalized}',
            'cr3': f'0x{cr3_normalized}',
            'physical': None,
            'success': is_success,
            'output': stdout,
            'error': failure or (stderr.strip() if returncode != 0 else None)
        }

        if is_success:
            # Try to extract physical address from output
            phys_match = re.search(r'physical[:\s]*(0x[0-9a-fA-F]+)', stdout, re.IGNORECASE)
            if phys_match:
                result['physical'] = phys_match.group(1)
            else:
                # Try to find any hex address in output that's not the input
                for match in re.finditer(r'0x[0-9a-fA-F]+', stdout):
                    addr = match.group()
                    if addr.lower() != f'0x{virt_normalized}' and addr.lower() != f'0x{cr3_normalized}':
                        result['physical'] = addr
                        break

        return result

    def process_virt2phys(self, pid: int, virt_addr: str) -> dict:
        """
        Translate process virtual address to physical address.

        Args:
            pid: Process ID
            virt_addr: Virtual address in hex

        Returns:
            dict: Translation result with 'pid', 'virtual', 'physical', 'success', 'error'
        """
        # Validate pid
        if not isinstance(pid, int):
            raise PCILeechError(f"pid must be int, got {type(pid).__name__}")
        if pid <= 0:
            raise PCILeechError(f"pid must be positive, got {pid}")

        # Parse and validate address
        virt_int = _parse_hex_address(virt_addr, "virtual_address")
        virt_normalized = f"{virt_int:x}"

        args = ['psvirt2phys', '-0', str(pid), '-1', f'0x{virt_normalized}']

        stdout, stderr, returncode = self._run_command(args)

        # Detect business-level failures (PCILeech may return 0 on failure)
        failure = _detect_failure(stdout, stderr)
        is_success = (returncode == 0) and (failure is None)

        result = {
            'pid': pid,
            'virtual': f'0x{virt_normalized}',
            'physical': None,
            'success': is_success,
            'output': stdout,
            'error': failure or (stderr.strip() if returncode != 0 else None)
        }

        if is_success:
            # Try to extract physical address from output
            phys_match = re.search(r'physical[:\s]*(0x[0-9a-fA-F]+)', stdout, re.IGNORECASE)
            if phys_match:
                result['physical'] = phys_match.group(1)
            else:
                # Try to find any hex address in output
                for match in re.finditer(r'0x[0-9a-fA-F]+', stdout):
                    addr = match.group()
                    if addr.lower() != f'0x{virt_normalized}':
                        result['physical'] = addr
                        break

        return result

    # ==================== Phase 3: Kernel Module (KMD) ====================

    def load_kmd(self, kmd_type: str, use_pt: bool = False,
                 cr3: str | None = None, sysmap: str | None = None) -> dict:
        """
        Load kernel module to target system.

        Args:
            kmd_type: KMD type (e.g., 'WIN10_X64_3', 'LINUX_X64_48')
            use_pt: Use page table hijacking method
            cr3: Page table base address (optional)
            sysmap: Linux System.map file path (for LINUX_X64_MAP)

        Returns:
            dict: Load result with 'success', 'kmd_address', 'kmd_type'
        """
        args = ['kmdload', '-kmd', kmd_type]

        if use_pt:
            args.append('-pt')

        if cr3:
            cr3_normalized = cr3.lower().replace('0x', '')
            args.extend(['-cr3', f'0x{cr3_normalized}'])

        if sysmap:
            args.extend(['-in', sysmap])

        stdout, stderr, returncode = self._run_command(args)

        result = {
            'kmd_type': kmd_type,
            'success': returncode == 0,
            'kmd_address': None,
            'output': stdout,
            'error': stderr if returncode != 0 else None
        }

        if returncode == 0:
            # Try to extract KMD address from output
            addr_match = re.search(r'KMD[:\s]*(0x[0-9a-fA-F]+)', stdout, re.IGNORECASE)
            if addr_match:
                result['kmd_address'] = addr_match.group(1)
                self._kmd_address = result['kmd_address']
                self._kmd_type = kmd_type
            else:
                # Try any address pattern after "loaded" or "success"
                for match in re.finditer(r'0x[0-9a-fA-F]+', stdout):
                    result['kmd_address'] = match.group()
                    self._kmd_address = result['kmd_address']
                    self._kmd_type = kmd_type
                    break
        else:
            raise KMDError(f"Failed to load KMD: {stderr}")

        return result

    def unload_kmd(self, kmd_address: str | None = None) -> dict:
        """
        Unload kernel module from target system.

        Args:
            kmd_address: KMD address (uses cached address if not provided)

        Returns:
            dict: Unload result with 'success'
        """
        addr = kmd_address or self._kmd_address
        if not addr:
            raise KMDError("No KMD address provided and no KMD currently loaded")

        addr_normalized = addr.lower().replace('0x', '')
        args = ['kmdexit', '-kmd', f'0x{addr_normalized}']

        stdout, stderr, returncode = self._run_command(args)

        result = {
            'kmd_address': f'0x{addr_normalized}',
            'success': returncode == 0,
            'output': stdout,
            'error': stderr if returncode != 0 else None
        }

        if returncode == 0:
            # Clear cached KMD state
            if addr_normalized == self._kmd_address.lower().replace('0x', '') if self._kmd_address else '':
                self._kmd_address = None
                self._kmd_type = None

        return result

    def execute_ksh(self, script_name: str, kmd_address: str | None = None,
                    input_file: str | None = None, output_file: str | None = None,
                    string_param: str | None = None,
                    numeric_params: dict | None = None) -> dict:
        """
        Execute kernel script (.ksh).

        Args:
            script_name: Script name without .ksh extension
            kmd_address: KMD address (uses cached if not provided)
            input_file: Input file path (WARNING: user-controlled, verify with caution)
            output_file: Output file path (WARNING: user-controlled, verify with caution)
            string_param: String parameter (-s)
            numeric_params: Dict of numeric params {0: 'value', 1: 'value', ...}

        Returns:
            dict: Execution result
        """
        addr = kmd_address or self._kmd_address
        if not addr:
            raise KMDError("No KMD address provided and no KMD currently loaded")

        # Sanitize script name to prevent path traversal
        safe_script = _sanitize_path_component(script_name, "script_name")

        # Check if script exists
        script_file = os.path.join(os.path.dirname(self.executable), f"{safe_script}.ksh")
        if not os.path.exists(script_file):
            raise PCILeechError(f"Script file not found: {script_file}")

        addr_normalized = addr.lower().replace('0x', '')
        args = [safe_script, '-kmd', f'0x{addr_normalized}']

        # NOTE: input_file and output_file are passed directly to PCILeech
        # These could be security-sensitive paths - the caller is responsible for validation
        if input_file:
            args.extend(['-in', input_file])

        if output_file:
            args.extend(['-out', output_file])

        if string_param:
            args.extend(['-s', string_param])

        if numeric_params:
            for key, value in numeric_params.items():
                if key in range(10):  # -0 to -9
                    args.extend([f'-{key}', str(value)])

        stdout, stderr, returncode = self._run_command(args)

        result = {
            'script': script_name,
            'kmd_address': f'0x{addr_normalized}',
            'success': returncode == 0,
            'output': stdout,
            'error': stderr if returncode != 0 else None
        }

        return result

    def list_available_scripts(self, platform: str = "all") -> list[dict]:
        """
        List available kernel scripts (.ksh files).

        Args:
            platform: Filter by platform ('all', 'windows', 'linux', 'macos', 'freebsd', 'uefi')

        Returns:
            list[dict]: List of available scripts with 'name', 'platform', 'path'
        """
        pcileech_dir = os.path.dirname(self.executable)
        scripts = []

        # Platform prefixes
        platform_prefixes = {
            'windows': ['wx64_', 'wx86_'],
            'linux': ['lx64_'],
            'macos': ['macos_'],
            'freebsd': ['fbsdx64_'],
            'uefi': ['uefi_']
        }

        for file in os.listdir(pcileech_dir):
            if file.endswith('.ksh'):
                script_name = file[:-4]  # Remove .ksh
                script_platform = 'unknown'

                # Determine platform
                for plat, prefixes in platform_prefixes.items():
                    if any(file.startswith(prefix) for prefix in prefixes):
                        script_platform = plat
                        break

                # Filter by platform
                if platform != 'all' and script_platform != platform:
                    continue

                scripts.append({
                    'name': script_name,
                    'platform': script_platform,
                    'path': os.path.join(pcileech_dir, file)
                })

        return sorted(scripts, key=lambda x: (x['platform'], x['name']))

    # ==================== Phase 4: Advanced/FPGA Functions ====================

    def run_benchmark(self, test_type: str = "read", address: str = "0x1000") -> dict:
        """
        Run memory read/write performance benchmark.

        Args:
            test_type: Type of test ('read', 'readwrite', 'full')
            address: Test address

        Returns:
            dict: Benchmark results
        """
        addr_normalized = address.lower().replace('0x', '')

        if test_type == "full":
            args = ['benchmark']
        elif test_type == "readwrite":
            args = ['testmemreadwrite', '-min', f'0x{addr_normalized}']
        else:  # read
            args = ['testmemread', '-min', f'0x{addr_normalized}']

        stdout, stderr, returncode = self._run_command(args)

        result = {
            'test_type': test_type,
            'address': f'0x{addr_normalized}',
            'success': returncode == 0,
            'output': stdout,
            'speed_mbps': None
        }

        # Try to extract speed from output
        speed_match = re.search(r'(\d+(?:\.\d+)?)\s*(?:MB/s|Mbps|MB)', stdout, re.IGNORECASE)
        if speed_match:
            result['speed_mbps'] = float(speed_match.group(1))

        return result

    def send_tlp(self, tlp_data: str | None = None, wait_seconds: float = 0.5,
                 verbose: bool = True) -> dict:
        """
        Send/receive PCIe TLP packets (FPGA only).

        Args:
            tlp_data: TLP packet data in hex (optional)
            wait_seconds: Time to wait for TLP responses
            verbose: Show detailed TLP info

        Returns:
            dict: TLP operation result
        """
        args = ['tlp']

        if tlp_data:
            args.extend(['-in', tlp_data])

        args.extend(['-wait', str(wait_seconds)])

        if verbose:
            args.append('-vv')

        stdout, stderr, returncode = self._run_command(args)

        result = {
            'success': returncode == 0,
            'tlp_sent': tlp_data,
            'wait_seconds': wait_seconds,
            'output': stdout,
            'tlp_received': []
        }

        # Try to parse TLP packets from output
        tlp_pattern = re.compile(r'TLP[:\s]*([0-9a-fA-F\s]+)', re.IGNORECASE)
        for match in tlp_pattern.finditer(stdout):
            result['tlp_received'].append(match.group(1).strip())

        return result

    def fpga_config(self, action: str = "read", address: str | None = None,
                    data: str | None = None, output_file: str | None = None) -> dict:
        """
        Read/write FPGA PCIe configuration space.

        Args:
            action: 'read' or 'write'
            address: Configuration space address
            data: Data to write (hex, for write action)
            output_file: Output file path

        Returns:
            dict: Configuration operation result

        Raises:
            PCILeechError: If write action is specified without data
        """
        # Validate write action requires data
        if action == "write" and not data:
            raise PCILeechError("FPGA config write action requires 'data' parameter")

        args = ['regcfg']

        if address:
            addr_normalized = address.lower().replace('0x', '')
            args.extend(['-min', f'0x{addr_normalized}'])

        if action == "write" and data:
            args.extend(['-in', data])

        if output_file:
            args.extend(['-out', output_file])

        stdout, stderr, returncode = self._run_command(args)

        result = {
            'action': action,
            'address': address,
            'success': returncode == 0,
            'output': stdout,
            'data': None
        }

        if action == "read" and returncode == 0:
            # Try to extract config data
            hex_match = re.search(r'([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)', stdout)
            if hex_match:
                result['data'] = hex_match.group(1)

        return result

    # ==================== Output Parsers ====================

    def _parse_info_output(self, output: str) -> dict:
        """
        Parse info command output.

        Returns:
            dict: Parsed system info
        """
        info = {
            'raw_output': output,
            'device': None,
            'fpga': False,
            'memory_max': None
        }

        for line in output.splitlines():
            line_lower = line.lower()

            # Device type
            if 'device:' in line_lower or 'type:' in line_lower:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    info['device'] = parts[1].strip()

            # FPGA detection
            if 'fpga' in line_lower:
                info['fpga'] = True

            # Memory size
            if 'memory' in line_lower and ('max' in line_lower or 'size' in line_lower):
                # Try to extract hex address
                hex_match = re.search(r'0x[0-9a-fA-F]+', line)
                if hex_match:
                    info['memory_max'] = hex_match.group()

        return info

    def _parse_probe_output(self, output: str) -> list[dict]:
        """
        Parse probe command output.

        Returns:
            list[dict]: List of memory regions
        """
        regions = []

        for line in output.splitlines():
            # Look for address ranges like "0x00000000 - 0x0FFFFFFF : OK"
            range_match = re.search(
                r'(0x[0-9a-fA-F]+)\s*[-:]\s*(0x[0-9a-fA-F]+).*?(OK|FAIL|readable|writable)',
                line, re.IGNORECASE
            )
            if range_match:
                start = range_match.group(1)
                end = range_match.group(2)
                status = range_match.group(3).upper()

                start_int = int(start, 16)
                end_int = int(end, 16)

                regions.append({
                    'start': start,
                    'end': end,
                    'size': end_int - start_int,
                    'size_mb': (end_int - start_int) / (1024 * 1024),
                    'status': 'readable' if status == 'OK' else status.lower()
                })

        return regions

    def _parse_search_output(self, output: str) -> list[dict]:
        """
        Parse search command output.

        Returns:
            list[dict]: List of search matches
        """
        matches = []

        for line in output.splitlines():
            # Look for address matches like "Match at 0x12345678" or "0x12345678: ..."
            addr_match = re.search(r'(?:match|found|at)?\s*(0x[0-9a-fA-F]+)', line, re.IGNORECASE)
            if addr_match and 'search' not in line.lower():
                matches.append({
                    'address': addr_match.group(1),
                    'line': line.strip()
                })

        return matches

    def _parse_pslist_output(self, output: str) -> list[dict]:
        """
        Parse pslist command output.

        Returns:
            list[dict]: List of processes
        """
        processes = []

        # Skip header lines
        in_data = False

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Detect header line (contains PID, Name, etc.)
            if 'pid' in line.lower() and 'name' in line.lower():
                in_data = True
                continue

            if not in_data:
                # Also try to detect data lines without explicit header
                if re.match(r'^\s*\d+\s+', line):
                    in_data = True
                else:
                    continue

            # Parse process line
            # Typical format: "PID    PPID   Name"
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pid = int(parts[0])
                    proc = {'pid': pid}

                    # Try to get more fields
                    if len(parts) >= 3:
                        # Check if second field is numeric (PPID)
                        try:
                            proc['ppid'] = int(parts[1])
                            proc['name'] = ' '.join(parts[2:])
                        except ValueError:
                            proc['name'] = ' '.join(parts[1:])
                    else:
                        proc['name'] = parts[1]

                    processes.append(proc)
                except ValueError:
                    # First field not a number, skip
                    continue

        return processes
