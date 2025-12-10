"""
PCILeech wrapper for memory operations.

This module provides a Python interface to PCILeech command-line tool
for DMA-based memory read/write operations.
"""

import subprocess
import os
import json
import re
from typing import Optional, Tuple
from pathlib import Path


class PCILeechError(Exception):
    """Base exception for PCILeech operations."""
    pass


class PCILeechWrapper:
    """Wrapper for PCILeech command-line tool."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize PCILeech wrapper with configuration."""
        # Default to config.json in the same directory as this script
        if config_path is None:
            script_dir = Path(__file__).parent
            config_path = script_dir / "config.json"

        with open(config_path, 'r') as f:
            config = json.load(f)

        # Make executable path absolute relative to config file location
        exe_path = config['pcileech']['executable_path']
        if not os.path.isabs(exe_path):
            config_dir = Path(config_path).parent
            exe_path = str(config_dir / exe_path)

        self.executable = exe_path
        self.timeout = config['pcileech']['timeout_seconds']

        # Verify PCILeech executable exists
        if not os.path.exists(self.executable):
            raise PCILeechError(f"PCILeech executable not found at: {self.executable}")

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

    def read_memory(self, address: str, length: int) -> bytes:
        """
        Read memory from specified address.

        Uses PCILeech 'display' command which always returns 256 bytes aligned to
        16-byte boundaries. This method handles alignment and extraction of the
        requested data range.

        Args:
            address: Memory address in hex format (e.g., "0x1000" or "1000")
            length: Number of bytes to read

        Returns:
            bytes: Memory content

        Raises:
            PCILeechError: If read operation fails
        """
        # Normalize address format (remove 0x prefix if present)
        addr = address.lower().replace('0x', '')
        target_addr = int(addr, 16)

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

            # Read 256-byte chunk using display
            args = ['display', '-min', f'0x{aligned_addr:x}']
            stdout, stderr, returncode = self._run_command(args)

            if returncode != 0:
                raise PCILeechError(f"Memory read failed: {stderr}")

            # Parse the 256-byte chunk
            chunk_hex = self._parse_display_output(stdout)
            if not chunk_hex:
                raise PCILeechError(f"Failed to parse PCILeech output")

            chunk_data = bytes.fromhex(chunk_hex)

            # Verify we got 256 bytes
            if len(chunk_data) != DISPLAY_SIZE:
                raise PCILeechError(f"Expected {DISPLAY_SIZE} bytes, got {len(chunk_data)}")

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

    def write_memory(self, address: str, data: bytes) -> bool:
        """
        Write data to memory at specified address.

        Args:
            address: Memory address in hex format
            data: Data to write

        Returns:
            bool: True if write succeeded

        Raises:
            PCILeechError: If write operation fails
        """
        # Normalize address
        addr = address.lower().replace('0x', '')

        # Convert data to hex string
        hex_data = data.hex()

        # PCILeech command: write -min <address> -in <hex_data>
        args = [
            'write',
            '-min', f'0x{addr}',
            '-in', hex_data,
        ]

        stdout, stderr, returncode = self._run_command(args)

        if returncode != 0:
            raise PCILeechError(f"Memory write failed: {stderr}")

        return True

    def _parse_display_output(self, output: str) -> str:
        """
        Parse PCILeech display output to extract hex data.

        Format example:
        0000    e9 4d 06 00 01 00 00 00  01 00 00 00 3f 00 18 10   .M..........?...
                ^offset  ^8 hex bytes       ^8 hex bytes          ^ASCII

        Args:
            output: Raw PCILeech display output

        Returns:
            str: Concatenated hex data (without spaces)
        """
        hex_data = []

        for line in output.splitlines():
            line = line.strip()

            # Skip headers and empty lines
            if not line or 'Memory Display:' in line or 'Contents for address:' in line:
                continue

            # Match lines starting with 4-digit hex offset
            if re.match(r'^[0-9a-fA-F]{4}\s+', line):
                # Split line: offset | hex_part1 | hex_part2 | ascii
                # Format: "0000    e9 4d ... 00 00  01 00 ... 10   .M...?..."

                # Remove the offset (first 4 chars + spaces)
                without_offset = line[4:].lstrip()

                # Find ASCII part (starts after 2+ consecutive spaces)
                # Split by 2+ spaces
                parts = re.split(r'\s{2,}', without_offset)

                # The hex data is everything before the last part (ASCII)
                if len(parts) >= 2:
                    # Everything except the last part (ASCII) is hex data
                    hex_parts = parts[:-1]
                    # Join all hex parts and remove spaces
                    hex_bytes = ''.join(hex_parts).replace(' ', '')
                    hex_data.append(hex_bytes)
                elif len(parts) == 1:
                    # No ASCII part, entire line is hex
                    hex_bytes = parts[0].replace(' ', '')
                    hex_data.append(hex_bytes)

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
