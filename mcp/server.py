"""STDIO MCP adapter for the in-process Cheat Engine GUI bridge (Windows)."""
import json
import os
import re
import struct
import threading
import time
from urllib.parse import quote

from mcp.server.fastmcp import FastMCP

MAX_FRAME = 1024 * 1024
LOCK = threading.Lock()
mcp = FastMCP("Cheat Engine GUI")


def encode_request(operation, *args):
    payload = "\t".join(quote(str(v), safe="") for v in (operation, *args)).encode("ascii")
    if len(payload) > MAX_FRAME:
        raise ValueError("Request too large")
    return struct.pack("<I", len(payload)) + payload


def exchange(frame, pipe_name, timeout=10):
    """One connection per command; deadline covers connection and all I/O."""
    import pywintypes
    import win32con
    import win32event
    import win32file
    import win32pipe

    deadline = time.monotonic() + timeout

    def remaining():
        return max(1, int((deadline - time.monotonic()) * 1000))

    path = "\\\\.\\pipe\\" + pipe_name
    win32pipe.WaitNamedPipe(path, remaining())
    handle = win32file.CreateFile(path, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                                 0, None, win32con.OPEN_EXISTING,
                                 win32con.FILE_FLAG_OVERLAPPED, None)

    def io(data, writing=False):
        overlap = pywintypes.OVERLAPPED()
        overlap.hEvent = win32event.CreateEvent(None, True, False, None)
        try:
            if writing:
                win32file.WriteFile(handle, data, overlap)
            else:
                data = win32file.AllocateReadBuffer(data)
                win32file.ReadFile(handle, data, overlap)
            if win32event.WaitForSingleObject(overlap.hEvent, remaining()) != win32event.WAIT_OBJECT_0:
                # This handle belongs to this call, with one pending I/O on this thread.
                win32file.CancelIo(handle)
                # Drain cancellation before releasing the OVERLAPPED and its buffer.
                try:
                    win32file.GetOverlappedResult(handle, overlap, True)
                except pywintypes.error:
                    pass
                raise TimeoutError("CE response timed out; command outcome unknown. Inspect state before retrying.")
            size = win32file.GetOverlappedResult(handle, overlap, False)
            return size if writing else bytes(data[:size])
        finally:
            overlap.hEvent.Close()

    def read_exact(size):
        result = bytearray()
        while len(result) < size:
            chunk = io(size - len(result))
            if not chunk:
                raise ConnectionError("CE disconnected; command outcome may be unknown")
            result.extend(chunk)
        return bytes(result)

    try:
        offset = 0
        while offset < len(frame):
            count = io(frame[offset:], True)
            if not count:
                raise ConnectionError("CE disconnected while sending")
            offset += count
        size, = struct.unpack("<I", read_exact(4))
        if not 0 < size <= MAX_FRAME:
            raise ValueError("Invalid CE response length")
        return json.loads(read_exact(size).decode("utf-8"))
    finally:
        handle.Close()


def call(operation, *args):
    pipe = os.environ.get("CE_MCP_PIPE", "ce-mcp")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", pipe):
        raise ValueError("Invalid CE_MCP_PIPE")
    with LOCK:
        response = exchange(encode_request(operation, *args), pipe)
    if not response.get("ok"):
        raise ValueError(response.get("error", "CE command failed"))
    return response["result"]


@mcp.tool()
def get_state() -> dict:
    """Read attached process ID and address-list count from the live GUI."""
    return call("state")


@mcp.tool()
def list_processes() -> list:
    """List processes visible to Cheat Engine."""
    return call("processes")


@mcp.tool()
def attach_process(pid: int) -> dict:
    """Attach CE to a PID, updating its normal GUI process selection."""
    return call("attach", pid)


@mcp.tool()
def list_records(offset: int = 0, limit: int = 100) -> list:
    """Read live address-list records, including changes made manually in CE."""
    return call("records", offset, limit)


@mcp.tool()
def add_record(expected_pid: int, address: str, description: str, value_type: str = "dword") -> dict:
    """Add and select a visible numeric record. Types: byte, word, dword, qword, float, double."""
    return call("add", expected_pid, address, description, value_type)


@mcp.tool()
def set_record_value(expected_pid: int, record_id: int, value: str) -> dict:
    """Write a numeric record's value through CE and return the observed value."""
    return call("value", expected_pid, record_id, value)


@mcp.tool()
def freeze_record(expected_pid: int, record_id: int, frozen: bool) -> dict:
    """Set the GUI freeze checkbox of a numeric record; script records are rejected."""
    return call("freeze", expected_pid, record_id, "1" if frozen else "0")


@mcp.tool()
def first_scan(expected_pid: int, value: str = "", value_type: str = "dword",
               scan_type: str = "exact", value2: str = "", start_address: str = "",
               stop_address: str = "") -> dict:
    """Start an asynchronous scan in CE's GUI. Types: exact, bigger, smaller, between, unknown.

    Numeric value types: byte, word, dword, qword, float, double. Replaces existing scan
    results. Empty address bounds preserve the GUI bounds. Poll scan_status until idle.
    """
    return call("scan_first", expected_pid, value_type, scan_type, value, value2, start_address, stop_address)


@mcp.tool()
def next_scan(expected_pid: int, scan_type: str = "exact", value: str = "", value2: str = "") -> dict:
    """Filter current GUI scan asynchronously. Also supports increased, increased_by,
    decreased, decreased_by, changed, unchanged. Poll scan_status before reading results.
    """
    return call("scan_next", expected_pid, scan_type, value, value2)


@mcp.tool()
def scan_status(expected_pid: int) -> dict:
    """Read GUI scan busy state, progress and result count without blocking the GUI."""
    return call("scan_status", expected_pid)


@mcp.tool()
def scan_results(expected_pid: int, offset: int = 0, limit: int = 100) -> dict:
    """Read a page of the current GUI scan results, including scans started manually.
    Unknown-initial-value region snapshots must first be narrowed with next_scan.
    """
    return call("scan_results", expected_pid, offset, limit)


@mcp.tool()
def reset_scan(expected_pid: int) -> dict:
    """Clear the current GUI scan results while idle. Address-list records remain."""
    return call("scan_reset", expected_pid)


@mcp.tool()
def read_memory(expected_pid: int, address: str, size: int = 32) -> dict:
    """Read 1..4096 bytes as hex and navigate the GUI memory viewer to the address."""
    return call("memory_read", expected_pid, address, size)


@mcp.tool()
def write_memory(expected_pid: int, address: str, hex_bytes: str, expected_hex: str) -> dict:
    """Write 1..4096 bytes only if current bytes equal expected_hex; verify by rereading.
    Returns original and observed bytes for restoring patches. No automatic retries.
    """
    return call("memory_write", expected_pid, address, hex_bytes, expected_hex)


@mcp.tool()
def list_modules(expected_pid: int) -> list:
    """List target modules with hex base addresses, sizes and paths."""
    return call("modules", expected_pid)


@mcp.tool()
def disassemble(expected_pid: int, address: str, count: int = 16) -> list:
    """Disassemble 1..100 instructions and select the address in CE's disassembler."""
    return call("disassemble", expected_pid, address, count)


@mcp.tool()
def resolve_pointer_chain(expected_pid: int, base: str, offsets: list[int]) -> dict:
    """Resolve a chain in traversal order: address = readPointer(address) + offset
    for each offset. Returns every intermediate pointer as an exact hex string.
    """
    return call("pointer_resolve", expected_pid, base, ",".join(map(str, offsets)))


@mcp.tool()
def add_pointer_record(expected_pid: int, base: str, offsets: list[int], description: str,
                       value_type: str = "dword") -> dict:
    """Add a visible CE pointer record; offsets are in base-to-value traversal order."""
    return call("pointer_add", expected_pid, base, ",".join(map(str, offsets)), description, value_type)


@mcp.tool()
def update_record(expected_pid: int, record_id: int, description: str) -> dict:
    """Rename a visible address-list record."""
    return call("record_rename", expected_pid, record_id, description)


@mcp.tool()
def watch_memory(expected_pid: int, address: str, trigger: str = "write", size: int = 4) -> dict:
    """Arm a hardware write/access/execute breakpoint. Starts the Windows debugger
    if needed. Captures up to 100 register snapshots and auto-continues the target.
    Read get_watch_hits after triggering the watched operation; remove_watch when done.
    """
    return call("watch_add", expected_pid, address, trigger, size)


@mcp.tool()
def get_watch_hits(expected_pid: int, address: str) -> dict:
    """Read captured IP/register snapshots for an MCP-owned breakpoint."""
    return call("watch_hits", expected_pid, address)


@mcp.tool()
def remove_watch(expected_pid: int, address: str) -> dict:
    """Remove an MCP-owned breakpoint. Captured events are returned before cleanup."""
    return call("watch_remove", expected_pid, address)


@mcp.tool()
def add_assembler_script(expected_pid: int, description: str, script: str) -> dict:
    """Add an INACTIVE, visible Auto Assembler record with ENABLE/DISABLE sections.
    Use set_script_enabled explicitly to activate or deactivate an injection.
    """
    return call("script_add", expected_pid, description, script)


@mcp.tool()
def set_script_enabled(expected_pid: int, record_id: int, enabled: bool) -> dict:
    """Activate/deactivate a visible Auto Assembler script record through CE."""
    return call("script_enable", expected_pid, record_id, "1" if enabled else "0")


@mcp.tool()
def stop_bridge() -> dict:
    """Disable this CE bridge until manually started again in the Lua console."""
    return call("stop")


if __name__ == "__main__":
    mcp.run(transport="stdio")
