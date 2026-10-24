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


def encode_request(token, operation, *args):
    payload = "\t".join(quote(str(v), safe="") for v in (token, operation, *args)).encode("ascii")
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
    token = os.environ.get("CE_MCP_TOKEN", "")
    pipe = os.environ.get("CE_MCP_PIPE", "ce-mcp")
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("CE_MCP_TOKEN must be a 64-character lowercase hex secret")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", pipe):
        raise ValueError("Invalid CE_MCP_PIPE")
    with LOCK:
        response = exchange(encode_request(token, operation, *args), pipe)
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
def stop_bridge() -> dict:
    """Disable this CE bridge until manually started again in the Lua console."""
    return call("stop")


if __name__ == "__main__":
    mcp.run(transport="stdio")
