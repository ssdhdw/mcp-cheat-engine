"""Protocol, Lua dispatch, Windows pipe, and real MCP STDIO tests.

The Lua CE API below is a test double, not a substitute for live GUI validation.
"""
import asyncio
import json
from pathlib import Path
import struct
import sys
import threading
import unittest
import uuid
import tempfile

from lupa import LuaRuntime
import server
import install_autorun

HARNESS = r'''
vtByte, vtWord, vtDword, vtQword, vtSingle, vtDouble = 0,1,2,3,4,5
alClient = 5
local main = false
local function gui() assert(main, 'CE API accessed outside GUI thread') end
local pid = 42
local records = {}
local al = {Count=0}
function al.createMemoryRecord()
  gui()
  local r = {ID=al.Count+1, Type=2, Address='', Description='', Value='7', Active=false}
  function r.destroy() al.Count=al.Count-1 end
  records[al.Count] = r
  al.Count=al.Count+1
  return r
end
function al.getMemoryRecordByID(id)
  gui()
  for _, r in pairs(records) do if r.ID == id then return r end end
end
function al.repaint() gui() end
setmetatable(al, {__index=function(_,k) return records[k] end})
function getAddressList() gui(); return al end
function getOpenedProcessID() gui(); return pid end
function getProcesslist() gui(); return {[42]='Tutorial.exe'} end
function openProcess(n) gui(); assert(type(n)=='number'); pid=n; return true end
function getAddressSafe(a) gui(); if a == 'invalid' then return nil end; return 4096 end
function createForm()
  return {show=function() end}
end
function createMemo()
  local lines = {Count=0}
  function lines.add(s) lines.Count=lines.Count+1 end
  function lines.delete(i) lines.Count=lines.Count-1 end
  return {Lines=lines}
end
function synchronize(fn) main=true; fn(); main=false end
function createNativeThread(fn) worker=fn; return {} end
requests, responses = {}, {}
local nextRequest = 0
function createPipe()
  nextRequest=nextRequest+1
  local request = assert(requests[nextRequest], 'Unexpected connection')
  return {valid=true, acceptConnection=function() end,
    readDword=function() return #request end,
    readString=function(size) assert(size==#request); return request end,
    writeDword=function(size) end,
    writeString=function(s) responses[#responses+1]=s end,
    destroy=function() end}
end
'''


class LuaTests(unittest.TestCase):
    def run_commands(self, commands):
        lua = LuaRuntime(unpack_returned_tuples=True)
        lua.execute(HARNESS)
        lua.execute(Path(__file__).with_name("ce_bridge.lua").read_text(encoding="utf-8"))
        for i, (op, args) in enumerate(commands + [("stop", ())], 1):
            lua.globals().requests[i] = server.encode_request(op, *args)[4:].decode("ascii")
        lua.globals().ce_mcp.start()
        lua.globals().worker()
        return [json.loads(v) for _, v in lua.globals().responses.items()]

    def test_gui_roundtrip_unicode_and_freeze(self):
        result = self.run_commands([
            ("state", ()),
            ("add", (42, "1000", 'Здоровье\t"\\\n', "dword")),
            ("value", (42, 1, "99")),
            ("freeze", (42, 1, "1")),
            ("records", (0, 100)),
            ("processes", ()),
            ("attach", (43,)),
        ])
        self.assertTrue(all(r["ok"] for r in result), result)
        self.assertEqual(result[1]["result"]["description"], 'Здоровье\t"\\\n')
        self.assertEqual(result[2]["result"]["value"], "99")
        self.assertTrue(result[4]["result"][0]["frozen"])
        self.assertEqual(result[6]["result"]["pid"], 43)

    def test_pid_change_does_not_mutate(self):
        result = self.run_commands([
            ("add", (99, "1000", "wrong pid", "dword")),
            ("state", ()),
        ])
        self.assertFalse(result[0]["ok"])
        self.assertEqual(result[1]["result"], {"pid":42, "record_count":0})

    def test_validation_and_unknown_operation(self):
        commands = [("add", (42, "1000", "script", "autoassembler")),
                    ("add", (42, "invalid", "bad address", "dword")),
                    ("records", (0, 201)),
                    ("value", (42, 123, "99")),
                    ("execute_lua", ("print('no')",))]
        result = self.run_commands(commands)
        self.assertTrue(all(not r["ok"] for r in result[:-1]), result)


@unittest.skipUnless(sys.platform == "win32", "Windows named pipes")
class PipeTests(unittest.TestCase):
    def test_real_pipe_fragmented_response(self):
        import win32file
        import win32pipe
        pipe_name = "ce-mcp-test-" + uuid.uuid4().hex
        pipe = win32pipe.CreateNamedPipe("\\\\.\\pipe\\" + pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX, win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT,
            1, 65536, 65536, 1000, None)
        errors = []

        def peer():
            try:
                win32pipe.ConnectNamedPipe(pipe, None)
                _, header = win32file.ReadFile(pipe, 4)
                size, = struct.unpack("<I", header)
                _, request = win32file.ReadFile(pipe, size)
                self.assertIn(b"state", request)
                data = json.dumps({"ok":True, "result":{"pid":42}}).encode()
                wire = struct.pack("<I", len(data)) + data
                for b in wire:
                    win32file.WriteFile(pipe, bytes([b]))
                win32file.FlushFileBuffers(pipe)
            except BaseException as exc:
                errors.append(exc)
            finally:
                pipe.Close()
        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        response = server.exchange(server.encode_request("state"), pipe_name)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(response["result"]["pid"], 42)


class AdditionalTests(unittest.TestCase):
    def test_packaged_autorun_starts_without_console_and_is_self_contained(self):
        packaged = install_autorun.PACKAGED.read_text(encoding="utf-8")
        self.assertEqual(packaged, install_autorun.render_autorun())
        lua = LuaRuntime(unpack_returned_tuples=True)
        lua.execute(HARNESS)
        lua.execute(packaged)
        self.assertTrue(lua.globals().ce_mcp.running)
        # Reloading the autorun must not create a second worker.
        lua.execute(packaged)
        for i, op in enumerate(("state", "stop"), 1):
            lua.globals().requests[i] = server.encode_request(op)[4:].decode("ascii")
        lua.globals().worker()
        result = json.loads(lua.globals().responses[1])
        self.assertEqual(result["result"], {"pid":42, "record_count":0})

    def test_autorun_install_update_and_uninstall_preserve_other_files(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "cheatengine-x86_64.exe").touch()
            target = install_autorun.install(directory)
            self.assertEqual(target.read_text(encoding="utf-8"), install_autorun.render_autorun())
            install_autorun.install(directory)
            other = target.with_name("other.lua")
            other.write_text("-- user script", encoding="utf-8")
            install_autorun.install(directory, uninstall=True)
            self.assertFalse(target.exists())
            self.assertTrue(other.exists())
            target.write_text("-- user script", encoding="utf-8")
            with self.assertRaises(ValueError):
                install_autorun.install(directory)
            with self.assertRaises(ValueError):
                install_autorun.install(directory, uninstall=True)

    def test_script_record_cannot_be_written_or_activated(self):
        lua = LuaRuntime(unpack_returned_tuples=True)
        lua.execute(HARNESS)
        lua.execute(Path(__file__).with_name("ce_bridge.lua").read_text(encoding="utf-8"))
        lua.execute("synchronize(function() local r=getAddressList().createMemoryRecord(); r.Type=11 end)")
        commands = [("value", (42, 1, "99")), ("freeze", (42, 1, "1")), ("stop", ())]
        for i, (op, args) in enumerate(commands, 1):
            lua.globals().requests[i] = server.encode_request(op, *args)[4:].decode("ascii")
        lua.globals().ce_mcp.start("test")
        lua.globals().worker()
        result = [json.loads(v) for _, v in lua.globals().responses.items()]
        self.assertFalse(result[0]["ok"])
        self.assertFalse(result[1]["ok"])

    @unittest.skipUnless(sys.platform == "win32", "Windows named pipes")
    def test_unresponsive_pipe_has_bounded_timeout(self):
        import win32file
        import win32pipe
        pipe_name = "ce-mcp-timeout-" + uuid.uuid4().hex
        pipe = win32pipe.CreateNamedPipe("\\\\.\\pipe\\" + pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX, win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT,
            1, 65536, 65536, 1000, None)
        release = threading.Event()
        def peer():
            try:
                win32pipe.ConnectNamedPipe(pipe, None)
                win32file.ReadFile(pipe, 65536)
                release.wait(3)
            finally:
                pipe.Close()
        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        try:
            with self.assertRaisesRegex(TimeoutError, 'outcome unknown'):
                server.exchange(server.encode_request("state"), pipe_name, timeout=0.1)
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())


class McpTests(unittest.TestCase):
    def test_stdio_initialization_and_tools(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        async def run():
            params = StdioServerParameters(command=sys.executable,
                args=[str(Path(__file__).with_name("server.py"))], env={"CE_MCP_PIPE":"ce-mcp-missing-" + uuid.uuid4().hex})
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    self.assertEqual(len(result.tools), 8)
                    # A missing pipe must be a tool error, not a successful result.
                    response = await session.call_tool("get_state", {})
                    self.assertTrue(response.isError)
        async def bounded():
            await asyncio.wait_for(run(), timeout=20)
        asyncio.run(bounded())


if __name__ == "__main__":
    unittest.main()
