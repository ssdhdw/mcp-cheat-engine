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
vtAutoAssembler = 11
bptWrite, bptAccess, bptExecute, bpmDebugRegister, co_run = 1,2,0,0,0
alClient = 5
local main = false
local function gui() assert(main, 'CE API accessed outside GUI thread') end
local pid = 42
local records = {}
local al = {Count=0}
function al.createMemoryRecord()
  gui()
  local r = {ID=al.Count+1, _type=2, Address='', Description='', Value='7', _active=false,
    OffsetCount=0, Offset={}}
  setmetatable(r, {
    __index=function(t,k)
      if k=='Type' then return t._type elseif k=='Active' then return t._active end
    end,
    __newindex=function(t,k,v)
      if k=='Type' then rawset(t,'_type',v); rawset(t,'Script','')
      elseif k=='Active' then
        if v and t._type==11 then assert(t.Script:find('%[ENABLE%]'), 'Script cleared by Type change') end
        rawset(t,'_active',v)
      else rawset(t,k,v) end
    end})
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
function getAddressSafe(a) gui(); if a == 'invalid' then return nil end; return tonumber(a,16) or 4096 end
function getOpenedProcessHandle() gui(); return pid+100 end
function targetIs64Bit() gui(); return true end
local form = {btnNewScan={Enabled=true}, btnNextScan={Enabled=false}, btnFirst={Tag=0},
  VarType={ItemIndex=3}, ScanType={ItemIndex=0}, FromAddress={Text='1000'}, ToAddress={Text='2000'},
  scanvalue={Text=''}, scanvalue2={Text=''}, cbLuaFormula={}, cbNot={}, cbpercentage={}, cbHexadecimal={}}
local scan = {LastScanWasRegionScan=false, FoundList={Count=2, Address={[0]='1000',[1]='1004'},
  Value={[0]='90',[1]='98'}}}
local ticks=0
function scan.getProgress()
  gui()
  if not form.btnNewScan.Enabled then
    ticks=ticks+1
    if ticks >= 2 then
      form.btnNewScan.Enabled=true; form.btnFirst.Tag=2; form.btnNextScan.Enabled=true
    end
  end
  return {TotalAddressesToScan=1000, CurrentlyScanned=ticks*500, ResultsFound=2}
end
function form.VarType.OnChange(sender) gui() end
function form.ScanType.OnChange(sender) gui() end
function form.btnNewScan.doClick()
  gui()
  if form.btnFirst.Tag==2 then
    form.btnFirst.Tag=0; form.btnNextScan.Enabled=false
  else
    form.btnNewScan.Enabled=false; ticks=0
    scan.LastScanWasRegionScan=form.ScanType.ItemIndex==4
  end
end
function form.btnNextScan.doClick()
  gui(); form.btnNewScan.Enabled=false; ticks=0; scan.LastScanWasRegionScan=false
end
function getMainForm() gui(); return form end
function getCurrentMemscan() gui(); return scan end
local memoryview = {DisassemblerView={}, HexadecimalView={}, show=function() gui() end}
function getMemoryViewForm() gui(); return memoryview end
function enumModules() gui(); return {{Name='Tutorial.exe', Address=4096, Size=8192, PathToFile='C:/Tutorial.exe'}} end
local memory = {[4096]=144,[4097]=144,[4098]=100,[4099]=0}
function readBytes(addr,size,astable)
  gui()
  if addr>=20480 then return nil end
  local result={}
  for i=0,size-1 do result[i+1]=memory[addr+i] or 0 end
  return result
end
function writeBytes(addr,bytes)
  gui()
  for i,b in ipairs(bytes) do memory[addr+i-1]=b end
  return #bytes
end
function readPointer(addr) gui(); return ({[4096]=8192,[8208]=12288})[addr] end
function getInstructionSize(addr) gui(); return 2 end
function disassemble(addr) gui(); return string.format('%X - 90 90 - nop', addr) end
local debugging=false
test_breakpoints={}
function debug_isDebugging() gui(); return debugging end
function debugProcess(interface) gui(); assert(interface==1); debugging=true end
function debug_getBreakpointList()
  gui(); local r={}; for addr,_ in pairs(test_breakpoints) do r[#r+1]=addr end; return r
end
function debug_setBreakpoint(addr,size,trigger,method,onhit)
  gui(); test_breakpoints[addr]=onhit; RIP=addr+2; RAX=123; onhit()
end
function debug_continueFromBreakpoint(method) gui(); assert(method==co_run) end
function debug_removeBreakpoint(addr) gui(); test_breakpoints[addr]=nil; return true end
function createForm()
  return {show=function() end}
end
activity_log={}
function createMemo()
  local lines = {Count=0}
  function lines.add(s) lines.Count=lines.Count+1; activity_log[#activity_log+1]=s end
  function lines.delete(i) lines.Count=lines.Count-1 end
  test_memo={Lines=lines}
  return test_memo
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
        self.log_lines = [v for _, v in lua.globals().activity_log.items()]
        self.log_count = lua.globals().test_memo.Lines.Count
        self.log_wrap = lua.globals().test_memo.WordWrap
        return [json.loads(v) for _, v in lua.globals().responses.items()]

    def test_activity_records_show_address_value_and_type(self):
        result = self.run_commands([
            ("add", (42, "014B0F50", "Health", "dword")),
            ("value", (42, 1, "-10")),
            ("freeze", (42, 1, "1")),
            ("value", (42, 99, "20")),
        ])
        self.assertIn("[add] address - 014B0F50, value - 7, type - 4 Bytes | OK", self.log_lines[1])
        self.assertIn("[value] address - 014B0F50, value - -10 | OK", self.log_lines[2])
        self.assertIn("[freeze] address - 014B0F50, freeze | OK", self.log_lines[3])
        self.assertIn("[value] record - 99, value - 20 | FAILED", self.log_lines[4])
        self.assertFalse(result[3]["ok"])
        self.assertFalse(self.log_wrap)

    def test_activity_scans_distinguish_first_next_and_values(self):
        self.run_commands([
            ("scan_first", (42, "dword", "exact", "98", "", "1000", "2000")),
            ("scan_status", (42,)), ("scan_status", (42,)), ("scan_status", (42,)),
            ("scan_next", (42, "between", "80", "90")),
        ])
        self.assertIn("[scan_first] exact - 98, type - 4 Bytes | OK", self.log_lines[1])
        self.assertIn("[scan_next] between - 80..90 | OK", self.log_lines[5])
        self.assertIn("[scan_status] busy | OK", self.log_lines[2])

    def test_activity_memory_and_disassembly_show_ranges_not_dumps(self):
        self.run_commands([
            ("memory_read", (42, "1000", 4)),
            ("memory_write", (42, "1000", "90 91", "90 90")),
            ("disassemble", (42, "1000", 3)),
            ("memory_read", (42, "5000", 2)),
            ("state", ()),
        ])
        self.assertIn("[memory_read] range - 00001000-00001003 | OK", self.log_lines[1])
        self.assertIn("[memory_write] range - 00001000-00001001 | OK", self.log_lines[2])
        self.assertIn("[disassemble] range - 00001000-00001005 | OK", self.log_lines[3])
        self.assertIn("[memory_read] range - 00005000-00005001 | FAILED", self.log_lines[4])
        self.assertNotIn("range", self.log_lines[5])
        self.assertTrue(all("90 90" not in line and "nop" not in line for line in self.log_lines))

    def test_activity_truncates_multiline_text_and_never_logs_script_bodies(self):
        secret_body = "[ENABLE]\n// BODY_MUST_NOT_BE_LOGGED\n[DISABLE]"
        self.run_commands([
            ("script_add", (42, "Injection\r\n" + "Тест" * 80 + "\u2028another line", secret_body)),
            ("scan_first", (42, "dword", "exact", "9" * 500, "", "1000", "2000")),
        ])
        for line in self.log_lines:
            self.assertNotIn("\n", line)
            self.assertNotIn("\r", line)
            self.assertNotIn("\u2028", line)
            self.assertNotIn("BODY_MUST_NOT_BE_LOGGED", line)
            self.assertLessEqual(len(line.encode("utf-8")), 205)
        self.assertIn("...", self.log_lines[1])

    def test_activity_keeps_only_200_visible_lines(self):
        self.run_commands([("state", ())] * 220)
        self.assertEqual(self.log_count, 200)

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

    def test_async_gui_scan_and_results(self):
        result = self.run_commands([
            ("scan_first", (42, "dword", "exact", "98", "", "1000", "2000")),
            ("scan_results", (42, 0, 10)),
            ("scan_status", (42,)), ("scan_status", (42,)), ("scan_status", (42,)),
            ("scan_results", (42, 0, 1)),
            ("scan_next", (42, "decreased", "", "")),
            ("scan_status", (42,)), ("scan_status", (42,)), ("scan_status", (42,)),
            ("scan_reset", (42,)),
        ])
        self.assertTrue(result[0]["ok"], result)
        self.assertFalse(result[1]["ok"])
        self.assertTrue(result[2]["result"]["busy"])
        self.assertFalse(result[4]["result"]["busy"])
        self.assertEqual(result[5]["result"]["results"], [{"index":0,"address":"1000","value":"90"}])
        self.assertTrue(result[6]["ok"])
        self.assertFalse(result[10]["result"]["has_scan"])

    def test_unknown_scan_needs_narrowing_and_validation(self):
        result = self.run_commands([
            ("scan_first", (42, "float", "unknown", "", "", "1000", "2000")),
            ("scan_status", (42,)), ("scan_status", (42,)), ("scan_status", (42,)),
            ("scan_results", (42, 0, 10)),
            ("scan_first", (42, "dword", "between", "1", "bad", "1000", "2000")),
            ("scan_first", (42, "dword", "exact", "98", "", "3000", "2000")),
        ])
        self.assertTrue(result[0]["ok"])
        self.assertTrue(all(not r["ok"] for r in result[4:-1]), result)

    def test_memory_patch_is_conditional_and_returns_original(self):
        result = self.run_commands([
            ("memory_read", (42, "1000", 4)),
            ("memory_write", (42, "1000", "90 91", "90 90")),
            ("memory_write", (42, "1000", "90 92", "90 90")),
            ("memory_read", (42, "1000", 2)),
            ("memory_read", (99, "1000", 2)),
            ("memory_read", (42, "1000", 4097)),
        ])
        self.assertEqual(result[0]["result"]["hex"], "90 90 64 00")
        self.assertEqual(result[1]["result"]["original"], "90 90")
        self.assertTrue(result[1]["result"]["verified"])
        self.assertFalse(result[2]["ok"])
        self.assertEqual(result[3]["result"]["hex"], "90 91")
        self.assertTrue(all(not r["ok"] for r in result[4:-1]))

    def test_modules_disassembly_and_pointer_record(self):
        result = self.run_commands([
            ("modules", (42,)),
            ("disassemble", (42, "1000", 2)),
            ("pointer_resolve", (42, "1000", "16,4")),
            ("pointer_add", (42, "1000", "16,4", "health pointer", "dword")),
            ("record_rename", (42, 1, "Health")),
            ("pointer_resolve", (42, "1000", "16,,4")),
        ])
        self.assertEqual(result[0]["result"][0]["address"], "1000")
        self.assertEqual(result[1]["result"][1]["address"], "1002")
        self.assertEqual(result[2]["result"]["address"], "3004")
        self.assertEqual(result[3]["result"]["pointer_offsets"], [16, 4])
        self.assertEqual(result[4]["result"]["description"], "Health")
        self.assertFalse(result[5]["ok"])

    def test_watch_captures_registers_and_removes_only_owned_breakpoint(self):
        result = self.run_commands([
            ("watch_add", (42, "1000", "write", 4)),
            ("watch_hits", (42, "1000")),
            ("watch_add", (42, "1000", "write", 4)),
            ("watch_remove", (42, "1000")),
            ("watch_hits", (42, "1000")),
            ("watch_add", (42, "1001", "write", 4)),
        ])
        self.assertTrue(result[0]["result"]["armed"])
        self.assertEqual(result[1]["result"]["hits"][0]["registers"]["RAX"], "7B")
        self.assertFalse(result[2]["ok"])
        self.assertTrue(result[3]["result"]["removed"])
        self.assertFalse(result[4]["ok"])
        self.assertFalse(result[5]["ok"])

    def test_assembler_scripts_are_inactive_until_explicit_enable(self):
        script = "[ENABLE]\n1000:\nnop\n[DISABLE]\n1000:\ndb 90"
        result = self.run_commands([
            ("script_add", (42, "Tutorial injection", script)),
            ("script_enable", (42, 1, "1")),
            ("script_enable", (42, 1, "0")),
            ("script_add", (42, "Invalid", "nop")),
        ])
        self.assertFalse(result[0]["result"]["frozen"])
        self.assertTrue(result[1]["result"]["frozen"])
        self.assertFalse(result[2]["result"]["frozen"])
        self.assertFalse(result[3]["ok"])


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
                    self.assertEqual(len(result.tools), 25)
                    # A missing pipe must be a tool error, not a successful result.
                    response = await session.call_tool("get_state", {})
                    self.assertTrue(response.isError)
        async def bounded():
            await asyncio.wait_for(run(), timeout=20)
        asyncio.run(bounded())


if __name__ == "__main__":
    unittest.main()
