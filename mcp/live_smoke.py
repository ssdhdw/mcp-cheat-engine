"""Opt-in live test against a NEW CE instance and an isolated Python test target.

Never connects to the user's existing CE instance. Runs a temporary copy of CE
with a test-only autorun. Does not update the installed CE or its autorun.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import time
import uuid
import tempfile

import server
import install_autorun

TARGET = r'''
import ctypes, json, os, sys
health = ctypes.c_int(98)
float_value = ctypes.c_float(100.5)
double_value = ctypes.c_double(5000.25)
pointer = ctypes.c_void_p(ctypes.addressof(health)-16)
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
code = ctypes.windll.kernel32.VirtualAlloc(None, 4096, 0x3000, 0x40)
assert code
ctypes.memmove(code, b'\xb8\x07\x00\x00\x00\xc3', 6)
print(json.dumps({'pid':os.getpid(), 'health':format(ctypes.addressof(health),'X'),
 'pointer':format(ctypes.addressof(pointer),'X'), 'code':format(code,'X'),
 'float':format(ctypes.addressof(float_value),'X'),
 'double':format(ctypes.addressof(double_value),'X')}), flush=True)
for line in sys.stdin:
    health.value = int(line)
    print(health.value, flush=True)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ce-exe", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Windows only")
    pipe = "ce-mcp-smoke-" + uuid.uuid4().hex
    os.environ["CE_MCP_PIPE"] = pipe
    target = ce = None
    staging = tempfile.TemporaryDirectory(prefix="ce-mcp-live-", dir=Path(__file__).parent)
    results = []

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        results.append(name)
        print("PASS " + name, flush=True)

    def call(op, *values):
        return server.call(op, *values)

    def wait_scan(pid):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status = call("scan_status", pid)
            if not status["busy"]:
                return status
            time.sleep(0.05)
        raise TimeoutError("Test scan did not complete")

    try:
        staged_dir = Path(staging.name) / "CE"
        shutil.copytree(args.ce_exe.resolve().parent, staged_dir,
                        ignore=shutil.ignore_patterns("autorun", "plugins"))
        install_autorun.install(staged_dir)
        # Observe the real activity memo through a test-only timer in this temporary CE.
        # The installed bridge and its public API remain unchanged.
        activity_path = Path(staging.name) / "activity.txt"
        autorun = staged_dir / "autorun" / install_autorun.FILENAME
        observe = """
local originalCreateMemo = createMemo
function createMemo(owner)
  local memo = originalCreateMemo(owner)
  if owner and owner.Caption == 'MCP agent activity - ' .. os.getenv('CE_MCP_PIPE') then
    local timer = createTimer(owner, false)
    timer.Interval = 30
    timer.OnTimer = function()
      local file = io.open([=[%s]=], 'w')
      if file then file:write(memo.Lines.Text); file:close() end
    end
    timer.Enabled = true
  end
  return memo
end
""" % activity_path
        autorun.write_text(observe + autorun.read_text(encoding="utf-8"), encoding="utf-8")
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        target = subprocess.Popen([sys.executable, "-u", "-c", TARGET],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            startupinfo=startup)
        # Read startup metadata with a deadline; a startup failure must not hang the test.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(target.stdout.readline)
            metadata = json.loads(future.result(timeout=10))
        pid, health, pointer, code = (metadata[k] for k in ("pid", "health", "pointer", "code"))
        print(json.dumps({"target_pid":pid, "pipe":pipe}), flush=True)
        ce = subprocess.Popen([str(staged_dir / args.ce_exe.name)], env=dict(os.environ), startupinfo=startup)
        deadline = time.monotonic() + 20
        while True:
            try:
                state = call("state")
                break
            except Exception:
                if ce.poll() is not None or time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        check("isolated autorun bridge", state["record_count"] == 0)
        check("attach isolated target", call("attach", pid)["pid"] == pid)
        for value_type, key, value in (("float","float","100.5"), ("double","double","5000.25")):
            addr = metadata[key]
            call("scan_first", pid, value_type, "exact", value, "", addr, format(int(addr,16)+64,"X"))
            wait_scan(pid)
            rows = call("scan_results", pid, 0, 100)
            check(value_type + " GUI scan", any(int(r['address'],16)==int(addr,16) for r in rows['results']))
        check("initial target memory", call("memory_read", pid, health, 4)["hex"] == "62 00 00 00")
        call("scan_first", pid, "dword", "exact", "98", "", health, format(int(health,16)+64,"X"))
        wait_scan(pid)
        initial = call("scan_results", pid, 0, 100)
        print(json.dumps({"first_scan":initial}), flush=True)
        check("first scan GUI results", any(int(r['address'],16) == int(health,16) for r in initial['results']))
        target.stdin.write("90\n")
        target.stdin.flush()
        check("target changed value", target.stdout.readline().strip() == "90")
        call("scan_next", pid, "decreased", "", "")
        wait_scan(pid)
        rows = call("scan_results", pid, 0, 10)
        check("next scan GUI results", len(rows["results"]) == 1 and rows["results"][0]["value"] == "90")
        call("scan_first", pid, "dword", "unknown", "", "", health, format(int(health,16)+64,"X"))
        check("unknown initial snapshot", wait_scan(pid)["unknown_initial"])
        target.stdin.write("89\n")
        target.stdin.flush()
        check("unknown scan target change", target.stdout.readline().strip() == "89")
        call("scan_next", pid, "changed", "", "")
        wait_scan(pid)
        rows = call("scan_results", pid, 0, 100)
        check("changed-value filter", any(int(r['address'],16)==int(health,16) for r in rows['results']))
        target.stdin.write("90\n")
        target.stdin.flush()
        check("restore test value", target.stdout.readline().strip() == "90")
        check("read memory", call("memory_read", pid, health, 4)["hex"] == "5A 00 00 00")
        check("conditional write", call("memory_write", pid, health, "59 00 00 00", "5A 00 00 00")["verified"])
        call("memory_write", pid, health, "5A 00 00 00", "59 00 00 00")
        check("pointer resolution", int(call("pointer_resolve", pid, pointer, "16")["address"],16) == int(health,16))
        record = call("pointer_add", pid, pointer, "16", "Smoke health pointer", "dword")
        check("pointer GUI record", record["value"] == "90")
        check("module enumeration", len(call("modules", pid)) > 0)
        check("disassembly", call("disassemble", pid, code, 2)[0]["size"] == 5)
        script = f"[ENABLE]\n{health}:\ndb 59 00 00 00\n[DISABLE]\n{health}:\ndb 5A 00 00 00"
        record = call("script_add", pid, "Smoke reversible data patch", script)
        call("script_enable", pid, record["id"], "1")
        check("assembler enable", call("memory_read", pid, health, 4)["hex"] == "59 00 00 00")
        call("script_enable", pid, record["id"], "0")
        check("assembler disable", call("memory_read", pid, health, 4)["hex"] == "5A 00 00 00")
        call("watch_add", pid, health, "write", 4)
        target.stdin.write("88\n")
        target.stdin.flush()
        # Do not block on target stdout while validating a debugger callback.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            hits = call("watch_hits", pid, health)
            if hits["hits"]:
                break
            time.sleep(0.05)
        check("hardware watchpoint register capture", bool(hits["hits"]))
        call("watch_remove", pid, health)
        call("scan_reset", pid)
        call("stop")
        deadline = time.monotonic() + 2
        activity = ""
        while time.monotonic() < deadline:
            if activity_path.exists():
                activity = activity_path.read_text(encoding="utf-8")
                if "[stop]" in activity:
                    break
            time.sleep(0.05)
        check("detailed GUI activity log", all(text in activity for text in (
            "[scan_first] exact - 98, type - 4 Bytes | OK",
            "[scan_next] decreased | OK", "[memory_read] range - ", "[disassemble] range - ")))
        check("compact activity log without dumps", all(len(line.encode("utf-8")) <= 205
            for line in activity.splitlines()) and "B8 07 00 00 00" not in activity)
        print(json.dumps({"passed":len(results), "checks":results}), flush=True)
    finally:
        # Only processes created by this test are stopped. Never touch existing CE/targets.
        for process in (ce, target):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        staging.cleanup()


if __name__ == "__main__":
    main()
