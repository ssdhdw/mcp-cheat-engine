-- Load from CE's Lua console, then explicitly call ce_mcp.start().
-- Pipe I/O runs on a worker; ALL access to CE state and controls is synchronized.
-- TODO(security): Replace upstream createPipe's broad local ACL with a native
-- pipe server restricted to the current Windows user (and reject remote clients).
-- Add per-connection read deadlines and a GUI switch to enable/disable agent access.
-- Keep setup automatic: do not require users to copy a shared token manually.
-- Until then, local processes with pipe access can write memory and enable scripts.
assert(not ce_mcp, 'MCP bridge is already loaded')
ce_mcp = {}
local MAX_FRAME = 1024 * 1024
local types = {byte=vtByte, word=vtWord, dword=vtDword, qword=vtQword,
               float=vtSingle, double=vtDouble}
local numeric = {}
for _, v in pairs(types) do numeric[v] = true end
local array_mt = {}
local function as_array(v) return setmetatable(v, array_mt) end

local function json(v)
  local t = type(v)
  if t == 'nil' then return 'null' end
  if t == 'boolean' or t == 'number' then return tostring(v) end
  if t == 'string' then
    return '"' .. v:gsub('[%z\1-\31\\"]', function(c)
      return string.format('\\u%04x', c:byte())
    end) .. '"'
  end
  local parts = {}
  if getmetatable(v) == array_mt then
    for _, value in ipairs(v) do parts[#parts+1] = json(value) end
    return '[' .. table.concat(parts, ',') .. ']'
  end
  for k, value in pairs(v) do
    parts[#parts+1] = json(tostring(k)) .. ':' .. json(value)
  end
  return '{' .. table.concat(parts, ',') .. '}'
end

local function array(items)
  local out = {}
  for _, item in ipairs(items) do out[#out+1] = json(item) end
  return '[' .. table.concat(out, ',') .. ']'
end

local function integer(s, minimum, maximum)
  local n = tonumber(s)
  assert(n and n == math.floor(n) and n >= minimum and n <= maximum, 'Invalid integer')
  return n
end

local function snapshot(r)
  local chain = as_array({})
  for i=(r.OffsetCount or 0)-1,0,-1 do chain[#chain+1] = r.Offset[i] end
  return {id=r.ID, description=r.Description, address=r.Address,
          value=r.Value, value_type=r.Type, frozen=r.Active, active=r.Active,
          pointer_offsets=chain}
end

local function hex(n) return string.format('%X', n) end
local function address(s)
  assert(type(s) == 'string' and #s > 0 and #s <= 1024, 'Invalid address expression')
  return assert(getAddressSafe(s), 'Address could not be resolved')
end

local function offsets(s)
  local result = {}
  assert(type(s) == 'string' and #s <= 256, 'Invalid offsets')
  if s == '' then return result end
  for field in (s .. ','):gmatch('(.-),') do
    result[#result+1] = integer(field, -2147483648, 2147483647)
  end
  assert(#result <= 16, 'At most 16 pointer offsets')
  return result
end

local function bytehex(bytes)
  local out = {}
  for _, b in ipairs(bytes) do out[#out+1] = string.format('%02X', b) end
  return table.concat(out, ' ')
end

local function parsebytes(s)
  assert(type(s) == 'string' and #s <= 12288, 'Invalid hex bytes')
  s = s:gsub('%s', '')
  assert(#s > 0 and #s % 2 == 0 and not s:find('[^%x]') and #s <= 8192, 'Invalid hex bytes')
  local result = {}
  for b in s:gmatch('%x%x') do result[#result+1] = tonumber(b,16) end
  return result
end

local function readbytes(addr, size)
  local bytes = assert(readBytes(addr, size, true), 'Memory is unreadable')
  assert(#bytes == size, 'Partial memory read')
  return bytes
end

local function view(addr, code)
  local v = getMemoryViewForm()
  if code then v.DisassemblerView.SelectedAddress = addr
  else v.HexadecimalView.Address = addr end
  v.show()
end

local scan_indices = {exact=0, bigger=1, smaller=2, between=3, unknown=4,
  increased=4, increased_by=5, decreased=6, decreased_by=7, changed=8, unchanged=9}
local type_indices = {byte=1, word=2, dword=3, qword=4, float=5, double=6}
local watches = {}
local extra_ops = {scan_first=true, scan_next=true, scan_status=true, scan_results=true,
  scan_reset=true, memory_read=true, memory_write=true, modules=true, disassemble=true,
  pointer_resolve=true, pointer_add=true, record_rename=true, watch_add=true,
  watch_hits=true, watch_remove=true, script_add=true, script_enable=true}

local function scanstate()
  local f, scan = getMainForm(), getCurrentMemscan()
  local busy = not f.btnNewScan.Enabled
  local progress = scan.getProgress()
  return {busy=busy, has_scan=f.btnFirst.Tag == 2,
    total=tostring(progress.TotalAddressesToScan), scanned=tostring(progress.CurrentlyScanned),
    found=tostring(progress.ResultsFound), unknown_initial=scan.LastScanWasRegionScan}
end

local function dispatch_extra(a)
  local op = a[1]
  if not extra_ops[op] then return nil end
  local pid = integer(a[2], 1, 4294967295)
  assert(getOpenedProcessID() == pid, 'Attached process changed; refresh state')
  if op:sub(1,5) == 'scan_' then
    local f, scan = getMainForm(), getCurrentMemscan()
    if op == 'scan_status' then return json(scanstate()) end
    assert(f.btnNewScan.Enabled, 'Scan is busy; poll scan_status')
    if op == 'scan_results' then
      assert(f.btnFirst.Tag == 2, 'No completed GUI scan')
      assert(not scan.LastScanWasRegionScan, 'Narrow unknown initial scan with next_scan first')
      local offset, limit = integer(a[3], 0, 2147483647), integer(a[4], 1, 200)
      local found = assert(scan.FoundList, 'GUI found list is unavailable')
      local rows = as_array({})
      for i=offset, math.min(found.Count-1, offset+limit-1) do
        rows[#rows+1] = {index=i, address=found.Address[i], value=found.Value[i]}
      end
      return json({count=tostring(found.Count), offset=offset, results=rows})
    end
    if op == 'scan_reset' then
      if f.btnFirst.Tag == 2 then f.btnNewScan.doClick() end
      return json(scanstate())
    end
    local first = op == 'scan_first'
    local kind, value, value2
    if first then kind, value, value2 = a[4], a[5], a[6]
    else kind, value, value2 = a[3], a[4], a[5] end
    local index = assert(scan_indices[kind], 'Unsupported scan type')
    assert(not (first and index > 4) and not (first and kind == 'increased'), 'Invalid first scan type')
    assert(first or kind ~= 'unknown', 'Unknown initial value is a first-scan option')
    local no_value = kind == 'unknown' or kind == 'increased' or kind == 'decreased'
                     or kind == 'changed' or kind == 'unchanged'
    if not no_value then
      local n = tonumber(value)
      assert(type(value) == 'string' and #value <= 128 and n and n == n
        and math.abs(n) < math.huge, 'Finite numeric scan value required')
    end
    if kind == 'between' then
      local n = tonumber(value2)
      assert(type(value2) == 'string' and #value2 <= 128 and n and n == n
        and math.abs(n) < math.huge and tonumber(value) <= n, 'Invalid numeric range')
    end
    if first then
      local vt = assert(type_indices[a[3]], 'Unsupported scan value type')
      local lo = a[7] ~= '' and address(a[7]) or address(f.FromAddress.Text)
      local hi = a[8] ~= '' and address(a[8]) or address(f.ToAddress.Text)
      assert(lo <= hi, 'Start address exceeds stop address')
      if f.btnFirst.Tag == 2 then f.btnNewScan.doClick() end
      f.VarType.ItemIndex = vt
      f.VarType.OnChange(f.VarType)
      f.FromAddress.Text, f.ToAddress.Text = hex(lo), hex(hi)
    else
      assert(f.btnNextScan.Enabled, 'Run a first scan before next_scan')
      assert(f.VarType.ItemIndex >= 1 and f.VarType.ItemIndex <= 6, 'Only numeric GUI scans supported')
    end
    -- Explicitly use normal numeric scans rather than any manually enabled Lua formula.
    f.cbLuaFormula.Checked, f.cbNot.Checked, f.cbpercentage.Checked = false, false, false
    f.cbHexadecimal.Checked = false
    f.ScanType.ItemIndex = index
    f.ScanType.OnChange(f.ScanType)
    f.scanvalue.Text = value or ''
    if kind == 'between' then f.scanvalue2.Text = value2 end
    if first then f.btnNewScan.doClick() else f.btnNextScan.doClick() end
    return json({started=true, asynchronous=true})
  elseif op == 'modules' then
    local result = {}
    for _, m in ipairs(enumModules()) do
      result[#result+1] = {name=m.Name, address=hex(m.Address), size=m.Size, path=m.PathToFile}
    end
    return array(result)
  elseif op == 'memory_read' or op == 'memory_write' then
    local addr = address(a[3])
    if op == 'memory_read' then
      local bytes = readbytes(addr, integer(a[4], 1, 4096))
      view(addr, false)
      return json({address=hex(addr), hex=bytehex(bytes), size=#bytes})
    end
    local bytes, expected = parsebytes(a[4]), parsebytes(a[5])
    assert(#bytes == #expected, 'New and expected byte lengths must match')
    local original = bytehex(readbytes(addr, #bytes))
    assert(original == bytehex(expected), 'Original bytes changed; write rejected')
    assert(writeBytes(addr, bytes) == #bytes, 'Partial or failed memory write; inspect memory before retrying')
    local observed = bytehex(readbytes(addr, #bytes))
    view(addr, false)
    return json({address=hex(addr), original=original, observed=observed,
      verified=observed == bytehex(bytes)})
  elseif op == 'disassemble' then
    local addr, count = address(a[3]), integer(a[4], 1, 100)
    local rows = {}
    view(addr, true)
    for i=1,count do
      local size = getInstructionSize(addr)
      assert(size and size > 0 and size <= 15, 'Instruction decode failed')
      rows[#rows+1] = {address=hex(addr), size=size, text=disassemble(addr)}
      addr = addr + size
    end
    return array(rows)
  elseif op == 'pointer_resolve' or op == 'pointer_add' then
    local base, chain = address(a[3]), offsets(a[4])
    local addr, steps = base, as_array({})
    for _, offset in ipairs(chain) do
      local pointer = assert(readPointer(addr), 'Unreadable pointer')
      assert(pointer ~= 0, 'Null pointer')
      steps[#steps+1] = {address=hex(addr), pointer=hex(pointer), offset=offset}
      addr = pointer + offset
    end
    if op == 'pointer_resolve' then return json({address=hex(addr), steps=steps}) end
    local vt = assert(types[a[6]], 'Unsupported numeric type')
    assert(a[5] and #a[5] <= 1024, 'Invalid description')
    local al = getAddressList()
    local r = al.createMemoryRecord()
    local ok, err = pcall(function()
      r.Type = vt
      r.Address = a[3]
      r.Description = a[5]
      r.OffsetCount = #chain
      for i=0,#chain-1 do r.Offset[i] = chain[#chain-i] end
    end)
    if not ok then r.destroy(); error(err) end
    al.SelectedRecord = r
    al.repaint()
    return json(snapshot(r))
  elseif op == 'record_rename' or op == 'script_enable' then
    local al = getAddressList()
    local r = assert(al.getMemoryRecordByID(integer(a[3], 0, 2147483647)), 'Record not found')
    if op == 'record_rename' then
      assert(a[4] and #a[4] <= 1024, 'Invalid description')
      r.Description = a[4]
    else
      assert(r.Type == vtAutoAssembler, 'Record is not an Auto Assembler script')
      assert(a[4] == '0' or a[4] == '1', 'Invalid enabled state')
      r.Async = false
      r.Active = a[4] == '1'
      assert(r.Active == (a[4] == '1'), 'CE rejected script state; inspect its assembler error')
    end
    al.SelectedRecord = r
    al.repaint()
    return json(snapshot(r))
  elseif op == 'script_add' then
    assert(a[3] and #a[3] <= 1024, 'Invalid description')
    assert(a[4] and #a[4] <= 65536 and a[4]:find('%[ENABLE%]') and a[4]:find('%[DISABLE%]'),
      'Provide a script with [ENABLE] and [DISABLE] sections (up to 64 KiB)')
    local al = getAddressList()
    local r = al.createMemoryRecord()
    local ok, err = pcall(function()
      -- CE resets type-specific data on Type changes; set Type before Script.
      r.Type = vtAutoAssembler
      r.Description = a[3]
      r.Script = a[4]
    end)
    if not ok then r.destroy(); error(err) end
    al.SelectedRecord = r
    al.repaint()
    return json(snapshot(r))
  elseif op:sub(1,6) == 'watch_' then
    local addr = address(a[3])
    local w = watches[addr]
    if op == 'watch_add' then
      if w and (w.pid ~= pid or w.handle ~= getOpenedProcessHandle()) then
        watches[addr], w = nil, nil
      end
      assert(not w, 'MCP watch already exists at this address')
      local triggers = {write=bptWrite, access=bptAccess, execute=bptExecute}
      local trigger = assert(triggers[a[4]], 'Unsupported breakpoint trigger')
      local size = integer(a[5], 1, 8)
      assert(size == 1 or size == 2 or size == 4 or (size == 8 and targetIs64Bit()), 'Invalid hardware breakpoint size')
      if a[4] ~= 'execute' then assert(addr % size == 0, 'Hardware data breakpoint must be aligned') end
      for _, existing in ipairs(debug_getBreakpointList() or {}) do
        assert(existing ~= addr, 'An existing breakpoint occupies this address')
      end
      if not debug_isDebugging() then debugProcess(1) end
      assert(debug_isDebugging(), 'Could not start debugger')
      w = {pid=pid, handle=getOpenedProcessHandle(), hits=as_array({}), dropped=0}
      local function onhit()
        if #w.hits < 100 then
          local regs = {}
          for _, name in ipairs({'EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP','EIP',
            'RAX','RBX','RCX','RDX','RSI','RDI','RBP','RSP','RIP','R8','R9','R10','R11','R12','R13','R14','R15'}) do
            if type(_G[name]) == 'number' then regs[name] = hex(_G[name]) end
          end
          w.hits[#w.hits+1] = {ip=regs.RIP or regs.EIP, registers=regs}
        else w.dropped = w.dropped + 1 end
        debug_continueFromBreakpoint(co_run)
        return 1
      end
      debug_setBreakpoint(addr, size, trigger, bpmDebugRegister, onhit)
      local installed = false
      for _, bp in ipairs(debug_getBreakpointList() or {}) do if bp == addr then installed = true end end
      assert(installed, 'Could not install breakpoint; hardware slots may be exhausted')
      watches[addr] = w
      view(addr, a[4] == 'execute')
      return json({armed=true, address=hex(addr), trigger=a[4], max_hits=100})
    end
    assert(w and w.pid == pid and w.handle == getOpenedProcessHandle(), 'No watch in this process session')
    if op == 'watch_remove' then
      assert(debug_removeBreakpoint(addr), 'Could not remove breakpoint')
      watches[addr] = nil
    end
    return json({address=hex(addr), hits=w.hits, dropped=w.dropped, removed=op == 'watch_remove'})
  end
end

local function dispatch(a)
  local op, al = a[1], getAddressList()
  if op == 'state' then
    return json({pid=getOpenedProcessID(), record_count=al.Count})
  elseif op == 'processes' then
    local result = {}
    for pid, name in pairs(getProcesslist()) do result[#result+1] = {pid=pid, name=name} end
    return array(result)
  elseif op == 'attach' then
    local pid = integer(a[2], 1, 4294967295)
    -- tonumber is important: CE interprets Lua strings as process names.
    assert(openProcess(pid), 'Could not open process')
    return json({pid=getOpenedProcessID()})
  elseif op == 'records' then
    local offset, limit = integer(a[2], 0, 2147483647), integer(a[3], 1, 200)
    local result = {}
    for i=offset, math.min(al.Count-1, offset+limit-1) do
      result[#result+1] = snapshot(al[i])
    end
    return array(result)
  elseif op == 'stop' then
    for addr, w in pairs(watches) do
      if w.pid == getOpenedProcessID() and w.handle == getOpenedProcessHandle() then
        debug_removeBreakpoint(addr)
      end
    end
    ce_mcp.running = false
    return json({stopped=true})
  end
  local extra = dispatch_extra(a)
  if extra then return extra end
  assert(op == 'add' or op == 'value' or op == 'freeze', 'Unknown operation')
  local pid = integer(a[2], 1, 4294967295)
  assert(pid == getOpenedProcessID(), 'Attached process changed; refresh state')
  local r
  if op == 'add' then
    assert(a[3] and #a[3] > 0 and #a[3] <= 1024, 'Invalid address')
    assert(a[4] and #a[4] <= 1024, 'Invalid description')
    local vt = assert(types[a[5]], 'Unsupported numeric type')
    assert(getAddressSafe(a[3]), 'Address could not be resolved')
    r = al.createMemoryRecord()
    local ok, err = pcall(function()
      r.Type = vt
      r.Address = a[3]
      r.Description = a[4]
    end)
    if not ok then r.destroy(); error(err) end
  else
    r = assert(al.getMemoryRecordByID(integer(a[3], 0, 2147483647)), 'Record not found')
    assert(numeric[r.Type] and not r.IsGroupHeader, 'Only numeric memory records are supported')
    if op == 'value' then
      assert(a[4] and #a[4] <= 128 and tonumber(a[4]), 'Invalid numeric value')
      r.Value = a[4]
    else
      assert(a[4] == '0' or a[4] == '1', 'Invalid freeze state')
      r.Active = a[4] == '1'
      assert(r.Active == (a[4] == '1'), 'CE rejected freeze change')
    end
  end
  al.SelectedRecord = r
  al.repaint()
  return json(snapshot(r))
end

function ce_mcp.start(pipeName)
  pipeName = pipeName or os.getenv('CE_MCP_PIPE') or 'ce-mcp'
  assert(not ce_mcp.worker, 'Bridge worker already exists; restart CE to reconfigure')
  assert(type(pipeName) == 'string' and #pipeName <= 100 and pipeName:match('^[%w_-]+$'),
         'Invalid pipe name')
  local form = createForm(false)
  form.Caption = 'MCP agent activity - ' .. pipeName
  form.Width, form.Height = 720, 300
  local memo = createMemo(form)
  memo.Align = alClient
  memo.ReadOnly = true
  local function log(message)
    if memo.Lines.Count >= 200 then memo.Lines.delete(0) end
    memo.Lines.add(os.date('%H:%M:%S ') .. message)
  end
  log('Enabled. Close/hide this window without stopping the bridge; use stop_bridge to disable.')
  form.show()
  ce_mcp.running = true
  ce_mcp.worker = createNativeThread(function()
    while ce_mcp.running do
      local pipe = createPipe(pipeName, 65536, 65536)
      if not pipe.valid then
        pipe.destroy()
        synchronize(function() log('Could not create pipe; bridge stopped') end)
        break
      end
      pcall(function()
        pipe.acceptConnection()
        local size = pipe.readDword()
        assert(size and size > 0 and size <= MAX_FRAME, 'Invalid frame')
        local request = assert(pipe.readString(size), 'Disconnected')
        local args = {}
        for field in (request .. '\t'):gmatch('(.-)\t') do
          args[#args+1] = field:gsub('%%(%x%x)', function(h) return string.char(tonumber(h,16)) end)
        end
        local response
        synchronize(function()
          local ok, result = pcall(dispatch, args)
          log((args[1] or '?'):gsub('[%c]', '?') .. (ok and ' OK' or ' FAILED'))
          response = ok and ('{"ok":true,"result":' .. result .. '}')
                        or json({ok=false, error=tostring(result)})
        end)
        assert(#response <= MAX_FRAME, 'Response too large')
        pipe.writeDword(#response)
        pipe.writeString(response)
      end)
      pipe.destroy()
    end
    ce_mcp.running = false
    synchronize(function() log('Bridge stopped. Restart CE before starting again.') end)
  end)
end
