-- Load from CE's Lua console, then explicitly call ce_mcp.start(pipeName, token).
-- Pipe I/O runs on a worker; ALL access to CE state and controls is synchronized.
assert(not ce_mcp, 'MCP bridge is already loaded')
ce_mcp = {}
local MAX_FRAME = 1024 * 1024
local types = {byte=vtByte, word=vtWord, dword=vtDword, qword=vtQword,
               float=vtSingle, double=vtDouble}
local numeric = {}
for _, v in pairs(types) do numeric[v] = true end

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
  return {id=r.ID, description=r.Description, address=r.Address,
          value=r.Value, value_type=r.Type, frozen=r.Active}
end

local function dispatch(a)
  local op, al = a[2], getAddressList()
  if op == 'state' then
    return json({pid=getOpenedProcessID(), record_count=al.Count})
  elseif op == 'processes' then
    local result = {}
    for pid, name in pairs(getProcesslist()) do result[#result+1] = {pid=pid, name=name} end
    return array(result)
  elseif op == 'attach' then
    local pid = integer(a[3], 1, 4294967295)
    -- tonumber is important: CE interprets Lua strings as process names.
    assert(openProcess(pid), 'Could not open process')
    return json({pid=getOpenedProcessID()})
  elseif op == 'records' then
    local offset, limit = integer(a[3], 0, 2147483647), integer(a[4], 1, 200)
    local result = {}
    for i=offset, math.min(al.Count-1, offset+limit-1) do
      result[#result+1] = snapshot(al[i])
    end
    return array(result)
  elseif op == 'stop' then
    ce_mcp.running = false
    return json({stopped=true})
  end
  assert(op == 'add' or op == 'value' or op == 'freeze', 'Unknown operation')
  local pid = integer(a[3], 1, 4294967295)
  assert(pid == getOpenedProcessID(), 'Attached process changed; refresh state')
  local r
  if op == 'add' then
    assert(a[4] and #a[4] > 0 and #a[4] <= 1024, 'Invalid address')
    assert(a[5] and #a[5] <= 1024, 'Invalid description')
    local vt = assert(types[a[6]], 'Unsupported numeric type')
    assert(getAddressSafe(a[4]), 'Address could not be resolved')
    r = al.createMemoryRecord()
    local ok, err = pcall(function()
      r.Type = vt
      r.Address = a[4]
      r.Description = a[5]
    end)
    if not ok then r.destroy(); error(err) end
  else
    r = assert(al.getMemoryRecordByID(integer(a[4], 0, 2147483647)), 'Record not found')
    assert(numeric[r.Type] and not r.IsGroupHeader, 'Only numeric memory records are supported')
    if op == 'value' then
      assert(a[5] and #a[5] <= 128 and tonumber(a[5]), 'Invalid numeric value')
      r.Value = a[5]
    else
      assert(a[5] == '0' or a[5] == '1', 'Invalid freeze state')
      r.Active = a[5] == '1'
      assert(r.Active == (a[5] == '1'), 'CE rejected freeze change')
    end
  end
  al.SelectedRecord = r
  al.repaint()
  return json(snapshot(r))
end

function ce_mcp.start(pipeName, token)
  assert(not ce_mcp.worker, 'Bridge worker already exists; restart CE to reconfigure')
  assert(type(token) == 'string' and #token == 64 and token:match('^[0-9a-f]+$'),
         'Use a random 64-character lowercase hex token')
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
        if args[1] ~= token then
          response = json({ok=false, error='Unauthorized'})
        else
          synchronize(function()
            local ok, result = pcall(dispatch, args)
            log((args[2] or '?'):gsub('[%c]', '?') .. (ok and ' OK' or ' FAILED'))
            response = ok and ('{"ok":true,"result":' .. result .. '}')
                          or json({ok=false, error=tostring(result)})
          end)
        end
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
