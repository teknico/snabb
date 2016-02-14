module(..., package.seeall)

local ffi = require("ffi")
local lib = require("core.lib")
local shm = require("core.shm")
local syscall = require("syscall")
local ipv4 = require("lib.protocol.ipv4")
local usage = require("program.snabbvmx.monitor.README_inc")

local uint32_ptr_t = ffi.typeof('uint32_t*')

local long_opts = {
   help = "h"
}

function run (args)

  local opt = {}
  function opt.h (arg) print(usage) main.exit(1) end
  args = lib.dogetopt(args, opt, "h", long_opts)

  if #args > 1 then print(usage) main.exit(1) end

  local ipv4_address
  if #args == 0 then
    ipv4_address = "0.0.0.0"
    print("monitor off")
  else
    ipv4_address = args[1]
    print("monitor set to " .. ipv4_address)
  end

  local b1, b2, b3, b4 = ipv4_address:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  b1,b2,b3,b4 = tonumber(b1), tonumber(b2), tonumber(b3), tonumber(b4)

  local ipv4_address = ((b4 * 256 + b3) * 256 + b2) * 256 + b1

  for _, pid in ipairs(shm.children("//")) do
    local pid_value = tonumber(pid)
    if pid_value  then
      if not syscall.kill(pid_value, 0) then
        shm.unlink("//"..pid)
      else
--        print("pid " .. pid .. " type is " .. type(pid))
        local path = "//" .. pid .. "/v4v6_mirror"
        local v4v6_mirror = shm.map(path, "struct { uint32_t ipv4; }")
        v4v6_mirror.ipv4 = ipv4_address
        shm.unmap(v4v6_mirror)
      end
    end
  end

end

