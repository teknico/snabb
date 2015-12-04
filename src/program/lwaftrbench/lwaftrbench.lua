module(..., package.seeall)

local app = require("core.app")
local basic_apps = require("apps.basic.basic_apps")
local c_config = require("core.config")
local ipv6 = require("lib.protocol.ipv6")
local ethernet = require("lib.protocol.ethernet")
local lib = require("core.lib")
local pcap = require("apps.pcap.pcap")
local lwaftr = require("apps.lwaftr.lwaftr").lwaftr

local long_opts = {
     duration     = "D",
}

local function ether_pton (addr)
  if type(addr) == "string" then
    return ethernet:pton(addr)
  else
    return addr
  end
end

local function ipv6_pton (addr)
  if type(addr) == "string" then
    return ipv6:pton(addr)
  else
    return addr
  end
end

function run(args)
  local opt = {}
  local duration
  function opt.D (arg) duration = tonumber(arg)  end
  args = lib.dogetopt(args, opt, "D:", long_opts)
  if not (#args == 3) then
    print("Usage: lwaftrbench [-D seconds] <tunnel config file> <ipv6 pcap> <trunk pcap>")
    main.exit(1)
  end

  local file = table.remove(args, 1)
  local ipv6_pcap = table.remove(args, 1)
  local trunk_pcap = table.remove(args, 1)

  print ("Configuration file: " .. file)
  if duration then
    print("running for " .. duration .. " seconds")
  end
  local ports = lib.load_conf(file)
  local c = c_config.new()
  local configured = false

  for _,t in ipairs(ports) do
    local mac_address = t.mac_address

    if t.tunnel and t.tunnel.type == "lwaftr" then

      local conf = {local_mac = mac_address,
      ipv6_interface = t.tunnel.ipv6_interface,
      ipv4_interface = t.tunnel.ipv4_interface,
      binding_table = t.tunnel.binding_table}
      c_config.app(c, "lwaftr", lwaftr, conf)
      configured = true
    end
  end

  if false == configured then
    print("no lwaftr tunnel configuration found in " .. file)
    exit(1)
  end

  c_config.app(c, "capture1", pcap.PcapReader, ipv6_pcap)
  c_config.app(c, "capture2", pcap.PcapReader, trunk_pcap)
  c_config.app(c, "repeater1", basic_apps.Repeater)
  c_config.app(c, "repeater2", basic_apps.Repeater)
  c_config.app(c, "ipv4_to_ipv6", basic_apps.Statistics)
  c_config.app(c, "ipv6_to_ipv4", basic_apps.Statistics)
  c_config.app(c, "sink1", basic_apps.Sink)
  c_config.app(c, "sink2", basic_apps.Sink)

  c_config.link(c, "capture1.output -> repeater1.input")
  c_config.link(c, "repeater1.output -> lwaftr.encapsulated")
  c_config.link(c, "lwaftr.decapsulated -> ipv6_to_ipv4.input")
  c_config.link(c, "ipv6_to_ipv4.output -> sink2.input")

  c_config.link(c, "capture2.output -> repeater2.input")
  c_config.link(c, "repeater2.output -> lwaftr.decapsulated")
  c_config.link(c, "lwaftr.encapsulated -> ipv4_to_ipv6.input")
  c_config.link(c, "ipv4_to_ipv6.output -> sink1.input")

  app.configure(c)
  app.main({duration=duration})

end
