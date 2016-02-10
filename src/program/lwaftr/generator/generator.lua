module(..., package.seeall)

local Intel82599 = require("apps.intel.intel_app").Intel82599
local PcapWriter = require("apps.pcap.pcap").PcapWriter
local binding_table = require("apps.lwaftr.binding_table")
local config = require("core.config")
local generator = require("apps.lwaftr.generator")
local lib = require("core.lib")
local stream = require("apps.lwaftr.stream")
local lwconf = require("apps.lwaftr.conf")

function show_usage(code)
   print(require("program.lwaftr.generator.README_inc"))
   main.exit(code)
end

function parse_args(args)
   local opts, handlers = {}, {}
   function handlers.i()
      opts.from_inet = true
   end
   function handlers.b()
      opts.from_b4 = true
   end
   function handlers.n(arg)
      opts.num_ips = tonumber(arg)
   end
   function handlers.s(arg)
      opts.packet_size = tonumber(arg)
   end
   function handlers.m(arg)
      opts.max_packets = tonumber(arg)
   end
   function handlers.p(arg)
      opts.pcap = arg
   end
   function handlers.v(arg)
      opts.vlan_tag = assert(tonumber(arg), "VLAN tag must be a number")
   end
   function handlers.h() show_usage(0) end
   args = lib.dogetopt(args, handlers, "bin:m:s:v:p:h",
      { ["from-inet"]="i", ["from-b4"]="b", ["num-ips"]="n",
        ["max-packets"]="m", ["packet-size"]="s", ["vlan-tag"]="v",
        pcap="p", help="h" })
   return opts, args
end

function run(args)
   local opts, args = parse_args(args)

   if opts.from_inet and opts.from_b4
         or not (opts.from_inet or opts.from_b4) then
      show_usage(1)
   end

   local pciaddr
   local c = config.new()

   -- Default max_packets value when printing to pcap.
   if opts.pcap and not opts.max_packets then
      opts.max_packets = 10
   end

   if opts.from_inet then
      if #args < 1 or #args > 4 then
         print("#args: "..#args)
         show_usage(1)
      end
      local lwaftr_config, start_inet, psid_len, _pciaddr = unpack(args)
      local conf = lwconf.load_lwaftr_config(lwaftr_config)
      config.app(c, "generator", generator.from_inet, {
         dst_mac = conf.aftr_mac_inet_side,
         src_mac = conf.inet_mac,
         start_inet = start_inet,
         psid_len = 6,
         max_packets = opts.max_packets,
         num_ips = opts.num_ips,
         packet_size = opts.packet_size,
         vlan_tag = opts.vlan_tag,
      })
      pciaddr = _pciaddr
   end
   if opts.from_b4 then
      if #args < 1 or #args > 6 then show_usage(1) end
      local lwaftr_config, start_inet, start_b4, br, psid_len, _pciaddr = unpack(args)
      local conf = lwconf.load_lwaftr_config(lwaftr_config)
      config.app(c, "generator", generator.from_b4, {
         src_mac = conf.next_hop6_mac,
         dst_mac = conf.aftr_mac_b4_side,
         start_inet = start_inet,
         start_b4 = start_b4,
         br = br,
         psid_len = psid_len,
         max_packets = opts.max_packets,
         num_ips = opts.num_ips,
         packet_size = opts.packet_size,
         vlan_tag = opts.vlan_tag,
      })
      pciaddr = _pciaddr
   end

   if opts.pcap then
      config.app(c, "pcap", PcapWriter, opts.pcap)
      config.link(c, "generator.output -> pcap.input")
      opts.duration = 1
   else
      config.app(c, "nic", Intel82599, { pciaddr = pciaddr })
      config.link(c, "generator.output -> nic.rx")
   end

   engine.configure(c)
   if opts.duration then
      engine.main({ duration = opts.duration })
   else
      engine.main({ noreport = true })
   end
end
