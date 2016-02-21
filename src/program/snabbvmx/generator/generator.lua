module(..., package.seeall)

local S          = require("syscall")
local lib        = require("core.lib")
local pci = require("lib.hardware.pci")
local basic_apps = require("apps.basic.basic_apps")
local RateLimiter = require("apps.rate_limiter.rate_limiter").RateLimiter
local generator = require("apps.nh_fwd.generator").generator
local tap = require("apps.tap.tap").Tap

local function show_usage(exit_code)
   print(require("program.snabbvmx.generator.README_inc"))
   if exit_code then main.exit(exit_code) end
end

local function fatal(msg)
   show_usage()
   print(msg)
   main.exit(1)
end

local function file_exists(path)
   local stat = S.stat(path)
   return stat and stat.isreg
end

function parse_args(args)
   if #args == 0 then show_usage(1) end
   local pciaddr, mac, ipv4, ipv6, lwaftr_ipv6, count, port, size, protocol, mtu
   local rate = 1
   local opts = { verbosity = 0, debug = 0 }
   local handlers = {}
   function handlers.v () opts.verbosity = opts.verbosity + 1 end
   function handlers.d () opts.debug = opts.debug + 1 end
   function handlers.D (arg)
      opts.duration = assert(tonumber(arg), "duration must be a number")
   end
   function handlers.p(arg)
      pciaddr = arg
   end
   function handlers.t(arg)
      tapaddr = arg
   end
   function handlers.P(arg)
      protocol = arg
   end
   function handlers.m(arg)
      mac = arg
      if not arg then
         fatal("Argument '--mac' was not set")
      end
   end
   function handlers.i(arg)
     ipv4 = arg
   end
   function handlers.j(arg)
     ipv6 = arg
   end
   function handlers.l(arg)
     lwaftr_ipv6 = arg
   end
   function handlers.n(arg)
     count = tonumber(arg)
   end
   function handlers.X(arg)
     mtu = tonumber(arg)
   end
   function handlers.o(arg)
     port = tonumber(arg)
   end
   function handlers.r(arg)
     rate = tonumber(arg)
   end
   function handlers.s(arg)
     size = tonumber(arg)
   end
   function handlers.h() show_usage(0) end
   lib.dogetopt(args, handlers, "p:t:m:i:j:n:l:r:o:s:P:X:dvD:h",
      { ["pci"] = "p", ["tap"] = 't', ["mac"] = "m", ["ipv4"] = "i", ["ipv6"] = "j", ["count"] = "n",
        ["lwaftr"] = "l", ["rate"] = "r", 
        ["port"] = "o", ["size"] = "s", ["protocol"] = "P", ["mtu"] = "X", debug = "d",
        verbose = "v", duration = "D", help = "h" })
   return opts, pciaddr, mac, ipv4, ipv6, lwaftr_ipv6, count, port, size, protocol, mtu, rate
end

function run(args)
  local opts, pciaddr, mac, ipv4, ipv6, lwaftr_ipv6, count, port, size, protocol, mtu, rate = parse_args(args)
  local conf = {}

  local c = config.new()

  config.app(c, "generator", generator, 
  {mac = mac, ipv4 = ipv4, ipv6 = ipv6, lwaftr_ipv6 = lwaftr_ipv6, count = count, port = port, size = size, protocol = protocol, debug = opts.debug})

  config.app(c, "rx", basic_apps.Statistics)

  print(string.format("rate limiting to %s Gbps", rate))
  rate_bytes = rate * 1e9 / 8
  config.app(c, "policer", RateLimiter, {rate = rate_bytes, bucket_capacity = rate_bytes})

  if pciaddr then
    local device_info = pci.device_info(pciaddr)

    if not device_info then 
      fatal(("Couldn't find device information for PCI address '%s'"):format(pciaddr))
    end
    config.app(c, "nic", require(device_info.driver).driver,
    {pciaddr = pciaddr, vmdq = false, snmp = { directory = "/tmp", status_timer = 1 }, mtu = mtu})
    config.link(c, "nic.tx -> rx.input")
    config.link(c, "generator.output -> policer.input")
    config.link(c, "policer.output -> nic.rx")

  elseif tapaddr then
    config.app(c, "nic", tap, tapaddr)
    config.link(c, "nic.output -> rx.input")
    config.link(c, "generator.output -> policer.input")
    config.link(c, "policer.output -> nic.input")
  end

  config.link(c, "rx.output -> generator.input")

  if opts.verbosity > 0 then
     local t = timer.new("loadreport", engine.report_load, 1*1e9, 'repeating')
     timer.activate(t)
  end

  if opts.verbosity > 1 then
    local t = timer.new("linkreport", engine.report_links, 10*1e9, 'repeating')
    timer.activate(t)
  end

  engine.configure(c)

 --  engine.busywait = true
  if opts.duration then
    engine.main({duration=opts.duration, report={showlinks=true}})
  else
    engine.main({report={showlinks=true}})
  end
end
