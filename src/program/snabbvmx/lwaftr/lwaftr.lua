module(..., package.seeall)

local S          = require("syscall")
local config     = require("core.config")
local lib        = require("core.lib")
local setup      = require("program.snabbvmx.lwaftr.setup")
-- local intel10g  = require("apps.intel.intel10g")

local function show_usage(exit_code)
   print(require("program.snabbvmx.lwaftr.README_inc"))
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

local function nic_exists(pci_addr)
  local devices="/sys/bus/pci/devices"
  return dir_exists(("%s/%s"):format(devices, pci_addr)) or
  dir_exists(("%s/0000:%s"):format(devices, pci_addr))
end

function parse_args(args)
   if #args == 0 then show_usage(1) end
   local conf_file, sock_path, v6_id, v6_pci, v6_mac, v4_id, v4_pci, v4_mac
   local opts = { verbosity = 0 }
   local handlers = {}
   function handlers.v () opts.verbosity = opts.verbosity + 1 end
   function handlers.D (arg)
      opts.duration = assert(tonumber(arg), "duration must be a number")
   end
   function handlers.c(arg)
     conf_file = arg
     if not arg then
       fatal("Argument '--conf' was not set")
     end
     if not file_exists(conf_file) then
       fatal(("Couldn't locate configuration file at %s"):format(conf_file))
     end
   end
   function handlers.e(arg)
      v6_id = arg
      if not arg then
         fatal("Argument '--v6_id' was not set")
      end
   end
   function handlers.f(arg)
      v6_pci = arg
      if not arg then
         fatal("Argument '--v6_pci' was not set")
      end
   end
   function handlers.g(arg)
      v6_mac = arg
      if not arg then
         fatal("Argument '--v6_mac' was not set")
      end
   end
   function handlers.i(arg)
      v4_id = arg
      if not arg then
         fatal("Argument '--v4_id' was not set")
      end
   end
   function handlers.j(arg)
      v4_pci = arg
      if not arg then
         fatal("Argument '--v4_pci' was not set")
      end
   end
   function handlers.k(arg)
      v4_mac = arg
      if not arg then
         fatal("Argument '--v4_mac' was not set")
      end
   end
   function handlers.s(arg)
      sock_path = arg
      if not arg then
         fatal("Argument '--sock' was not set")
      end
   end
   function handlers.h() show_usage(0) end
   lib.dogetopt(args, handlers, "c:s:e:f:g:i:j:k:vD:ht",
      { ["conf"] = "c", ["sock"] = "s",
        ["v6_id"] = "e", ["v6_pci"] = "f", ["v6_mac"] = "g",
        ["v4_id"] = "i", ["v4_pci"] = "j", ["v4_mac"] = "k",
        verbose = "v", duration = "D", help = "h" })
   return opts, conf_file, v6_id, v6_pci, v6_mac, v4_id, v4_pci, v4_mac, sock_path
end

function run(args)
   local opts, conf_file, v6_id, v6_pci, v6_mac, v4_id, v4_pci, v4_mac, sock_path = parse_args(args)

   local conf = lib.load_conf(conf_file)
   if not file_exists(conf.lwaftr) then
       fatal(("lwaftr conf file %s not found"):format(conf.lwaftr))
   end
   local lwconf = require('apps.lwaftr.conf').load_lwaftr_config(conf.lwaftr)

   local c = config.new()

   if not (conf.ipv6_interface and conf.ipv4_interface) then
     fatal(("need ipv4_interface and ipv6_interface group in %s"):format(conf_file))
   end

   conf.ipv6_interface.mac_address = v6_mac
   conf.ipv6_interface.pci = v6_pci
   conf.ipv6_interface.id = v6_id
   conf.ipv6_interface.mtu = lwconf and lwconf.ipv6_mtu or 1500

   conf.ipv4_interface.mac_address = v4_mac
   conf.ipv4_interface.pci = v4_pci
   conf.ipv4_interface.id = v4_id
   conf.ipv4_interface.mtu = lwconf and lwconf.ipv4_mtu or 1460


   -- intel10g.num_descriptors = 2*1024
   setup.lwaftr_app(c, conf, lwconf, sock_path)

   engine.configure(c)

   if opts.verbosity >= 2 then
     local function lnicui_info()
       app.report_apps()
     end
     local t = timer.new("report", lnicui_info, 1e9, 'repeating')
     timer.activate(t)
   end

   engine.busywait = true
   if opts.duration then
      engine.main({duration=opts.duration, report={showlinks=true}})
   else
      engine.main({report={showlinks=true}})
   end
end
