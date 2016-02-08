module(..., package.seeall)

local lib = require("core.lib")
local channel = require("apps.lwaftr.channel")
local messages = require("apps.lwaftr.messages")

local command_names = {
   reload = messages.lwaftr_message_reload,
   dump_config = messages.lwaftr_message_reload
}

function show_usage(code)
   print(require("program.lwaftr.control.README_inc"))
   main.exit(code)
end

function parse_args(args)
   local handlers = {}
   function handlers.h() show_usage(0) end
   args = lib.dogetopt(args, handlers, "h", { help="h" })
   if #args ~= 2 then show_usage(1) end
   local pid, command = unpack(args)
   pid = tonumber(pid)
   if not pid then show_usage(1) end
   if command == 'reload' then
      return pid, { messages.lwaftr_message_reload }
   elseif command == 'dump-configuration' then
      return pid, { messages.lwaftr_message_reload }
   end
   print('Unknown command: '..command)
   show_usage(1)
end

function run(args)
   local pid, message = parse_args(args)
   local channel = channel.open(pid, 'lwaftr/control',
                                messages.lwaftr_message_t)
   if channel:put(message) then main.exit(0) end
   local name = channel.root..'/'..tostring(pid)..'/channels/lwaftr/control'
   print(string.format(
            'Channel lwaftr/control for %d is full; try again later.', pid))
   main.exit(1)
end
