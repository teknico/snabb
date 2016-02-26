module(..., package.seeall)

local config     = require("core.config")
local pci        = require("lib.hardware.pci")
local VhostUser  = require("apps.vhost.vhost_user").VhostUser
local PcapFilter = require("apps.packet_filter.pcap_filter").PcapFilter
local lwaftr     = require("apps.lwaftr.lwaftr")
local basic_apps = require("apps.basic.basic_apps")
local pcap       = require("apps.pcap.pcap")
local bt         = require("apps.lwaftr.binding_table")
local ipv4_apps  = require("apps.lwaftr.ipv4_apps")
local ipv6_apps  = require("apps.lwaftr.ipv6_apps")
local ethernet   = require("lib.protocol.ethernet")
local nh_fwd     = require("apps.nh_fwd.nh_fwd").nh_fwd
local v4v6       = require("apps.nh_fwd.v4v6").v4v6
local Tap        = require("apps.tap.tap").Tap

local function load_phy(c, nic_id, interface)

  assert(type(interface) == 'table')
  local vlan = interface.vlan and tonumber(interface.vlan)
  local device_info = pci.device_info(interface.pci)

  if not device_info then 
    fatal(("Couldn't find device info for PCI address '%s'"):format(interface.pci))
  end
  local snmp = { directory = "/tmp", status_timer = 1 }
--  local snmp
  print(string.format("%s ether %s", nic_id, interface.mac_address))
  if vlan then
    print(string.format("%s vlan %d", nic_id, vlan))
  end
  config.app(c, nic_id, require(device_info.driver).driver, 
  {pciaddr = interface.pci, vmdq = true, vlan = vlan, snmp = snmp,
  macaddr = interface.mac_address, mtu = interface.mtu})

end

function lwaftr_app(c, conf, lwconf, sock_path)

  assert(type(conf) == 'table')
  assert(type(lwconf) == 'table')

  if lwconf.binding_table then
    conf.preloaded_binding_table = bt.load(lwconf.binding_table)
  end

  local phy_id = "nic_" .. conf.interface.id
  local mirror_id = conf.interface.mirror_id
  local virt_id = "vmx_" .. conf.interface.id

  load_phy(c, phy_id, conf.interface)

  local chain_input =  phy_id .. ".rx"
  local chain_output = phy_id .. ".tx"
  local v4_input, v4_output, v6_input, v6_output

  if conf.ipv4_interface or conf.ipv6_interface then

    local mirror = false
    if mirror_id then
      mirror = true
      config.app(c, "Mirror", Tap, mirror_id)
      config.app(c, "Sink", basic_apps.Sink)
--     config.app(c, "Join", basic_apps.Join)
--     config.link(c, "Join.out -> Mirror.input")
      config.link(c, "Mirror.output -> Sink.input")
      config.link(c, "nic_v4v6.mirror -> Mirror.input")
      print(string.format("mirror port %s found", mirror_id))
    end

    config.app(c, "nic_v4v6", v4v6, { description = "nic_v4v6", mirror = mirror })
    config.link(c, chain_output .. " -> nic_v4v6.input")
    config.link(c, "nic_v4v6.output -> " .. chain_input)
--    config.link(c, "nic_v4v6.mirror -> Join.input.nic")
    v4_output, v6_output = "nic_v4v6.v4", "nic_v4v6.v6"
    v4_input, v6_input   = "nic_v4v6.v4", "nic_v4v6.v6"
  end

  if conf.ipv6_interface then
    conf.ipv6_interface.mac_address = conf.interface.mac_address
    if conf.ipv6_interface.fragmentation then
      print("IPv6 fragmentation and reassembly enabled")
      config.app(c, "reassemblerv6", ipv6_apps.Reassembler, {})
      config.link(c, v6_output .. " -> reassemblerv6.input")
      v6_output = "reassemblerv6.output"
      local mtu = conf.ipv6_interface.mtu or lwconf.ipv6_mtu
      config.app(c, "fragmenterv6", ipv6_apps.Fragmenter, { mtu = mtu })
      config.link(c, "fragmenterv6.output -> " .. v6_input)
      v6_input  = "fragmenterv6.input"
    else
      print("IPv6 fragmentation and reassembly disabled")
    end
  end

  if conf.ipv4_interface then
    conf.ipv4_interface.mac_address = conf.interface.mac_address
    if conf.ipv4_interface.fragmentation then
      print("IPv4 fragmentation and reassembly enabled")
      config.app(c, "reassemblerv4", ipv4_apps.Reassembler, {})
      config.link(c, v4_output .. " -> reassemblerv4.input")
      v4_output = "reassemblerv4.output"
      local mtu = conf.ipv4_interface.mtu or lwconf.ipv4_mtu
      config.app(c, "fragmenterv4", ipv4_apps.Fragmenter, { mtu = mtu })
      config.link(c, "fragmenterv4.output -> " .. v4_input)
      v4_input  = "fragmenterv4.input"
    else
      print("IPv4 fragmentation and reassembly disabled")
    end
  end

  if conf.ipv4_interface and conf.ipv6_interface and conf.preloaded_binding_table then
    print("lwaftr service enabled")
    config.app(c, "nh_fwd6", nh_fwd, conf.ipv6_interface)
    config.link(c, v6_output .. " -> nh_fwd6.wire")
    config.link(c, "nh_fwd6.wire -> " .. v6_input)
    v6_input, v6_output = "nh_fwd6.vmx", "nh_fwd6.vmx"

    config.app(c, "nh_fwd4", nh_fwd, conf.ipv4_interface)
    config.link(c, v4_output .. " -> nh_fwd4.wire")
    config.link(c, "nh_fwd4.wire -> " .. v4_input)
    v4_input, v4_output = "nh_fwd4.vmx", "nh_fwd4.vmx"

    config.app(c, "lwaftr", lwaftr.LwAftr, lwconf)
    config.link(c, "nh_fwd6.service -> lwaftr.v6")
    config.link(c, "lwaftr.v6 -> nh_fwd6.service")
    config.link(c, "nh_fwd4.service -> lwaftr.v4")
    config.link(c, "lwaftr.v4 -> nh_fwd4.service")
  else
    print("lwaftr service disabled (either empty binding_table or v6 or v4 interface config missing)")
  end

  if conf.ipv4_interface or conf.ipv6_interface then
    config.app(c, "vmx_v4v6", v4v6, { description = "vmx_v4v6", mirror = false })
    config.link(c, v6_output .. " -> vmx_v4v6.v6")
    config.link(c, "vmx_v4v6.v6 -> " .. v6_input)
    config.link(c, v4_output .. " -> vmx_v4v6.v4")
    config.link(c, "vmx_v4v6.v4 -> " .. v4_input)
--    config.link(c, "vmx_v4v6.mirror -> Join.input.vmx")
    chain_input, chain_output = "vmx_v4v6.input", "vmx_v4v6.output"
  end

  if sock_path then
    config.app(c, virt_id, VhostUser, {socket_path=sock_path:format(conf.interface.id)})
    config.link(c, virt_id .. ".tx -> " .. chain_input)
    config.link(c, chain_output .. " -> " .. virt_id  .. ".rx")
  else
    config.app(c, "DummyVhost", basic_apps.Sink)
    config.link(c, "DummyVhost" .. ".tx -> " .. chain_input)
    config.link(c, chain_output .. " -> " .. "DummyVhost"  .. ".rx")
    print("running without vMX (no vHostUser sock_path set)")
  end

end

