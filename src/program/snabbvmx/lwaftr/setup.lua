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
local nh_fwd     = require("apps.nh_fwd.nh_fwd")

local function load_phy(c, nic_id, interface)

  assert(type(interface) == 'table')
  local vlan = interface.vlan and tonumber(interface.vlan)
  local device_info = pci.device_info(interface.pci)

  if not device_info then 
    fatal(("Couldn't find device info for PCI address '%s'"):format(interface.pci))
  end
  local snmp = { directory = "/tmp" }
  config.app(c, nic_id, require(device_info.driver).driver, 
  {pciaddr = interface.pci, vmdq = true, vlan = vlan, snmp = snmp,
  macaddr = interface.mac_address, mtu = interface.mtu})

end

function lwaftr_app(c, conf, lwconf, sock_path)
  assert(type(conf) == 'table')
  assert(type(lwconf) == 'table')
  conf.preloaded_binding_table = bt.load(lwconf.binding_table)

  load_phy(c, "v6nic", conf.ipv6_interface)

  local chain_input =  "v6nic.rx"
  local chain_output = "v6nic.tx"

  local v6_fragmentation = conf.ipv6_interface.fragmentation
  if false ~= v6_fragmentation then
    v6_fragmentation = true
    print("IPv6 fragmentation and reassembly enabled")

    config.app(c, "reassemblerv6", ipv6_apps.Reassembler, {})
    config.link(c, chain_output .. " -> reassemblerv6.input")
    chain_output = "reassemblerv6.output"

    config.app(c, "fragmenterv6", ipv6_apps.Fragmenter, { mtu=conf.ipv6_interface.mtu })
    config.link(c, "fragmenterv6.output -> " .. chain_input)
    chain_input  = "fragmenterv6.input"
  else
    print("IPv6 fragmentation and reassembly disabled")
  end

  if conf.ipv6_interface.ingress_filter then
    config.app(c, "ingress_filterv6", PcapFilter, 
    { filter = conf.ipv6_interface.ingress_filter })
    config.link(c, chain_output .. " -> ingress_filterv6.input")
    chain_output = "ingress_filterv6.output"
    print("IPv6 ingress filter enabled")
  end

  if conf.ipv6_interface.egress_filter then
    config.app(c, "egress_filterv6", PcapFilter, 
    { filter = conf.ipv6_interface.egress_filter })
    config.link(c, "egress_filter6.output -> " .. chain_input)
    chain_input = "egress_filter6.input"
    print("IPv6 egress filter enabled")
  end

  config.app(c, "nh_fwd6", nh_fwd.nh_fwd, conf.ipv6_interface)

  if conf.ipv6_interface.id then
    config.app(c, conf.ipv6_interface.id, VhostUser, 
    {socket_path=sock_path:format(conf.ipv6_interface.id)})
    config.link(c, conf.ipv6_interface.id .. ".tx -> " .. "nh_fwd6.vmx")
    config.link(c, "nh_fwd6.vmx -> " .. conf.ipv6_interface.id  .. ".rx")
  end

  config.link(c, chain_output .. " -> nh_fwd6.wire")
  chain_output = "nh_fwd6.service"
  config.link(c, "nh_fwd6.wire -> " .. chain_input)
  chain_input  = "nh_fwd6.service"

  config.app(c, "lwaftr", lwaftr.LwAftr, lwconf)
  config.link(c, chain_output .. " -> lwaftr.v6")
  chain_output = "lwaftr.v4"
  config.link(c, "lwaftr.v6 -> " .. chain_input)
  chain_input  = "lwaftr.v4"

  config.app(c, "nh_fwd4", nh_fwd.nh_fwd, conf.ipv4_interface)

  if conf.ipv4_interface.id then
    config.app(c, conf.ipv4_interface.id, VhostUser, 
    {socket_path=sock_path:format(conf.ipv4_interface.id)})
    config.link(c, conf.ipv4_interface.id .. ".tx -> " .. "nh_fwd4.vmx")
    config.link(c, "nh_fwd4.vmx -> " .. conf.ipv4_interface.id  .. ".rx")
  end

  config.link(c, chain_output .. " -> nh_fwd4.service")
  chain_output = "nh_fwd4.wire"
  config.link(c, "nh_fwd4.service -> " .. chain_input)
  chain_input  = "nh_fwd4.wire"

  if conf.ipv4_interface.ingress_filter then
    config.app(c, "ingress_filterv4", PcapFilter, 
    { filter = conf.ipv4_interface.ingress_filter })
    config.link(c, chain_output .. " -> ingress_filterv4.input")
    chain_output = "ingress_filterv4.output"
    print("IPv4 ingress filter enabled")
  end
  if conf.ipv4_interface.egress_filter then
    config.app(c, "egress_filterv4", PcapFilter, 
    { filter = conf.ipv4_interface.egress_filter })
    config.link(c, "egress_filter4.output -> " .. chain_input)
    chain_input = "egress_filter4.input"
    print("IPv4 egress filter enabled")
  end

  local v4_fragmentation = conf.ipv4_interface.fragmentation
  if false ~= v4_fragmentation then
    v4_fragmentation = true
    print("IPv4 fragmentation and reassembly enabled")
    config.app(c, "reassemblerv4", ipv4_apps.Reassembler, {})
    config.app(c, "fragmenterv4", ipv4_apps.Fragmenter, { mtu=conf.ipv4_interface.mtu })
    config.link(c, chain_output .. " -> reassemblerv4.input")
    chain_output = "reassemblerv4.output"
    config.link(c, "fragmenterv4.output -> " .. chain_input)
    chain_input = "fragmenterv4.input"
  else
    print("IPv4 fragmentation and reassembly disabled")
  end

  load_phy(c, "v4nic", conf.ipv4_interface)

  config.link(c, chain_output .. " -> v4nic.rx")
  config.link(c, "v4nic.tx -> " .. chain_input)

end

