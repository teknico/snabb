module(...,package.seeall)

local app = require("core.app")
local packet = require("core.packet")
local link = require("core.link")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local ipsum = require("lib.checksum").ipsum

local lib = require("core.lib")
local htons = lib.htons

local ffi = require("ffi")
local C = ffi.C

local ether_header_t = ffi.typeof[[
struct {
  uint8_t  ether_dhost[6];
  uint8_t  ether_shost[6];
  uint16_t ether_type;
} __attribute__((packed))
]]
local ethernet_header_ptr_type = ffi.typeof("$*", ether_header_t)

local ipv4hdr_t = ffi.typeof[[
struct {
  uint16_t ihl_v_tos; // ihl:4, version:4, tos(dscp:6 + ecn:2)
  uint16_t total_length;
  uint16_t id;
  uint16_t frag_off; // flags:3, fragmen_offset:13
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t checksum;
  uint8_t  src_ip[4];
  uint8_t  dst_ip[4];
} __attribute__((packed))
]]
local ipv4_header_ptr_type = ffi.typeof("$*", ipv4hdr_t)

local ipv6hdr_t = ffi.typeof[[
struct {
  uint32_t v_tc_fl; // version, tc, flow_label
  uint16_t payload_length;
  uint8_t  next_header;
  uint8_t hop_limit;
  uint8_t src_ip[16];
  uint8_t dst_ip[16];
} __attribute__((packed))
]]
local ipv6_header_ptr_type = ffi.typeof("$*", ipv6hdr_t)

local n_ether_hdr_size = 14
local n_ipv4_hdr_size = 20
local n_ethertype_ipv4 = htons(0x0800)
local n_ethertype_ipv6 = htons(0x86DD)
local n_ipencap = 4
local n_ipfragment = 44
local n_cache_src_ipv4 = ipv4:pton("0.0.0.0")
local n_cache_src_ipv6 = ipv6:pton("fe80::")
local n_next_hop_mac_empty = ethernet:pton("00:00:00:00:00:00")


local receive, transmit = link.receive, link.transmit

--- # `nh_fwd` app: Finds next hop mac by sending packets to VM interface

nh_fwd6 = {}
nh_fwd4 = {}

local function send_ipv6_cache_trigger(r, p, mac)

-- set a bogus source IP address fe80::, so we can recognize it
-- later when it comes back from the vMX.
-- Tried initially to use ::0 as source, but such packets are discarded
-- by the vmx due to RFC 4007, chapter 9, which also considers the source IPv6
-- address.
-- Using the link local address fe80::, the packets are properly routed back
-- thru the same interface. Not sure if its ok to use that address or if there
-- is a better way.

  local eth_hdr = ffi.cast(ethernet_header_ptr_type, p.data)
  local ethertype = eth_hdr.ether_type
  local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, p.data + n_ether_hdr_size)

  -- vMX will discard packets not matching its MAC address on the interface
  ffi.copy(eth_hdr.ether_dhost, mac, 6)
  ffi.copy(ipv6_hdr.src_ip, n_cache_src_ipv6, 16)
  transmit(r, p)

end

local function send_ipv4_cache_trigger(r, p, mac)

-- set a bogus source IP address of 0.0.0.0 
  local eth_hdr = ffi.cast(ethernet_header_ptr_type, p.data)
  local ethertype = eth_hdr.ether_type
  local ipv4_hdr = ffi.cast(ipv4_header_ptr_type, p.data + n_ether_hdr_size)

  -- vMX will discard packets not matching its MAC address on the interface
  ffi.copy(eth_hdr.ether_dhost, mac, 6)
  ipv4_hdr.src_ip = n_cache_src_ipv4
  -- clear checksum to recalculate it with new source IPv4 address
  ipv4_hdr.checksum =  0  
  ipv4_hdr.checksum = htons(ipsum(p.data + n_ether_hdr_size, n_ipv4_hdr_size, 0))
  transmit(r, p)

end

function nh_fwd6:new(arg)
  local conf = arg and config.parse_app_arg(arg) or {}
  local mac_address = conf.mac_address and ethernet:pton(conf.mac_address)
  local ipv6_address = conf.ipv6_address and ipv6:pton(conf.ipv6_address)
  local service_mac = conf.service_mac and ethernet:pton(conf.service_mac)
  local debug = conf.debug or 0
  local cache_refresh_interval = conf.cache_refresh_interval or 0
  local next_hop_mac = ethernet:pton("00:00:00:00:00:00")

  if conf.next_hop_mac then
    next_hop_mac = conf.next_hop_mac and ethernet:pton(conf.next_hop_mac)
    print(string.format("nh_fwd6: static next_hop_mac %s", ethernet:ntop(next_hop_mac)))
  end

  print(string.format("nh_fwd6: cache_refresh_interval set to %d seconds", cache_refresh_interval))

  if nil == mac_address then
    error("need mac_address!")
  end

  if nil == ipv6_address then
    error("need ipv6_address!")
  end

  local o = {
    mac_address = mac_address,
    next_hop_mac = next_hop_mac,
    ipv6_address = ipv6_address,
    service_mac = service_mac,
    debug = debug,
    cache_refresh_time = 0,
    cache_refresh_interval = cache_refresh_interval
  }

  return setmetatable(o, {__index=nh_fwd6})
end

function nh_fwd4:new(arg)
  local conf = arg and config.parse_app_arg(arg) or {}
  local mac_address = conf.mac_address and ethernet:pton(conf.mac_address)
  local ipv4_address = conf.ipv4_address and ipv4:pton(conf.ipv4_address)
  local service_mac = conf.service_mac and ethernet:pton(conf.service_mac)
  local debug = conf.debug or 0
  local cache_refresh_interval = conf.cache_refresh_interval or 0
  local next_hop_mac = ethernet:pton("00:00:00:00:00:00")

  if conf.next_hop_mac then
    next_hop_mac = conf.next_hop_mac and ethernet:pton(conf.next_hop_mac)
    print(string.format("nh_fwd4: static next_hop_mac %s", ethernet:ntop(next_hop_mac)))
  end

  print(string.format("nh_fwd4: cache_refresh_interval set to %d seconds", cache_refresh_interval))

  if nil == ipv4_address then
    error("need ipv4_address!")
  end

  if nil == mac_address then
    error("need mac_address!")
  end

  local o = {
    mac_address = mac_address,
    next_hop_mac = next_hop_mac,
    ipv4_address = ipv4_address,
    service_mac = service_mac,
    debug = debug,
    cache_refresh_time = 0,
    cache_refresh_interval = cache_refresh_interval
  }

  return setmetatable(o, {__index=nh_fwd4})
end

function nh_fwd6:push ()

  local input_service, output_service = self.input.service, self.output.service
  local input_wire, output_wire = self.input.wire, self.output.wire
  local input_vmx, output_vmx = self.input.vmx, self.output.vmx

  local next_hop_mac = self.next_hop_mac
  local service_mac = self.service_mac
  local mac_address = self.mac_address
  local current_time = tonumber(app.now())

  -- ipv6 from wire
  for _=1,link.nreadable(input_wire) do
    local pkt = receive(input_wire)
    local eth_hdr = ffi.cast(ethernet_header_ptr_type, pkt.data)
    local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, pkt.data + n_ether_hdr_size)

    -- print(string.format("ipv6 %s", ipv6:ntop(ipv6_hdr.dst_ip)))
    if ipv6_hdr.next_header == n_ipencap or ipv6_hdr.next_header == n_ipfragment then
      transmit(output_service, pkt)
    elseif output_vmx then
      transmit(output_vmx, pkt)
    else
      packet.free(pkt)
    end
  end

  -- ipv6 from vmx
  if input_vmx then
    for _=1,link.nreadable(input_vmx) do
      local pkt = receive(input_vmx)
      local eth_hdr = ffi.cast(ethernet_header_ptr_type, pkt.data)
      local ipv6_hdr = ffi.cast(ipv6_header_ptr_type, pkt.data + n_ether_hdr_size)

      -- print(string.format("from vmx ipv6 %s", ipv6:ntop(ipv6_hdr.dst_ip)))
      if service_mac and C.memcmp(eth_hdr.ether_dhost, service_mac, 6) == 0 then
        transmit(output_service, pkt)
      elseif self.cache_refresh_interval > 0 then
        if C.memcmp(ipv6_hdr.src_ip, n_cache_src_ipv6, 16) == 0 then
          ffi.copy(self.next_hop_mac, eth_hdr.ether_dhost, 6)
          if self.debug > 0 then
            print("nh_fwd6: learning next-hop " .. ethernet:ntop(self.next_hop_mac))
          end
          packet.free(pkt)
        else
          transmit(output_wire, pkt)
        end
      else
        transmit(output_wire, pkt)
      end
    end
  end

  -- ipv6 from service
  for _=1,link.nreadable(input_service) do
    local pkt = receive(input_service)
    local eth_hdr = ffi.cast(ethernet_header_ptr_type, pkt.data)

    if self.cache_refresh_interval > 0 and output_vmx then
      if current_time > self.cache_refresh_time + self.cache_refresh_interval then
        self.cache_refresh_time = current_time
        send_ipv6_cache_trigger(output_vmx, packet.clone(pkt), mac_address)
      end
    end

    -- only use a cached, non-empty, mac address  (4 digits compare is enough)
    if C.memcmp(next_hop_mac, n_next_hop_mac_empty, 4) ~= 0 then
      -- set nh mac and send the packet out the wire
      ffi.copy(eth_hdr.ether_dhost, next_hop_mac, 6)
      transmit(output_wire, pkt)
    else
      packet.free(pkt)
    end
  end

end

function nh_fwd4:push ()

  local input_service, output_service = self.input.service, self.output.service
  local input_wire, output_wire = self.input.wire, self.output.wire
  local input_vmx, output_vmx = self.input.vmx, self.output.vmx

  local next_hop_mac = self.next_hop_mac
  local service_mac = self.service_mac
  local mac_address = self.mac_address
  local current_time = tonumber(app.now())

  -- ipv4 from wire
  for _=1,link.nreadable(input_wire) do
    local pkt = receive(input_wire)
    local eth_hdr = ffi.cast(ethernet_header_ptr_type, pkt.data)
    local ipv4_hdr = ffi.cast(ipv4_header_ptr_type, pkt.data + n_ether_hdr_size)
    local ipv4_address = self.ipv4_address

    -- print(string.format("ipv4 %s", ipv4:ntop(ipv4_hdr.dst_ip)))
    if C.memcmp(ipv4_hdr.dst_ip, ipv4_address, 4) ~= 0 then
      transmit(output_service, pkt)
    elseif output_vmx then
      transmit(output_vmx, pkt)
    else
      packet.free(pkt)
    end
  end

  -- ipv4 from vmx
  if input_vmx then
    for _=1,link.nreadable(input_vmx) do
      local pkt = receive(input_vmx)
      local eth_hdr = ffi.cast(ethernet_header_ptr_type, pkt.data)
      local ipv4_hdr = ffi.cast(ipv4_header_ptr_type, pkt.data + n_ether_hdr_size)

      -- print(string.format("from vmx ipv4 %s", ipv4:ntop(ipv4_hdr.dst_ip)))
      if service_mac and C.memcmp(eth_hdr.ether_dhost, service_mac, 6) == 0 then
        transmit(output_service, pkt)
      elseif self.cache_refresh_interval > 0 then
        if C.memcmp(ipv4_hdr.src_ip, n_cache_src_ipv4,4) == 0 then    
          -- our magic cache next-hop resolution packet. Never send this out
          ffi.copy(self.next_hop_mac, eth_hdr.ether_dhost, 6)
          if self.debug > 0 then
            print("nh_fwd4: learning next-hop " .. ethernet:ntop(self.next_hop_mac))
          end
          packet.free(pkt)
        else
          transmit(output_wire, pkt)
        end
      else
        transmit(output_wire, pkt)
      end
    end
  end

  -- ipv4 from service
  for _=1,link.nreadable(input_service) do
    local pkt = receive(input_service)
    local eth_hdr = ffi.cast(ethernet_header_ptr_type, pkt.data)

    if self.cache_refresh_interval > 0 and output_vmx then
      if current_time > self.cache_refresh_time + self.cache_refresh_interval then
        self.cache_refresh_time = current_time
        send_ipv4_cache_trigger(output_vmx, packet.clone(pkt), mac_address)
      end
    end

    -- only use a cached, non-empty, mac address  (4 digits compare is enough)
    if C.memcmp(next_hop_mac, n_next_hop_mac_empty, 4) ~= 0 then
      -- set nh mac and send the packet out the wire
      ffi.copy(eth_hdr.ether_dhost, next_hop_mac, 6)
      transmit(output_wire, pkt)
    else
      packet.free(pkt)
    end
  end

end
