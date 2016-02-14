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
local cast = ffi.cast

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
local n_next_hop_mac = ethernet:pton("00:00:00:00:00:00")
local n_next_hop_mac_empty = ethernet:pton("00:00:00:00:00:00")


local receive, transmit = link.receive, link.transmit

--- # `nh_fwd` app: Finds next hop mac by sending packets to VM interface

nh_fwd = {}

function send_cache_trigger(r, p, mac)

-- set a bogus source IP address of 0.0.0.0 or fe80::, so we can recognize it
-- later when it comes back from the vMX.
-- TODO: tried initially to use ::0 as source, but such packets are discarded
-- by the vmx due to RFC 4007, chapter 9, which also considers the source IPv6
-- address.
-- Using the link local address fe80::, the packets are properly routed back
-- thru the same interface. Not sure if its ok to use that address or if there
-- is a better way.

  local eth_hdr = cast(ethernet_header_ptr_type, p.data)
  local ethertype = eth_hdr.ether_type
  local ipv4_hdr = cast(ipv4_header_ptr_type, p.data + n_ether_hdr_size)
  local ipv6_hdr = cast(ipv6_header_ptr_type, p.data + n_ether_hdr_size)

  -- vMX will discard packets not matching its MAC address on the interface
  ffi.copy(eth_hdr.ether_dhost, mac, 6)

  if ethertype == n_ethertype_ipv4 then
    ipv4_hdr.src_ip = n_cache_src_ipv4
    -- clear checksum before calculation
    ipv4_hdr.checksum =  0  
    ipv4_hdr.checksum = htons(ipsum(p.data + n_ether_hdr_size, n_ipv4_hdr_size, 0))
    transmit(r, p)
  elseif ethertype == n_ethertype_ipv6 then
    ffi.copy(ipv6_hdr.src_ip, n_cache_src_ipv6, 16)
    transmit(r, p)
  else
    packet.free(r)
  end

end

function nh_fwd:new(arg)
  local conf = arg and config.parse_app_arg(arg) or {}
  local mac_address = conf.mac_address and ethernet:pton(conf.mac_address)
  local ipv6_address = conf.ipv6_address and ipv6:pton(conf.ipv6_address)
  local ipv4_address = conf.ipv4_address and ipv4:pton(conf.ipv4_address)
  local next_hop_mac = conf.next_hop_mac and ethernet:pton(conf.next_hop_mac)
  local service_mac = conf.service_mac and ethernet:pton(conf.service_mac)
  local cache_refresh_interval = conf.cache_refresh_interval or 0
  local description = conf.description or "nh_fwd"

  if next_hop_mac then
    print("next_hop_mac " .. ethernet:ntop(next_hop_mac) .. " on " .. description)
  else
    next_hop_mac = n_next_hop_mac
  end
  print(string.format("%s: cache_refresh_interval set to %d seconds",description, cache_refresh_interval))

  if nil == mac_address then
    error("need mac_address!")
  end

  local o = {
    mac_address = mac_address,
    next_hop_mac = next_hop_mac,
    ipv4_address = ipv4_address,
    ipv6_address = ipv6_address,
    description = description,
    service_mac = service_mac,
    cache_refresh_time = tonumber(app.now()),
    cache_refresh_interval = cache_refresh_interval
  }

  return setmetatable(o, {__index=nh_fwd})
end

function nh_fwd:push ()

  local input_service, output_service = self.input.service, self.output.service
  local input_wire, output_wire = self.input.wire, self.output.wire
  local input_vmx, output_vmx = self.input.vmx, self.output.vmx

  local description = self.description
  local next_hop_mac = self.next_hop_mac
  local service_mac = self.service_mac
  local mac_address = self.mac_address
  local cache_refresh_interval = self.cache_refresh_interval
  local current_time = tonumber(app.now())
  local cache_refresh_time = self.cache_refresh_time

  -- from service
  if output_wire then
    for _=1,link.nreadable(input_service) do

      local pkt = receive(input_service)
      local eth_hdr = cast(ethernet_header_ptr_type, pkt.data)

      if cache_refresh_interval > 0 and output_vmx then
        if current_time > cache_refresh_time + cache_refresh_interval then
          self.cache_refresh_time = current_time
          -- only required for one packet per breath
          -- because next_hop_mac won't be learned until much later
          cache_refresh_interval = 0
          send_cache_trigger(output_vmx, packet.clone(pkt), mac_address)
        end
      end

      -- only use a cached, non-empty, mac address  (4 digits compare is enough)
      if C.memcmp(next_hop_mac, n_next_hop_mac_empty, 4) ~= 0 then
        -- set nh mac and send the packet out the wire
        ffi.copy(eth_hdr.ether_dhost, next_hop_mac, 6)
        transmit(output_wire, pkt)
      elseif output_vmx and cache_refresh_interval == 0 then
        -- no nh mac. Punch it to the vMX
        transmit(output_vmx, pkt)
      else
        packet.free(pkt)
      end

    end
  elseif output_vmx then
    -- no wire, thats ok. We run in "service pic" mode, only talking 
    -- to the vMX
    for _=1,link.nreadable(input_service) do
      local pkt = receive(input_service)
      transmit(output_vmx, pkt)
    end
  end

  -- from wire
  if input_wire then
    for _=1,link.nreadable(input_wire) do

      local pkt = receive(input_wire)
      local eth_hdr = cast(ethernet_header_ptr_type, pkt.data)
      local ethertype = eth_hdr.ether_type
      local ipv4_hdr = cast(ipv4_header_ptr_type, pkt.data + n_ether_hdr_size)
      local ipv6_hdr = cast(ipv6_header_ptr_type, pkt.data + n_ether_hdr_size)
      local ipv4_address = self.ipv4_address

      --[[
      if ethertype == n_ethertype_ipv4 then
        print(string.format("ipv4 %s", ipv4:ntop(ipv4_hdr.dst_ip)))
      elseif ethertype == n_ethertype_ipv6 then
        print(string.format("ipv6 %s", ipv6:ntop(ipv6_hdr.dst_ip)))
      end
      --]]

      if ethertype == n_ethertype_ipv4 and ipv4_address and C.memcmp(ipv4_hdr.dst_ip, ipv4_address, 4) ~= 0 then
        transmit(output_service, pkt)
      elseif ethertype == n_ethertype_ipv6 and 
        (ipv6_hdr.next_header == n_ipencap or ipv6_hdr.next_header == n_ipfragment) then
        transmit(output_service, pkt)
      elseif output_vmx then
        transmit(output_vmx, pkt)
      else
        packet.free(pkt)
      end
    end
  end

  -- from vmx: most packets will go straight out the wire, so check
  -- for room in the outbound wire queue, even though some packets may 
  -- actually go to another app
  --
  local cache_refresh_interval = self.cache_refresh_interval
  if output_wire and output_vmx then
    for _=1,link.nreadable(input_vmx) do

      local pkt = receive(input_vmx)
      local eth_hdr = cast(ethernet_header_ptr_type, pkt.data)
      local ethertype = eth_hdr.ether_type
      local ipv4_hdr = cast(ipv4_header_ptr_type, pkt.data + n_ether_hdr_size)
      local ipv6_hdr = cast(ipv6_header_ptr_type, pkt.data + n_ether_hdr_size)

   --[[ 
  if ethertype == n_ethertype_ipv4 then
    print(string.format("from vmx ipv4 %s", ipv4:ntop(ipv4_hdr.dst_ip)))
  elseif ethertype == n_ethertype_ipv6 then
    print(string.format("from vmx ipv6 %s", ipv6:ntop(ipv6_hdr.dst_ip)))
  end
  --]]

      if service_mac and C.memcmp(eth_hdr.ether_dhost, service_mac, 6) == 0 then
        transmit(output_service, pkt)
      elseif cache_refresh_interval > 0 then
        if ethertype == n_ethertype_ipv4 and C.memcmp(ipv4_hdr.src_ip, n_cache_src_ipv4,4) == 0 then    
          -- our magic cache next-hop resolution packet. Never send this out
          ffi.copy(self.next_hop_mac, eth_hdr.ether_dhost, 6)
--          print(description .. " learning ipv4 nh mac address " .. ethernet:ntop(self.next_hop_mac))
          packet.free(pkt)
        elseif ethertype == n_ethertype_ipv6 and C.memcmp(ipv6_hdr.src_ip, n_cache_src_ipv6,16) == 0 then
          ffi.copy(self.next_hop_mac, eth_hdr.ether_dhost, 6)
--          print(description .. " learning ipv6 nh mac address " .. ethernet:ntop(self.next_hop_mac))
          packet.free(pkt)
        else
          transmit(output_wire, pkt)
        end
      else
        transmit(output_wire, pkt)
      end

    end
  elseif input_vmx then
    -- no wire, just pass it to the next app
    for _=1,link.nreadable(input_vmx) do
      local pkt = receive(input_vmx)
      transmit(output_service, pkt)
    end

  end


end
