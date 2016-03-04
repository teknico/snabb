module(...,package.seeall)

local lib = require("core.lib")
local app = require("core.app")
local packet = require("core.packet")
local link = require("core.link")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local udp = require("lib.protocol.udp")
local ipv6 = require("lib.protocol.ipv6")
local ipsum = require("lib.checksum").ipsum
local lwutil = require("apps.lwaftr.lwutil")

local ffi = require("ffi")
local C = ffi.C
local cast = ffi.cast

local bitfield = lib.bitfield

local PROTO_IPV4_ENCAPSULATION = 0x4
local DEFAULT_TTL = 255

local ether_header_t = ffi.typeof[[
struct {
  uint8_t  ether_dhost[6];
  uint8_t  ether_shost[6];
  uint16_t ether_type;
} __attribute__((packed))
]]
local ether_header_ptr_type = ffi.typeof("$*", ether_header_t)

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

local ipv6_ptr_type = ffi.typeof([[
struct {
  uint32_t v_tc_fl; // version, tc, flow_label
  uint16_t payload_length;
  uint8_t  next_header;
  uint8_t  hop_limit;
  uint8_t  src_ip[16];
  uint8_t  dst_ip[16];
} __attribute__((packed))
]])
ipv6_header_ptr_type = ffi.typeof("$*", ipv6_ptr_type)
ipv6_header_size = ffi.sizeof(ipv6_ptr_type)


local udp_header_t = ffi.typeof[[
struct {
  uint16_t    src_port;
  uint16_t    dst_port;
  uint16_t    len;
  uint16_t    checksum;
} __attribute__((packed))
]]

udp_header_ptr_type = ffi.typeof("$*", udp_header_t)

local icmp_header_t = ffi.typeof[[
struct {
  uint8_t    icmp_type;
  uint8_t    code;
  uint16_t   checksum;
  uint16_t   id;
  uint16_t   sequence;
} __attribute__((packed))
]]

local n_cache_src_ipv6 = ipv6:pton("::")

icmp_header_ptr_type = ffi.typeof("$*", icmp_header_t)

local rd32, wr32 = lwutil.rd32, lwutil.wr32

local receive, transmit = link.receive, link.transmit

--- # `generator` app: Finds next hop mac by sending packets to VM interface

generator = {}

local function inc_ipv6(ipv6)
  for i=15,0,-1 do
    if ipv6[i] == 255 then
      ipv6[i] = 0
    else
      ipv6[i] = ipv6[i] + 1
      break
    end
  end
  return ipv6
end


function generator:new(arg)
  local conf = arg and config.parse_app_arg(arg) or {}
  local mac_address = ethernet:pton(conf.mac)
  local ipv4_address = conf.ipv4 and ipv4:pton(conf.ipv4)
  local ipv6_address_running = conf.ipv6 and ipv6:pton(conf.ipv6)
  local lwaftr_ipv6 = conf.lwaftr_ipv6 and ipv6:pton(conf.lwaftr_ipv6)
  local count = conf.count or 1
  local port = conf.port or 1024
  local protocol = conf.protocol or "udp"
  local payload_size = conf.size or 0
  local ipv4_address_offset = 0
  local debug = conf.debug or 0
  conf.bucket_capacity = conf.bucket_capacity or conf.rate
  conf.initial_capacity = conf.initial_capacity or conf.bucket_capacity

  ffi.copy(n_cache_src_ipv6, ipv6_address_running, 16)

  print(string.format("debug level %d", debug))

  local ipv4_pkt = packet.allocate()
  local eth_hdr = cast(ether_header_ptr_type, ipv4_pkt.data)
  eth_hdr.ether_dhost = mac_address
  eth_hdr.ether_shost = ethernet:pton("46:46:46:46:46:46")
  eth_hdr.ether_type = C.htons(0x0800)

  local ipv4_hdr = cast(ipv4_header_ptr_type, ipv4_pkt.data + 14)
  ipv4_hdr.src_ip = ipv4:pton("1.1.1.1")
  ipv4_hdr.ttl = 15
  ipv4_hdr.ihl_v_tos = C.htons(0x4500) -- v4
  ipv4_hdr.id = 0
  ipv4_hdr.frag_off = 0
  ipv4_hdr.total_length = C.htons(28 + payload_size)

  local ipv4_udp_hdr, ipv4_icmp_hdr

  if protocol == 'udp' then
    ipv4_hdr.protocol = 17  -- UDP(17)
    ipv4_udp_hdr = cast(udp_header_ptr_type, ipv4_pkt.data + 34)
    ipv4_udp_hdr.src_port = C.htons(12345)
    ipv4_udp_hdr.len = C.htons(payload_size)
    ipv4_udp_hdr.checksum = 0
  else
    ipv4_hdr.protocol = 1   -- ICMP(1)
    ipv4_icmp_hdr = cast(icmp_header_ptr_type, ipv4_pkt.data + 34)
    ipv4_icmp_hdr.icmp_type = 8 -- echo request
    ipv4_icmp_hdr.code = 0
    ipv4_icmp_hdr.checksum = 0
  end

  local ipv4_pkt_length = 34 + 8 + payload_size
  local ipv6_pkt_length = 34 + 8 + ipv6_header_size + payload_size

  -- IPv4 in IPv6 packet

  local ipv6_pkt = packet.allocate()
  local eth_hdr = cast(ether_header_ptr_type, ipv6_pkt.data)
  eth_hdr.ether_dhost = mac_address
  eth_hdr.ether_shost = ethernet:pton("46:46:46:46:46:46")
  eth_hdr.ether_type = C.htons(0x86DD)

  local ipv6_hdr = cast(ipv6_header_ptr_type, ipv6_pkt.data + 14)
  bitfield(32, ipv6_hdr, 'v_tc_fl', 0, 4, 6) -- IPv6 Version
  bitfield(32, ipv6_hdr, 'v_tc_fl', 4, 8, 1) -- Traffic class
  ipv6_hdr.payload_length = C.htons(payload_size + 28)
  ipv6_hdr.next_header = PROTO_IPV4_ENCAPSULATION
  ipv6_hdr.hop_limit = DEFAULT_TTL
  ipv6_hdr.dst_ip = lwaftr_ipv6

  local ipv6_ipv4_hdr = cast(ipv4_header_ptr_type, ipv6_pkt.data + 14 + ipv6_header_size)
  ipv6_ipv4_hdr.dst_ip = ipv4:pton("1.1.1.1")
  ipv6_ipv4_hdr.ttl = 15
  ipv6_ipv4_hdr.ihl_v_tos = C.htons(0x4500) -- v4
  ipv6_ipv4_hdr.id = 0
  ipv6_ipv4_hdr.frag_off = 0
  ipv6_ipv4_hdr.total_length = C.htons(28 + payload_size)

  local ipv6_ipv4_udp_hdr, ipv6_ipv4_icmp_hdr

  local ipv4_packet_sizes
  if payload_size > 0 then
    local size = payload_size + 20
    print(string.format("Using IP packet size of %d", size))
    ipv4_packet_sizes = { size }
  else
    ipv4_packet_sizes = { 64, 64, 64, 64, 64, 64, 64, 594, 594, 594, 1500 }
  end
  local total_length = 0
  local total_packet_count = 0
  for _,size in ipairs(ipv4_packet_sizes) do
    -- count for IPv4 and IPv6 packets (40 bytes IPv6 encap header)
    total_length = total_length + size * 2 + 40
    total_packet_count = total_packet_count + 2
  end

  if protocol == 'udp' then
    ipv6_ipv4_hdr.protocol = 17  -- UDP(17)
    ipv6_ipv4_udp_hdr = cast(udp_header_ptr_type, ipv6_pkt.data + 34 + ipv6_header_size)
    ipv6_ipv4_udp_hdr.dst_port = C.htons(12345)
    ipv6_ipv4_udp_hdr.len = C.htons(payload_size)
    ipv6_ipv4_udp_hdr.checksum = 0
  else
    ipv4_hdr.protocol = 1   -- ICMP(1)
    ipv6_ipv4_icmp_hdr = cast(icmp_header_ptr_type, ipv6_pkt.data + 34 + ipv6_header_size)
    ipv6_ipv4_icmp_hdr.icmp_type = 8 -- echo request
    ipv6_ipv4_icmp_hdr.code = 0
    ipv6_ipv4_icmp_hdr.checksum = 0
  end

  local ipv4_pkt_length = 34 + 8 + payload_size

  local o = {
    ipv4_address = ipv4_address,
    ipv4_address_offset = ipv4_address_offset,
    ipv6_address = n_cache_src_ipv6,
    ipv6_address_running = ipv6_address_running,
    count = count,
    port = port,
    current_count = 0,
    current_port = port,
    ipv4_pkt_length = ipv4_pkt_length,
    ipv4_pkt = ipv4_pkt,
    ipv4_hdr = ipv4_hdr,
    ipv6_hdr = ipv6_hdr,
    ipv6_pkt_length = ipv6_pkt_length,
    ipv6_pkt = ipv6_pkt,
    ipv6_ipv4_hdr = ipv6_ipv4_hdr,
    ipv4_udp_hdr = ipv4_udp_hdr,
    ipv4_icmp_hdr = ipv4_icmp_hdr,
    ipv6_ipv4_udp_hdr = ipv6_ipv4_udp_hdr,
    ipv6_ipv4_icmp_hdr = ipv6_ipv4_icmp_hdr,
    protocol = protocol,
    rate = conf.rate,
    bucket_capacity = conf.bucket_capacity,
    bucket_content = conf.initial_capacity,
    ipv4_packet_sizes = ipv4_packet_sizes,
    total_length = total_length,
    total_packet_count = total_packet_count,
    debug = debug
  }
  return setmetatable(o, {__index=generator})
end

function generator:push ()

  local input = self.input.input
  local output = self.output.output

  -- trash any incoming packets for now
  for _=1,link.nreadable(input) do
    local pkt = receive(input)
    packet.free(pkt)
  end

  local ipv4_hdr = self.ipv4_hdr
  local ipv6_hdr = self.ipv6_hdr
  local ipv6_ipv4_hdr = self.ipv6_ipv4_hdr
  local ipv4_udp_hdr = self.ipv4_udp_hdr
  local ipv4_icmp_hdr = self.ipv4_icmp_hdr
  local ipv6_ipv4_udp_hdr = self.ipv6_ipv4_udp_hdr
  local ipv6_ipv4_icmp_hdr = self.ipv6_ipv4_icmp_hdr
  local debug = self.debug
  local protocol = self.protocol

  do
    local cur_now = tonumber(app.now())
    local last_time = self.last_time or cur_now
    self.bucket_content = math.min(
    self.bucket_content + self.rate * (cur_now - last_time),
    self.bucket_capacity)
    self.last_time = cur_now
  end

  while link.nwritable(output) > self.total_packet_count and
    self.total_length <= self.bucket_content do

      self.bucket_content = self.bucket_content - self.total_length

      ipv4_hdr.dst_ip = self.ipv4_address 
      ipv6_ipv4_hdr.src_ip = self.ipv4_address 
      ipv6_hdr.src_ip = self.ipv6_address_running
      local ipdst = C.ntohl(rd32(ipv4_hdr.dst_ip))
      ipdst = C.htonl(ipdst + self.ipv4_address_offset)
      wr32(ipv4_hdr.dst_ip, ipdst)
      wr32(ipv6_ipv4_hdr.src_ip, ipdst)

      if protocol == 'udp' then
        ipv4_udp_hdr.dst_port = C.htons(self.current_port)
        ipv6_ipv4_udp_hdr.src_port = C.htons(self.current_port)
      else
        ipv4_icmp_hdr.id = C.htons(self.current_port)
        ipv6_ipv4_icmp_hdr.id = C.htons(self.current_port)
        ipv4_icmp_hdr.checksum =  0
        ipv4_icmp_hdr.checksum =  C.htons(ipsum(self.ipv4_pkt.data + 34, 8, 0))
        ipv6_ipv4_icmp_hdr.checksum =  0
        ipv6_ipv4_icmp_hdr.checksum =  C.htons(ipsum(self.ipv6_pkt.data + 34 + ipv6_header_size, 8, 0))
      end

      if debug > 1 then
        print(string.format("sending packet for %s port %d payload %d bytes", ipv4:ntop(ipv4_hdr.dst_ip), C.ntohs(udp_hdr.dst_port), C.ntohs(udp_hdr.len) ))
        C.usleep(10000)
      end

      for _,size in ipairs(self.ipv4_packet_sizes) do

        ipv4_hdr.total_length = C.htons(size)
        ipv4_udp_hdr.len = C.htons(size - 28)
        ipv6_hdr.payload_length = C.htons(size)
        ipv6_ipv4_hdr.total_length = C.htons(size)
        ipv6_ipv4_udp_hdr.len = C.htons(size - 28)
        self.ipv4_pkt.length = size + 14
        self.ipv6_pkt.length = size + 54

        ipv4_hdr.checksum =  0
        ipv4_hdr.checksum = C.htons(ipsum(self.ipv4_pkt.data + 14, 20, 0))
        local ipv4_pkt = packet.clone(self.ipv4_pkt)
        local ipv6_pkt = packet.clone(self.ipv6_pkt)

        self.current_count = self.current_count + 1
        self.current_port = self.current_port + self.port

        self.ipv6_address_running = inc_ipv6(self.ipv6_address_running)

        if self.current_port > 65535 then
          self.current_port = self.port
          self.ipv4_address_offset = self.ipv4_address_offset + 1
        end

        if self.current_count >= self.count then
          self.current_count = 0
          self.current_port = self.port
          self.ipv4_address_offset = 0
          ffi.copy(self.ipv6_address_running, self.ipv6_address, 16)
        end

        transmit(output, ipv6_pkt)
        transmit(output, ipv4_pkt)

      end 
  end
end

