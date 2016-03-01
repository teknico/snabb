
module(...,package.seeall)

local shm = require("core.shm")
local packet = require("core.packet")
local ffi = require("ffi")
local C = ffi.C

local receive, transmit = link.receive, link.transmit
--local cast = ffi.cast

v4v6 = {}

local o_ethernet_ethertype = 12
local o_ethertype_ipv6 = C.htons(0x86DD)
local o_ethertype_ipv4 = C.htons(0x0800)
local o_src_ipv4 = 26
local o_dst_ipv4 = 30
local o_ipv6_src_ipv4 = 0x42
local o_ipv6_dst_ipv4 = 0x46
local uint16_ptr_t = ffi.typeof('uint16_t*')
local uint32_ptr_t = ffi.typeof('uint32_t*')

-- keeping this shm here speeds things up
local v4v6_mirror = shm.map("v4v6_mirror", "struct { uint32_t ipv4; }")

local function mirror_v6_packet (pkt, mirror, ipv4_num)
  local ipv4_num = v4v6_mirror.ipv4
  if ffi.cast(uint32_ptr_t, pkt.data + o_ipv6_src_ipv4)[0] == ipv4_num or
    ffi.cast(uint32_ptr_t, pkt.data + o_ipv6_dst_ipv4)[0] == ipv4_num then
    if link.nwritable(mirror) then
      transmit(mirror, packet.clone(pkt))
    end
  end
end

local function mirror_v4_packet (pkt, mirror)
  local ipv4_num = v4v6_mirror.ipv4
  if ffi.cast(uint32_ptr_t, pkt.data + o_src_ipv4)[0] == ipv4_num or
    ffi.cast(uint32_ptr_t, pkt.data + o_dst_ipv4)[0] == ipv4_num then
    if link.nwritable(mirror) then
      transmit(mirror, packet.clone(pkt))
    end
  end
end

function v4v6:new(conf)

  local o = {
    description = conf.description or "v4v6",
    mirror = conf.mirror or false
  }
  return setmetatable(o, {__index=v4v6})
end

function v4v6:push ()

  local v4in, v6in = self.input.v4, self.input.v6
  local v4out, v6out = self.output.v4, self.output.v6
  local input, output = self.input.input, self.output.output
  local mirror
  local ipv4_num = 0
  if self.mirror then
    mirror = self.output.mirror
    ipv4_num = v4v6_mirror.ipv4
  end

  -- v4v6
  for _=1,link.nreadable(input) do
    local pkt = receive(input)
    local payload = pkt.data + o_ethernet_ethertype
    if ffi.cast(uint16_ptr_t, payload)[0] == o_ethertype_ipv6 then
      if ipv4_num > 0 then
        mirror_v6_packet(pkt, mirror, ipv4_num)
      end
      transmit(v6out, pkt)
    else
      -- IPv4, ARP
      if ipv4_num > 0 then
        mirror_v4_packet(pkt, mirror, ipv4_num)
      end
      transmit(v4out, pkt)
    end
  end

  -- v4
  for _=1,link.nreadable(v4in) do
    local pkt = receive(v4in)
    if ipv4_num > 0 then
      mirror_v4_packet(pkt, mirror, ipv4_num)
    end
    transmit(output, pkt)
  end

  -- v6
  for _=1,link.nreadable(v6in) do
    local pkt = receive(v6in)
    if ipv4_num > 0 then
      mirror_v6_packet(pkt, mirror, ipv4_num)
    end
    transmit(output, pkt)
  end

end
