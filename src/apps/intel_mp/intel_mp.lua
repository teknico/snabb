-- intel_mp: Device driver app for Intel 1G and 10G network cards
-- It supports
--    - Intel1G i210 and i350 based 1G network cards
--    - Intel82599 82599 based 10G network cards
-- The driver supports multiple processes connecting to the same physical nic.
-- Per process RX / TX queues are available via RSS. Statistics collection
-- processes can read counter registers
--
-- Data sheets (reference documentation):
-- http://www.intel.com/content/dam/www/public/us/en/documents/datasheets/ethernet-controller-i350-datasheet.pdf
-- http://www.intel.com/content/dam/www/public/us/en/documents/datasheets/i210-ethernet-controller-datasheet.pdf
-- http://www.intel.co.uk/content/dam/www/public/us/en/documents/datasheets/82599-10-gbe-controller-datasheet.pdf
-- Note: section and page numbers in the comments below refer to the i210 data sheet

module(..., package.seeall)

local ffi         = require("ffi")
local C           = ffi.C
local pci         = require("lib.hardware.pci")
local band, bor, lshift = bit.band, bit.bor, bit.lshift
local lib         = require("core.lib")
local bits        = lib.bits
local tophysical  = core.memory.virtual_to_physical
local register    = require("lib.hardware.register")
local counter     = require("core.counter")
local macaddress  = require("lib.macaddress")
local shm         = require("core.shm")

-- It's not clear what address to use for EEMNGCTL_i210 DPDK PMD / linux e1000
-- both use 1010 but the docs say 12030
-- https://sourceforge.net/p/e1000/mailman/message/34457421/
-- http://dpdk.org/browse/dpdk/tree/drivers/net/e1000/base/e1000_regs.h

reg = { }
reg.gbl = {
   array = [[
RETA        0x5c00 +0x04*0..31      RW Redirection Table
RSSRK       0x5C80 +0x04*0..9       RW RSS Random Key
]],
   singleton = [[
BPRC        0x04078 -               RC Broadcast Packets Received Count
BPTC        0x040F4 -               RC Broadcast Packets Transmitted Count
CTRL        0x00000 -               RW Device Control
CTRL_EXT    0x00018 -               RW Extended Device Control
STATUS      0x00008 -               RO Device Status
RCTL        0x00100 -               RW RX Control
CRCERRS     0x04000 -               RC CRC Error Count
GPRC        0x04074 -               RC Good Packets Received Count
GPTC        0x04080 -               RC Good Packets Transmitted Count
GORC64      0x04088 -               RC64 Good Octets Received Count 64-bit
GOTC64      0x04090 -               RC64 Good Octets Transmitted Count 64-bit
MPRC        0x0407C -               RC Multicast Packets Received Count
MPTC        0x040F0 -               RC Multicast Packets Transmitted Count
BPRC        0x04078 -               RC Broadcast Packets Received Count
BPTC        0x040F4 -               RC Broadcast Packets Transmitted
]]
}
reg['82599ES'] = {
   array = [[
ALLRXDCTL   0x01028 +0x40*0..63     RW Receive Descriptor Control
ALLRXDCTL   0x0D028 +0x40*64..127   RW Receive Descriptor Control
DAQF        0x0E200 +0x04*0..127    RW Destination Address Queue Filter
FTQF        0x0E600 +0x04*0..127    RW Five Tuple Queue Filter
MPSAR       0x0A600 +0x04*0..255    RW MAC Pool Select Array
PFUTA       0X0F400 +0x04*0..127    RW PF Unicast Table Array
PFVLVF      0x0F100 +0x04*0..63     RW PF VM VLAN Pool Filter
PFVLVFB     0x0F200 +0x04*0..127    RW PF VM VLAN Pool Filter Bitmap
PFMRCTL     0x0F600 +0x04*0..3      RW PF Mirror Rule Control
PFMRVLAN    0x0F610 +0x04*0..7      RW PF Mirror Rule VLAN
PFMRVM      0x0F630 +0x04*0..7      RW PF Mirror Rule Pool
PFVFRE      0x051E0 +0x04*0..1      RW PF VF Receive Enable
PFVFTE      0x08110 +0x04*0..1      RW PF VF Transmit Enable
PFVFSPOOF   0x08200 +0x04*0..7      RW PF VF Anti Spoof Control
PFVMVIR     0x08000 +0x04*0..63     RW PF VM VLAN Insert Register
PFVML2FLT   0x0F000 +0x04*0..63     RW PF VM L2 Control Register
QPRC        0x01030 +0x40*0..15     RC Queue Packets Received Count
QPRDC       0x01430 +0x40*0..15     RC Queue Packets Received Drop Count
QBRC64      0x01034 +0x40*0..15     RC64 Queue Bytes Received Count
QPTC        0x08680 +0x04*0..15     RC Queue Packets Transmitted Count
QBTC64      0x08700 +0x08*0..15     RC64 Queue Bytes Transmitted Count Low
SAQF        0x0E000 +0x04*0..127    RW Source Address Queue Filter
SDPQF       0x0E400 +0x04*0..127    RW Source Destination Port Queue Filter
PSRTYPE     0x0EA00 +0x04*0..63     RW Packet Split Receive Type Register
RAH         0x0A204 +0x08*0..127    RW Receive Address High
RAL         0x0A200 +0x08*0..127    RW Receive Address Low
RAL64       0x0A200 +0x08*0..127    RW64 Receive Address Low and High
RQSM        0x02300 +0x04*0..31     RW Receive Queue Statistic Mapping Registers
RTTDT2C     0x04910 +0x04*0..7      RW DCB Transmit Descriptor Plane T2 Config
RTTPT2C     0x0CD20 +0x04*0..7      RW DCB Transmit Packet Plane T2 Config
RTRPT4C     0x02140 +0x04*0..7      RW DCB Receive Packet Plane T4 Config
RXPBSIZE    0x03C00 +0x04*0..7      RW Receive Packet Buffer Size
RQSMR       0x02300 +0x04*0..31     RW Receive Queue Statistic Mapping Registers
TQSM        0x08600 +0x04*0..31     RW Transmit Queue Statistic Mapping Registers
TXPBSIZE    0x0CC00 +0x04*0..7      RW Transmit Packet Buffer Size
TXPBTHRESH  0x04950 +0x04*0..7      RW Tx Packet Buffer Threshold
VFTA        0x0A000 +0x04*0..127    RW VLAN Filter Table Array
QPRDC       0x01430 +0x40*0..15     RC Queue Packets Received Drop Count
FCRTH       0x03260 +0x40*0..7      RW Flow Control Receive Threshold High
]],
   inherit = "gbl",
   rxq = [[
DCA_RXCTRL  0x0100C +0x40*0..63     RW Rx DCA Control Register
DCA_RXCTRL  0x0D00C +0x40*64..127   RW Rx DCA Control Register
SRRCTL      0x01014 +0x40*0..63     RW Split Receive Control Registers
SRRCTL      0x0D014 +0x40*64..127   RW Split Receive Control Registers
RDBAL       0x01000 +0x40*0..63     RW Receive Descriptor Base Address Low
RDBAL       0x0D000 +0x40*64..127   RW Receive Descriptor Base Address Low
RDBAH       0x01004 +0x40*0..63     RW Receive Descriptor Base Address High
RDBAH       0x0D004 +0x40*64..127   RW Receive Descriptor Base Address High
RDLEN       0x01008 +0x40*0..63     RW Receive Descriptor Length
RDLEN       0x0D008 +0x40*64..127   RW Receive Descriptor Length
RDH         0x01010 +0x40*0..63     RO Receive Descriptor Head
RDH         0x0D010 +0x40*64..127   RO Receive Descriptor Head
RDT         0x01018 +0x40*0..63     RW Receive Descriptor Tail
RDT         0x0D018 +0x40*64..127   RW Receive Descriptor Tail
RXDCTL      0x01028 +0x40*0..63     RW Receive Descriptor Control
RXDCTL      0x0D028 +0x40*64..127   RW Receive Descriptor Control
]],
   singleton = [[
AUTOC       0x042A0 -               RW Auto Negotiation Control
AUTOC2      0x042A8 -               RW Auto Negotiation Control 2
DMATXCTL    0x04A80 -               RW DMA Tx Control
DTXMXSZRQ   0x08100 -               RW DMA Tx Map Allow Size Requests
EEC         0x10010 -               RW EEPROM/Flash Control Register
EIMC        0x00888 -               RW Extended Interrupt Mask Clear
ERRBC       0x04008 -               RC Error Byte Count
FCCFG       0x03D00 -               RW Flow Control Configuration
FCTRL       0x05080 -               RW Filter Control
HLREG0      0x04240 -               RW MAC Core Control 0
ILLERRC     0x04004 -               RC Illegal Byte Error Count
LINKS       0x042A4 -               RO Link Status Register
MAXFRS      0x04268 -               RW Max Frame Size
MFLCN       0x04294 -               RW MAC Flow Control Register
MRQC        0x0EC80 -               RW Multiple Receive Queues Command Register
MTQC        0x08120 -               RW Multiple Transmit Queues Command Register
PFVTCTL     0x051B0 -               RW PF Virtual Control Register
PFQDE       0x02F04 -               RW PF Queue Drop Enable Register
PFDTXGSWC   0x08220 -               RW PF DMA Tx General Switch Control
RDRXCTL     0x02F00 -               RW Receive DMA Control Register
RTRPCS      0x02430 -               RW DCB Receive Packet plane Control and Status
RTTDCS      0x04900 -               RW DCB Transmit Descriptor Plane Control and Status
RTTPCS      0x0CD00 -               RW DCB Transmit Packet Plane Control and Status
RTRUP2TC    0x03020 -            RW DCB Receive Use rPriority to Traffic Class
RTTUP2TC    0x0C800 -            RW DCB Transmit User Priority to Traffic Class
RTTDQSEL    0x04904 -               RW DCB Transmit Descriptor Plane Queue Select
RTTDT1C     0x04908 -               RW DCB Transmit Descriptor Plane T1 Config
RTTBCNRC    0x04984 -            RW DCB Transmit Rate-Scheduler Config
RXCSUM      0x05000 -               RW Receive Checksum Control
RFCTL       0x05008 -               RW Receive Filter Control Register
RXCTRL      0x03000 -               RW Receive Control
RXDGPC      0x02F50 -               RC DMA Good Rx Packet Counter
TXDGPC      0x087A0 -               RC DMA Good Tx Packet Counter
RXDSTATCTRL 0x02F40 -               RW Rx DMA Statistic Counter Control
RUC         0x040A4 -               RC Receive Undersize Count
RFC         0x040A8 -               RC Receive Fragment Count
ROC         0x040AC -               RC Receive Oversize Count
RJC         0x040B0 -               RC Receive Jabber Count
SWSM        0x10140 -               RW Software Semaphore
VLNCTRL     0x05088 -               RW VLAN Control Register
ILLERRC     0x04004 -               RC Illegal Byte Error Count
ERRBC       0x04008 -               RC Error Byte Count
GORC64      0x04088 -               RC64 Good Octets Received Count 64-bit
GOTC64      0x04090 -               RC64 Good Octets Transmitted Count 64-bit
RUC         0x040A4 -               RC Receive Undersize Count
RFC         0x040A8 -               RC Receive Fragment Count
ROC         0x040AC -               RC Receive Oversize Count
RJC         0x040B0 -               RC Receive Jabber Count
GORCL       0x04088 -               RC Good Octets Received Count Low
GOTCL       0x04090 -               RC Good Octets Transmitted Count Low
]],
   txq = [[
DCA_TXCTRL  0x0600C +0x40*0..127    RW Tx DCA Control Register
TDBAL       0x06000 +0x40*0..127    RW Transmit Descriptor Base Address Low
TDBAH       0x06004 +0x40*0..127    RW Transmit Descriptor Base Address High
TDLEN       0x06008 +0x40*0..127    RW Transmit Descriptor Length
TDH         0x06010 +0x40*0..127    RW Transmit Descriptor Head
TDT         0x06018 +0x40*0..127    RW Transmit Descriptor Tail
TXDCTL      0x06028 +0x40*0..127    RW Transmit Descriptor Control
TDWBAL      0x06038 +0x40*0..127    RW Tx Descriptor Completion Write Back Address Low
TDWBAH      0x0603C +0x40*0..127    RW Tx Descriptor Completion Write Back Address High
]]
}
reg['1000BaseX'] = {
   array = [[
ALLRXDCTL   0x0c028 +0x40*0..7      RW Re Descriptor Control Queue
RAL64       0x05400 +0x08*0..15     RW64 Receive Address Low
RAL         0x05400 +0x08*0..15     RW Receive Address Low
RAH         0x05404 +0x08*0..15     RW Receive Address High
]],
   inherit = "gbl",
   rxq = [[
RDBAL       0x0c000 +0x40*0..7      RW Rx Descriptor Base low
RDBAH       0x0c004 +0x40*0..7      RW Rx Descriptor Base High
RDLEN       0x0c008 +0x40*0..7      RW Rx Descriptor Ring Length
RDH         0x0c010 +0x40*0..7      RO Rx Descriptor Head
RDT         0x0c018 +0x40*0..7      RW Rx Descriptor Tail
RXDCTL      0x0c028 +0x40*0..7      RW Re Descriptor Control Queue
RXCTL       0x0c014 +0x40*0..7      RW RX DCA CTRL Register Queue
SRRCTL      0x0c00c +0x40*0..7      RW Split and Replication Receive Control
]],
   singleton = [[
ALGNERRC  0x04004 -                 RC Alignment Error Count
RXERRC    0x0400C -                 RC RX Error Count
RLEC      0x04040 -                 RC Receive Length Error Count
CRCERRS   0x04000 -                 RC CRC Error Count
MPC       0x04010 -                 RC Missed Packets Count
MRQC      0x05818 -                 RW Multiple Receive Queues Command Register
EEER      0x00E30 -                 RW Energy Efficient Ethernet (EEE) Register
EIMC      0x01528 -                 RW Extended Interrupt Mask Clear
SWSM      0x05b50 -                 RW Software Semaphore
MANC      0x05820 -                 RW Management Control
MDIC      0x00020 -                 RW MDI Control
MDICNFG   0x00E04 -                 RW MDI Configuration
RLPML     0x05004 -                 RW Receive Long packet maximal length
RPTHC     0x04104 -                 RC Rx Packets to host count
SW_FW_SYNC 0x05b5c -                RW Software Firmware Synchronization
TCTL      0x00400 -                 RW TX Control
TCTL_EXT  0x00400 -                 RW Extended TX Control
ALGNERRC  0x04004 -                 RC Alignment Error - R/clr
RXERRC    0x0400C -                 RC RX Error - R/clr
MPC       0x04010 -                 RC Missed Packets - R/clr
ECOL      0x04018 -                 RC Excessive Collisions - R/clr
LATECOL   0x0401C -                 RC Late Collisions - R/clr
RLEC      0x04040 -                 RC Receive Length Error - R/clr
GORCL     0x04088 -                 RC Good Octets Received - R/clr
GORCH     0x0408C -                 RC Good Octets Received - R/clr
GOTCL     0x04090 -                 RC Good Octets Transmitted - R/clr
GOTCH     0x04094 -                 RC Good Octets Transmitted - R/clr
RNBC      0x040A0 -                 RC Receive No Buffers Count - R/clr
]],
   txq = [[
TDBAL  0xe000 +0x40*0..7            RW Tx Descriptor Base Low
TDBAH  0xe004 +0x40*0..7            RW Tx Descriptor Base High
TDLEN  0xe008 +0x40*0..7            RW Tx Descriptor Ring Length
TDH    0xe010 +0x40*0..7            RO Tx Descriptor Head
TDT    0xe018 +0x40*0..7            RW Tx Descriptor Tail
TXDCTL 0xe028 +0x40*0..7            RW Tx Descriptor Control Queue
TXCTL  0xe014 +0x40*0..7            RW Tx DCA CTRL Register Queue
]]
}
reg.i210 = {
   array = [[
RQDPC       0x0C030 +0x40*0..4      RC Receive Queue Drop Packet Count
TQDPC       0x0E030 +0x40*0..4      RC Transmit Queue Drop Packet Count
PQGPRC      0x10010 +0x100*0..4     RC Per Queue Good Packets Received Count
PQGPTC      0x10014 +0x100*0..4     RC Per Queue Good Packets Transmitted Count
PQGORC      0x10018 +0x100*0..4     RC Per Queue Good Octets Received Count
PQGOTC      0x10034 +0x100*0..4     RC Per Queue Octets Transmitted Count
PQMPRC      0x10038 +0x100*0..4     RC Per Queue Multicast Packets Received
]],
   inherit = "1000BaseX",
   singleton = [[
EEMNGCTL  0x12030 -            RW Manageability EEPROM-Mode Control Register
EEC       0x12010 -            RW EEPROM-Mode Control Register
]]
}
reg.i350 = {
   array = [[
RQDPC       0x0C030 +0x40*0..7      RCR Receive Queue Drop Packet Count
TQDPC       0x0E030 +0x40*0..7      RCR Transmit Queue Drop Packet Count
PQGPRC      0x10010 +0x100*0..7     RCR Per Queue Good Packets Received Count
PQGPTC      0x10014 +0x100*0..7     RCR Per Queue Good Packets Transmitted Count
PQGORC      0x10018 +0x100*0..7     RCR Per Queue Good Octets Received Count
PQGOTC      0x10034 +0x100*0..7     RCR Per Queue Octets Transmitted Count
PQMPRC      0x10038 +0x100*0..7     RCR Per Queue Multicast Packets Received
]],
   inherit = "1000BaseX",
   singleton = [[
EEMNGCTL  0x01010 -            RW Manageability EEPROM-Mode Control Register
EEC       0x00010 -            RW EEPROM-Mode Control Register
]]
}

Intel = {
   config = {
      pciaddr = {required=true},
      ndescriptors = {default=2048},
      vmdq = {default=false},
      macaddr = {},
      poolnum = {default=0},
      vlan = {},
      mirror = {},
      rxcounter = {},
      txcounter = {},
      rate_limit = {default=0},
      priority = {default=1.0},
      txq = {default=0},
      rxq = {default=0},
      mtu = {default=9014},
      linkup_wait = {default=120},
      wait_for_link = {default=false},
      master_stats = {default=true},
      run_stats = {default=false}
   },
   shm = {
      mtu    = {counter},
      txdrop = {counter}
   }
}
Intel1g = setmetatable({}, {__index = Intel })
Intel82599 = setmetatable({}, {__index = Intel})
byPciID = {
  [0x1521] = { registers = "i350", driver = Intel1g, max_q = 8 },
  [0x1533] = { registers = "i210", driver = Intel1g, max_q = 4 },
  [0x157b] = { registers = "i210", driver = Intel1g, max_q = 4 },
  [0x10fb] = { registers = "82599ES", driver = Intel82599, max_q = 16 }
}

-- The `driver' variable is used as a reference to the driver class in
-- order to interchangably use NIC drivers.
driver = Intel

function Intel:new (conf)
   local self = {
      r = {},
      pciaddress = conf.pciaddr,
      path = pci.path(conf.pciaddr),
      -- falling back to defaults for selftest bypassing config.app
      ndesc = conf.ndescriptors or self.config.ndescriptors.default,
      txq = conf.txq,
      rxq = conf.rxq,
      mtu = conf.mtu or self.config.mtu.default,
      linkup_wait = conf.linkup_wait or self.config.linkup_wait.default,
      wait_for_link = conf.wait_for_link,
      vmdq = conf.vmdq,
      poolnum = conf.poolnum,
      macaddr = conf.macaddr,
      vlan = conf.vlan,
      want_mirror = conf.mirror,
      rxcounter = conf.rxcounter,
      txcounter = conf.txcounter,
      rate_limit = conf.rate_limit,
      priority = conf.priority
   }

   local vendor = lib.firstline(self.path .. "/vendor")
   local device = lib.firstline(self.path .. "/device")
   local byid = byPciID[tonumber(device)]
   assert(vendor == '0x8086', "unsupported nic")
   assert(byid, "unsupported intel nic")
   self = setmetatable(self, { __index = byid.driver})

   self.max_q = byid.max_q

   -- VMDq checks
   if self.vmdq then
      assert(byid.driver == Intel82599, "VMDq only supported on 82599")
      assert(self.macaddr, "MAC address must be set in VMDq mode")

      -- for VMDq, make rxq/txq relative to the pool number
      assert(self.rxq >= 0 and self.rxq < 2, "rxqueue must be in 0..1")
      self.rxq = self.rxq + 2 * self.poolnum
      assert(self.txq >= 0 and self.txq < 1, "txqueue must be in 0..1")
      self.txq = self.txq + 2 * self.poolnum

      -- max queue number is different in VMDq mode
      self.max_q = 128

      if self.driver == "Intel82599" then
         assert(self.poolnum < 64,
                "Pool overflow: Intel 82599 supports up to 64 VMDq pools")
      elseif self.driver == "Intel1g" then
         assert(self.poolnum < 8,
                "Pool overflow: Intel i350 supports up to 8 VMDq pools")
      end
   else
      assert(not self.macaddr, "VMDq must be set to use MAC address")
      assert(not self.mirror, "VMDq must be set to specify mirroring rules")
   end

   -- Setup device access
   self.base, self.fd = pci.map_pci_memory_unlocked(self.pciaddress, 0)
   self.master = self.fd:flock("ex, nb")

   self:load_registers(byid.registers)

   self:init()
   self.fd:flock("sh")
   if self.vmdq then
      self:check_vmdq()
   end
   self:init_tx_q()
   self:init_rx_q()
   self:set_MAC()
   self:set_VLAN()
   self:set_mirror()
   self:set_rxstats()
   self:set_txstats()
   self:set_tx_rate()

   -- Initialize per app statistics
   counter.set(self.shm.mtu, self.mtu)

   -- Figure out if we are supposed to collect device statistics
   self.run_stats = conf.run_stats or (self.master and conf.master_stats)

   -- Expose per-device statistics from master
   if self.run_stats then
      local frame = {
         dtime     = {counter, C.get_unix_time()},
         speed     = {counter},
         status    = {counter, 2}, -- Link down
         promisc   = {counter},
         macaddr   = {counter, self.r.RAL64[0]:bits(0,48)},
         rxbytes   = {counter},
         rxpackets = {counter},
         rxmcast   = {counter},
         rxbcast   = {counter},
         rxdrop    = {counter},
         rxerrors  = {counter},
         txbytes   = {counter},
         txpackets = {counter},
         txmcast   = {counter},
         txbcast   = {counter},
         txdrop    = {counter},
         txerrors  = {counter},
         rxdmapackets = {counter}
      }
      self:init_queue_stats(frame)
      self.stats = shm.create_frame("pci/"..self.pciaddress, frame)
      self.sync_timer = lib.throttle(0.01)
   end

   return self
end

function Intel:disable_interrupts ()
   self.r.EIMC(0xffffffff)
end

rxdesc_t = ffi.typeof([[
struct {
   uint64_t address;
   uint16_t length, cksum;
   uint8_t status, errors;
   uint16_t vlan;
} __attribute__((packed))
]])

function Intel:init_rx_q ()
   if not self.rxq then return end
   assert((self.rxq >=0) and (self.rxq < self.max_q),
   "rxqueue must be in 0.." .. self.max_q-1)
   assert((self.ndesc %128) == 0,
   "ndesc must be a multiple of 128 (for Rx only)")  -- see 7.1.4.5

   self.rxqueue = ffi.new("struct packet *[?]", self.ndesc)
   self.rdh = 0
   self.rdt = 0
   -- setup 4.5.9
   local rxdesc_ring_t = ffi.typeof("$[$]", rxdesc_t, self.ndesc)
   self.rxdesc = ffi.cast(ffi.typeof("$&", rxdesc_ring_t),
   memory.dma_alloc(ffi.sizeof(rxdesc_ring_t)))

   -- VMDq pool state (4.6.10.1.4)
   if self.vmdq then
      -- packet splitting none, enable 2 RSS queues per pool
      self.r.PSRTYPE[self.poolnum](bits { RQPL=29 })
      -- multicast promiscuous, broadcast accept, accept untagged pkts
      self.r.PFVML2FLT[self.poolnum]:set(bits { MPE=28, BAM=27, AUPE=24 })
   end

   -- Receive state
   self.r.RDBAL(tophysical(self.rxdesc) % 2^32)
   self.r.RDBAH(tophysical(self.rxdesc) / 2^32)
   self.r.RDLEN(self.ndesc * ffi.sizeof(rxdesc_t))

   for i = 0, self.ndesc-1 do
      local p= packet.allocate()
      self.rxqueue[i]= p
      self.rxdesc[i].address= tophysical(p.data)
      self.rxdesc[i].status= 0
   end
   self.r.SRRCTL(0)
   self.r.SRRCTL:set(bits {
      -- Set packet buff size to 0b1010 kbytes
      BSIZEPACKET1 = 1,
      BSIZEPACKET3 = 3,
      -- Drop packets when no descriptors
      Drop_En = self:offset("SRRCTL", "Drop_En")
   })
   self:lock_sw_sem()

   -- enable VLAN tag stripping in VMDq mode
   if self.vmdq then
      self.r.RXDCTL:set(bits { VME = 30 })
   end

   self.r.RXDCTL:set( bits { Enable = 25 })
   self.r.RXDCTL:wait( bits { Enable = 25 })
   C.full_memory_barrier()
   self.r.RDT(self.ndesc - 1)

   self:rss_tab_build()
   if self.driver == "Intel82599" then
      self.r.RXCTRL:set(bits{ RXEN=0 })
      self.r.DCA_RXCTRL:clr(bits{RxCTRL=12})
      if self.vmdq then
         self.r.PFVFRE[math.floor(self.poolnum/32)]:set(bits{VFRE=self.poolnum%32})
      end
   elseif self.driver == "Intel1g" then
      self.r.RCTL:set(bits { RXEN = 1 })
   end
   self:unlock_sw_sem()
end
function Intel:init_tx_q ()                               -- 4.5.10
   if not self.txq then return end
   assert((self.txq >=0) and (self.txq < self.max_q),
   "txqueue must be in 0.." .. self.max_q-1)
   self.tdh = 0
   self.tdt = 0
   self.txqueue = ffi.new("struct packet *[?]", self.ndesc)

   -- 7.2.2.3
   local txdesc_t = ffi.typeof("struct { uint64_t address, flags; }")
   local txdesc_ring_t = ffi.typeof("$[$]", txdesc_t, self.ndesc)
   self.txdesc = ffi.cast(ffi.typeof("$&", txdesc_ring_t),
   memory.dma_alloc(ffi.sizeof(txdesc_ring_t)))

   -- Transmit state variables 7.2.2.3.4 / 7.2.2.3.5
   self.txdesc_flags = bits({
      dtyp0=20,
      dtyp1=21,
      eop=24,
      ifcs=25,
      dext=29
   })

   -- Initialize transmit queue
   self.r.TDBAL(tophysical(self.txdesc) % 2^32)
   self.r.TDBAH(tophysical(self.txdesc) / 2^32)
   self.r.TDLEN(self.ndesc * ffi.sizeof(txdesc_t))

   -- for VMDq need some additional pool configs
   if self.vmdq then
      self.r.RTTDQSEL(self.poolnum)
      -- set baseline value for credit refill for tx bandwidth algorithm
      self.r.RTTDT1C(0x80)
      -- enables packet Tx for this VF's pool
      self.r.PFVFTE[math.floor(self.poolnum/32)]:set(bits{VFTE=self.poolnum%32})
   end

   if self.r.DMATXCTL then
      self.r.DMATXCTL:set(bits { TE = 0 })
      self.r.TXDCTL:set(bits{SWFLSH=26, hthresh=8} + 32)
   end

   self.r.TXDCTL:set(bits { WTHRESH = 16, ENABLE = 25 })
   self.r.TXDCTL:wait(bits { ENABLE = 25 })

   if self.driver == "Intel1g" then
      self.r.TCTL:set(bits { TxEnable = 1 })
   end
end
function Intel:load_registers(key)
   local v = reg[key]
   if v.inherit then self:load_registers(v.inherit) end
   if v.singleton then register.define(v.singleton, self.r, self.base) end
   if v.array then register.define_array(v.array, self.r, self.base) end
   if v.txq and self.txq then
      register.define(v.txq, self.r, self.base, self.txq)
   end
   if v.rxq and self.rxq then
      register.define(v.rxq, self.r, self.base, self.rxq)
   end
end
function Intel:lock_sw_sem()
   for i=1,50,1 do
      if band(self.r.SWSM(), 0x01) == 1 then
         C.usleep(100000)
      else
         return
      end
   end
   error("Couldn't get lock")
end
function Intel:offset(reg, key)
   return self.offsets[reg][key]
end
function Intel:push ()
   if not self.txq then return end
   local li = self.input["input"]
   if li == nil then return end
--   assert(li, "intel_mp:push: no input link")

   while not link.empty(li) and self:can_transmit() do
      local p = link.receive(li)
      -- NB: see comment in intel10g for why this is commented out,
      --     the rest of the loop body goes in an else branch
      --if p.length > self.mtu then
      --   packet.free(p)
      --   counter.add(self.shm.txdrop)
      --end
      self:transmit(p)
   end
   -- Reclaim transmit contexts
   local cursor = self.tdh
   self.tdh = self.r.TDH()  -- possible race condition, 7.2.2.4, check DD
   --C.full_memory_barrier()
   while cursor ~= self.tdh do
      if self.txqueue[cursor] then
         packet.free(self.txqueue[cursor])
         self.txqueue[cursor] = nil
      end
      cursor = self:ringnext(cursor)
   end
   self.r.TDT(self.tdt)

   -- same code as in pull, we repeat it in case this app only enables Tx
   if self.run_stats and self.sync_timer() then
      self:sync_stats()
   end
end

function Intel:pull ()
   if not self.rxq then return end
   local lo = self.output["output"]
   if lo == nil then return end
--   assert(lo, "intel_mp:pull: output link required")

   local pkts = 0
   while band(self.rxdesc[self.rdt].status, 0x01) == 1 and pkts < engine.pull_npackets do
      local p = self.rxqueue[self.rdt]
      p.length = self.rxdesc[self.rdt].length
      link.transmit(lo, p)

      local np = packet.allocate()
      self.rxqueue[self.rdt] = np
      self.rxdesc[self.rdt].address = tophysical(np.data)
      self.rxdesc[self.rdt].status = 0

      self.rdt = band(self.rdt + 1, self.ndesc-1)
      pkts = pkts + 1
   end
   -- This avoids RDT == RDH when every descriptor is available.
   self.r.RDT(band(self.rdt - 1, self.ndesc-1))

   -- Sync device statistics if we are master.
   if self.run_stats and self.sync_timer() then
      self:sync_stats()
   end
end

function Intel:unlock_sw_sem()
   self.r.SWSM:clr(bits { SMBI = 0 })
end

function Intel:ringnext (index)
   return band(index+1, self.ndesc-1)
end

function Intel:can_transmit ()
   return self:ringnext(self.tdt) ~= self.tdh
end

function Intel:transmit (p)
   self.txdesc[self.tdt].address = tophysical(p.data)
   self.txdesc[self.tdt].flags =
      bor(p.length, self.txdesc_flags, lshift(p.length+0ULL, 46))
   self.txqueue[self.tdt] = p
   self.tdt = self:ringnext(self.tdt)
end

function Intel:rss_enable ()
   -- set default q = 0 on i350,i210 noop on 82599
   self.r.MRQC(0)
   self.r.MRQC:set(bits { RSS = self:offset("MRQC", "RSS") })
   -- Enable all RSS hash on all available input keys
   self.r.MRQC:set(bits {
      TcpIPv4 = 16, IPv4 = 17, IPv6 = 20,
      TcpIPv6 = 21, UdpIPv4 = 22, UdpIPv6 = 23
   })
   self:rss_tab({0})
   self:rss_key()
end
function Intel:rss_key ()
   for i=0,9,1 do
      self.r.RSSRK[i](math.random(2^32))
   end
end

-- Set RSS redirection table, which has 64 * 2 entries which contain
-- RSS indices, the lower 4 bits (or fewer) of which are used to
-- select an RSS queue.
--
-- Also returns the current state of the redirection table
function Intel:rss_tab (newtab)
   local current = {}
   local pos = 0

   for i=0,31,1 do
      for j=0,3,1 do
         current[self.r.RETA[i]:byte(j)] = 1
         if newtab ~= nil then
            local new = newtab[pos%#newtab+1]
            self.r.RETA[i]:byte(j, new)
         end
         pos = pos + 1
      end
   end
   return current
end
function Intel:rss_tab_build ()
   local tab = {}
   for i=0,self.max_q-1,1 do
      if band(self.r.ALLRXDCTL[i](), bits { Enable = 25 }) > 0 then
         table.insert(tab, i)
      end
   end
   self:rss_tab(tab)
end
function Intel:stop ()
   if self.rxq then
      -- 4.5.9
      -- PBRWAC.PBE is mentioned in i350 only, not implemented here.
      self.r.RXDCTL:clr(bits { ENABLE = 25 })
      self.r.RXDCTL:wait(bits { ENABLE = 25 }, 0)
      -- removing the queue from rss first would be better but this
      -- is easier :(, we are going to throw the packets away anyway
      self:lock_sw_sem()
      self:rss_tab_build()
      self:unlock_sw_sem()
      C.usleep(100)
      -- TODO
      -- zero rxd.status, set rdt = rdh - 1
      -- poll for RXMEMWRAP to loop twice or buffer to empty
      self.r.RDT(0)
      self.r.RDH(0)
      self.r.RDBAL(0)
      self.r.RDBAH(0)
      for i = 0, self.ndesc-1 do
         if self.rxqueue[i] then
            packet.free(self.rxqueue[i])
            self.rxqueue[i] = nil
         end
      end
   end
   if self.txq then
      --TODO
      --TXDCTL[n].SWFLSH and wait
      --wait until tdh == tdt
      --wait on rxd[tdh].status = dd
      self:discard_unsent_packets()
      self.r.TXDCTL(0)
      self.r.TXDCTL:wait(bits { ENABLE = 25 }, 0)
   end
   if self.vmdq then
      self:unset_MAC()
      self:unset_VLAN()
      self:unset_mirror()
   end
   self:unset_tx_rate()
   if self.fd:flock("nb, ex") then
      self.r.CTRL:clr( bits { SETLINKUP = 6 } )
      --self.r.CTRL_EXT:clear( bits { DriverLoaded = 28 })
      pci.set_bus_master(self.pciaddress, false)
      pci.close_pci_resource(self.fd, self.base)
   end
   if self.run_stats then
      shm.delete_frame(self.stats)
   end
end

function Intel:discard_unsent_packets ()
   local old_tdt = self.tdt
   self.tdt = self.r.TDT()
   self.tdh = self.r.TDH()
   self.r.TDT(self.tdh)
   while old_tdt ~= self.tdh do
      old_tdt = band(old_tdt - 1, self.ndesc - 1)
      packet.free(self.txqueue[old_tdt])
      self.txdesc[old_tdt].address = -1
      self.txdesc[old_tdt].flags = 0
   end
   self.tdt = self.tdh
end

function Intel:sync_stats ()
   local set, stats = counter.set, self.stats
   set(stats.speed, self:link_speed())
   set(stats.status, self:link_status() and 1 or 2)
   set(stats.promisc, self:promisc() and 1 or 2)
   set(stats.rxbytes, self:rxbytes())
   set(stats.rxpackets, self:rxpackets())
   set(stats.rxmcast, self:rxmcast())
   set(stats.rxbcast, self:rxbcast())
   set(stats.rxdrop, self:rxdrop())
   set(stats.rxerrors, self:rxerrors())
   set(stats.txbytes, self:txbytes())
   set(stats.txpackets, self:txpackets())
   set(stats.txmcast, self:txmcast())
   set(stats.txbcast, self:txbcast())
   set(stats.txdrop, self:txdrop())
   set(stats.txerrors, self:txerrors())
   set(stats.rxdmapackets, self:rxdmapackets())
   for idx = 1, #self.queue_stats, 2 do
      local name, register = self.queue_stats[idx], self.queue_stats[idx+1]
      set(stats[name], register())
   end
end

-- set MAC address (4.6.10.1.4)
function Intel:set_MAC ()
   if not self.macaddr then return end
   local mac = macaddress:new(self.macaddr)
   self:add_receive_MAC(mac)
   self:set_transmit_MAC(mac)
end

function Intel:add_receive_MAC (mac)
   local mac_index

   -- scan to see if the MAC is already recorded or find the
   -- first free MAC index
   for idx=1, self.max_mac_addr do
      local valid = self.r.RAH[idx]:bits(31, 1)

      if valid == 0 then
         mac_index = idx
         self.r.RAL[mac_index](mac:subbits(0,32))
         self.r.RAH[mac_index](bits({AV=31},mac:subbits(32,48)))
         break
      else
         if self.r.RAL[idx]() == mac:subbits(0, 32) and
            self.r.RAH[idx]:bits(0, 15) == mac:subbits(32, 48) then
            mac_index = idx
            break
         end
      end
   end

   assert(mac_index, "Max number of MAC addresses reached")

   -- associate MAC with the app's VMDq pool
   self:enable_MAC_for_pool(mac_index)
end

function Intel:set_transmit_MAC (mac)
   local poolnum = self.poolnum or 0
   self.r.PFVFSPOOF[math.floor(poolnum/8)]:set(bits{MACAS=poolnum%8})
end

-- set VLAN for the driver instance
function Intel:set_VLAN ()
   local vlan = self.vlan
   if not vlan then return end
   assert(vlan>=0 and vlan<4096, "bad VLAN number")
   self:add_receive_VLAN(vlan)
   self:set_tag_VLAN(vlan)
end

function Intel:add_receive_VLAN (vlan)
   assert(vlan>=0 and vlan<4096, "bad VLAN number")
   local vlan_index, first_empty

   -- scan to see if the VLAN is already recorded or find the
   -- first free VLAN index
   for idx=0, self.max_vlan-1 do
      local valid = self.r.PFVLVF[idx]:bits(31, 1)

      if valid == 0 then
         if not first_empty then
            first_empty = idx
         end
      elseif self.r.PFVLVF[idx]:bits(0, 11) == vlan then
         vlan_index = idx
         break
      end
   end

   if not vlan_index and first_empty then
      vlan_index = first_empty
      self.r.VFTA[math.floor(vlan/32)]:set(bits{Ena=vlan%32})
      self.r.PFVLVF[vlan_index](bits({Vl_En=31},vlan))
   end

   assert(vlan_index, "Max number of VLAN IDs reached")

   self.r.PFVLVFB[2*vlan_index + math.floor(self.poolnum/32)]
      :set(bits{PoolEna=self.poolnum%32})
end

function Intel:set_tag_VLAN (vlan)
   local poolnum = self.poolnum or 0
   self.r.PFVFSPOOF[math.floor(poolnum/8)]:set(bits{VLANAS=poolnum%8+8})
   -- set Port VLAN ID & VLANA to always add VLAN tag
   -- TODO: on i350 it's the VMVIR register
   self.r.PFVMVIR[poolnum](bits({VLANA=30}, vlan))
end

function Intel:unset_VLAN ()
   local r = self.r
   local offs, mask = math.floor(self.poolnum/32), bits{PoolEna=self.poolnum%32}

   for vln_ndx = 0, 63 do
      if band(r.PFVLVFB[2*vln_ndx+offs](), mask) ~= 0 then
         -- found a vlan this pool belongs to
         r.PFVLVFB[2*vln_ndx+offs]:clr(mask)
         if r.PFVLVFB[2*vln_ndx+offs]() == 0 then
            -- it was the last pool of the vlan
            local vlan = tonumber(band(r.PFVLVF[vln_ndx](), 0xFFF))
            r.PFVLVF[vln_ndx](0x0)
            r.VFTA[math.floor(vlan/32)]:clr(bits{Ena=vlan%32})
         end
      end
   end
end

function Intel:set_mirror ()
   if not self.want_mirror then return end
   want_mirror = self.want_mirror

   -- set MAC promiscuous
   self.r.PFVML2FLT[self.poolnum]:set(bits{
      AUPE=24, ROMPE=25, ROPE=26, BAM=27, MPE=28})

   -- pick one of a limited (4) number of mirroring rules
   for idx=0, 3 do
      -- check if no mirroring enable bits (3:0) are set
      -- (i.e., this rule is unused and available)
      if self.r.PFMRCTL[idx]:bits(0, 4) == 0 then
         mirror_ndx = idx
         break
      -- there's already a rule for this pool, overwrite
      elseif self.r.PFMRCTL[idx]:bits(8, 5) == self.poolnum then
         mirror_ndx = idx
         break
      end
   end

   assert(mirror_ndx, "Max number of mirroring rules reached")

   local mirror_rule = 0ULL

   -- mirror some or all pools
   if want_mirror.pool then
      mirror_rule = bor(bits{VPME=0}, mirror_rule)
      if want_mirror.pool == true then -- mirror all pools
         self.r.PFMRVM[mirror_ndx](0xFFFFFFFF)
         self.r.PFMRVM[mirror_ndx+4](0xFFFFFFFF)
      elseif type(want_mirror.pool) == 'table' then
         local bm0 = self.r.PFMRVM[mirror_ndx]()
         local bm1 = self.r.PFMRVM[mirror_ndx+4]()
         for _, pool in ipairs(want_mirror.pool) do
            if pool <= 64 then
               bm0 = bor(lshift(1, pool), bm0)
            else
               bm1 = bor(lshift(1, pool-64), bm1)
            end
         end
         self.r.PFMRVM[mirror_ndx](bm0)
         self.r.PFMRVM[mirror_ndx+4](bm1)
      end
   end

   -- mirror hardware port
   if want_mirror.port then
      if want_mirror.port == true or
            want_mirror.port == 'in' or
            want_mirror.port == 'inout' then
         mirror_rule = bor(bits{UPME=1}, mirror_rule)
      end
      if want_mirror.port == true or
            want_mirror.port == 'out' or
            want_mirror.port == 'inout' then
         mirror_rule = bor(bits{DPME=2}, mirror_rule)
      end
   end

   -- TODO: implement VLAN mirroring

   if mirror_rule ~= 0 then
      mirror_rule = bor(mirror_rule, lshift(self.poolnum, 8))
      self.r.PFMRCTL[mirror_ndx]:set(mirror_rule)
   end
end

function Intel:unset_mirror ()
   for rule_i = 0, 3 do
      -- check if any mirror rule points here
      local rule_dest = band(bit.rshift(self.r.PFMRCTL[rule_i](), 8), 63)
      local bits = band(self.r.PFMRCTL[rule_i](), 0x07)
      if bits ~= 0 and rule_dest == self.poolnum then
         self.r.PFMRCTL[rule_i](0x0)     -- clear rule
         self.r.PFMRVLAN[rule_i](0x0)    -- clear VLANs mirrored
         self.r.PFMRVLAN[rule_i+4](0x0)
         self.r.PFMRVM[rule_i](0x0)      -- clear pools mirrored
         self.r.PFMRVM[rule_i+4](0x0)
      end
   end
end

function Intel:rxpackets () return self.r.GPRC()                 end
function Intel:txpackets () return self.r.GPTC()                 end
function Intel:rxmcast   () return self.r.MPRC() + self.r.BPRC() end
function Intel:rxbcast   () return self.r.BPRC()                 end
function Intel:txmcast   () return self.r.MPTC() + self.r.BPTC() end
function Intel:txbcast   () return self.r.BPTC()                 end

Intel1g.driver = "Intel1g"
Intel1g.offsets = {
    SRRCTL = {
       Drop_En = 31
    },
    MRQC = {
       RSS = 1
    }
}
Intel1g.max_mac_addr = 15
Intel1g.max_vlan = 8
function Intel1g:init_phy ()
   -- 4.3.1.4 PHY Reset
   self.r.MANC:wait(bits { BLK_Phy_Rst_On_IDE = 18 }, 0)

   -- 4.6.1  Acquiring Ownership Over a Shared Resource
   self:lock_fw_sem()
   self.r.SW_FW_SYNC:wait(bits { SW_PHY_SM = 1 }, 0)
   self.r.SW_FW_SYNC:set(bits { SW_PHY_SM = 1 })
   self:unlock_fw_sem()

   self.r.CTRL:set(bits { PHYreset = 31 })
   C.usleep(1*100)
   self.r.CTRL:clr(bits { PHYreset = 31 })

   -- 4.6.2 Releasing Ownership Over a Shared Resource
   self:lock_fw_sem()
   self.r.SW_FW_SYNC:clr(bits { SW_PHY_SM = 1 })
   self:unlock_fw_sem()

   self.r.EEMNGCTL:wait(bits { CFG_DONE0 = 18 })

   --[[
   self:lock_fw_sem()
   self.r.SW_FW_SYNC:wait(bits { SW_PHY_SM = 1}, 0)
   self.r.SW_FW_SYNC:set(bits { SW_PHY_SM = 1 })
   self:unlock_fw_sem()

   -- If you where going to configure the PHY to none defaults
   -- this is where you would do it

   self:lock_fw_sem()
   self.r.SW_FW_SYNC:clr(bits { SW_PHY_SM = 1 })
   self:unlock_fw_sem()
   ]]
end
function Intel1g:lock_fw_sem()
   self.r.SWSM:set(bits { SWESMBI = 1 })
   while band(self.r.SWSM(), 0x02) == 0 do
      self.r.SWSM:set(bits { SWESMBI = 1 })
   end
end
function Intel1g:unlock_fw_sem()
   self.r.SWSM:clr(bits { SWESMBI = 1 })
end
function Intel1g:init ()
   if not self.master then return end
   pci.unbind_device_from_linux(self.pciaddress)
   pci.set_bus_master(self.pciaddress, true)
   pci.disable_bus_master_cleanup(self.pciaddress)

   -- 4.5.3  Initialization Sequence
   self:disable_interrupts()
   -- 4.3.1 Software Reset (RST)
   self.r.CTRL(bits { RST = 26 })
   C.usleep(4*1000)
   self.r.EEC:wait(bits { Auto_RD = 9 })
   self.r.STATUS:wait(bits { PF_RST_DONE = 21 })
   self:disable_interrupts()                        -- 4.5.4

   -- use Internal PHY                             -- 8.2.5
   self.r.MDICNFG(0)
   self:init_phy()

   self:rss_enable()

   self.r.RCTL:clr(bits { RXEN = 1 })
   self.r.RCTL(bits {
      UPE = 3,       -- Unicast Promiscuous
      MPE = 4,       -- Mutlicast Promiscuous
      LPE = 5,       -- Long Packet Reception / Jumbos
      BAM = 15,      -- Broadcast Accept Mode
      SECRC = 26,    -- Strip ethernet CRC
   })

   self.r.CTRL:set(bits { SETLINKUP = 6 })
   self.r.CTRL_EXT:clr( bits { LinkMode0 = 22, LinkMode1 = 23} )
   self.r.CTRL_EXT:clr( bits { PowerDown = 20 } )
   self.r.CTRL_EXT:set( bits { AutoSpeedDetect = 12, DriverLoaded = 28 })
   self.r.RLPML(self.mtu + 4) -- mtu + crc
   self:unlock_sw_sem()
   for i=1, math.floor(self.linkup_wait/2) do
      if self:link_status() then break end
      if not self.wait_for_link then break end
      C.usleep(2000000)
   end
end

function Intel1g:link_status ()
   local mask = lshift(1, 1)
   return bit.band(self.r.STATUS(), mask) == mask
end
function Intel1g:link_speed ()
   return ({10000,100000,1000000,1000000})[1+bit.band(bit.rshift(self.r.STATUS(), 6),3)]
end
function Intel1g:promisc ()
   return band(self.r.RCTL(), lshift(1, 3)) ~= 0ULL
end
function Intel1g:rxbytes   () return self.r.GORCH()*2^32 + self.r.GORCL() end
function Intel1g:rxdrop    () return self.r.MPC() + self.r.RNBC()         end
function Intel1g:rxerrors  ()
   return self.r.CRCERRS() + self.r.RLEC()
      + self.r.RXERRC() + self.r.ALGNERRC()
end
function Intel1g:txbytes   () return self.r.GOTCH()*2^32 + self.r.GOTCL() end
function Intel1g:txdrop    () return self.r.ECOL()                        end
function Intel1g:txerrors  () return self.r.LATECOL()                     end
function Intel1g:rxdmapackets ()
   return self.r.RPTHC()
end

function Intel1g:init_queue_stats (frame)
   local perqregs = {
      rxdrops = "RQDPC",
      txdrops = "TQDPC",
      rxpackets = "PQGPRC",
      txpackets = "PQGPTC",
      rxbytes = "PQGORC",
      txbytes = "PQGOTC",
      rxmcast = "PQMPRC"
   }
   self.queue_stats = {}
   for i=0,self.max_q-1 do
      for k,v in pairs(perqregs) do
         local name = "q" .. i .. "_" .. k
         table.insert(self.queue_stats, name)
         table.insert(self.queue_stats, self.r[v][i])
         frame[name] = {counter}
      end
   end
end

function Intel1g:get_rxstats ()
   assert(self.rxq, "cannot retrieve rxstats without rxq")
   local frame = shm.open_frame("pci/"..self.pciaddress)
   local rxc   = self.rxq
   return {
      counter_id = rxc,
      packets = counter.read(frame["q"..rxc.."_rxpackets"]),
      dropped = counter.read(frame["q"..rxc.."_rxdrops"]),
      bytes = counter.read(frame["q"..rxc.."_rxbytes"])
   }
end

function Intel1g:get_txstats ()
   assert(self.txq, "cannot retrieve rxstats without txq")
   local frame = shm.open_frame("pci/"..self.pciaddress)
   local txc   = self.txq
   return {
      counter_id = txc,
      packets = counter.read(frame["q"..txc.."_txpackets"]),
      bytes = counter.read(frame["q"..txc.."_txbytes"])
   }
end

-- noop because 1g NICs have per-queue counters that aren't
-- configurable
function Intel1g:set_rxstats () return end
function Intel1g:set_txstats () return end

function Intel1g:check_vmdq ()
   error("unimplemented")
end
function Intel1g:vmdq_enable ()
   error("unimplemented")
end

function Intel1g:enable_MAC_for_pool(mac_index)
   self.r.RAH[mac_index]:set(bits { Ena = 18 + self.poolnum })
end

function Intel1g:unset_MAC ()
   local msk = bits { Ena = 18 + self.poolnum }
   for mac_index = 0, self.max_mac_addr do
      pf.r.RAH[mac_index]:clr(msk)
   end
end

function Intel1g:set_tx_rate () return end
function Intel1g:unset_tx_rate () return end

Intel82599.driver = "Intel82599"
Intel82599.offsets = {
   SRRCTL = {
      Drop_En = 28
   },
   MRQC = {
       RSS = 0
   }
}
Intel82599.max_mac_addr = 127
Intel82599.max_vlan = 64

-- 1010 -> 32 pools, 4 RSS queues each
-- 1011 -> 64 pools, 2 RSS queues each
Intel82599.mrqc_bits = 0xB

function Intel82599:link_status ()
   local mask = lshift(1, 30)
   return bit.band(self.r.LINKS(), mask) == mask
end
function Intel82599:link_speed ()
   local links = self.r.LINKS()
   local speed1, speed2 = lib.bitset(links, 29), lib.bitset(links, 28)
   return (speed1 and speed2 and 10000000000)    --  10 GbE
      or  (speed1 and not speed2 and 1000000000) --   1 GbE
      or  1000000                                -- 100 Mb/s
end
function Intel82599:promisc ()
   return band(self.r.FCTRL(), lshift(1, 9)) ~= 0ULL
end
function Intel82599:rxbytes  () return self.r.GORC64()   end
function Intel82599:rxdrop   () return self.r.QPRDC[0]() end
function Intel82599:rxerrors ()
   return self.r.CRCERRS() + self.r.ILLERRC() + self.r.ERRBC() +
      self.r.RUC() + self.r.RFC() + self.r.ROC() + self.r.RJC()
end
function Intel82599:txbytes   () return self.r.GOTC64() end
function Intel82599:txdrop    () return 0               end
function Intel82599:txerrors  () return 0               end
function Intel82599:rxdmapackets ()
   return self.r.RXDGPC()
end

function Intel82599:init_queue_stats (frame)
   local perqregs = {
      rxdrops = "QPRDC",
      rxpackets = "QPRC",
      txpackets = "QPTC",
      rxbytes = "QBRC64",
      txbytes = "QBTC64",
   }
   self.queue_stats = {}
   for i=0,15 do
      for k,v in pairs(perqregs) do
         local name = "q" .. i .. "_" .. k
         table.insert(self.queue_stats, name)
         table.insert(self.queue_stats, self.r[v][i])
         frame[name] = {counter}
      end
   end
end

function Intel82599:init ()
   if not self.master then return end
   pci.unbind_device_from_linux(self.pciaddress)
   pci.set_bus_master(self.pciaddress, true)
   pci.disable_bus_master_cleanup(self.pciaddress)

   for i=1,math.floor(self.linkup_wait/2) do
      self:disable_interrupts()
      local reset = bits{ LinkReset=3, DeviceReset=26 }
      self.r.CTRL(reset)
      C.usleep(1000)
      self.r.CTRL:wait(reset, 0)
      self.r.EEC:wait(bits{AutoreadDone=9})           -- 3.
      self.r.RDRXCTL:wait(bits{DMAInitDone=3})        -- 4.

      -- 4.6.4.2
      -- 3.7.4.2
      self.r.AUTOC:set(bits { LMS0 = 13, LMS1 = 14 })
      self.r.AUTOC2(0)
      self.r.AUTOC2:set(bits { tenG_PMA_PMD_Serial = 17 })
      self.r.AUTOC:set(bits{restart_AN=12})
      C.usleep(2000000)
      if self:link_status() then break end
      if not self.wait_for_link then break end
   end

   -- 4.6.7
   self.r.RXCTRL(0)                             -- disable receive
   self.r.RXDSTATCTRL(0x10) -- map all queues to RXDGPC
   for i=1,127 do -- preserve device MAC
      self.r.RAL[i](0)
      self.r.RAH[i](0)
   end
   for i=0,127 do
      self.r.PFUTA[i](0)
      self.r.VFTA[i](0)
      self.r.PFVLVFB[i](0)
      self.r.SAQF[i](0)
      self.r.DAQF[i](0)
      self.r.SDPQF[i](0)
      self.r.FTQF[i](0)
   end
   for i=0,63 do
      self.r.PFVLVF[i](0)
      self.r.MPSAR[i](0)
   end
   for i=0,255 do
      self.r.MPSAR[i](0)
   end

   self.r.FCTRL:set(bits {
      MPE = 8,
      UPE = 9,
      BAM = 10
   })

   self.r.VLNCTRL(0x8100)                    -- explicity set default
   self.r.RXCSUM(0)                          -- turn off all checksum offload

   self.r.RXPBSIZE[0]:bits(10,19, 0x200)
   self.r.TXPBSIZE[0]:bits(10,19, 0xA0)
   self.r.TXPBTHRESH[0](0xA0)
   for i=1,7 do
      self.r.RXPBSIZE[i]:bits(10,19, 0)
      self.r.TXPBSIZE[i]:bits(10,19, 0)
      self.r.TXPBTHRESH[i](0)
   end

   self.r.MTQC(0)
   self.r.PFVTCTL(0)
   self.r.RTRUP2TC(0)
   self.r.RTTUP2TC(0)
   self.r.DTXMXSZRQ(0xFFF)

   self.r.MFLCN(bits{RFCE=3})
   self.r.FCCFG(bits{TFCE=3})

   for i=0,7 do
      self.r.RTTDT2C[i](0)
      self.r.RTTPT2C[i](0)
      self.r.RTRPT4C[i](0)
   end

   self.r.HLREG0(bits{
      TXCRCEN=0, RXCRCSTRP=1, JUMBOEN=2, rsv2=3,
      TXPADEN=10, rsvd3=11, rsvd4=13, MDCSPD=16
   })
   self.r.MAXFRS(lshift(self.mtu + 4, 16)) -- mtu + crc

   self.r.RDRXCTL(bits { CRCStrip = 1 })
   self.r.CTRL_EXT:set(bits {NS_DIS = 1})

   self:rss_enable()

   if self.vmdq then
      self:vmdq_enable()
   end

   self:unlock_sw_sem()
end

-- helper method for checking that the main process used the same
-- VMDq setting if this is a worker process (noop on main)
function Intel82599:check_vmdq ()
   if not self.master then
      if self.vmdq then
         assert(self.r.MRQC:bits(0, 4) == self.mrqc_bits,
                "VMDq not set by the main process for this NIC")
      else
         assert(self.r.MRQC:bits(0, 4) ~= self.mrqc_bits,
                "VMDq was set by the main process for this NIC")
      end
   end
end

-- enable VMDq mode, see 4.6.10.1
-- follows the configuration flow in 4.6.11.3.3
-- (should only be called on the master instance)
function Intel82599:vmdq_enable ()
   -- must be set prior to setting MTQC (7.2.1.2.1)
   self.r.RTTDCS:set(bits { ARBDIS=6 })

   self.r.MRQC:bits(0, 4, self.mrqc_bits)

   -- TODO: not sure this is needed, but it's in intel10g
   -- disable RSC (7.11)
   self.r.RFCTL:set(bits { RSC_Dis=5 })

   -- 128 Tx Queues, 64 VMs (4.6.11.3.3 and 8.2.3.9.15)
   self.r.MTQC(bits { VT_Ena=1, Num_TC_OR_Q=2 })

   -- enable virtualization, replication enabled, disable default pool
   self.r.PFVTCTL(bits { VT_Ena=0, Rpl_En=30, DisDefPool=29 })

   -- enable VMDq Tx to Rx loopback
   self.r.PFDTXGSWC:set(bits { LBE=0 })

   -- needs to be set for loopback (7.10.3.4)
   self.r.FCRTH[0](0x10000)

   -- enable vlan filter (4.6.7, 7.1.1.2)
   self.r.VLNCTRL:set(bits { VFE=30 })

   -- intel10g zeroes out ETQF,ETQS here but they are init to 0

   -- RTRUP2TC/RTTUP2TC cleared above in init

   -- DMA TX TCP max allowed size requests (set to 1MB)
   self.r.DTXMXSZRQ(0xFFF)

   -- disable PFC, enable legacy control flow
   self.r.MFLCN(bits { RFCE=3 })
   self.r.FCCFG(bits { TFCE=3 })

   -- RTTDT2C, RTTPT2C, RTRPT4C cleared above in init()

   -- QDE bit = 0 for all queues
   for i = 0, 127 do
      self.r.PFQDE(bor(lshift(1,16), lshift(i,8)))
   end

   -- clear RTTDT1C, PFVLVF for all pools, set them later
   for i = 0, 63 do
      self.r.RTTDQSEL(i)
      self.r.RTTDT1C(0x00)
   end

   -- disable TC arbitrations, enable packet buffer free space monitor
   self.r.RTTDCS:clr(bits { TDPAC=0, TDRM=4, BPBFSM=23 })
   self.r.RTTDCS:set(bits { VMPAC=1, BDPM=22 })
   self.r.RTTPCS:clr(bits { TPPAC=5, TPRM=8 })
   -- set RTTPCS.ARBD
   self.r.RTTPCS:bits(22, 10, 0x244)
   self.r.RTRPCS:clr(bits { RAC=2, RRM=1 })

   -- must be cleared after MTQC configuration (7.2.1.2.1)
   self.r.RTTDCS:clr(bits { ARBDIS=6 })
end

function Intel82599:enable_MAC_for_pool (mac_index)
   self.r.MPSAR[2*mac_index + math.floor(self.poolnum/32)]
      :set(bits{Ena=self.poolnum%32})
end

function Intel82599:unset_MAC ()
   local msk = bits { Ena=self.poolnum%32 }
   for mac_index = 0, self.max_mac_addr do
      self.r.MPSAR[2*mac_index + math.floor(self.poolnum/32)]:clr(msk)
   end
end

function Intel82599:set_tx_rate ()
   if not self.txq then return end
   self.r.RTTDQSEL(self.poolnum or self.txq)
   if self.rate_limit >= 10 then
      -- line rate = 10,000 Mb/s
      local factor = 10000 / tonumber(self.rate_limit)
      -- 10.14 bits
      factor = bit.band(math.floor(factor*2^14+0.5), 2^24-1)
      self.r.RTTBCNRC(bits({RS_ENA=31}, factor))
   else
      self.r.RTTBCNRC(0x00)
   end
   self.r.RTTDT1C(bit.band(math.floor(self.priority * 0x80), 0x3FF))
end

function Intel82599:unset_tx_rate ()
   self.rate_limit = 0
   self.priority = 0
   self:set_tx_rate()
end

-- return rxstats for the counter assigned to this queue
-- the data has to be read from the shm frame since the main instance
-- is in control of the counter registers (and clears them on read)
function Intel82599:get_rxstats ()
   assert(self.rxcounter and self.rxq, "cannot retrieve rxstats")
   local frame = shm.open_frame("pci/"..self.pciaddress)
   local rxc   = self.rxcounter
   return {
      counter_id = rxc,
      packets = counter.read(frame["q"..rxc.."_rxpackets"]),
      dropped = counter.read(frame["q"..rxc.."_rxdrops"]),
      bytes = counter.read(frame["q"..rxc.."_rxbytes"])
   }
end

function Intel82599:get_txstats ()
   assert(self.txcounter and self.txq, "cannot retrieve txstats")
   local frame = shm.open_frame("pci/"..self.pciaddress)
   local txc   = self.txcounter
   return {
      counter_id = txc,
      packets = counter.read(frame["q"..txc.."_txpackets"]),
      bytes = counter.read(frame["q"..txc.."_txbytes"])
   }
end

-- enable the given counter for this app's rx queue
function Intel82599:set_rxstats ()
   if not self.rxcounter or not self.rxq then return end
   local counter = self.rxcounter
   assert(counter>=0 and counter<16, "bad Rx counter")
   self.r.RQSMR[math.floor(self.rxq/4)]:set(lshift(counter,8*(self.rxq%4)))
end

-- enable the given counter for this app's tx queue
function Intel82599:set_txstats ()
   if not self.txcounter or not self.txq then return end
   local counter = self.txcounter
   assert(counter>=0 and counter<16, "bad Tx counter")
   self.r.TQSM[math.floor(self.txq/4)]:set(lshift(counter,8*(self.txq%4)))
end

function Intel:debug (args)
   local args = args or {}
   local pfx = args.prefix or "DEBUG_"
   local prnt = args.print or true
   local r = { rss = "", rxds = 0 }
   r.LINK_STATUS = self:link_status()
   r.rdt = self.rdt
   if self.output.output then
      r.txpackets = counter.read(self.output.output.stats.txpackets)
   end
   if self.input.input then
      r.rxpackets = counter.read(self.input.input.stats.rxpackets)
   end
   r.rdtstatus = band(self.rxdesc[self.rdt].status, 1) == 1
   self:lock_sw_sem()
   for k,_ in pairs(self:rss_tab()) do
      r.rss = r.rss .. k .. " "
   end
   self:unlock_sw_sem()

   r.rxds = 0
   for i=0,self.ndesc-1 do
      if band(self.rxdesc[i].status, 1) == 1 then
         r.rxds = r.rxds + 1
      end
   end
   r.rdbal = tophysical(self.rxdesc) % 2^32
   r.rdbah = tophysical(self.rxdesc) / 2^32
   r.rdlen = self.ndesc * 16
   r.ndesc = self.ndesc

   r.master = self.master

   for _,k in pairs({"RDH", "RDT", "RDBAL", "RDBAH", "RDLEN"}) do
      r[k] = tonumber(self.r[k]())
   end

   local master_regs = {}
   if self.driver == "Intel82599" then
      r.rxdctrl =
         band(self.r.RXDCTL(), bits{enabled = 25}) == bits{enabled = 25}
      master_regs = {"RXCTRL"}
   elseif self.driver == "Intel1g" then
      r.rxen = band(self.r.RCTL(), bits{ RXEN = 1 }) == bits{ RXEN = 1 }
   end
   if self.run_stats then
      for k,v in pairs(self.stats) do
         r[k] = counter.read(v)
      end
   end
   if r.master then
      for _,k in pairs(master_regs) do
         r[k] = tonumber(self.r[k]())
      end
   end

   if prnt then
     local keys = {}
     for k,_ in pairs(r) do
       table.insert(keys, k)
     end
     table.sort(keys)
     for _,k in ipairs(keys) do
        print(pfx..k, r[k])
     end
   end
   return r
end
