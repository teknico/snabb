Usage: lwaftr --help
run --conf <config-file> --v1id <port-id> --v1pci <pci-addr> --v1mac <mac address> \
    --v2id <port-id> --v2pci <pci-addr> --v2mac <mac address> \
    --sock <socket-path> [-D <seconds>] [-v] [-u]

  --conf   <config-file>   configuration file for lwaftr service
  --v1id   <port-id>       port_id for virtio socket of INET-side
  --v1pci  <pci-addr>      PCI device number for the INET-side NIC
  --v1mac  <mac address>   Ethernet address of virtio interface of INET-side
  --v2id   <port-id>       port_id for virtio socket of B4-side
  --v2pci  <pci-addr>      PCI device number for the B4-side NIC
  --v2mac  <mac address>   Ethernet address of virtio interface of B4-side
  --sock   <socket-path>   Socket path for virtio-user interfaces
  -D       <seconds>       Duration in seconds
  -v                       Verbose (repeat for more verbosity)

Example config file:

# cat snabbvmx-lwaftr-em3-em4.cfg
return {
  lwaftr = "snabbvmx-lwaftr-em3-em4.conf",
         ipv6_interface = {
           ipv6_address = "fc00::100",
           description = "b4",
           next_hop_cache = true,
           cache_refresh_interval = 10,
         },
         ipv4_interface = {
           ipv4_address = "10.0.1.1",
           description = "aftr",
           service_mac = "44:44:44:44:44:44",
           vlan = 1,
         },
}

and the referenced snabbvmx-lwaftr-em3-em4.conf file:

# cat snabbvmx-lwaftr-em3-em4.conf
address_map = snabbvmx-lwaftr-em3-em4.address,
binding_table = snabbvmx-lwaftr-em3-em4.binding,
vlan_tagging = false,
aftr_ipv6_ip = fc00::100,
aftr_mac_inet_side = 12:12:12:12:12:12,
inet_mac = 66:66:66:66:66:66,
ipv6_mtu = 1500,
aftr_ipv4_ip = 10.0.1.1,
aftr_mac_b4_side = 22:22:22:22:22:22,
b4_mac = 44:44:44:44:44:44,
ipv4_mtu = 1460,
policy_icmpv4_incoming = ALLOW,
policy_icmpv6_incoming = ALLOW,
policy_icmpv4_outgoing = ALLOW,
policy_icmpv6_outgoing = ALLOW,
hairpinning = true,
icmpv6_rate_limiter_n_packets = 6e5,
icmpv6_rate_limiter_n_seconds = 2,

which references two more files: snabbvmx-lwaftr-em3-em4.address and snabbvmx-lwaftr-em3-em4.binding:

cat snabbvmx-lwaftr-em3-em4.address
193.5.1.100 {psid_length=6, shift=10}

cat snabbvmx-lwaftr-em3-em4.binding
{
   {'fc00:1:2:3:4:5:7:127', '193.5.1.100', {psid=1, psid_len=6, shift=10}},
   {'fc00:1:2:3:4:5:7:128', '193.5.1.100', {psid=2, psid_len=6, shift=10}},
   {'fc00:1:2:3:4:5:7:129', '193.5.1.100', {psid=3, psid_len=6, shift=10}},
}

