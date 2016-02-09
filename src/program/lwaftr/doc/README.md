# Snabb lwAFTR

## About lightweight 4-over-6

Lightweight 4-over-6 (lw4o6) is an IPv6 transition mechanism, specified
as [RFC 7596](https://tools.ietf.org/html/rfc7596).  An lwAFTR is the
internet-facing component of an lw4o6 implementation.

Snabb lwAFTR allows a network operator to run a pure IPv6 network
internally, while providing interoperability with the IPv4 internet.
Each customer IPv6 address may be associated with a limited range of
ports on an IPv4 address.  Restricting port ranges allows an ISP to
serve more customers with a smaller IPv4 address space, which keeps
legacy IPv4 costs low.

The mapping between IPv4 addresses and customers is done in such a way
that the lwAFTR instance only needs to know about the mapping between
each assigned IPv6 address and an IPv4 address and port range.  In
particular, an lwAFTR doesn't need to keep per-flow state, lowering
complexity and cost. This also means that lwAFTR scales horizontally;
multiple lwAFTR functions can service the same set of customers, and any
flow can be processed by any lwAFTR function in the node.

## See a talk!

Katerina Barone-Adesi and Andy Wingo gave a talk on Snabb and the lwAFTR
at [FOSDEM 2016](http://fosdem.org/2016/)!  Eventually there will be a
video here: https://fosdem.org/2016/schedule/event/snabbswitch/

In the meantime, you might like to check out [the
slides](https://wingolog.org/pub/fosdem-2016-lwaftr-slides.pdf).

## Status

The Snabb lwAFTR has a fully functional data plane that can encapsulate
and decapsulate traffic at line rate over two 10 Gb NICs.  It supports
arbitrarily large binding tables, IPv4 address sharing using the
port-set ID scheme, VLAN tagging, fragmentation, reassembly, NDP,
and implements all of RFC 7596 including hairpinning and configurable
ICMP error handling.

An lwAFTR is just one part of a lw4o6 deployment.  The routers that
directly serve the users (the customer premise equipment, or CPE boxes;
e.g. running OpenWRT) need to do the job of terminating a softwire to the
lwAFTR.  The piece of software on the CPE that does this is called the
*B4*, or in the case of lw4o6 the *lwB4*.  Each B4 needs to be deployed
with the IPv6 address of the lwAFTR, the IPv6 address of the B4, and the
corresponding IPv4 address and PSID.  In a real deployment, probably you
will use DHCPv6 or some big NETCONF management system to configure both
the lwAFTR and the CPE.

The lwAFTR only has a data plane for now; you need some external control
plane to update its configuration.  Or, you do what we do now, and you
configure it all at the command like with little text files :)  

## Getting started

[Build](./README.build.md)

[Testing](./README.testing.md)

[Configuration](./README.configuration.md)

[Running](./README.running.md)

## Troubleshooting

[Troubleshooting](./README.troubleshooting.md)

## Tuning for production

[Bindingtable](./README.bindingtable.md)

[Breaking changes](./README.breaking_changes.md)

[Ndp](./README.ndp.md)

[RFC Compliance](./README.rfccompliance.md)

[Virtualization](./README.virtualization.md)

## Performance

[Benchmarking](./README.benchmarking.md)

[Performance](./README.performance.md)
