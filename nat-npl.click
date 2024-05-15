define(
 $iface0    0,
 $iface1    1,
 $queueSize 1024,
 $burst     32
);

inbound :: FromDPDKDevice($iface0, BURST $burst);
outbound :: ToDPDKDevice($iface0, IQUEUE $queueSize, BURST $burst);

// Nah, such element binds IP and MAC together, but in the following
// we actually do not use them as a whole
AddressInfo(
    // dest, pc1 01:00.0
    // dst_if    10.181.0.0    b8:ce:f6:31:3b:56,
    // dest, pc1 01:00.1
    dst_if    10.181.0.0    b8:ce:f6:31:3b:57,
    // src, t440 af:00.0
    src_if    10.181.0.1    b8:ce:f6:31:3e:42
);

// classifying inbound traffic
class :: Classifier(12/0800,        // IP
                    12/0806 20/0002 // ARP response
);

inbound 
    // -> Print(MAXLENGTH 38)
    // -> c1::AverageCounter()
    -> class;

// Script(print "inbound", wait 1, print c1.byte_count, write c1.reset, loop)

ip_class :: IPClassifier(proto tcp, proto udp);

// allowing empty space for ~64K concurrent flows
// One super weird thing is that if the lower bound is low (e.g. 1024)
// the NAT will refuse to rewrite port SILENTLY
ip_pattern :: IPRewriterPatterns(NAT src_if 10000-65535# - -);
// since IPRewriter does not seem to allow IP range
// we will have to use RR for multiple IPs
// creating a space for 3*60000= ~180K concurrent flows
// rrip :: RoundRobinIPMapper(
//     10.181.0.11 1024-65535 - - 0 0,
//     10.181.0.12 1024-65535 - - 1 0,
//     10.181.0.13 1024-65535 - - 2 0
// );

// *Rewriter can take multiple input
// In this example, traffic from input port 0 are NAT-ed
tcp_rewrite :: TCPRewriter(pattern NAT 0 0);
udp_rewrite :: UDPRewriter(pattern NAT 0 0);

// tcp_rewrite :: TCPRewriter(pass 0);
// udp_rewrite :: UDPRewriter(pass 0);

// tcp_rewrite :: TCPRewriter(rrip);
// udp_rewrite :: UDPRewriter(rrip);

// class[0] -> Strip(14) -> CheckIPHeader -> ip_class;
class[0] -> Strip(14)
// full ip header and TCP sport/dport
    // -> Print(MAXLENGTH 28)
    -> CheckIPHeader -> ip_class;
ip_class[0] -> [0]tcp_rewrite;
ip_class[1] -> [0]udp_rewrite;

// wrap the packets with ethernet layer
// TODO: is this violating 0 copy? Maybe run without this
// NB: arp_wrapper is acting weird
// arp_wrapper :: ARPQuerier(src_if)
arp_wrapper :: EtherEncap(0x0800, src_if, dst_if)
// before the arp_wrapper send out packets, do some statistics
    // -> Print(MAXLENGTH 38)
    -> c2::AverageCounter()
    -> outbound;

Script(wait 1, printn "pps: ", printn $(div $(c2.count) 1000000), 
    printn "M\tbps: ", 
    set bps $(mul $(c2.byte_count) 8),
    set bps $(div $bps 1000000000),
    print $bps"G",
    write c2.reset, loop)
Script(wait 5, printn "tcp table size: ", print tcp_rewrite.table_size, loop)
Script(wait 5, printn "udp table size: ", print udp_rewrite.table_size, loop)

// TCP rewrite now has 3 legit output ports
tcp_rewrite[0] 
    // -> Print(MAXLENGTH 24)
    -> arp_wrapper;
// tcp_rewrite[1] 
//     -> Print(MAXLENGTH 24)
//     -> arp_wrapper;
// tcp_rewrite[2] -> arp_wrapper;
udp_rewrite[0] -> arp_wrapper;
// udp_rewrite[1] -> arp_wrapper;
// udp_rewrite[2] -> arp_wrapper;

// don't know for sure why ARPQuerier must take ARP response
// class[1] -> [1]arp_wrapper;
class[1] -> arp_wrapper