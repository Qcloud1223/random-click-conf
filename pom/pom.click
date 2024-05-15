/* 
 * Configuration from Reframer: Flow Stat -> Router -> FW -> NAT
 */

define(
 $iface0    0,
 $queueSize 1024,
 $burst     32
);

AddressInfo(
    dut    192.168.50.31    b8:ce:f6:31:3e:42,
    pktgen 192.168.50.29    b8:ce:f6:31:3b:56
);

nicIn0  :: FromDPDKDevice($iface0, BURST $burst);
nicOut0 :: ToDPDKDevice($iface0, BURST $burst, IQUEUE $queueSize, BLOCKING false);

// class_left :: Classifier(12/0806 20/0001,  // ARP query
//                          12/0806 20/0002,  // ARP response
//                          12/0800);         // IPv4
// only focusing on IP, ignore ARP
// TODO: check if fallback behavior of Classifier is to discard
class_left :: Classifier(12/0800);         // IPv4


// define (a lot of) flow stat
bs :: BurstStats;
aggLen :: AggregateLength;
avgBatchCnt :: AverageBatchCounter(LENGTH_STATS true);
pms :: PacketMemStats;

// define router
rt :: LinearIPLookup(
    40.67.255.199/32 1,
    52.114.32.8/32 1,
    13.81.26.204/32 1,
    52.109.88.122/32 1,
    52.109.124.21/32 1,
    52.114.158.91/32 1,
    13.80.31.209/32 1,
    52.185.224.174/32 1,
    52.109.76.6/32 1,
    40.101.50.2/32 1,
    52.233.190.5/32 1,
    52.114.6.46/32 1,
    13.107.4.50/32 1,
    52.112.194.62/32 1,
    52.156.194.135/32 1,
    52.112.194.60/32 1,
    40.114.241.141/32 1,
    52.109.120.18/32 1,
    20.190.137.97/32 1,
    40.101.49.82/32 1,
    52.109.120.20/32 1,
    52.158.30.62/32 1,
    40.77.167.169/32 1,
    13.107.5.80/32 1,
    104.40.180.100/32 1,
    65.55.252.93/32 1,
    40.67.251.132/32 1,
    40.67.254.36/32 1,
    52.112.194.18/32 1,
    40.87.92.60/32 1,
    40.79.66.209/32 1,
    52.109.16.2/32 1,
    104.47.50.36/32 1,
    13.107.42.12/32 1,
    207.46.13.250/32 1,
    40.101.65.130/32 1,
    52.125.138.52/32 1,
    52.232.79.222/32 1,
    52.230.223.124/32 1,
    40.77.226.250/32 1,
    137.117.144.39/32 1,
    13.107.6.159/32 1,
    65.52.98.231/32 1,
    52.174.238.136/32 1,
    52.178.207.179/32 1,
    13.69.188.18/32 1,
    52.174.92.242/32 1,
    13.91.60.30/32 1,
    52.109.88.22/32 1,
    13.107.3.128/32 1,
    13.107.136.9/32 1,
    52.108.24.5/32 1,
    40.119.147.79/32 1,
    52.162.166.27/32 1,
    13.74.191.167/32 1,
    13.107.255.130/32 1,
    20.44.86.43/32 1,
    40.77.167.65/32 1,
    52.114.158.92/32 1,
    40.68.214.185/32 1,
    52.114.76.35/32 1,
    52.108.24.1/32 1,
    40.79.65.123/32 1,
    40.101.126.130/32 1,
    207.46.13.171/32 1,
    52.112.194.61/32 1,
    52.155.217.156/32 1,
    13.107.42.13/32 1,
    157.55.39.205/32 1,
    40.67.252.61/32 1,
    13.68.93.109/32 1,
    104.47.8.36/32 1,
    52.178.161.139/32 1,
    13.107.42.254/32 1,
    40.90.217.39/32 1,
    13.69.158.96/32 1,
    52.114.88.29/32 1,
    52.178.94.2/32 1,
    52.114.6.45/32 1,
    137.116.78.48/32 1,
    168.62.183.101/32 1,
    40.90.136.179/32 1,
    40.90.136.182/32 1,
    40.114.95.106/32 1,
    52.232.19.237/32 1,
    13.107.18.11/32 1,
    40.90.10.136/32 1,
    52.114.6.47/32 1,
    40.114.218.71/32 1,
    52.166.115.200/32 1,
    52.114.128.44/32 1,
    40.69.43.225/32 1,
    52.125.140.98/32 1,
    52.109.88.38/32 1,
    13.79.247.219/32 1,
    52.114.88.48/32 1,
    52.109.76.5/32 1,
    52.174.30.124/32 1,
    52.114.74.39/32 1,
    52.114.132.23/32 1,
    40.77.229.199/32 1,
    0.0.0.0/1 1,
    128.0.0.0/1 1
    );

// define firewall
// TODO: check whether to enable caching
firewall :: IPFilter(file /home/iom/fastclick/conf/pom/fw-rules);

// define NAT
// IP Classifier before the NAT
ip_rw_l :: IPClassifier(proto tcp, proto udp, -);
// NAT logic
rwpattern :: IPRewriterPatterns(NAT dut 1024-65535 - -);
tcp_rw :: TCPRewriter(pattern NAT 0 0);
udp_rw :: UDPRewriter(pattern NAT 0 0);

// chain them all up
nicIn0 
    -> class_left
    -> CheckIPHeader(OFFSET 14, CHECKSUM false)
    -> tcpudpcls :: IPClassifier (tcp or udp, -)
    -> bs
    -> aggLen
    -> avgBatchCnt
    -> pms
    -> Strip(14)
    -> GetIPAddress(16)
    -> rt;
rt[1]
    // -> Print("pkt pass router")
    -> firewall
    // -> Print("pkt pass fw")
    -> ip_rw_l;

rt[0] -> Discard;
firewall[1] -> Discard;
tcpudpcls[1] -> Discard;

ip_rw_l[0] -> [0]tcp_rw;
ip_rw_l[1] -> [0]udp_rw;
ip_rw_l[2] -> Discard;

// wrap the packets with Ether header and send out
ee :: EtherEncap(ETHERTYPE 0x0800, SRC dut, DST pktgen);
tcp_rw[0] -> ee;
udp_rw[0] -> ee;
ee -> nicOut0;