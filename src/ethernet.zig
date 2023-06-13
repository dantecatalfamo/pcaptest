const mem = @import("std").mem;

pub const EtherType = enum(u16) {
    /// Ethernet Loopback packet
    loop = 0x0060,
    /// Xerox PUP packet
    pup = 0x0200,
    /// Xerox PUP Addr Trans packet
    pupat = 0x0201,
    /// TSN (IEEE 1722) packet
    tsn = 0x22F0,
    /// ERSPAN version 2 (type III)
    erspan2 = 0x22EB,
    /// Internet Protocol packet
    ip = 0x0800,
    /// CCITT X.25
    x25 = 0x0805,
    /// Address Resolution packet
    arp = 0x0806,
    /// G8BPQ AX.25 Ethernet Packet
    bpq = 0x08FF,
    /// Xerox IEEE802.3 PUP packet
    ieeepup = 0x0a00,
    /// Xerox IEEE802.3 PUP Addr Trans packet
    ieeepupat = 0x0a01,
    /// B.A.T.M.A.N.- Advanced packet
    batman = 0x4305,
    /// DEC Assigned proto
    dec = 0x6000,
    /// DEC DNA Dump/Load
    dna_dl = 0x6001,
    /// DEC DNA Remote Console
    dna_rc = 0x6002,
    /// DEC DNA Routing
    dna_rt = 0x6003,
    /// DEC LAT
    lat = 0x6004,
    /// DEC Diagnostics
    diag = 0x6005,
    /// DEC Customer use
    cust = 0x6006,
    /// DEC Systems Comms Arch
    sca = 0x6007,
    /// Trans Ether Bridging
    teb = 0x6558,
    /// Reverse Addr Res packet
    rarp = 0x8035,
    /// Appletalk DDP
    atalk = 0x809B,
    /// Appletalk AARP
    aarp = 0x80F3,
    /// 802.1Q VLAN Extended Header
    @"8021q" = 0x8100,
    /// ERSPAN type II
    erspan = 0x88BE,
    /// IPX over DIX
    ipx = 0x8137,
    /// IPv6 over bluebook
    ipv6 = 0x86DD,
    /// IEEE Pause frames. See 802.3 31B
    pause = 0x8808,
    /// Slow Protocol. See 802.3ad 43B
    slow = 0x8809,
    /// Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt
    wccp = 0x883E,
    /// MPLS Unicast traffic
    mpls_uc = 0x8847,
    /// MPLS Multicast traffic
    mpls_mc = 0x8848,
    /// MultiProtocol Over ATM
    atmmpoa = 0x884c,
    /// PPPoE discovery messages
    ppp_disc = 0x8863,
    /// PPPoE session messages
    ppp_ses = 0x8864,
    /// HPNA, wlan link local tunnel
    link_ctl = 0x886c,
    /// Frame-based ATM Transport over Ethernet
    atmfate = 0x8884,
    /// Port Access Entity (IEEE 802.1X)
    pae = 0x888E,
    /// PROFINET
    profinet = 0x8892,
    /// Multiple proprietary protocols
    realtek = 0x8899,
    /// ATA over Ethernet
    aoe = 0x88A2,
    /// EtherCAT
    ethercat = 0x88A4,
    /// 802.1ad Service VLAN
    @"8021ad" = 0x88A8,
    ///  802.1 Local Experimental 1
    @"802_ex1" = 0x88B5,
    /// 802.11 Preauthentication
    preauth = 0x88C7,
    /// TIPC
    tipc = 0x88CA,
    /// Link Layer Discovery Protocol
    lldp = 0x88CC,
    /// Media Redundancy Protocol
    mrp = 0x88E3,
    /// 802.1ae MACsec
    macsec = 0x88E5,
    /// 802.1ah Backbone Service Tag
    @"8021ah" = 0x88E7,
    /// 802.1Q MVRP
    mvrp = 0x88F5,
    /// IEEE 1588 Timesync
    @"1588" = 0x88F7,
    /// NCSI protocol
    ncsi = 0x88F8,
    /// IEC 62439-3 PRP/HSRv0
    prp = 0x88FB,
    /// Connectivity Fault Management
    cfm = 0x8902,
    /// Fibre Channel over Ethernet
    fcoe = 0x8906,
    /// Infiniband over Ethernet
    iboe = 0x8915,
    /// TDLS
    tdls = 0x890D,
    /// FCoE Initialization Protocol
    fip = 0x8914,
    /// IEEE 802.21 Media Independent Handover Protocol
    @"80221" = 0x8917,
    /// IEC 62439-3 HSRv1
    hsr = 0x892F,
    /// Network Service Header
    nsh = 0x894F,
    /// Ethernet loopback packet, per IEEE 802.3
    loopback = 0x9000,
    /// deprecated QinQ VLAN
    qinq1 = 0x9100,
    /// deprecated QinQ VLAN
    qinq2 = 0x9200,
    /// deprecated QinQ VLAN
    qinq3 = 0x9300,
    /// Ethertype DSA
    edsa = 0xDADA,
    /// Fake VLAN Header for DSA
    dsa_8021q = 0xDADB,
    /// A5PSW Tag Value
    dsa_a5psw = 0xE001,
    /// ForCES inter-FE LFB type
    ife = 0xED3E,
    /// IBM af_iucv
    af_iucv = 0xFBFB,
    /// If the value in the ethernet type is more than this value * then the frame is Ethernet II. Else it is 802.3
    @"802_3_min" = 0x0600,
    /// Who knows
    _,
};

pub const Header = struct {
    /// Destunation ethernet address
    dest: [6]u8,
    /// Source ethernet address
    source: [6]u8,
    /// Packet type
    ether_type: EtherType,

    pub fn parse(bytes: []const u8) !Header {
        if (bytes.len < 14) {
            return error.InsufficientBytes;
        }
        var header = Header{
            .dest = undefined,
            .source = undefined,
            .ether_type = @intToEnum(EtherType, mem.readIntBig(u16, bytes[12..14])),
        };
        @memcpy(&header.dest, bytes[0..6]);
        @memcpy(&header.source, bytes[6..12]);
        return header;
    }

    pub fn toBytes(self: Header) [14]u8 {
        var out: [14]u8 = undefined;
        @memcpy(out[0..6], &self.dest);
        @memcpy(out[6..12], &self.source);
        mem.writeIntBig(u16, out[12..14], @enumToInt(self.ether_type));
        return out;
    }
};
