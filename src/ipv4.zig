const std = @import("std");
const mem = std.mem;
const debug = std.debug;
const testing = std.testing;

pub const Header = struct {
    /// Version. For IPv4, this is always equal to 4
    version: u4,
    /// Internet Header length. Number of 32-but words in the header.
    /// Minimum 5.
    ihl: u4,
    /// Differentiated Services Code Point
    dscp: u6,
    /// Explicit Congestion Notification
    ecn: u2,
    /// Total length
    len: u16,
    /// Packet ID
    id: u16,
    /// Flags
    flags: Flags,
    /// Fragment offset
    frag_offset: u13,
    /// Time to live
    ttl: u8,
    /// Protocol
    proto: Protocol,
    /// Checksum
    check: u16,
    /// Source address
    source: [4]u8,
    /// Destination address
    dest: [4]u8,
    // TODO options: Options

    pub fn parse(bytes: []const u8) !Header {
        var buffer = std.io.fixedBufferStream(bytes);
        var reader = std.io.bitReader(.Big, buffer.reader());
        const version = try reader.readBitsNoEof(u4, 4);
        const ihl = try reader.readBitsNoEof(u4, 4);
        const dscp = try reader.readBitsNoEof(u6, 6);
        const ecn = try reader.readBitsNoEof(u2, 2);
        const len = try reader.reader().readIntBig(u16);
        const id = try reader.reader().readIntBig(u16);
        const flags = @bitCast(Flags, try reader.readBitsNoEof(u3, 3));
        const frag_offset = try reader.readBitsNoEof(u13, 13);
        const ttl = try reader.reader().readByte();
        const proto = @intToEnum(Protocol, try reader.reader().readByte());
        const check = try reader.reader().readIntBig(u16);
        const source = try reader.reader().readBytesNoEof(4);
        const dest = try reader.reader().readBytesNoEof(4);
        // TODO Options
        return Header{
            .version = version,
            .ihl = ihl,
            .dscp = dscp,
            .ecn = ecn,
            .len = len,
            .id = id,
            .flags = flags,
            .frag_offset = frag_offset,
            .ttl = ttl,
            .proto = proto,
            .check = check,
            .source = source,
            .dest = dest,
            // TODO options
        };
    }

    pub fn toBytes(self: Header) !std.BoundedArray(u8, 60) {
        // Room for header plus options
        var bounded = try std.BoundedArray(u8, 60).init(0);
        var writer = std.io.bitWriter(.Big, bounded.writer());
        try writer.writeBits(self.version, 4);
        try writer.writeBits(self.ihl, 4);
        try writer.writeBits(self.dscp, 6);
        try writer.writeBits(self.ecn, 2);
        try writer.writer().writeIntBig(u16, self.len);
        try writer.writer().writeIntBig(u16, self.id);
        try writer.writeBits(@bitCast(u3, self.flags), 3);
        try writer.writeBits(self.frag_offset, 13);
        try writer.writer().writeByte(self.ttl);
        try writer.writer().writeByte(@enumToInt(self.proto));
        try writer.writer().writeIntBig(u16, self.check);
        try writer.writer().writeAll(&self.source);
        try writer.writer().writeAll(&self.dest);
        // TODO options
        return bounded;
    }
};

pub const Flags = packed struct(u3) {
    /// More Fragments
    mf: bool,
    /// Don't Fragment
    df: bool,
    /// Reserved, must be zero
    res: bool,
};

pub const Protocol = enum(u8) {
    /// IPv6 Hop-by-Hop Option [RFC 8200]
    hopopt = 0x00,
    /// Internet Control Message Protocol [RFC 792]
    icmp = 0x01,
    /// Internet Group Management Protocol [RFC 1112]
    igmp = 0x02,
    /// Gateway-to-Gateway Protocol [RFC 823]
    ggp = 0x03,
    /// IP in IP (encapsulation) [RFC 2003]
    ip_in_ip = 0x04,
    /// Internet Stream Protocol [RFC 1190, RFC 1819]
    st = 0x05,
    /// Transmission Control Protocol [RFC 793]
    tcp = 0x06,
    /// Core-based trees [RFC 2189]
    cbt = 0x07,
    /// Exterior Gateway Protocol [RFC 888]
    egp = 0x08,
    /// Interior Gateway Protocol (any private interior gateway, for example Cisco's IGRP)
    igp = 0x09,
    /// BBN RCC Monitoring
    bbn_rcc_mon = 0x0A,
    /// Network Voice Protocol [RFC 741]
    nvp_ii = 0x0B,
    /// Xerox PUP
    pup = 0x0C,
    /// ARGUS
    argus = 0x0D,
    /// EMCON
    emcon = 0x0E,
    /// Cross Net Debugger [IEN 158]
    xnet = 0x0F,
    /// Chaos
    chaos = 0x10,
    /// User Datagram Protocol [RFC 768]
    udp = 0x11,
    /// Multiplexing [IEN 90]
    mux = 0x12,
    /// DCN Measurement Subsystems
    dcn_meas = 0x13,
    /// Host Monitoring Protocol [RFC 869]
    hmp = 0x14,
    /// Packet Radio Measurement
    prm = 0x15,
    /// XEROX NS IDP
    xns_idp = 0x16,
    /// Trunk-1
    trunk_1 = 0x17,
    /// Trunk-2
    trunk_2 = 0x18,
    /// Leaf-1
    leaf_1 = 0x19,
    /// Leaf-2
    leaf_2 = 0x1A,
    /// Reliable Data Protocol [RFC 908]
    rdp = 0x1B,
    /// Internet Reliable Transaction Protocol [RFC 938]
    irtp = 0x1C,
    /// ISO Transport Protocol Class 4 [RFC 905]
    iso_tp4 = 0x1D,
    /// Bulk Data Transfer Protocol [RFC 998]
    netblt = 0x1E,
    /// MFE Network Services Protocol
    mfe_nsp = 0x1F,
    /// MERIT Internodal Protocol
    merit_inp = 0x20,
    /// Datagram Congestion Control Protocol [RFC 4340]
    dccp = 0x21,
    /// Third Party Connect Protocol
    @"3pc" = 0x22,
    /// Inter-Domain Policy Routing Protocol [RFC 1479]
    idpr = 0x23,
    /// Xpress Transport Protocol
    xtp = 0x24,
    /// Datagram Delivery Protocol
    ddp = 0x25,
    /// IDPR Control Message Transport Protocol
    idpr_cmtp = 0x26,
    /// TP++ Transport Protocol
    @"tp++" = 0x27,
    /// IL Transport Protocol
    il = 0x28,
    /// IPv6 Encapsulation (6to4 and 6in4) [RFC 2473]
    ipv6 = 0x29,
    /// Source Demand Routing Protocol [RFC 1940]
    sdrp = 0x2A,
    /// Routing Header for IPv6 [RFC 8200]
    ipv6_route = 0x2B,
    /// Fragment Header for IPv6 [RFC 8200]
    ipv6_frag = 0x2C,
    /// Inter-Domain Routing Protocol
    idrp = 0x2D,
    /// Resource Reservation Protocol [RFC 2205]
    rsvp = 0x2E,
    /// Generic Routing Encapsulation [RFC 2784, RFC 2890]
    gre = 0x2F,
    /// Dynamic Source Routing Protocol [RFC 4728]
    dsr = 0x30,
    /// Burroughs Network Architecture
    bna = 0x31,
    /// Encapsulating Security Payload [RFC 4303]
    esp = 0x32,
    /// Authentication Header [RFC 4302]
    ah = 0x33,
    /// Integrated Net Layer Security Protocol [TUBA]
    i_nlsp = 0x34,
    /// SwIPe [RFC 5237]
    swipe = 0x35,
    /// NBMA Address Resolution Protocol [RFC 1735]
    narp = 0x36,
    /// IP Mobility (Min Encap) [RFC 2004]
    mobile = 0x37,
    /// Transport Layer Security Protocol (using Kryptonet key management)
    tlsp = 0x38,
    /// Simple Key-Management for Internet Protocol [RFC 2356]
    skip = 0x39,
    /// ICMP for IPv6 [RFC 4443, RFC 4884]
    ipv6_icmp = 0x3A,
    /// No Next Header for IPv6 [RFC 8200]
    ipv6_nonxt = 0x3B,
    /// Destination Options for IPv6 [RFC 8200]
    ipv6_opts = 0x3C,
    /// Any host internal protocol
    host_internal = 0x3D,
    /// CFTP
    cftp = 0x3E,
    /// Any local network
    local_network = 0x3F,
    /// SATNET and Backroom EXPAK
    sat_expak = 0x40,
    /// Kryptolan
    kryptolan = 0x41,
    /// MIT Remote Virtual Disk Protocol
    rvd = 0x42,
    /// Internet Pluribus Packet Core
    ippc = 0x43,
    /// Any distributed file system
    file_system = 0x44,
    /// SATNET Monitoring
    sat_mon = 0x45,
    /// VISA Protocol
    visa = 0x46,
    /// Internet Packet Core Utility
    ipcu = 0x47,
    /// Computer Protocol Network Executive
    cpnx = 0x48,
    /// Computer Protocol Heart Beat
    cphb = 0x49,
    /// Wang Span Network
    wsn = 0x4A,
    /// Packet Video Protocol
    pvp = 0x4B,
    /// Backroom SATNET Monitoring
    br_sat_mon = 0x4C,
    /// SUN ND PROTOCOL-Temporary
    sun_nd = 0x4D,
    /// WIDEBAND Monitoring
    wb_mon = 0x4E,
    /// WIDEBAND EXPAK
    wb_expak = 0x4F,
    /// International Organization for Standardization Internet Protocol
    iso_ip = 0x50,
    /// Versatile Message Transaction Protocol [RFC 1045]
    vmtp = 0x51,
    /// Secure Versatile Message Transaction Protocol [RFC 1045]
    secure_vmtp = 0x52,
    /// VINES
    vines = 0x53,
    /// Internet Protocol Traffic Manager
    iptm = 0x54,
    /// NSFNET-IGP
    nsfnet_igp = 0x55,
    /// Dissimilar Gateway Protocol
    dgp = 0x56,
    /// TCF
    tcf = 0x57,
    /// EIGRP [Informational RFC 7868]
    eigrp = 0x58,
    /// Open Shortest Path First [RFC 2328]
    ospf = 0x59,
    /// Sprite RPC Protocol
    sprite_rpc = 0x5A,
    /// Locus Address Resolution Protocol
    larp = 0x5B,
    /// Multicast Transport Protocol
    mtp = 0x5C,
    /// AX.25
    ax_25 = 0x5D,
    /// KA9Q NOS compatible IP over IP tunneling
    os = 0x5E,
    /// Mobile Internetworking Control Protocol
    micp = 0x5F,
    /// Semaphore Communications Sec. Pro
    scc_sp = 0x60,
    /// Ethernet-within-IP Encapsulation [RFC 3378]
    etherip = 0x61,
    /// Encapsulation Header [RFC 1241]
    encap = 0x62,
    /// private encryption scheme
    any = 0x63,
    /// GMTP
    gmtp = 0x64,
    /// Ipsilon Flow Management Protocol
    ifmp = 0x65,
    /// PNNI over IP
    pnni = 0x66,
    /// Protocol Independent Multicast
    pim = 0x67,
    /// IBM's ARIS (Aggregate Route IP Switching) Protocol
    aris = 0x68,
    /// SCPS (Space Communications Protocol Standards) [SCPS-TP]
    scps = 0x69,
    /// QNX
    qnx = 0x6A,
    /// Active Networks
    a_n = 0x6B,
    /// IP Payload Compression Protocol [RFC 3173]
    ipcomp = 0x6C,
    /// Sitara Networks Protocol
    snp = 0x6D,
    /// Compaq Peer Protocol
    compaq_peer = 0x6E,
    /// IPX in IP
    ipx_in_ip = 0x6F,
    /// Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned) [RFC 5798]
    vrrp = 0x70,
    /// PGM Reliable Transport Protocol [RFC 3208]
    pgm = 0x71,
    /// Any 0-hop protocol
    zero_hop = 0x72,
    /// Layer Two Tunneling Protocol Version 3 [RFC 3931]
    l2tp = 0x73,
    /// D-II Data Exchange (DDX)
    ddx = 0x74,
    /// Interactive Agent Transfer Protocol
    iatp = 0x75,
    /// Schedule Transfer Protocol
    stp = 0x76,
    /// SpectraLink Radio Protocol
    srp = 0x77,
    /// Universal Transport Interface Protocol
    uti = 0x78,
    /// Simple Message Protocol
    smp = 0x79,
    /// Simple Multicast Protocol [draft-perlman-simple-multicast-03]
    sm = 0x7A,
    /// Performance Transparency Protocol
    ptp = 0x7B,
    /// Intermediate System to Intermediate System (IS-IS) Protocol over IPv4 [RFC 1142 and RFC 1195]
    is_is_ipv4 = 0x7C,
    /// Flexible Intra-AS Routing Environment
    fire = 0x7D,
    /// Combat Radio Transport Protocol
    crtp = 0x7E,
    /// Combat Radio User Datagram
    crudp = 0x7F,
    /// Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment [ITU-T Q.2111 (1999)]
    sscopmce = 0x80,
    /// IPLT
    iplt = 0x81,
    /// Secure Packet Shield
    sps = 0x82,
    /// Private IP Encapsulation within IP [Expired I-D draft-petri-mobileip-pipe-00.txt]
    pipe = 0x83,
    /// Stream Control Transmission Protocol [RFC 4960]
    sctp = 0x84,
    /// Fibre Channel
    fc = 0x85,
    /// Reservation Protocol (RSVP) End-to-End Ignore [RFC 3175]
    rsvp_e2e_ignore = 0x86,
    /// Mobility Extension Header for IPv6 [RFC 6275]
    mobility_header = 0x87,
    /// Lightweight User Datagram Protocol [RFC 3828]
    udplite = 0x88,
    /// Multiprotocol Label Switching Encapsulated in IP [RFC 4023, RFC 5332]
    mpls_in_ip = 0x89,
    /// MANET Protocols [RFC 5498]
    manet = 0x8A,
    /// Host Identity Protocol [RFC 5201]
    hip = 0x8B,
    /// Site Multihoming by IPv6 Intermediation [RFC 5533]
    shim6 = 0x8C,
    /// Wrapped Encapsulating Security Payload [RFC 5840]
    wesp = 0x8D,
    /// Robust Header Compression [RFC 5856]
    rohc = 0x8E,
    /// IPv6 Segment Routing (TEMPORARY - registered 2020-01-31, expired 2021-01-31)
    ethernet = 0x8F,
    /// AGGFRAG Encapsulation Payload for ESP
    aggfrag = 0x90,
    /// Reserved
    reserved = 0xFF,
    _,
};

pub const Options = struct {
    /// Set to 1 if the options need to be copied into all fragments
    /// of a fragmented packet.
    copied: bool,
    class: Class,
    type: Type,
    length: u8,

    pub const Class = enum (u2) {
        control = 0,
        reserved_1 = 1,
        debugging = 2,
        reserved_2 = 3,
    };

    pub const Type = enum(u5) {
        /// End of Option List
        eool = 0x00,
        /// No Operation
        nop = 0x01,
        /// Security (defunct)
        sec = 0x02,
        /// Record Route
        rr = 0x07,
        /// Experimental Measurement
        zsu = 0x0A,
        /// MTU Probe
        mtup = 0x0B,
        /// MTU Reply
        mtur = 0x0C,
        /// ENCODE
        encode = 0x0F,
        /// Quick-Start
        qs = 0x19,
        /// RFC3692-style Experiment
        exp = 0x1E,
        /// Time Stamp
        ts = 0x44,
        /// Traceroute
        tr = 0x52,
        /// RFC3692-style Experiment
        exp = 0x5E,
        /// Security (RIPSO)
        sec = 0x82,
        /// Loose Source Route
        lsr = 0x83,
        /// -SEC 	Extended Security (RIPSO)
        e = 0x85,
        /// Commercial IP Security Option
        cipso = 0x86,
        /// Stream ID
        sid = 0x88,
        /// Strict Source Route
        ssr = 0x89,
        /// Experimental Access Control
        visa = 0x8E,
        /// IMI Traffic Descriptor
        imitd = 0x90,
        /// Extended Internet Protocol
        eip = 0x91,
        /// Address Extension
        addext = 0x93,
        /// Router Alert
        rtralt = 0x94,
        /// Selective Directed Broadcast
        sdb = 0x95,
        /// Dynamic Packet State
        dps = 0x97,
        /// Upstream Multicast Packet
        ump = 0x98,
        /// RFC3692-style Experiment
        exp = 0x9E,
        /// Experimental Flow Control
        finn = 0xCD,
        /// RFC3692-style Experiment
        exp = 0xDE,
    };
};
