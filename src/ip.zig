
pub const Header = struct {
    /// Header length
    header_length: u4,
    /// Version
    version: u4,
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
    proto: u8,
    /// Checksum
    check: u16,
    /// Source address
    source: u32,
    /// Destination address
    dest: u32,
    // TODO options: Options
};

pub const Flags = packed struct(u3) {
    /// More Fragments
    mf: bool,
    /// Don't Fragment
    df: bool,
    /// Reserved, must be zero
    res: bool,
};
