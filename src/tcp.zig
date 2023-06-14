const std = @import("std");
const mem = std.mem;
const debug = std.debug;
const testing = std.testing;

pub const header_size_min = 20;
pub const header_size_max = 60;

pub const Header = struct {
    /// Source port
    source_port: u16,
    /// Destination port
    dest_port: u16,
    /// Sequence number
    seq: u32,
    /// Acknowledgment number
    ack_number: u32,
    /// Data offset. Size of the TCP header in 32-bit words.
    /// Minimum 5.
    data_offset: u4,
    /// Reserved
    reserved: u4,
    flags: Flags,
    /// Window size
    win_size: u16,
    /// Checksum
    check: u16,
    /// Offset from the sequence number indicating the last urgent data byte
    urgent_ptr: u16,
    // TODO Options

    pub const Flags = struct {
        /// Congestion Window Reduced
        cwr: bool,
        /// ECN-Echo
        ece: bool,
        /// Urgent pointer field is significant
        urg: bool,
        /// Acknowledgment field is significant
        ack: bool,
        /// Push function
        psh: bool,
        /// Reset the connection
        rst: bool,
        /// Synchronize sequence numbers
        syn: bool,
        /// Last packet from sender
        fin: bool,
    };

    pub fn parse(bytes: []const u8) !Header {
        var buffer = std.io.fixedBufferStream(bytes);
        var reader = std.io.bitReader(.Big, buffer.reader());
        const source_port = try reader.reader().readIntBig(u16);
        const dest_port = try reader.reader().readIntBig(u16);
        const seq = try reader.reader().readIntBig(u32);
        const ack_number = try reader.reader().readIntBig(u32);
        const data_offset = try reader.readBitsNoEof(u4, 4);
        const reserved = try reader.readBitsNoEof(u4, 4);
        const cwr = @bitCast(bool, try reader.readBitsNoEof(u1, 1));
        const ece = @bitCast(bool, try reader.readBitsNoEof(u1, 1));
        const urg = @bitCast(bool, try reader.readBitsNoEof(u1, 1));
        const ack = @bitCast(bool, try reader.readBitsNoEof(u1, 1));
        const psh = @bitCast(bool, try reader.readBitsNoEof(u1, 1));
        const rst = @bitCast(bool, try reader.readBitsNoEof(u1, 1));
        const syn = @bitCast(bool, try reader.readBitsNoEof(u1, 1));
        const fin = @bitCast(bool, try reader.readBitsNoEof(u1, 1));
        const win_size = try reader.reader().readIntBig(u16);
        const check = try reader.reader().readIntBig(u16);
        const urgent_ptr = try reader.reader().readIntBig(u16);
        // TODO Options
        return Header{
            .source_port = source_port,
            .dest_port = dest_port,
            .seq = seq,
            .ack_number = ack_number,
            .data_offset = data_offset,
            .reserved = reserved,
            .flags = .{
                .cwr = cwr,
                .ece = ece,
                .urg = urg,
                .ack = ack,
                .psh = psh,
                .rst = rst,
                .syn = syn,
                .fin = fin,
            },
            .win_size = win_size,
            .check = check,
            .urgent_ptr = urgent_ptr,
        };
    }

    pub fn toBytes(self: Header) std.BoundedArray(u8, header_size_max) {
        // Room for header plus options
        var bounded = std.BoundedArray(u8, header_size_max).init(0) catch unreachable;
        var writer = std.io.bitWriter(.Big, bounded.writer());
        // It shoudn't be possible to fail writing since we know the
        // size, and it's all heap allocated. If this fails we made a
        // mistake
        writer.writer().writeIntBig(u16, self.source_port) catch unreachable;
        writer.writer().writeIntBig(u16, self.dest_port) catch unreachable;
        writer.writer().writeIntBig(u32, self.seq) catch unreachable;
        writer.writer().writeIntBig(u32, self.ack_number) catch unreachable;
        writer.writeBits(self.data_offset, 4) catch unreachable;
        writer.writeBits(self.reserved, 4) catch unreachable;
        writer.writeBits(@boolToInt(self.flags.cwr), 1) catch unreachable;
        writer.writeBits(@boolToInt(self.flags.ece), 1) catch unreachable;
        writer.writeBits(@boolToInt(self.flags.urg), 1) catch unreachable;
        writer.writeBits(@boolToInt(self.flags.ack), 1) catch unreachable;
        writer.writeBits(@boolToInt(self.flags.psh), 1) catch unreachable;
        writer.writeBits(@boolToInt(self.flags.rst), 1) catch unreachable;
        writer.writeBits(@boolToInt(self.flags.syn), 1) catch unreachable;
        writer.writeBits(@boolToInt(self.flags.fin), 1) catch unreachable;
        writer.writer().writeIntBig(u16, self.win_size) catch unreachable;
        writer.writer().writeIntBig(u16, self.check) catch unreachable;
        writer.writer().writeIntBig(u16, self.urgent_ptr) catch unreachable;
        // TODO Options
        return bounded;
    }

    /// Size of the header in bytes
    pub inline fn byteSize(self: Header) usize {
        return @as(usize, self.data_offset) * 4;
    }

    pub fn format(
        self: Header,
        comptime fmtString: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype
    ) !void {
        _ = fmtString;
        _ = options;

        try writer.print("\x1B[48;5;22mTCP src={d:<5} dst={d:<5} seq={d:<10} ack={d:<10} doff={d:<2} res={d} flags=\"{s}{s}{s}{s}{s}{s}{s}{s}\" win={d:<5} urg={d}\x1B[0m", .{
            self.source_port,
            self.dest_port,
            self.seq,
            self.ack_number,
            self.data_offset,
            self.reserved,
            if (self.flags.cwr) "C" else ".",
            if (self.flags.ece) "E" else ".",
            if (self.flags.urg) "U" else ".",
            if (self.flags.ack) "A" else ".",
            if (self.flags.psh) "P" else ".",
            if (self.flags.rst) "R" else ".",
            if (self.flags.syn) "S" else ".",
            if (self.flags.fin) "F" else ".",
            self.win_size,
            self.urgent_ptr,
        });
    }
};
