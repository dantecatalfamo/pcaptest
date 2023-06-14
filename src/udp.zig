const std = @import("std");
const mem = std.mem;
const debug = std.debug;
const testing = std.testing;

pub const header_size = 8;

pub const Header = struct {
    source_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,

    pub fn parse(bytes: []const u8) !Header {
        var buffer = std.io.fixedBufferStream(bytes);
        const reader = buffer.reader();
        const source_port = try reader.readIntBig(u16);
        const dest_port = try reader.readIntBig(u16);
        const length = try reader.readIntBig(u16);
        const checksum = try reader.readIntBig(u16);
        return Header{
            .source_port = source_port,
            .dest_port = dest_port,
            .length = length,
            .checksum = checksum,
        };
    }

    pub fn toBytes(self: Header) [8]u8 {
        var buffer: [8]u8 = undefined;
        var fixed = std.io.fixedBufferStream(&buffer);
        const writer = fixed.writer();
        writer.writeIntBig(u16, self.source_port) catch unreachable;
        writer.writeIntBig(u16, self.dest_port) catch unreachable;
        writer.writeIntBig(u16, self.length) catch unreachable;
        writer.writeIntBig(u16, self.checksum) catch unreachable;
        return buffer;
    }

    pub fn format(
        self: Header,
        comptime fmtString: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype
    ) !void {
        _ = fmtString;
        _ = options;
        try writer.print("\x1B[48;5;52mUDP src={d:<5} dst={d:<5} len={d:<5} chk={d:<5}\x1B[0m", .{
            self.source_port,
            self.dest_port,
            self.length,
            self.checksum,
        });
    }
};
