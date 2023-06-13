const std = @import("std");
const mem = std.mem;
const ether = @import("ethernet.zig");
const ipv4 = @import("ipv4.zig");
const tcp = @import("tcp.zig");
const c = @cImport({
    @cInclude("pcap/pcap.h");
});

pub fn main() !void {
    var pcap_err_buf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    const init_ret = c.pcap_init(c.PCAP_CHAR_ENC_UTF_8, &pcap_err_buf);
    std.debug.print("init_ret: {d}\n", .{ init_ret });

    var pcap_devs: ?*c.pcap_if_t = null;
    const dev_ret = c.pcap_findalldevs(&pcap_devs, &pcap_err_buf);
    std.debug.print("dev_et: {d}\n", .{ dev_ret });
    defer c.pcap_freealldevs(pcap_devs);

    std.debug.print("{any}\n", .{ pcap_devs });

    if (pcap_devs) |dev| {
        debugDev(dev);
    } else {
        std.debug.print("No devices\n", .{});
        return;
    }

    const dev = c.pcap_create(pcap_devs.?.name, &pcap_err_buf) orelse {
        std.debug.print("No dev device: {s}\n", .{ pcap_err_buf });
        return;
    };
    defer c.pcap_close(dev);

    std.debug.print("Any: {any}\n", .{ dev });

    var bpf: c.bpf_program = undefined;
    _ = bpf;

    // const rfmon_ret = c.pcap_set_rfmon(dev, 1);
    // std.debug.print("rfmon_ret: {d}\n", .{ rfmon_ret });

    // const promisc_ret = c.pcap_set_promisc(dev, 1);
    // std.debug.print("promisc_ret: {d}\n", .{ promisc_ret });

    const timeout_ret = c.pcap_set_timeout(dev, 200);
    std.debug.print("timeout_ret: {d}\n", .{ timeout_ret });

    // const snaplen_ret = c.pcap_set_snaplen(dev, 65535);
    // std.debug.print("snapshot_ret: {d}\n", .{ snaplen_ret });

    const activate_ret = c.pcap_activate(dev);
    std.debug.print("activate_ret: {d}\n", .{ activate_ret });
    if (activate_ret < 0) {
        std.debug.print("Error: {s}\n", .{ c.pcap_geterr(dev) });
        return;
    }

    const loop_ret = c.pcap_loop(dev, 0, callback, null);
    std.debug.print("loop_ret: {d}\n", .{ loop_ret });
}

pub export fn callback(user: [*c]u8, header: [*c]const c.pcap_pkthdr, bytes: [*c]const u8) void {
    _ = user;
    std.debug.print("\nHeader:\n", .{});
    std.debug.print("  Time: {d} {d}\n", .{ header.*.ts.tv_sec, header.*.ts.tv_usec });
    std.debug.print("  Len:    {d}\n", .{ header.*.len });
    std.debug.print("  Caplen: {d}\n", .{ header.*.caplen });
    const data = bytes[0..header.*.caplen];
    const eth = ether.Header.parse(data) catch {
        std.debug.panic("Ethernet packet too short\nBytes: {s}\n", .{ std.fmt.fmtSliceHexLower(data) });
    };
    std.debug.print("Ethernet:\n", .{});
    std.debug.print("  Source: {x}:{x}:{x}:{x}:{x}:{x}\n", .{
        eth.source[0],
        eth.source[1],
        eth.source[2],
        eth.source[3],
        eth.source[4],
        eth.source[5]
    });
    std.debug.print("  Dest:  {x}:{x}:{x}:{x}:{x}:{x}\n", .{
        eth.dest[0],
        eth.dest[1],
        eth.dest[2],
        eth.dest[3],
        eth.dest[4],
        eth.dest[5]
    });
    std.debug.print("  Proto: {any}\n", .{ eth.proto });
    // Make sure we decoded and encode the ethernet header correctly
    std.debug.assert(mem.eql(u8, data[0..14], &eth.toBytes()));
    if (eth.proto != .ip) {
        return;
    }
    const ip = ipv4.Header.parse(data[14..]) catch unreachable;
    std.debug.print("IPv4:\n", .{});
    std.debug.print("  Version: {d}\n", .{ ip.version });
    std.debug.print("  IHL: {d}\n", .{ ip.ihl });
    std.debug.print("  DSCP: {d}\n", .{ ip.dscp });
    std.debug.print("  ECN: {d}\n", .{ ip.ecn });
    std.debug.print("  Len: {d}\n", .{ ip.len });
    std.debug.print("  ID: {d}\n", .{ ip.id });
    std.debug.print("  Flags:{s}{s}{s}\n", .{
        if (ip.flags.mf) " MF" else "",
        if (ip.flags.df) " DF" else "",
        if (ip.flags.res) " RES" else ""
    });
    std.debug.print("  Frag Offset: {d}\n", .{ ip.frag_offset });
    std.debug.print("  TTL: {d}\n", .{ ip.ttl });
    std.debug.print("  Proto: {s}\n", .{ @tagName(ip.proto) });
    std.debug.print("  Checksum: {x}\n", .{ ip.check });
    std.debug.print("  Source: {d}.{d}.{d}.{d}\n", .{ ip.source[0], ip.source[1], ip.source[2], ip.source[3] });
    std.debug.print("  Dest:   {d}.{d}.{d}.{d}\n", .{ ip.dest[0], ip.dest[1], ip.dest[2], ip.dest[3] });
    const ip_header = ip.toBytes() catch unreachable;
    // Make sure we decode and encode the IP header correctly (before TODO options)
    std.debug.assert(mem.eql(u8, data[14..14+20], ip_header.slice()));
}

pub fn debugDev(dev: *const c.pcap_if_t) void {
    std.debug.print("Device: {s}\n", .{ dev.name });
    std.debug.print("Flags: {d}\n", .{ dev.flags });
    if (dev.description) |desc| {
        std.debug.print("Description: {s}\n", .{ desc });
    }
    if (dev.next) |next| {
        std.debug.print("-----\n", .{});
        debugDev(next);
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
