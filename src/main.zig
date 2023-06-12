const std = @import("std");
const ether = @import("ethernet.zig");
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
    std.debug.print("Callback called\n", .{});
    std.debug.print("Header: {any}\n", .{ header.* });
    const data = bytes[0..header.*.caplen];
    std.debug.print("{x}\n", .{ std.fmt.fmtSliceHexLower(data[0..40]) });
    const eth = ether.Header.parse(data);
    std.debug.print("Ethernet: {any}\n", .{ eth });
    std.debug.print("  From: {x}:{x}:{x}:{x}:{x}:{x}\n", .{ eth.source[0], eth.source[1], eth.source[2], eth.source[3], eth.source[4], eth.source[5] });
    std.debug.print("  To:   {x}:{x}:{x}:{x}:{x}:{x}\n", .{ eth.dest[0], eth.dest[1], eth.dest[2], eth.dest[3], eth.dest[4], eth.dest[5] });
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
