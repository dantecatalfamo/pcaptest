const std = @import("std");
const mem = std.mem;
const log = std.log;
const ether = @import("ethernet.zig");
const ipv4 = @import("ipv4.zig");
const tcp = @import("tcp.zig");
const udp = @import("udp.zig");
const gui = @import("gui.zig");
const c = @import("c.zig").c;

pub const std_options = struct {
    pub const log_level = .info;
};

pub fn main() !void {
    var gui_state = gui.GuiState{
        .graph_packets = try std.BoundedArray(gui.GraphData, gui.graph_buffer_len).init(0),
        .graph_bytes = try std.BoundedArray(gui.GraphData, gui.graph_buffer_len).init(0),
    };

    log.info("Spawning GUI thread", .{});
    _ = try std.Thread.spawn(.{}, gui.runGui, .{&gui_state});

    var pcap_err_buf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    const init_ret = c.pcap_init(c.PCAP_CHAR_ENC_UTF_8, &pcap_err_buf);
    log.debug("init_ret: {d}", .{init_ret});

    var pcap_devs: ?*c.pcap_if_t = null;
    const dev_ret = c.pcap_findalldevs(&pcap_devs, &pcap_err_buf);
    log.debug("dev_ret: {d}", .{dev_ret});
    defer c.pcap_freealldevs(pcap_devs);

    if (pcap_devs) |dev| {
        debugDev(dev);
    } else {
        log.err("No devices", .{});
        return;
    }

    gui_state.device = pcap_devs;
    log.info("Opening device: {s}", .{pcap_devs.?.name});
    const dev = c.pcap_create(pcap_devs.?.name, &pcap_err_buf) orelse {
        log.err("No device: {s}", .{pcap_err_buf});
        return;
    };
    defer c.pcap_close(dev);
    gui_state.pcap = dev;

    var bpf: c.bpf_program = undefined;
    _ = bpf;

    // const rfmon_ret = c.pcap_set_rfmon(dev, 1);
    // std.debug.print("rfmon_ret: {d}\n", .{ rfmon_ret });

    // const promisc_ret = c.pcap_set_promisc(dev, 1);
    // std.debug.print("promisc_ret: {d}\n", .{ promisc_ret });

    const timeout_ms = 200;
    log.debug("Setting timeout at {d}ms", .{timeout_ms});
    const timeout_ret = c.pcap_set_timeout(dev, timeout_ms);
    log.debug("timeout_ret: {d}", .{timeout_ret});

    // const snaplen_ret = c.pcap_set_snaplen(dev, 65535);
    // std.debug.print("snapshot_ret: {d}\n", .{ snaplen_ret });

    log.debug("Activating device", .{});
    const activate_ret = c.pcap_activate(dev);
    log.debug("activate_ret: {d}", .{activate_ret});
    if (activate_ret < 0) {
        log.err("Error activating: {s}", .{c.pcap_geterr(dev)});
        return;
    }

    log.debug("Starting pcap_loop", .{});
    const loop_ret = c.pcap_loop(dev, 0, callback, @ptrCast(*u8, &gui_state));
    log.debug("loop_ret: {d}", .{loop_ret});
}

pub export fn callback(user: [*c]u8, header: [*c]const c.pcap_pkthdr, bytes: [*c]const u8) void {
    var gui_state = @ptrCast(*gui.GuiState, @alignCast(@alignOf(gui.GuiState), user));
    if (gui_state.gui_closed) {
        log.debug("Calling pcap_breakloop", .{});
        c.pcap_breakloop(gui_state.pcap);
        return;
    }
    // log.debug("Header:", .{});
    // log.debug("  Time: {d} {d}", .{ header.*.ts.tv_sec, header.*.ts.tv_usec });
    // log.debug("  Len:    {d}", .{ header.*.len });
    // log.debug("  Caplen: {d}", .{ header.*.caplen });
    const data = bytes[0..header.*.caplen];
    const eth = ether.Header.parse(data) catch {
        std.debug.panic("Ethernet packet too short\nBytes: {s}\n", .{std.fmt.fmtSliceHexLower(data)});
    };
    // Make sure we decoded and encode the ethernet header correctly
    std.debug.assert(mem.eql(u8, data[0..ether.header_size], &eth.toBytes()));
    if (eth.ether_type != .ip) {
        log.info("{}", .{eth});
        return;
    }

    const ip = ipv4.Header.parse(data[ether.header_size..]) catch unreachable;
    const ip_header = ip.toBytes();
    // Make sure we decode and encode the IP header correctly (before TODO options)
    std.debug.assert(mem.eql(u8, data[ether.header_size..][0..ipv4.header_size_min], ip_header.slice()));

    const now = std.time.timestamp();

    // TODO Doesn't account for seconds where no packets are received
    if (gui_state.graph_packets.len == 0 or gui_state.graph_packets.slice()[gui_state.graph_packets.len - 1].time != now) {
        if (gui_state.graph_packets.len == gui_state.graph_packets.capacity()) {
            _ = gui_state.graph_packets.orderedRemove(0);
            _ = gui_state.graph_bytes.orderedRemove(0);
        }
        gui_state.graph_packets.append(gui.GraphData{ .time = @intCast(u64, now) }) catch unreachable;
        gui_state.graph_bytes.append(gui.GraphData{ .time = @intCast(u64, now) }) catch unreachable;
    }
    var current_packet_graph = &gui_state.graph_packets.slice()[gui_state.graph_packets.len - 1];
    var current_byte_graph = &gui_state.graph_bytes.slice()[gui_state.graph_packets.len - 1];

    switch (ip.proto) {
        .tcp => {
            const tcp_hdr = tcp.Header.parse(data[ether.header_size..][ip.byteSize()..]) catch unreachable;
            const tcp_bytes = tcp_hdr.toBytes();
            // Make sure we decode and encode TCP header correctly (before TODO options)
            // log.debug("Size: {d} ({d})", .{ tcp_hdr.byteSize(), tcp_hdr.data_offset });
            // log.debug("IN:  {s}", .{ std.fmt.fmtSliceHexLower(data[ether.header_size..][ip.byteSize()..][0..tcp_hdr.byteSize()]) });
            // log.debug("OUT: {s}", .{ std.fmt.fmtSliceHexLower(tcp_bytes.slice()) });
            std.debug.assert(mem.eql(u8, data[ether.header_size..][ip.byteSize()..][0..tcp.header_size_min], tcp_bytes.slice()));
            log.info("{} | {} | {}", .{ eth, ip, tcp_hdr });
            current_packet_graph.tcp += 1;
            current_byte_graph.tcp += ip.len;
        },
        .udp => {
            const udp_hdr = udp.Header.parse(data[ether.header_size..][ip.byteSize()..]) catch unreachable;
            log.info("{} | {} | {}", .{ eth, ip, udp_hdr });
            std.debug.assert(mem.eql(u8, data[ether.header_size..][ip.byteSize()..][0..udp.header_size], &udp_hdr.toBytes()));
            current_packet_graph.udp += 1;
            current_byte_graph.udp += ip.len;
        },
        else => {
            log.info("{} | {}", .{ eth, ip });
        },
    }
}

pub fn debugDev(dev: *const c.pcap_if_t) void {
    log.debug("Device: {s}", .{dev.name});
    log.debug("Flags: {d}", .{dev.flags});
    if (dev.description) |desc| {
        log.debug("Description: {s}", .{desc});
    }
    if (dev.next) |next| {
        log.debug("-----", .{});
        debugDev(next);
    }
}

test "ref all" {
    std.testing.refAllDeclsRecursive(@This());
}
