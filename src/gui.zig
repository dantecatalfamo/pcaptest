const std = @import("std");
const mem = std.mem;
const math = std.math;
const debug = std.debug;
const testing = std.testing;
const c = @import("c.zig").c;

pub const graph_buffer_len = 10_000;

pub const GuiState = struct {
    pcap: ?*c.pcap_t = null,
    device: ?*c.pcap_if_t = null,
    graph_packets: std.BoundedArray(GraphData, graph_buffer_len),
    graph_bytes: std.BoundedArray(GraphData, graph_buffer_len),
    packet_view: bool = false,
    gui_closed: bool = false,
    smoothing: c_int = 0,
};

pub const GraphData = struct {
    time: u64 = 0,
    tcp: u64 = 0,
    udp: u64 = 0,

    pub inline fn total(self: GraphData) u64 {
        return self.tcp + self.udp;
    }
};

pub fn runGui(gui_state: *GuiState) void {
    const win_height = 200;
    const win_width = 400;

    c.SetConfigFlags(c.FLAG_WINDOW_RESIZABLE);
    c.InitWindow(win_width, win_height, "PcapTest");
    defer c.CloseWindow();

    c.SetTargetFPS(60);

    while (!c.WindowShouldClose()) {
        const dev_name = if (gui_state.device) |dev|
            mem.span(dev.name)
        else
            "No device";

        c.BeginDrawing();
        c.ClearBackground(c.RAYWHITE);

        const raw_graph_slice = if (gui_state.packet_view)
            gui_state.graph_packets.slice()
        else
            gui_state.graph_bytes.slice();

        const avg_graph_slice = blk: {
            var averaged_data: [graph_buffer_len]GraphData = undefined;
            averageGraphData(raw_graph_slice, averaged_data[0..raw_graph_slice.len], @intCast(gui_state.smoothing));
            break :blk averaged_data;
        };

        const graph_slice = avg_graph_slice[0..raw_graph_slice.len];

        const screen_width = c.GetScreenWidth();
        const screen_height = c.GetScreenHeight();
        const slice_screen_start: u64 = @intCast(@max(0, @as(i64, @intCast(graph_slice.len)) - @as(i64, @intCast(screen_width))));

        const tallest_line = blk: {
            var largest: u64 = 0;
            for (graph_slice[slice_screen_start..]) |item| {
                if (item.total() > largest) {
                    largest = item.total();
                }
            }
            break :blk largest;
        };
        const scale = @as(f64, @floatFromInt(tallest_line)) / @as(f64, @floatFromInt(screen_height));

        var x_line = screen_width;
        while (x_line > 0) : (x_line -= 60) {
            if (x_line == screen_width)
                continue;
            var y_line: c_int = 3;
            while (y_line < screen_height) : (y_line += 10) {
                c.DrawLine(x_line, y_line, x_line, y_line + 5, c.LIGHTGRAY);
            }
        }

        var y_dotted_line = @as(c_int, 3);
        while (y_dotted_line < screen_width) : (y_dotted_line += 10) {
            c.DrawLine(y_dotted_line, @divTrunc(screen_height, 2), y_dotted_line + 5, @divTrunc(screen_height, 2), c.LIGHTGRAY);
        }

        for (graph_slice, 0..) |item, idx| {
            if (@as(isize, @intCast(graph_slice.len)) - @as(isize, @intCast(idx)) > c.GetScreenWidth())
                continue;
            const tcp_scaled: c_int = @intFromFloat(@as(f64, @floatFromInt(item.tcp)) / scale);
            const udp_scaled: c_int = @intFromFloat(@as(f64, @floatFromInt(item.udp)) / scale);

            const x_pos = @as(u64, @intCast(screen_width)) - @min(@as(u64, @intCast(screen_width)), graph_slice.len) + (idx - slice_screen_start);
            const tcp_y_pos = screen_height - @min(tcp_scaled, screen_height);
            const udp_y_pos = screen_height - @min(udp_scaled + tcp_scaled, screen_height);
            c.DrawRectangle(@as(c_int, @intCast(x_pos)), @as(c_int, @intCast(tcp_y_pos)), 1, @as(c_int, @intCast(tcp_scaled)), c.LIME);
            c.DrawRectangle(@as(c_int, @intCast(x_pos)), @as(c_int, @intCast(udp_y_pos)), 1, @as(c_int, @intCast(udp_scaled)), c.MAROON);
        }

        if (c.IsCursorOnScreen()) {
            const mouse_x = c.GetMouseX();

            const from_edge = screen_width - mouse_x + 1;
            const slice_item = if (from_edge <= graph_slice.len)
                graph_slice[graph_slice.len - @as(usize, @intCast(from_edge))]
            else
                GraphData{ .time = 0 };

            var longest_toolip_text: c_int = 0;
            inline for (.{
                .{ "Total: %s", formatBytes(slice_item.total(), gui_state.packet_view) },
                .{ "TCP: %s", formatBytes(slice_item.tcp, gui_state.packet_view) },
                .{ "UDP: %s", formatBytes(slice_item.udp, gui_state.packet_view) },
            }) |pair| {
                const len = c.MeasureText(c.TextFormat(pair.@"0", pair.@"1"), 10);
                if (len > longest_toolip_text)
                    longest_toolip_text = len;
            }

            var rect = c.Rectangle{ .x = 0, .y = 0, .width = @as(f32, @floatFromInt(longest_toolip_text)) + 6, .height = 35 };
            tooltipTransform(&rect);

            c.DrawLine(mouse_x, 0, mouse_x, screen_height, SkyTransparent);
            _ = c.GuiPanel(rect, null);
            c.DrawText(c.TextFormat("Total: %s", formatBytes(slice_item.total(), gui_state.packet_view)), @as(c_int, @intFromFloat(rect.x + 3)), @as(c_int, @intFromFloat(rect.y + 3)), 10, c.GRAY);
            c.DrawText(c.TextFormat("TCP: %s", formatBytes(slice_item.tcp, gui_state.packet_view)), @as(c_int, @intFromFloat(rect.x + 3)), @as(c_int, @intFromFloat(rect.y + 13)), 10, c.GRAY);
            c.DrawText(c.TextFormat("UDP: %s", formatBytes(slice_item.udp, gui_state.packet_view)), @as(c_int, @intFromFloat(rect.x + 3)), @as(c_int, @intFromFloat(rect.y + 23)), 10, c.GRAY);
        }

        const dev_name_width = c.MeasureText(dev_name, 10);
        c.DrawText(dev_name, @divTrunc(screen_width, 2) - @divTrunc(dev_name_width, 2), 5, 10, c.GRAY);
        c.DrawText(c.TextFormat("%s", formatBytes(tallest_line, gui_state.packet_view)), 5, 5, 10, c.GRAY);
        c.DrawText(c.TextFormat("%s", formatBytes(tallest_line / 2, gui_state.packet_view)), 5, @divTrunc(screen_height, 2) + 5, 10, c.GRAY);
        _ = c.GuiCheckBox(c.Rectangle{ .x = @as(f32, @floatFromInt(@max(80, screen_width) - 80)), .y = 5, .width = 10, .height = 10 }, "Packet view", &gui_state.packet_view);
        c.DrawText(c.TextFormat("FPS: %d", c.GetFPS()), 200, 5, 10, c.GRAY);
        _ = c.GuiSpinner(c.Rectangle{ .x = @divTrunc(@as(f32, @floatFromInt(screen_width)), 2) - 20, .y = 20, .width = 100, .height = 16 }, "Smoothing ", &gui_state.smoothing, 0, 5, false);

        c.EndDrawing();
    }

    gui_state.gui_closed = true;
}

const SkyTransparent = c.Color{ .r = 102, .g = 191, .b = 255, .a = 150 };

pub fn formatBytes(bytes: u64, packets: bool) [*:0]const u8 {
    const float: f64 = @floatFromInt(bytes);
    const ending = if (packets) "".ptr else "B".ptr;
    const ending_with_space = if (packets) "".ptr else " B".ptr;
    if (bytes < 1024) {
        return c.TextFormat("%d%s", bytes, ending_with_space);
    } else if (bytes < 1024 * 1024) {
        return c.TextFormat("%.2f K%s", float / 1024, ending);
    } else if (bytes < 1024 * 1024 * 1024) {
        return c.TextFormat("%.2f M%s", float / 1024 / 1024, ending);
    } else {
        return c.TextFormat("%.2f G%s", float / 1024 / 1024 / 1024, ending);
    }
}

const ViewUnits = enum {
    bytes,
    packets,
};

pub fn tooltipTransform(rect: *c.Rectangle) void {
    const padding_x: c_int = 5;
    const padding_y: c_int = 0;

    const screen_height = c.GetScreenHeight();
    const mouse_x = c.GetMouseX();
    const mouse_y = c.GetMouseY();
    const rect_height: c_int = @intFromFloat(rect.height);
    const rect_width: c_int = @intFromFloat(rect.width);

    if (mouse_x > rect_width + padding_x) {
        rect.x = @floatFromInt(mouse_x - rect_width - padding_x);
    } else {
        rect.x = @floatFromInt(mouse_x + padding_x);
    }
    if (screen_height - mouse_y > rect_height + padding_y) {
        rect.y = @floatFromInt(mouse_y + padding_y);
    } else {
        rect.y = @floatFromInt(mouse_y - rect_height - padding_y);
    }
}

pub fn averageGraphData(raw_graph_data: []const GraphData, averaged_data: []GraphData, window_radius: usize) void {
    debug.assert(raw_graph_data.len == averaged_data.len);
    var iter = GraphDataAverageIterator.init(raw_graph_data, window_radius);
    for (0..averaged_data.len) |idx| {
        averaged_data[idx] = iter.next().?;
    }
}

pub const GraphDataAverageIterator = struct {
    slice: []const GraphData,
    index: usize,
    window_radius: usize,

    pub fn init(slice: []const GraphData, window_radius: usize) GraphDataAverageIterator {
        return GraphDataAverageIterator{
            .slice = slice,
            .index = 0,
            .window_radius = window_radius,
        };
    }

    pub fn next(self: *GraphDataAverageIterator) ?GraphData {
        if (self.index == self.slice.len) {
            return null;
        }

        defer self.index += 1;

        const begin = if (self.window_radius > self.index)
            0
        else
            self.index - self.window_radius;

        const end = if (self.window_radius > self.slice.len - 1 - self.index)
            self.slice.len
        else
            self.index + 1 + self.window_radius;

        const slice = self.slice[begin..end];

        var sum: GraphData = GraphData{};
        for (slice) |item| {
            sum.tcp += item.tcp;
            sum.udp += item.udp;
        }

        return GraphData{
            .udp = @divTrunc(sum.udp, slice.len),
            .tcp = @divTrunc(sum.tcp, slice.len),
            .time = self.slice[self.index].time,
        };
    }
};

pub fn AverageIterator(comptime Type: type) type {
    return struct {
        array: []const Type,
        index: usize,
        window_radius: usize,

        const Self = @This();

        pub fn init(array: []const Type, window_radius: usize) Self {
            return Self{
                .array = array,
                .index = 0,
                .window_radius = window_radius,
            };
        }

        pub fn next(self: *Self) ?Type {
            if (self.index == self.array.len) {
                return null;
            }

            defer self.index += 1;

            const begin = if (self.window_radius > self.index)
                0
            else
                self.index - self.window_radius;

            const end = if (self.window_radius > self.array.len - 1 - self.index)
                self.array.len
            else
                self.index + 1 + self.window_radius;

            const slice = self.array[begin..end];

            var sum: Type = 0;
            for (slice) |item| {
                sum += item;
            }

            const avg = @divTrunc(sum, slice.len);

            return avg;
        }
    };
}

test "AverageIterator" {
    const array = [_]u64{ 10, 30, 40, 50, 90, 200, 900 };
    var iter = AverageIterator(u64).init(&array, 1);
    try testing.expectEqual(@as(u64, 20), iter.next().?);
    try testing.expectEqual(@as(u64, 26), iter.next().?);
    try testing.expectEqual(@as(u64, 40), iter.next().?);
    try testing.expectEqual(@as(u64, 60), iter.next().?);
    try testing.expectEqual(@as(u64, 113), iter.next().?);
    try testing.expectEqual(@as(u64, 396), iter.next().?);
    try testing.expectEqual(@as(u64, 550), iter.next().?);
    try testing.expect(iter.next() == null);
    try testing.expect(iter.next() == null);

    const array2 = [_]u64{ 1, 5, 20, 100 };
    var iter2 = AverageIterator(u64).init(&array2, 0);
    try testing.expectEqual(@as(u64, 1), iter2.next().?);
    try testing.expectEqual(@as(u64, 5), iter2.next().?);
    try testing.expectEqual(@as(u64, 20), iter2.next().?);
    try testing.expectEqual(@as(u64, 100), iter2.next().?);
    try testing.expect(iter.next() == null);
}
