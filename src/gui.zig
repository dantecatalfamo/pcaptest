const std = @import("std");
const mem = std.mem;
const math = std.math;
const debug = std.debug;
const testing = std.testing;
const root = @import("root");
const c = @cImport({
    @cInclude("raylib.h");
    @cInclude("raygui.h");
});

pub fn runGui(gui_state: *root.GuiState) void {
    const win_height = 200;
    const win_width  = 400;

    c.SetConfigFlags(c.FLAG_WINDOW_RESIZABLE);
    c.InitWindow(win_width, win_height, "PcapTest");
    defer c.CloseWindow();

    c.SetTargetFPS(60);

    while (!c.WindowShouldClose()) {

        const dev_name = if (gui_state.device) |dev|
            @ptrCast([*:0]u8, dev.name)
        else
            "No device";

        c.BeginDrawing();
        c.ClearBackground(c.RAYWHITE);

        const packet_slice = if (gui_state.packet_view)
            gui_state.graph_packets.slice()
        else
            gui_state.graph_bytes.slice();

        const screen_width = @intCast(u64, c.GetScreenWidth());
        const screen_height = @intCast(u64, c.GetScreenHeight());
        const x_over = @intCast(u64, @max(0, @intCast(i64, packet_slice.len) - @intCast(i64, screen_width)));

        const tallest_line = blk: {
            var largest: u64 = 0;
            for (packet_slice[x_over..]) |item| {
                if (item.total() > largest) {
                    largest = item.total();
                }
            }
            break :blk largest;
        };
        const scale = @intToFloat(f64, tallest_line) / @intToFloat(f64, screen_height);

        var x_line = @intCast(c_int, screen_width);
        while (x_line > 0) : (x_line -= 60) {
            if (x_line == screen_width)
                continue;
            var y_line = @intCast(c_int, 3);
            while (y_line < screen_height) : (y_line += 10) {
                c.DrawLine(x_line, y_line, x_line, y_line + 5, c.LIGHTGRAY);
            }
        }

        var y_dotted_line = @intCast(c_int, 3);
        while (y_dotted_line < screen_width) : (y_dotted_line += 10) {
            c.DrawLine(y_dotted_line, @divTrunc(@intCast(c_int, screen_height), 2), y_dotted_line + 5, @divTrunc( @intCast(c_int, screen_height), 2), c.LIGHTGRAY);
        }

        for (packet_slice, 0..) |item, idx| {
            if (@intCast(isize, packet_slice.len)-@intCast(isize, idx) > c.GetScreenWidth())
                continue;
            const tcp_scaled = @floatToInt(u64, @intToFloat(f64, item.tcp) / scale);
            const udp_scaled = @floatToInt(u64, @intToFloat(f64, item.udp) / scale);

            const x_pos = screen_width-@min(screen_width, packet_slice.len)+(idx-x_over);
            const tcp_y_pos = screen_height-@min(tcp_scaled, screen_height);
            const udp_y_pos = screen_height-@min(udp_scaled+tcp_scaled, screen_height);
            c.DrawRectangle(
                @intCast(c_int, x_pos),
                @intCast(c_int, tcp_y_pos),
                1,
                @intCast(c_int, tcp_scaled),
                c.LIME
            );
            c.DrawRectangle(
                @intCast(c_int, x_pos),
                @intCast(c_int, udp_y_pos),
                1,
                @intCast(c_int, udp_scaled),
                c.MAROON
            );
        }

        if (c.IsCursorOnScreen()) {
            const mouse_x = c.GetMouseX();

            const from_edge = @intCast(c_int, screen_width) - mouse_x;
            const slice_item = if (from_edge <= packet_slice.len)
                packet_slice[packet_slice.len-@intCast(usize, from_edge)]
            else
                root.GraphData{ .time = 0 };


            var longest_toolip_text: c_int = 0;
            inline for (.{
                .{ "Total: %d", slice_item.total() },
                .{ "TCP: %d", slice_item.tcp },
                .{ "UDP: %d", slice_item.udp },
            }) |pair| {
                const len = c.MeasureText(c.TextFormat(pair.@"0", pair.@"1"), 10);
                if (len > longest_toolip_text)
                    longest_toolip_text = len;
            }

            var rect = c.Rectangle{ .x = 0, .y = 0, .width = @intToFloat(f32, longest_toolip_text) + 6, .height = 35 };
            tooltipTransform(&rect);

            c.DrawLine(mouse_x, 0, mouse_x, @intCast(c_int, screen_height), SkyTransparent);
            _ = c.GuiPanel(rect, null);
            c.DrawText(c.TextFormat("Total: %d", slice_item.total()), @floatToInt(c_int, rect.x + 3), @floatToInt(c_int, rect.y + 3), 10, c.GRAY);
            c.DrawText(c.TextFormat("TCP: %d", slice_item.tcp), @floatToInt(c_int, rect.x + 3), @floatToInt(c_int, rect.y + 13), 10, c.GRAY);
            c.DrawText(c.TextFormat("UDP: %d", slice_item.udp), @floatToInt(c_int, rect.x + 3), @floatToInt(c_int, rect.y + 23), 10, c.GRAY);
        }

        const showing_type = if (gui_state.packet_view) "Packets".ptr else "Bytes".ptr;
        const dev_name_width = c.MeasureText(dev_name, 10);
        c.DrawText(dev_name, @divTrunc(@intCast(c_int, screen_width), 2) - @divTrunc(dev_name_width, 2), 5, 10, c.GRAY);
        c.DrawText(c.TextFormat("%d %s", tallest_line, showing_type), 5, 5, 10, c.GRAY);
        c.DrawText(c.TextFormat("%d", tallest_line / 2), 5, @divTrunc(@intCast(c_int, screen_height), 2) + 5, 10, c.GRAY);
        _ = c.GuiCheckBox(c.Rectangle{ .x = @intToFloat(f32, @max(80, screen_width) - 80), .y = 5, .width = 10, .height = 10 }, "Packet view", &gui_state.packet_view);

        c.EndDrawing();
    }

    std.process.exit(0);
}

const SkyTransparent = c.Color{ .r = 102, .g = 191, .b = 255, .a = 150 };

pub fn tooltipTransform(rect: *c.Rectangle) void {
    const padding_x: c_int = 5;
    const padding_y: c_int = 0;

    const screen_height = c.GetScreenHeight();
    const mouse_x = c.GetMouseX();
    const mouse_y = c.GetMouseY();
    const rect_height = @floatToInt(c_int, rect.height);
    const rect_width = @floatToInt(c_int, rect.width);

    if (mouse_x > rect_width + padding_x) {
        rect.x = @intToFloat(f32, mouse_x - rect_width - padding_x);
    } else {
        rect.x = @intToFloat(f32, mouse_x + padding_x);
    }
    if (screen_height - mouse_y > rect_height + padding_y) {
        rect.y = @intToFloat(f32, mouse_y + padding_y);
    } else {
        rect.y = @intToFloat(f32, mouse_y - rect_height - padding_y);
    }
}
