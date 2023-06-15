const std = @import("std");
const mem = std.mem;
const math = std.math;
const debug = std.debug;
const testing = std.testing;
const root = @import("root");
const c = @cImport({
    @cInclude("raylib.h");
});

pub fn runGui(gui_state: *const root.GuiState) void {
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

        const packet_slice = if (c.IsMouseButtonDown(c.MOUSE_BUTTON_LEFT))
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
            c.DrawLine(x_line, 0, x_line, @intCast(c_int, screen_height), c.LIGHTGRAY);
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

        c.DrawText(c.TextFormat("Device: %s", dev_name), 10, 10, 20, c.GRAY);
        c.DrawText(c.TextFormat("Largest: %d", tallest_line), 10, 30, 20, c.GRAY);
        const showing_type = if (c.IsMouseButtonDown(c.MOUSE_BUTTON_LEFT)) "Packets".ptr else "Bytes".ptr;
        c.DrawText(c.TextFormat("Showing: %s", showing_type), 10, 50, 20, c.GRAY);

        c.EndDrawing();
    }

    std.process.exit(0);
}
