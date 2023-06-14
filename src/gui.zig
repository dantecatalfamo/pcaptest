const std = @import("std");
const mem = std.mem;
const debug = std.debug;
const testing = std.testing;
const root = @import("root");
const c = @cImport({
    @cInclude("raylib.h");
});

pub fn runGui(gui_state: *const root.GuiState) void {
    const win_height = 200;
    const win_width  = 200;

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

        const slice = gui_state.graph_packets.slice();
        for (slice, 0..) |item, idx| {
            if (@intCast(isize, slice.len)-@intCast(isize, idx) > c.GetScreenWidth())
                continue;
            const screen_width = @intCast(u64, c.GetScreenWidth());
            const screen_height = @intCast(u64, c.GetScreenHeight());
            const x_over = @intCast(u64, @max(0, @intCast(i64, slice.len) - @intCast(i64, screen_width)));
            // const x_over = @intCast(u64, @max(0, @min(0, @intCast(i64, screen_width) - @intCast(i64, slice.len))));
            const tcp_x_pos = screen_width-@min(screen_width, slice.len)+(idx-x_over);
            const tcp_y_pos = screen_height-@min(item.tcp, screen_height);
            c.DrawRectangle(
                @intCast(c_int, tcp_x_pos),
                @intCast(c_int, tcp_y_pos),
                1,
                @intCast(c_int, item.tcp),
                c.GREEN
            );
        }

        c.DrawText(c.TextFormat("Device: %s", dev_name), 10, 10, 20, c.LIGHTGRAY);

        c.EndDrawing();
    }

    std.process.exit(0);
}
