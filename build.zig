const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    _ = target;
    const optimize = b.standardOptimizeOption(.{});
    _ = optimize;

    const p9p = b.addModule("9p", .{ .source_file = .{ .path = "src/9p.zig" } });
    _ = p9p;
}
