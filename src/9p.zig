const std = @import("std");

pub fn ReadError(reader: anytype) type {
    return error{InvalidMessage} || ReadError(reader);
}

pub fn WriteError(writer: anytype) type {
    return WriteError(writer);
}

pub const MessageReadError = error{
    InvalidMessage,
    MessageTooLarge,
    UnsupportedMessageType,
};

pub fn readMessage(comptime MessageType: type, reader: anytype, buf: []u8) (MessageReadError || @TypeOf(reader).Error)!MessageType {
    const size = try reader.readIntBig(u32);
    // Minimum message size: 4 byte size + 1 byte type + 2 byte tag == 7 bytes
    if (size < 7) return error.InvalidMessage;
    const @"type" = std.meta.intToEnum(MessageType.Type, try reader.readByte()) catch return error.UnsupportedMessageType;
    const tag: Tag = @enumFromInt(try reader.readIntBig(u16));
    const data_buf = buf[0 .. size - 7];
    try reader.readNoEof(data_buf);
    var data_stream = std.io.fixedBufferStream(data_buf);
    const data = switch (@"type") {
        inline else => |data_tag| std.meta.TagPayload(MessageType.Data, data_tag).read(data_stream.reader()) catch |e| switch (e) {
            error.Overflow => return error.InvalidMessage,
            else => |other| return other,
        },
    };
    if (data_stream.pos != data_buf.len) return error.InvalidMessage;
    return .{ .tag = tag, .data = data };
}

pub fn writeMessage(comptime MessageType: type, writer: anytype, message: MessageType) WriteError(writer)!void {
    var counting_writer = std.io.countingWriter(std.io.null_writer);
    switch (message.data) {
        inline else => |data| try data.write(counting_writer.writer()),
    }
    const size = 7 + counting_writer.bytes_written;
    try writer.writeIntBig(u32, @intCast(size));
    try writer.writeByte(@intFromEnum(message));
    try writer.writeIntBig(u16, @intFromEnum(message.tag));
    switch (message.data) {
        inline else => |data| try data.write(writer),
    }
}

pub const Message = struct {
    pub const version = "9P2000";

    pub const Type = enum(u8) {
        tversion = 100,
        rversion = 101,
        tauth = 102,
        rauth = 103,
        tattach = 104,
        rattach = 105,
        rerror = 107,
        tflush = 108,
        rflush = 109,
        twalk = 110,
        rwalk = 111,
        topen = 112,
        ropen = 113,
        tcreate = 114,
        rcreate = 115,
        tread = 116,
        rread = 117,
        twrite = 118,
        rwrite = 119,
        tclunk = 120,
        rclunk = 121,
        tremove = 122,
        rremove = 123,
        tstat = 124,
        rstat = 125,
        twstat = 126,
        rwstat = 127,
    };

    tag: Tag,
    data: Data,

    pub fn read(reader: anytype, buf: []u8) (MessageReadError || @TypeOf(reader).Error)!Message {
        return try readMessage(Message, reader, buf);
    }

    pub fn write(message: Message, writer: anytype) @TypeOf(writer).Error!void {
        try writeMessage(Message, writer, message);
    }

    pub const Data = union(Type) {
        tversion: Tversion,
        rversion: Rversion,
        tauth: Tauth,
        rauth: Rauth,
        tattach: Tattach,
        rattach: Rattach,
        rerror: Rerror,
        tflush: Tflush,
        rflush: Rflush,
        twalk: Twalk,
        rwalk: Rwalk,
        topen: Topen,
        ropen: Ropen,
        tcreate: Tcreate,
        rcreate: Rcreate,
        tread: Tread,
        rread: Rread,
        twrite: Twrite,
        rwrite: Rwrite,
        tclunk: Tclunk,
        rclunk: Rclunk,
        tremove: Tremove,
        rremove: Rremove,
        tstat: Tstat,
        rstat: Rstat,
        twstat: Twstat,
        rwstat: Rwstat,
    };

    pub const Tversion = struct {
        msize: u32,
        version: []const u8,

        pub fn read(reader: anytype) ReadError(reader)!Tversion {
            return .{
                .msize = try reader.readIntBig(u32),
                .version = try readSlice(reader, u16),
            };
        }

        pub fn write(tversion: Tversion, writer: anytype) WriteError(writer)!void {
            try writer.writeIntBig(u32, tversion.msize);
            try writeSlice(writer, u16, tversion.version);
        }
    };

    pub const Rversion = struct {
        msize: u32,
        version: []const u8,

        pub fn read(reader: anytype) ReadError(reader)!Rversion {
            return .{
                .msize = try reader.readIntBig(u32),
                .version = try readSlice(reader, u16),
            };
        }

        pub fn write(rversion: Rversion, writer: anytype) WriteError(writer)!void {
            try writer.writeIntBig(u32, rversion.msize);
            try writeSlice(writer, u16, rversion.version);
        }
    };

    pub const Tauth = struct {
        afid: Fid,
        uname: []const u8,
        aname: []const u8,

        pub fn read(reader: anytype) ReadError(reader)!Tauth {
            return .{
                .afid = try Fid.read(reader),
                .uname = try readSlice(reader, u16),
                .aname = try readSlice(reader, u16),
            };
        }

        pub fn write(tauth: Tauth, writer: anytype) WriteError(writer)!void {
            try tauth.afid.write(writer);
            try writeSlice(writer, u16, tauth.uname);
            try writeSlice(writer, u16, tauth.aname);
        }
    };

    pub const Rauth = struct {
        aqid: Qid,

        pub fn read(reader: anytype) ReadError(reader)!Rauth {
            return .{ .aqid = try Qid.read(reader) };
        }

        pub fn write(rauth: Rauth, writer: anytype) WriteError(writer)!void {
            try rauth.aqid.write(writer);
        }
    };

    pub const Tattach = struct {
        fid: Fid,
        afid: Fid,
        uname: []const u8,
        aname: []const u8,

        pub fn read(reader: anytype) ReadError(reader)!Tattach {
            return .{
                .fid = try Fid.read(reader),
                .afid = try Fid.read(reader),
                .uname = try readSlice(reader, u16),
                .aname = try readSlice(reader, u16),
            };
        }

        pub fn write(tattach: Tattach, writer: anytype) WriteError(writer)!void {
            try tattach.fid.write(writer);
            try tattach.afid.write(writer);
            try writeSlice(writer, u16, tattach.uname);
            try writeSlice(writer, u16, tattach.aname);
        }
    };

    pub const Rattach = struct {
        qid: Qid,

        pub fn read(reader: anytype) ReadError(reader)!Rattach {
            return .{ .qid = try Qid.read(reader) };
        }

        pub fn write(rattach: Rattach, writer: anytype) WriteError(writer)!void {
            try rattach.qid.write(writer);
        }
    };

    pub const Rerror = struct {
        ename: []const u8,

        pub fn read(reader: anytype) ReadError(reader)!Rerror {
            return .{ .ename = try readSlice(reader, u16) };
        }

        pub fn write(rerror: Rerror, writer: anytype) WriteError(writer)!void {
            try writeSlice(writer, u16, rerror.ename);
        }
    };

    pub const Tflush = struct {
        oldtag: u16,

        pub fn read(reader: anytype) ReadError(reader)!Tflush {
            return .{ .oldtag = try reader.readIntBig(u16) };
        }

        pub fn write(tflush: Tflush, writer: anytype) WriteError(writer)!void {
            try writer.writeIntBig(u16, tflush.oldtag);
        }
    };

    pub const Rflush = struct {
        pub fn read(reader: anytype) ReadError(reader)!Rflush {
            return .{};
        }

        pub fn write(rflush: Rflush, writer: anytype) WriteError(writer)!void {
            _ = rflush;
        }
    };

    pub const Twalk = struct {
        fid: Fid,
        newfid: Fid,
        wname: std.BoundedArray([]const u8, 16),

        pub fn read(reader: anytype) ReadError(reader)!Twalk {
            return .{
                .fid = try Fid.read(reader),
                .newfid = try Fid.read(reader),
                .wname = wname: {
                    var wname = std.BoundedArray([]const u8, 16){};
                    const nwname = try reader.readIntBig(u16);
                    if (nwname > 16) return error.InvalidMessage;
                    for (0..nwname) |_| {
                        wname.appendAssumeCapacity(try readSlice(reader, u16));
                    }
                    break :wname wname;
                },
            };
        }

        pub fn write(twalk: Twalk, writer: anytype) WriteError(writer)!void {
            try twalk.fid.write(writer);
            try twalk.newfid.write(writer);
            try writer.writeIntBig(u16, twalk.wname.len);
            for (twalk.wname.buffer) |name| {
                try writeSlice(writer, u16, name);
            }
        }
    };

    pub const Rwalk = struct {
        wqid: std.BoundedArray(Qid, 16),

        pub fn read(reader: anytype) ReadError(reader)!Rwalk {
            return .{
                .wqid = wqid: {
                    var wqid = std.BoundedArray(Qid, 16);
                    const nwqid = try reader.readIntBig(u16);
                    if (nwqid > 16) return error.InvalidMessage;
                    for (0..nwqid) |_| {
                        wqid.appendAssumeCapacity(try Qid.read(reader));
                    }
                    break :wqid;
                },
            };
        }

        pub fn write(rwalk: Rwalk, writer: anytype) WriteError(writer)!void {
            try writer.writeIntBig(u16, rwalk.wqid.len);
            for (rwalk.wqid.buffer) |qid| {
                try qid.write(writer);
            }
        }
    };

    pub const Topen = struct {
        fid: Fid,
        mode: u8,

        pub fn read(reader: anytype) ReadError(reader)!Topen {
            return .{
                .fid = try Fid.read(reader),
                .mode = try reader.readByte(),
            };
        }

        pub fn write(topen: Topen, writer: anytype) WriteError(writer)!void {
            try topen.fid.write(writer);
            try writer.writeByte(topen.mode);
        }
    };

    pub const Ropen = struct {
        qid: Qid,
        iounit: u32,

        pub fn read(reader: anytype) ReadError(reader)!Ropen {
            return .{
                .qid = try Qid.read(reader),
                .iounit = try reader.readIntBig(u32),
            };
        }

        pub fn write(ropen: Ropen, writer: anytype) WriteError(writer)!void {
            try ropen.qid.write(writer);
            try writer.writeIntBig(u32, ropen.iounit);
        }
    };

    pub const Tcreate = struct {
        fid: Fid,
        name: []const u8,
        perm: u32,
        mode: u8,

        pub fn read(reader: anytype) ReadError(reader)!Tcreate {
            return .{
                .fid = try Fid.read(reader),
                .name = try readSlice(reader, u16),
                .perm = try reader.readIntBig(u32),
                .mode = try reader.readByte(),
            };
        }

        pub fn write(tcreate: Tcreate, writer: anytype) WriteError(writer)!void {
            try tcreate.fid.write(writer);
            try writeSlice(writer, u16, tcreate.name);
            try writer.writeIntBig(u32, tcreate.perm);
            try writer.writeByte(tcreate.mode);
        }
    };

    pub const Rcreate = struct {
        qid: Qid,
        iounit: u32,

        pub fn read(reader: anytype) ReadError(reader)!Rcreate {
            return .{
                .qid = try Qid.read(reader),
                .iounit = try reader.readIntBig(u32),
            };
        }

        pub fn write(rcreate: Rcreate, writer: anytype) WriteError(writer)!void {
            try rcreate.qid.write(writer);
            try writer.writeIntBig(u32, rcreate.iounit);
        }
    };

    pub const Tread = struct {
        fid: Fid,
        offset: u64,
        count: u32,

        pub fn read(reader: anytype) ReadError(reader)!Tread {
            return .{
                .fid = try Fid.read(reader),
                .offset = try reader.readIntBig(u64),
                .count = try reader.readIntBig(u32),
            };
        }

        pub fn write(tread: Tread, writer: anytype) WriteError(writer)!void {
            try tread.fid.write(writer);
            try writer.writeIntBig(u64, tread.offset);
            try writer.writeIntBig(u32, tread.count);
        }
    };

    pub const Rread = struct {
        data: []const u8,

        pub fn read(reader: anytype) ReadError(reader)!Rread {
            return .{ .data = try readSlice(reader, u32) };
        }

        pub fn write(rread: Rread, writer: anytype) WriteError(writer)!void {
            try writeSlice(writer, u32, rread.data);
        }
    };

    pub const Twrite = struct {
        fid: Fid,
        offset: u64,
        data: []const u8,

        pub fn read(reader: anytype) ReadError(reader)!Twrite {
            return .{
                .fid = try Fid.read(reader),
                .offset = try reader.readIntBig(u64),
                .data = try readSlice(reader, u32),
            };
        }

        pub fn write(twrite: Twrite, writer: anytype) WriteError(writer)!void {
            try twrite.fid.write(writer);
            try writer.writeIntBig(u64, twrite.offset);
            try writeSlice(writer, u32, twrite.data);
        }
    };

    pub const Rwrite = struct {
        count: u32,

        pub fn read(reader: anytype) ReadError(reader)!Rwrite {
            return .{ .count = try reader.readIntBig(u32) };
        }

        pub fn write(rwrite: Rwrite, writer: anytype) WriteError(writer)!void {
            try writer.writeIntBig(u32, rwrite.count);
        }
    };

    pub const Tclunk = struct {
        fid: Fid,

        pub fn read(reader: anytype) ReadError(reader)!Tclunk {
            return .{ .fid = try Fid.read(reader) };
        }

        pub fn write(tclunk: Tclunk, writer: anytype) WriteError(writer)!void {
            try tclunk.fid.write(writer);
        }
    };

    pub const Rclunk = struct {
        pub fn read(reader: anytype) ReadError(reader)!Rclunk {
            return .{};
        }

        pub fn write(rclunk: Rclunk, writer: anytype) WriteError(writer)!void {
            _ = rclunk;
        }
    };

    pub const Tremove = struct {
        fid: Fid,

        pub fn read(reader: anytype) ReadError(reader)!Tremove {
            return .{ .fid = try Fid.read(reader) };
        }

        pub fn write(tremove: Tremove, writer: anytype) WriteError(writer)!void {
            try tremove.fid.write(writer);
        }
    };

    pub const Rremove = struct {
        pub fn read(reader: anytype) ReadError(reader)!Rremove {
            return .{};
        }

        pub fn write(rremove: Rremove, writer: anytype) WriteError(writer)!void {
            _ = rremove;
        }
    };

    pub const Tstat = struct {
        fid: Fid,

        pub fn read(reader: anytype) ReadError(reader)!Tstat {
            return .{ .fid = try Fid.read(reader) };
        }

        pub fn write(tstat: Tstat, writer: anytype) WriteError(writer)!void {
            try tstat.fid.write(writer);
        }
    };

    pub const Rstat = struct {
        stat: Stat,

        pub fn read(reader: anytype) ReadError(reader)!Rstat {
            return .{ .stat = try Stat.read(reader) };
        }

        pub fn write(rstat: Rstat, writer: anytype) WriteError(writer)!void {
            try rstat.stat.write(writer);
        }
    };

    pub const Twstat = struct {
        fid: Fid,
        stat: Stat,

        pub fn read(reader: anytype) ReadError(reader)!Twstat {
            return .{
                .fid = try Fid.read(reader),
                .stat = try Stat.read(reader),
            };
        }

        pub fn write(twstat: Twstat, writer: anytype) WriteError(writer)!void {
            try twstat.fid.write(writer);
            try twstat.stat.write(writer);
        }
    };

    pub const Rwstat = struct {
        pub fn read(reader: anytype) ReadError(reader)!Rwstat {
            return .{};
        }

        pub fn write(rwstat: Rwstat, writer: anytype) WriteError(writer)!void {
            _ = rwstat;
        }
    };
};

pub const Tag = enum(u16) {
    notag = 0xFFFF,
    _,
};

pub const Fid = enum(u32) {
    _,

    pub fn read(reader: anytype) ReadError(reader)!Fid {
        return @enumFromInt(try reader.readIntBig(u32));
    }

    pub fn write(fid: Fid, writer: anytype) WriteError(writer)!void {
        try writer.writeIntBig(u32, @intFromEnum(fid));
    }
};

pub const Qid = struct {
    type: u8,
    version: u32,
    path: u64,

    pub fn read(reader: anytype) ReadError(reader)!Qid {
        return .{
            .type = try reader.readByte(),
            .version = try reader.readIntBig(u32),
            .path = try reader.readIntBig(u64),
        };
    }

    pub fn write(qid: Qid, writer: anytype) WriteError(writer)!void {
        try writer.writeByte(qid.type);
        try writer.writeIntBig(u32, qid.version);
        try writer.writeIntBig(u64, qid.path);
    }
};

pub const Stat = struct {
    type: u16,
    dev: u32,
    qid: Qid,
    mode: u32,
    atime: u32,
    mtime: u32,
    length: u64,
    name: []const u8,
    uid: []const u8,
    gid: []const u8,
    muid: []const u8,

    pub fn size(stat: Stat) u16 {
        return 2 + // type
            4 + // dev
            13 + // qid
            4 + // mode
            4 + // atime
            4 + // mtime
            8 + // length
            2 + stat.name.len +
            2 + stat.uid.len +
            2 + stat.gid.len +
            2 + stat.muid.len;
    }

    pub fn read(reader: anytype) ReadError(reader)!Stat {
        const expected_size = try reader.readIntBig(u16);
        const start_pos = reader.context.pos;
        const stat = Stat{
            .type = try reader.readIntBig(u16),
            .dev = try reader.readIntBig(u32),
            .qid = try Qid.read(reader),
            .mode = try reader.readIntBig(u32),
            .atime = try reader.readIntBig(u32),
            .mtime = try reader.readIntBig(u32),
            .length = try reader.readIntBig(u64),
            .name = try readSlice(reader, u16),
            .uid = try readSlice(reader, u16),
            .gid = try readSlice(reader, u16),
            .muid = try readSlice(reader, u16),
        };
        if (reader.context.pos != start_pos + expected_size) return error.InvalidMessage;
        return stat;
    }

    pub fn write(stat: Stat, writer: anytype) WriteError(writer)!void {
        try writer.writeIntBig(u16, stat.size());
        try writer.writeIntBig(u16, stat.type);
        try writer.writeIntBig(u32, stat.dev);
        try stat.qid.write(writer);
        try writer.writeIntBig(u32, stat.mode);
        try writer.writeIntBig(u32, stat.atime);
        try writer.writeIntBig(u32, stat.mtime);
        try writer.writeIntBig(u64, stat.length);
        try writeSlice(writer, u16, stat.name);
        try writeSlice(writer, u16, stat.uid);
        try writeSlice(writer, u16, stat.gid);
        try writeSlice(writer, u16, stat.muid);
    }
};

pub fn readSlice(reader: anytype, comptime LenType: type) ReadError(reader)![]const u8 {
    const len = try reader.readIntBig(LenType);
    const fbs = reader.context;
    if (fbs.pos + len >= fbs.buffer.len) {
        return error.EndOfStream;
    }
    const slice = fbs.buffer[fbs.pos .. fbs.pos + len];
    fbs.pos += len;
    return slice;
}

pub fn writeSlice(writer: anytype, comptime LenType: type, slice: []const u8) WriteError(writer)!void {
    try writer.writeIntBig(LenType, @intCast(slice.len));
    try writer.writeAll(slice);
}
