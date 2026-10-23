const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const w = std.unicode.utf8ToUtf16LeStringLiteral;

comptime {
    if (builtin.os.tag != .windows) @compileError("The CNG oracle requires Windows");
    if (!std.mem.eql(u8, builtin.zig_version_string, "0.17.0")) @compileError("Use Zig 0.17.0");
}

extern "bcrypt" fn BCryptOpenAlgorithmProvider(*?*anyopaque, [*:0]const u16, ?[*:0]const u16, u32) callconv(.winapi) i32;
extern "bcrypt" fn BCryptCloseAlgorithmProvider(*anyopaque, u32) callconv(.winapi) i32;
extern "bcrypt" fn BCryptGenerateKeyPair(*anyopaque, *?*anyopaque, u32, u32) callconv(.winapi) i32;
extern "bcrypt" fn BCryptFinalizeKeyPair(*anyopaque, u32) callconv(.winapi) i32;
extern "bcrypt" fn BCryptDestroyKey(*anyopaque) callconv(.winapi) i32;
extern "bcrypt" fn BCryptExportKey(*anyopaque, ?*anyopaque, [*:0]const u16, [*]u8, u32, *u32, u32) callconv(.winapi) i32;
extern "bcrypt" fn BCryptSignHash(*anyopaque, ?*const anyopaque, [*]const u8, u32, [*]u8, u32, *u32, u32) callconv(.winapi) i32;
extern "bcrypt" fn BCryptVerifySignature(*anyopaque, ?*const anyopaque, [*]const u8, u32, [*]const u8, u32, u32) callconv(.winapi) i32;
extern "bcrypt" fn BCryptHash(*anyopaque, ?[*]const u8, u32, [*]const u8, u32, [*]u8, u32) callconv(.winapi) i32;
const Padding = extern struct { algorithm: [*:0]const u16 };

fn check(status: i32) !void {
    if (status < 0) return error.CngFailed;
}

fn closeProvider(provider: *anyopaque) void {
    check(BCryptCloseAlgorithmProvider(provider, 0)) catch @panic("CNG provider cleanup failed");
}

fn destroyKey(handle: *anyopaque) void {
    check(BCryptDestroyKey(handle)) catch @panic("CNG key cleanup failed");
}

// Private keys exist only in CNG handles. This tool exports public blobs only.
const Key = struct {
    provider: *anyopaque,
    handle: *anyopaque,
    rsa: bool,

    fn create(rsa: bool, bits: u32) !Key {
        var provider: ?*anyopaque = null;
        try check(BCryptOpenAlgorithmProvider(&provider, if (rsa) w("RSA") else w("ECDSA_P384"), null, 0));
        errdefer closeProvider(provider.?);
        var handle: ?*anyopaque = null;
        try check(BCryptGenerateKeyPair(provider.?, &handle, bits, 0));
        errdefer destroyKey(handle.?);
        try check(BCryptFinalizeKeyPair(handle.?, 0));
        return .{ .provider = provider.?, .handle = handle.?, .rsa = rsa };
    }

    fn deinit(self: *Key) void {
        destroyKey(self.handle);
        closeProvider(self.provider);
        self.* = undefined;
    }

    fn public(self: *const Key, allocator: Allocator, id: []const u8) !Value {
        var blob: [1024]u8 = undefined;
        var length: u32 = 0;
        try check(BCryptExportKey(self.handle, null, if (self.rsa) w("RSAPUBLICBLOB") else w("ECCPUBLICBLOB"), &blob, blob.len, &length, 0));
        if (length > blob.len) return error.InvalidPublicBlob;
        var result: Value = .{ .object = .empty };
        if (self.rsa) {
            if (length < 24 or std.mem.readInt(u32, blob[0..4], .little) != 0x31415352) return error.InvalidPublicBlob;
            const e = std.mem.readInt(u32, blob[8..12], .little);
            const n = std.mem.readInt(u32, blob[12..16], .little);
            if (e > 4 or n > 512 or 24 + e + n != length) return error.InvalidPublicBlob;
            try put(&result, allocator, "kty", .{ .string = "RSA" });
            try put(&result, allocator, "use", .{ .string = "sig" });
            try put(&result, allocator, "kid", .{ .string = id });
            try put(&result, allocator, "n", .{ .string = try base64(allocator, blob[24 + e ..][0..n], true) });
            try put(&result, allocator, "e", .{ .string = try base64(allocator, blob[24..][0..e], true) });
        } else {
            if (length != 104 or std.mem.readInt(u32, blob[0..4], .little) != 0x33534345 or std.mem.readInt(u32, blob[4..8], .little) != 48) return error.InvalidPublicBlob;
            try put(&result, allocator, "kty", .{ .string = "EC" });
            try put(&result, allocator, "crv", .{ .string = "P-384" });
            try put(&result, allocator, "x", .{ .string = try base64(allocator, blob[8..56], true) });
            try put(&result, allocator, "y", .{ .string = try base64(allocator, blob[56..104], true) });
        }
        return result;
    }

    fn sign(self: *const Key, allocator: Allocator, input: []const u8) ![]const u8 {
        var hash: [48]u8 = undefined;
        var hashing: ?*anyopaque = null;
        try check(BCryptOpenAlgorithmProvider(&hashing, if (self.rsa) w("SHA256") else w("SHA384"), null, 0));
        defer closeProvider(hashing.?);
        const digest = hash[0..@as(usize, if (self.rsa) 32 else 48)];
        try check(BCryptHash(hashing.?, null, 0, input.ptr, @intCast(input.len), digest.ptr, @intCast(digest.len)));
        const padding: Padding = .{ .algorithm = w("SHA256") };
        const pointer: ?*const anyopaque = if (self.rsa) &padding else null;
        const flags: u32 = if (self.rsa) 2 else 0;
        var signature: [512]u8 = undefined;
        var length: u32 = 0;
        try check(BCryptSignHash(self.handle, pointer, digest.ptr, @intCast(digest.len), &signature, signature.len, &length, flags));
        if (length > signature.len or (!self.rsa and length != 96)) return error.InvalidSignatureLength;
        try check(BCryptVerifySignature(self.handle, pointer, digest.ptr, @intCast(digest.len), &signature, length, flags));
        return allocator.dupe(u8, signature[0..length]);
    }
};

const issuer = "https://synthetic.service.example/";
const audience = "shulvyr-synthetic-multiplayer";
const key_bits = [_]u32{ 2048, 3072, 4096 };
const zeros = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
const ones = "01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:01";
const payload = "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"" ++ zeros ++ "\"}]}";
const media = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:synthetic\r\na=ice-pwd:synthetic-only\r\na=setup:actpass\r\na=max-message-size:65536\r\n";

const Case = struct { name: []const u8, attribute: []const u8, sdp: []const u8, @"error": ?[]const u8, key_bits: u32 };

fn put(object: *Value, allocator: Allocator, key: []const u8, value: Value) !void {
    try object.object.put(allocator, key, value);
}

fn base64(allocator: Allocator, input: []const u8, url: bool) ![]const u8 {
    const encoder = if (url) std.base64.url_safe_no_pad.Encoder else std.base64.standard.Encoder;
    return encoder.encode(try allocator.alloc(u8, encoder.calcSize(input.len)), input);
}

fn json(allocator: Allocator, value: anytype) ![]const u8 {
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 2) return error.ExpectedNewOutputDirectory;
    var output = try std.Io.Dir.cwd().openDir(init.io, args[1], .{});
    defer output.close(init.io);
    var rsa: [4]Key = undefined;
    var initialized: usize = 0;
    defer for (rsa[0..initialized]) |*key| key.deinit();
    for ([_]u32{ 2048, 3072, 4096, 2048 }, 0..) |bits, index| {
        rsa[index] = try Key.create(true, bits);
        initialized += 1;
    }
    var client = try Key.create(false, 384);
    defer client.deinit();
    var other_client = try Key.create(false, 384);
    defer other_client.deinit();
    var public_keys: [3]Value = undefined;
    for (&public_keys, 0..) |*key, index| key.* = try rsa[index].public(allocator, try std.fmt.allocPrint(allocator, "rsa-{d}", .{key_bits[index]}));
    const cpk = try client.public(allocator, "unused");
    const names = [_][]const u8{
        "valid_2048",     "valid_3072",            "valid_4096",       "audience_array",        "missing_optional_times",
        "wrong_issuer",   "wrong_audience",        "missing_audience", "missing_expiry",        "missing_subject",
        "expired",        "expiry_boundary",       "future_nbf",       "future_iat",            "fractional_expiry",
        "null_expiry",    "invalid_time_order",    "unknown_kid",      "unsupported_algorithm", "critical_header",
        "b64_header",     "embedded_attacker_key", "wrong_proof_key",  "wrong_fingerprint",     "all_scopes",
        "shadowed_media",
    };
    var cases: [names.len]Case = undefined;
    for (names, &cases, 0..) |case_name, *case, index| {
        const rsa_index: usize = if (index == 1) 1 else if (index == 2) 2 else 0;
        const kid = try std.fmt.allocPrint(allocator, "rsa-{d}", .{key_bits[rsa_index]});
        var header = try std.json.parseFromSliceLeaky(Value, allocator, try json(allocator, .{ .alg = "RS256", .kid = kid, .typ = "JWT" }), .{});
        var claims = try std.json.parseFromSliceLeaky(Value, allocator, try json(allocator, .{ .iss = issuer, .aud = audience, .sub = "synthetic-player", .exp = @as(i64, 2300), .iat = @as(i64, 1000), .nbf = @as(i64, 1000), .cpk = cpk }), .{});
        var wanted: ?[]const u8 = null;
        switch (index) {
            3 => {
                var values: Value = .{ .array = .init(allocator) };
                try values.array.append(.{ .string = "another-audience" });
                try values.array.append(.{ .string = audience });
                try put(&claims, allocator, "aud", values);
            },
            4 => {
                _ = claims.object.swapRemove("iat");
                _ = claims.object.swapRemove("nbf");
            },
            5 => {
                try put(&claims, allocator, "iss", .{ .string = "https://attacker.example/" });
                wanted = "ServiceIssuerMismatch";
            },
            6 => {
                try put(&claims, allocator, "aud", .{ .string = "other" });
                wanted = "ServiceAudienceMismatch";
            },
            7 => {
                _ = claims.object.swapRemove("aud");
                wanted = "MissingIdentityField";
            },
            8 => {
                _ = claims.object.swapRemove("exp");
                wanted = "MissingIdentityField";
            },
            9 => {
                _ = claims.object.swapRemove("sub");
                wanted = "MissingIdentityField";
            },
            10 => {
                try put(&claims, allocator, "exp", .{ .integer = 1900 });
                wanted = "IdentityExpired";
            },
            11 => {
                try put(&claims, allocator, "exp", .{ .integer = 1970 });
                wanted = "IdentityExpired";
            },
            12 => {
                try put(&claims, allocator, "nbf", .{ .integer = 2050 });
                wanted = "IdentityNotYetValid";
            },
            13 => {
                try put(&claims, allocator, "iat", .{ .integer = 2050 });
                wanted = "IdentityIssuedInFuture";
            },
            14 => {
                try put(&claims, allocator, "exp", .{ .float = 2300.5 });
                wanted = "InvalidServiceTimestamp";
            },
            15 => {
                try put(&claims, allocator, "exp", .null);
                wanted = "InvalidServiceTimestamp";
            },
            16 => {
                try put(&claims, allocator, "nbf", .{ .integer = 2300 });
                wanted = "InvalidServiceTimestamp";
            },
            17 => {
                try put(&header, allocator, "kid", .{ .string = "unknown" });
                wanted = "UnknownServiceKey";
            },
            18 => {
                try put(&header, allocator, "alg", .{ .string = "HS256" });
                wanted = "UnsupportedServiceAlgorithm";
            },
            19 => {
                try put(&header, allocator, "crit", .{ .array = .init(allocator) });
                wanted = "UnsupportedServiceHeader";
            },
            20 => {
                try put(&header, allocator, "b64", .{ .bool = true });
                wanted = "UnsupportedServiceHeader";
            },
            21 => {
                try put(&header, allocator, "jwk", try rsa[3].public(allocator, kid));
                wanted = "ServiceSignatureMismatch";
            },
            22, 23, 25 => wanted = "IdentitySignatureMismatch",
            else => {},
        }
        const unsigned = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ try base64(allocator, try json(allocator, header), true), try base64(allocator, try json(allocator, claims), true) });
        const signer = &rsa[if (index == 21) 3 else rsa_index];
        const token = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ unsigned, try base64(allocator, try signer.sign(allocator, unsigned), true) });
        const signed_payload = if (index == 23) "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"" ++ ones ++ "\"}]}" else if (index == 24) "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"" ++ zeros ++ "\"},{\"algorithm\":\"SHA-256\",\"digest\":\"" ++ zeros ++ "\"}]}" else payload;
        const proof_header = "eyJhbGciOiJFUzM4NCJ9";
        const proof_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ proof_header, try base64(allocator, signed_payload, true) });
        const proof_key = if (index == 22) &other_client else &client;
        const proof = try std.fmt.allocPrint(allocator, "{s}..{s}", .{ proof_header, try base64(allocator, try proof_key.sign(allocator, proof_input), true) });
        const inner = try json(allocator, .{ .token = token, .fingerprints = proof });
        const attribute = try base64(allocator, try json(allocator, .{ .idp = .{ .domain = issuer, .protocol = "default" }, .assertion = inner }), false);
        const extra = if (index == 24) "a=fingerprint:SHA-256 " ++ zeros ++ "\r\n" else if (index == 25) "a=fingerprint:sha-256 " ++ ones ++ "\r\n" else "";
        case.* = .{ .name = case_name, .attribute = attribute, .sdp = try std.fmt.allocPrint(allocator, "v=0\r\na=fingerprint:sha-256 {s}\r\na=identity:{s}\r\n{s}{s}", .{ zeros, attribute, media, extra }), .@"error" = wanted, .key_bits = key_bits[rsa_index] };
    }
    const source = try std.Io.Dir.cwd().readFileAlloc(init.io, "tools/generate_service_fixtures.zig", allocator, .limited(1024 * 1024));
    var source_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &source_hash, .{});
    const fixture = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = 1,
        .producer = .{ .name = "Windows CNG", .zig = builtin.zig_version_string, .source_path = "tools/generate_service_fixtures.zig", .source_sha256 = std.fmt.bytesToHex(source_hash, .lower), .signatures_verified_by_producer = true },
        .authority = .{ .issuer = issuer, .audience = audience, .not_before = 1000, .expires_at = 8000, .generation = 7 },
        .now = 2000,
        .jwks = .{ .keys = public_keys },
        .cases = cases,
    }, .{ .whitespace = .indent_2 });
    const file = try output.createFile(init.io, "service-identity.json", .{ .exclusive = true });
    defer file.close(init.io);
    try file.writePositionalAll(init.io, fixture, 0);
    var log_buffer: [256]u8 = undefined;
    var log = std.Io.File.Writer.init(.stdout(), init.io, &log_buffer);
    try log.interface.print("Generated {d} synthetic service identity cases using Windows CNG\n", .{cases.len});
    try log.interface.flush();
}
