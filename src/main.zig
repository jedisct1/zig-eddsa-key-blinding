const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Sha512 = crypto.hash.sha2.Sha512;
const Curve = crypto.ecc.Edwards25519;
const Scalar = Curve.scalar.Scalar;
const Ed25519 = crypto.sign.Ed25519;
const CompressedScalar = Curve.scalar.CompressedScalar;

/// Ed25519 signatures with blind keys.
pub const BlindEd25519 = struct {
    /// Length (in bytes) of optional random bytes, for non-deterministic signatures.
    pub const noise_length = Ed25519.noise_length;
    /// Length (in bytes) of a signature.
    pub const signature_length = Ed25519.signature_length;
    /// Length (in bytes) of a compressed public key.
    pub const public_key_length = Ed25519.public_length;
    /// Length (in bytes) of a blinding seed.
    pub const blind_seed_length = 32;

    /// A blind secret key.
    pub const BlindSecretKey = struct {
        prefix: [64]u8,
        blind_scalar: CompressedScalar,
        blind_public_key: CompressedScalar,
    };

    /// A blind key pair.
    pub const BlindKeyPair = struct {
        blind_public_key: [public_key_length]u8,
        blind_secret_key: BlindSecretKey,
    };

    /// Blind an existing key pair with a blinding seed.
    pub fn blind(key_pair: Ed25519.KeyPair, blind_seed: [blind_seed_length]u8) !BlindKeyPair {
        var h: [Sha512.digest_length]u8 = undefined;
        Sha512.hash(key_pair.secret_key[0..32], &h, .{});
        Curve.scalar.clamp(h[0..32]);
        const scalar = Curve.scalar.reduce(h[0..32].*);

        var blind_h: [Sha512.digest_length]u8 = undefined;
        Sha512.hash(blind_seed[0..], &blind_h, .{});
        const blind_factor = Curve.scalar.reduce(blind_h[0..32].*);

        const blind_scalar = Curve.scalar.mul(scalar, blind_factor);
        const blind_public_key = (Curve.basePoint.mul(blind_scalar) catch return error.IdentityElement).toBytes();

        var prefix: [64]u8 = undefined;
        mem.copy(u8, prefix[0..32], h[32..64]);
        mem.copy(u8, prefix[32..64], blind_h[32..64]);

        const blind_secret_key = .{
            .prefix = prefix,
            .blind_scalar = blind_scalar,
            .blind_public_key = blind_public_key,
        };
        return BlindKeyPair{
            .blind_public_key = blind_public_key,
            .blind_secret_key = blind_secret_key,
        };
    }

    /// Recover a public key from a blind version of it.
    pub fn unblindPublicKey(blind_public_key: [public_key_length]u8, blind_seed: [blind_seed_length]u8) ![public_key_length]u8 {
        var blind_h: [Sha512.digest_length]u8 = undefined;
        Sha512.hash(&blind_seed, &blind_h, .{});
        const inv_blind_factor = Scalar.fromBytes(blind_h[0..32].*).invert().toBytes();
        const public_key = try (try Curve.fromBytes(blind_public_key)).mul(inv_blind_factor);
        return public_key.toBytes();
    }

    /// Sign a message using a blind key pair, and optional random noise.
    /// Having noise creates non-standard, non-deterministic signatures,
    /// but has been proven to increase resilience against fault attacks.
    pub fn sign(msg: []const u8, key_pair: BlindKeyPair, noise: ?[noise_length]u8) ![signature_length]u8 {
        var h = Sha512.init(.{});
        if (noise) |*z| {
            h.update(z);
        }
        h.update(&key_pair.blind_secret_key.prefix);
        h.update(msg);
        var nonce64: [64]u8 = undefined;
        h.final(&nonce64);

        const nonce = Curve.scalar.reduce64(nonce64);
        const r = try Curve.basePoint.mul(nonce);

        var sig: [signature_length]u8 = undefined;
        mem.copy(u8, sig[0..32], &r.toBytes());
        mem.copy(u8, sig[32..], &key_pair.blind_public_key);
        h = Sha512.init(.{});
        h.update(&sig);
        h.update(msg);
        var hram64: [Sha512.digest_length]u8 = undefined;
        h.final(&hram64);
        const hram = Curve.scalar.reduce64(hram64);

        const s = Curve.scalar.mulAdd(hram, key_pair.blind_secret_key.blind_scalar, nonce);
        mem.copy(u8, sig[32..], s[0..]);
        return sig;
    }
};

test "Blind key EdDSA signature" {
    // Create a standard Ed25519 key pair
    const kp = try Ed25519.KeyPair.create(null);

    // Create a random blinding seed
    var blind: [32]u8 = undefined;
    crypto.random.bytes(&blind);

    // Blind the key pair
    const blind_kp = try BlindEd25519.blind(kp, blind);

    // Sign a message and check that it can be verified with the blind public key
    const msg = "test";
    const sig = try BlindEd25519.sign(msg, blind_kp, null);
    try Ed25519.verify(sig, msg, blind_kp.blind_public_key);

    // Unblind the public key
    const pk = try BlindEd25519.unblindPublicKey(blind_kp.blind_public_key, blind);
    try std.testing.expectEqualSlices(u8, &pk, &kp.public_key);
}
