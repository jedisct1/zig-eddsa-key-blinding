# EdDSA signatures with blind keys

A Zig implementation of the [EdDSA key blinding](https://chris-wood.github.io/draft-wood-cfrg-eddsa-blinding/draft-wood-cfrg-eddsa-blinding.html) proposal.

```zig
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
    const pk = try BlindEd25519.unblind_public_key(blind_kp.blind_public_key, blind);
    try std.testing.expectEqualSlices(u8, &pk, &kp.public_key);
```
