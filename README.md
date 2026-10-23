# Shulvyr reference tools

Reference fixture generators and native transport experiments for
[Shulvyr](https://github.com/Shulvyr/Shulvyr).

These tools call original implementations to produce independent evidence.
They are separate from the server's Zig build and tests. The server keeps its
frozen fixtures and records their sources and hashes.

## Fixture generation

Use a disposable Shulvyr checkout. Copy a selected generator from this
repository into that checkout's `tools/` directory. Keep the script unchanged
so its recorded SHA-256 still identifies the source that produced the bytes.
Generators use the server layout to read synthetic inputs and write fixtures.
They should not run directly in this repository or against runtime data.

Install 64-bit PHP 8.4 or newer with OpenSSL and Git. Supply clean reference
checkouts at the revisions recorded in the corresponding fixture manifests.
The scripts reject another revision or a dirty source tree.

| Generator | Reference checkout arguments, in order |
| --- | --- |
| `generate_nbt_fixtures.php` | NBT, BinaryUtils, BedrockProtocol |
| `generate_math_fixtures.php` | Math |
| `generate_registry_fixtures.php` | NBT, BedrockProtocol |
| `generate_block_fixtures.php` | NBT, BinaryUtils, BedrockProtocol, PocketMine-MP |
| `generate_framing_fixtures.php` | NetherNet |
| `generate_signaling_fixtures.php` | NetherNet |
| `generate_sdp_fixtures.php` | NetherNet |
| `generate_identity_fixtures.php` | NetherNet |
| `generate_issuer_fixtures.php` | NetherNet |

For example, from the disposable server checkout:

```sh
php tools/generate_issuer_fixtures.php /path/to/NetherNet
zig build check-fixtures --summary all
zig build test --summary all
```

Review the resulting fixtures and manifests before importing them into the
server repository. If a generator changes, record its new hash and published
revision. Key-generating fixtures intentionally use fresh synthetic keys and
signatures. No private keys belong in published output.

## Native transport experiment

The current server uses its own Zig build driver. Follow
[the native transport instructions](https://github.com/Shulvyr/Shulvyr/blob/main/docs/native-transport.md)
for normal validation. The Python harness below is retained as a reference for
the earlier experiment. The server's CI does not fetch or execute it.

Copy the four files in `tools/native-transport/` into the same location in a
disposable server checkout. The Zig probe and adapter remain server sources.
Use its pinned Zig compiler, CPython 3.14, Git, CMake and a C/C++ toolchain.

```sh
python -m pip install --require-hashes -r tools/native-transport/requirements.txt
python tools/native-transport/test_build_probe.py
python tools/native-transport/build_probe.py
```

The source manifest pins libdatachannel, mbedTLS and their submodules. The build
validates those sources and retains raw diagnostic logs under the checkout's
ignored `work/` directory. This backend remains an experiment with separate
production gates. A passing loopback probe does not prove Minecraft client
compatibility.

## Source manifest

`manifest.json` records the exact byte length and SHA-256 of each source file.
CI checks those records, lints the PHP scripts and tests native source validation.
Full fixture regeneration needs the reference runtimes listed above.
