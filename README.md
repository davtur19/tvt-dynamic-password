> _Note: this project (code and docs) was produced with AI assistance and validated against real hardware._

# TVT Dynamic Password Generator

This tool makes recovery codes for TVT recorders.
It supports NVMS-9000 and N0L-series recorders.
It works with the Find Password dialog.
The dialog shows "Password Dinamica" on Italian firmware.
The tool works offline.
It needs no network access.
It needs no vendor help.

If you lose admin access, use this tool.
The dialog shows two fixed strings.
One string is a MAC address.
One string is a time value.
Read both strings from the dialog.
Enter them in this tool.
The tool makes an 8-character code.
Enter the code in the dialog password field.

## How It Works

The algorithm comes from N0L 1.4.7 firmware.
It comes from the `NVMS9000` binary file.
See [Validation](#validation) for more data.

1. Read the two dialog strings.
   - `MAC`: Read the MAC field text as shown. Example: `AA:BB:CC:DD:EE:FF`.
   - `time`: Read the time field text as shown. Example: `2024-01-01 12:00:00 123`. Use the full text. Do not drop the last field.
   - Each string has 31 characters or less. The firmware enforces this limit.
2. Normalize each string (`norm`).
   - Change lowercase to uppercase. Change `a` through `z` to `A` through `Z`.
   - Change each space `' '` to `'0'`.
   - Keep all other characters as shown.
   - Hash the product string as shown. Do not normalize it.
3. Make the message from three parts.
   - Put the parts in this order: `normalized(time) ‖ 3536C_TVTProduct ‖ normalized(mac)`.
   - The firmware build uses `3536C_TVTProduct` as the fixed product string. Other builds use a different string (see `--product`). The order stays the same.
4. Hash the message with the SHA-1 compression function.
   - Use the standard message schedule.
   - Do 80 rounds.
   - Use standard padding.
   - Use reverse start state `(H4,H3,H2,H1,H0)` in place of standard `(H0..H4)`.
5. Map the digest to the code.
   - Use the first 16 digest bytes (`h[0..3]` in big-endian order). Do not use `h[4]`.
   - For `i` in 0..2, compute `s[i] = (d[2*i] + d[2*i+1]) & 0xFF`.
   - Compute `s[3] = (key ^ s[0] ^ s[1] ^ s[2]) & 0xFF`, with `key = ':'` (0x3A).
   - Write each byte as 2 uppercase hex characters. This step equals C `sprintf(buf, "%2x", b)` with normalization. Space becomes `'0'`. The result has 8 characters in `[0-9A-F]`.

## Usage

You need Python 3 only.
The tool uses the standard library.
It needs no extra packages.

Do these steps:

1. Do the self-test. It needs no device. It does 22 checks.

   ```bash
   python3 dynagen.py --selftest
   ```

2. Read the MAC string and the time string from the dialog. Keep the dialog open.
3. Enter the two strings in the command. Example:

   ```bash
   python3 dynagen.py --mac "AA:BB:CC:DD:EE:FF" --time "2024-01-01 12:00:00 123"
   ```

4. Get the 8-character code from the output. Enter it in the dialog password field.
5. Reference vector: the example below gives `29617D0F`. The output is deterministic.

   ```bash
   # --mac "00:11:22:33:44:55" --time "2024-01-01 12:00:00" -> 29617D0F
   python3 dynagen.py --mac "00:11:22:33:44:55" --time "2024-01-01 12:00:00"
   ```

6. If your firmware build uses a different product string, enter it with `--product`. Example:

   ```bash
   python3 dynagen.py --mac "AA:BB:CC:DD:EE:FF" --time "2024-01-01 12:00:00 123" --product "3536C_TVTProduct"
   ```

CAUTION: Copy both strings character-for-character. Do not close the dialog. Letter case does not matter. Separators matter. Spaces matter. The last time field matters.

## Validation

- The algorithm comes from the official N0L 1.4.7 `NVMS9000` binary file. The device uses the same routine to make the expected code and to verify it. Thus generation equals verification by design.
- The hash core matches `hashlib.sha1` with standard start state. Tests cover padding edge cases (55, 56, and 64-byte inputs, plus multi-block inputs). The reverse-start variant differs from standard SHA-1 as specified.
- Test result on real N0L hardware: the device accepted the code on the first try. The test used the fixed dialog strings.
- The `--selftest` suite does 22 checks. It tests SHA-1 conformance. It tests normalization. It tests the map step. It tests determinism. It tests the alphabet. It tests sensitivity. It tests the verifier. All checks pass.

## Supported / Known-Good

- Known-good: N0L 1.4.7. This build has full reverse analysis and a hardware test.
- Expected-compatible: 1.4.12. Analysis of that build shows the same code-string and seed structure. The generation function in that build has no full re-read. Thus this revision is structurally identical but has no hardware test.
- Other NVMS-9000 / N0L-lineage builds work if they use the same `3536C_TVTProduct`-style product string. A rejected code in most cases shows a copy error or a different product string. See [Troubleshooting](#troubleshooting) before you assume a different algorithm.

## Troubleshooting

NOTE: Keep the dialog open. The time string stays fixed while the dialog shows. If you close and open the dialog, it makes a new time value. The old code will not work. Do all steps with the dialog open.

NOTE: Copy both strings exactly. Use the full time text with the last field. The most common error is a lost last field or changed separators. Copy each character with spaces. Spaces become `'0'` in the tool.

NOTE: If the device rejects the code, retry with seconds at ±1. The dialog display and the internal sample can straddle a second boundary. Keep the MAC string the same. Change only the time string.

NOTE: If the device still rejects the code on a different firmware build, check the product string. The default is `3536C_TVTProduct` (N0L 1.4.7). Other builds use their own string.

NOTE: A valid code has exactly 8 uppercase hex characters (`[0-9A-F]{8}`). Any other output shows a copy error.

## Responsible Use

WARNING: Use this tool only on devices you own or administer with explicit approval. Example: recovery of a lost admin password on your own recorder. Do not access other systems without approval. The authors accept no liability for misuse.

## License

AGPL-3.0-only: see [LICENSE](LICENSE).
