#!/usr/bin/env python3
"""Make TVT NVMS-9000/N0L recovery codes. Use the recovered algorithm from FW N0L 1.4.7.

Source binary is ``squashfs-root/mnt/mtd/NVMS9000`` (ELF32 ARM). IDA shows these facts:
  * VERIFY site   : sub_9B5A44 (FindPWDDlg::slot_buttonClicked, "IDCS_INVALID_DYNAMICPSW"
                    branch at 0x9B5CD0). It calls sub_10F96E8. It then calls sub_10F9964.
  * GENERATION    : sub_10FB00C (virtual[1] of the "NxL" code-type object,
                    ctor sub_10F9A80, vtable at 0x1997FC8). The verifier
                    makes the expected code with this same routine.
                    It then compares the two codes. Thus generation
                    equals verification by design.
  * Hash          : SHA1 core (sub_10F9AC4 transform / sub_10FAE64 update,
                    constants 0x5A827999/0x6ED9EBA1/0x8F1BBCDC/0xCA62C1D6).
                    It uses REVERSE start state. IDA confirms this
                    at instruction level: LDR R2,=imm / STR pairs
                    at 0x10FB0E0-0x10FB114 put H4,H3,H2,H1,H0
                    in state slots h[0..4].
  * Message       : norm(time) || product || norm(mac).
                      - time is the "current time" field text (dlg offset 0x98).
                      - product is the fixed per-firmware string from the ctor.
                                  This build uses "3536C_TVTProduct" (rodata 0x17EC015).
                      - mac is the "MAC address" field text (dlg offset 0x90).
                    norm() is sub_10FAF74. It changes 'a'-'z' to 'A'-'Z'.
                    It changes ' ' to '0'.
                    NOTE: Hash the product string as shown. Do not normalize it.
  * Digest to code: use the first 16 digest bytes (h[0..3] big-endian).
                    Do not use h[4]. For i in 0..2, use this formula:
                      s[i] = (d[2*i] + d[2*i+1]) & 0xFF.
                    For s[3], use key = ':' (0x3A). sub_10F9A80 sets key at obj+4.
                    Formula: s[3] = (key ^ s[0] ^ s[1] ^ s[2]) & 0xFF.
                    Write each byte with C ``sprintf(buf, "%2x", b)``.
                    Then normalize it. Each byte gives exactly 2 uppercase
                    hex characters. Space pad becomes '0'. Total is 8
                    characters in [0-9A-F]. The dialog validator sub_404E30
                    accepts 8x[0-9a-zA-Z]. This set includes the made alphabet.

STATUS: This code copies the binary logic. The hash core matches hashlib
with standard start state. Real N0L hardware accepts the made code.
It passed on the first try. The code enforces the firmware length limit.
It rejects inputs with more than 31 characters.

Use:
  python3 dynagen.py --selftest
  python3 dynagen.py --mac "00:11:22:33:44:55" --time "2024-01-01 12:00:00"
"""

import argparse
import hashlib
import re
import sys

# --------------------------------------------------------------------------
# SHA-1 core. Standard schedule and rounds and padding. Start state is settable.
# --------------------------------------------------------------------------

STD_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
# Reversed start state. sub_10FB00C puts it in h[0..4]. See module docstring.
REV_INIT = (0xC3D2E1F0, 0x10325476, 0x98BADCFE, 0xEFCDAB89, 0x67452301)


def _rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sha1_core(msg: bytes, init=REV_INIT) -> bytes:
    """Do SHA-1 compression as sub_10F9AC4/sub_10FAE64 with inline padding.

    Use standard big-endian schedule. Do 80 rounds. Use standard
    0x80/zeros/64-bit-BE-bitlength padding. Write results back in order.
    Only the start state differs from FIPS 180. It uses the reverse
    state from the binary.
    """
    h = list(init)
    ml = len(msg)
    bitlen = (ml * 8) & 0xFFFFFFFFFFFFFFFF
    data = bytearray(msg)
    data.append(0x80)
    while (len(data) % 64) != 56:
        data.append(0x00)
    data += bitlen.to_bytes(8, "big")
    assert len(data) % 64 == 0
    for off in range(0, len(data), 64):
        w = [int.from_bytes(data[off + 4 * i:off + 4 * i + 4], "big")
             for i in range(16)]
        for i in range(16, 80):
            w.append(_rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
        a, b, c, d, e = h
        for i in range(80):
            if i < 20:
                f = ((b & c) | ((~b) & d)) & 0xFFFFFFFF
                k = 0x5A827999
            elif i < 40:
                f = (b ^ c ^ d) & 0xFFFFFFFF
                k = 0x6ED9EBA1
            elif i < 60:
                f = ((b & c) | (b & d) | (c & d)) & 0xFFFFFFFF
                k = 0x8F1BBCDC
            else:
                f = (b ^ c ^ d) & 0xFFFFFFFF
                k = 0xCA62C1D6
            tmp = (_rol32(a, 5) + f + e + w[i] + k) & 0xFFFFFFFF
            e = d
            d = c
            c = _rol32(b, 30)
            b = a
            a = tmp
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, (a, b, c, d, e))]
    return b"".join(x.to_bytes(4, "big") for x in h)


# --------------------------------------------------------------------------
# Helpers. They copy the firmware logic.
# --------------------------------------------------------------------------

def norm(s: str) -> str:
    """Do sub_10FAF74. Change 'a'-'z' to uppercase. Change ' ' to '0'. Keep all else."""
    out = []
    for ch in s:
        o = ord(ch)
        if 0x61 <= o <= 0x7A:      # 'a'..'z'
            out.append(chr(o - 0x20))
        elif ch == " ":
            out.append("0")
        else:
            out.append(ch)
    return "".join(out)


PRODUCT_DEFAULT = "3536C_TVTProduct"   # rodata 0x17EC015. sub_10F9A80 sets it.
KEY_DEFAULT = 0x3A                     # ':'. sub_10F9A80 sets it at obj+4.
TYPE_TAG = "NxL"                       # virtual[0] (sub_10F9A28). sub_10F9964 checks it.


def generate(mac: str, timestr: str,
             product: str = PRODUCT_DEFAULT,
             key: int = KEY_DEFAULT) -> str:
    """Do sub_10FB00C. Reject inputs with more than 31 characters. The firmware sets this limit."""
    if len(mac) > 31 or len(timestr) > 31:
        raise ValueError("The firmware rejects inputs with more than 31 characters.")
    a4 = norm(timestr)     # Copy of 0x98 field (v29). Hash it first.
    a3 = norm(mac)         # Copy of 0x90 field (v30). Hash it last.
    msg = a4.encode("ascii") + product.encode("ascii") + a3.encode("ascii")
    d = sha1_core(msg)     # 20 bytes. The binary keeps h[0..3] (first 16 bytes).
    s = [(d[0] + d[1]) & 0xFF, (d[2] + d[3]) & 0xFF, (d[4] + d[5]) & 0xFF]
    s.append((key ^ s[0] ^ s[1] ^ s[2]) & 0xFF)
    # C sprintf "%2x" with normalization gives "%02X" for byte values.
    return "".join("%02X" % b for b in s)


def verify(entered: str, type_tag: str, mac: str, timestr: str,
           product: str = PRODUCT_DEFAULT,
           key: int = KEY_DEFAULT) -> bool:
    """Do sub_10F9964. Check the type tag. Make the code again. Compare the two codes."""
    if type_tag != TYPE_TAG:
        return False
    return entered == generate(mac, timestr, product, key)


# --------------------------------------------------------------------------
# Self-test. It needs no device.
# --------------------------------------------------------------------------

def _check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ((": " + detail) if detail and not cond else ""))
    return cond


def selftest() -> bool:
    ok = True
    # 1. Use STANDARD start state. Core output must match hashlib SHA-1.
    #    Tests cover edge cases (55, 56, and 64 bytes, plus multi-block inputs).
    vectors = [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64,
               b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
               bytes(range(256)), b"0" * 1000]
    for v in vectors:
        got = sha1_core(v, init=STD_INIT).hex()
        exp = hashlib.sha1(v).hexdigest()
        ok &= _check("sha1-std len=%d" % len(v), got == exp, "%r got=%s exp=%s" % (v[:16], got, exp))
    # 2. The reverse-start variant must differ from standard SHA-1.
    #    The reverse start state is effective. It is not a no-op.
    ok &= _check("variant-differs",
                 sha1_core(b"abc") != hashlib.sha1(b"abc").digest())
    # 3. norm() tests. They check sub_10FAF74 logic.
    ok &= _check("norm-lower", norm("ab:cd") == "AB:CD", norm("ab:cd"))
    ok &= _check("norm-space", norm("a b 12:00:00") == "A0B012:00:00", norm("a b 12:00:00"))
    ok &= _check("norm-keep", norm("2024-01-01 12:00:00") == "2024-01-01012:00:00")
    # 4. Map tests. They use test digests. They check the generate tail.
    d = bytes([0] * 20)
    s = [(d[0] + d[1]) & 0xFF, (d[2] + d[3]) & 0xFF, (d[4] + d[5]) & 0xFF]
    s.append((0x3A ^ s[0] ^ s[1] ^ s[2]) & 0xFF)
    ok &= _check("map-zero", "".join("%02X" % b for b in s) == "0000003A")
    d = bytes([0xFF, 0x01, 0x10, 0x10, 0xAB, 0xCD] + [0] * 14)
    s = [(d[0] + d[1]) & 0xFF, (d[2] + d[3]) & 0xFF, (d[4] + d[5]) & 0xFF]
    s.append((0x3A ^ s[0] ^ s[1] ^ s[2]) & 0xFF)
    ok &= _check("map-carry", "".join("%02X" % b for b in s) == "00207862",
                 "".join("%02X" % b for b in s))
    # 5. End-to-end checks. They check determinism and alphabet and sensitivity.
    c1 = generate("00:11:22:33:44:55", "2024-01-01 12:00:00")
    c2 = generate("00:11:22:33:44:55", "2024-01-01 12:00:00")
    ok &= _check("deterministic", c1 == c2, c1)
    ok &= _check("alphabet", re.fullmatch(r"[0-9A-F]{8}", c1) is not None, c1)
    ok &= _check("sensitive-mac",
                 generate("00:11:22:33:44:56", "2024-01-01 12:00:00") != c1)
    ok &= _check("sensitive-time",
                 generate("00:11:22:33:44:55", "2024-01-01 12:00:01") != c1)
    ok &= _check("case-insensitive-mac",
                 generate("aa:bb:cc:dd:ee:ff", "2024-01-01 12:00:00") ==
                 generate("AA:BB:CC:DD:EE:FF", "2024-01-01 12:00:00"))
    # 6. verify() checks. They check sub_10F9964 logic.
    ok &= _check("verify-ok", verify(c1, "NxL", "00:11:22:33:44:55", "2024-01-01 12:00:00"))
    ok &= _check("verify-badtag", not verify(c1, "WRONG", "00:11:22:33:44:55", "2024-01-01 12:00:00"))
    ok &= _check("verify-badcode",
                 not verify("00000000", "NxL", "00:11:22:33:44:55", "2024-01-01 12:00:00"))
    print("DEMO mac=00:11:22:33:44:55 time='2024-01-01 12:00:00' -> %s. Reference vector." % c1)
    print("SELFTEST " + ("OK" if ok else "FAILED"))
    return ok


def main(argv):
    ap = argparse.ArgumentParser(description="Make TVT NVMS-9000/N0L recovery codes. Use the recovered algorithm.")
    ap.add_argument("--selftest", action="store_true", help="Do the self-test and then stop.")
    ap.add_argument("--mac", help="Read the MAC text from the Find Password dialog. Enter it as shown.")
    ap.add_argument("--time", dest="timestr", help="Read the time text from the Find Password dialog. Enter it as shown.")
    ap.add_argument("--product", default=PRODUCT_DEFAULT, help="Use this product string. Default: %(default)s.")
    a = ap.parse_args(argv)
    if a.selftest or (a.mac is None and a.timestr is None):
        return 0 if selftest() else 1
    if not a.mac or not a.timestr:
        ap.error("Enter --mac and --time.")
    print(generate(a.mac, a.timestr, a.product))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
