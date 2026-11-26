#!/usr/bin/env python3
# Galactica patcher — thin + strip + LC_LOAD_DYLIB + package
# Usage: python3 patch_ipa.py <orig.ipa> <output.ipa> [--gadget path] [--script path] [--config path]
#
# Inputs default to files next to this script:
#   libnativeunity.dylib  (fat universal from frida releases; thinned to arm64e here)
#   libnativeunity.config.json
#   ff.js

import os, sys, shutil, struct, tempfile, zipfile, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
DYLIB_INJECT_PATH = b"@executable_path/Frameworks/libnativeunity.dylib"
LC_LOAD_DYLIB      = 0x0c
LC_LOAD_WEAK_DYLIB = (0x18 | 0x80000000)   # weak: app runs even if dylib fails to load
LC_SEGMENT_64      = 0x19
# flip this to use the regular load; weak is safer during bring-up
INJECT_CMD = LC_LOAD_WEAK_DYLIB

# NOTE: do NOT zero out frida/gum strings. The gadget uses several of them
# as module-registry keys at init time; nulling them trips its own
# integrity path and dyld calls abort() during LibSystemHelpers::callInitializer.
# Known good: ship the gadget as released by frida.re.
FRIDA_STRIP_NEEDLES = []

def log(*a): print("[*]", *a)

def thin_universal_to_arm64(path):
    """
    Keep the plain arm64 slice (not arm64e). arm64 runs on every 64-bit iOS
    device (iPhone 5s / A7 and up); arm64e-only would break pre-A12 phones
    (iPhone X and older) because dyld can't load pointer-auth code there.
    """
    data = open(path, "rb").read()
    magic = struct.unpack(">I", data[:4])[0]
    if magic != 0xcafebabe:
        log(f"already thin (magic={hex(magic)})")
        return
    nfat = struct.unpack(">I", data[4:8])[0]
    pick = None
    for i in range(nfat):
        off = 8 + i * 20
        cpu, sub, of, sz, al = struct.unpack(">IIIII", data[off:off+20])
        # cpu 0x100000c = ARM64, sub top bit set = arm64e (ptrauth); we want the plain slice
        if cpu == 0x100000c and (sub & 0x80000000) == 0:
            pick = (of, sz); break
    if pick is None:
        # fallback: first arm64 slice of any kind
        for i in range(nfat):
            off = 8 + i * 20
            cpu, sub, of, sz, al = struct.unpack(">IIIII", data[off:off+20])
            if cpu == 0x100000c:
                pick = (of, sz); break
    open(path, "wb").write(data[pick[0]:pick[0]+pick[1]])
    log(f"thinned → {pick[1]:,} bytes (arm64, A7+)")

def strip_strings(path):
    d = bytearray(open(path, "rb").read())
    hits = 0
    for n in FRIDA_STRIP_NEEDLES:
        i = 0
        while True:
            i = d.find(n, i)
            if i == -1: break
            d[i:i+len(n)] = b"\x00" * len(n)
            hits += 1; i += len(n)
    open(path, "wb").write(bytes(d))
    log(f"stripped {hits} debug-string occurrences")

def insert_lc_load_dylib(binpath):
    d = bytearray(open(binpath, "rb").read())
    magic, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack("<IIIIIIII", d[:32])
    if magic != 0xfeedfacf:
        sys.exit(f"unexpected mach-O magic in {binpath}: {hex(magic)}")

    cursor, cmd_blob_end = 32, 32 + sizeofcmds
    text_start = None
    already = False
    for _ in range(ncmds):
        cmd, size = struct.unpack("<II", d[cursor:cursor+8])
        if cmd == LC_SEGMENT_64:
            segname = bytes(d[cursor+8:cursor+24]).rstrip(b"\x00").decode(errors="ignore")
            nsects = struct.unpack("<I", d[cursor+64:cursor+68])[0]
            if segname == "__TEXT":
                sc = cursor + 72
                for _s in range(nsects):
                    off = struct.unpack("<I", d[sc+48:sc+52])[0]
                    if off > 0 and (text_start is None or off < text_start):
                        text_start = off
                    sc += 80
        elif cmd == LC_LOAD_DYLIB or cmd == LC_LOAD_WEAK_DYLIB:
            if bytes(d[cursor+24:cursor+size]).split(b"\x00", 1)[0] == DYLIB_INJECT_PATH:
                already = True
        cursor += size

    if already:
        log("LC_LOAD_DYLIB already present")
        return

    path_bytes = DYLIB_INJECT_PATH + b"\x00"
    total = 24 + len(path_bytes)
    pad = (8 - (total % 8)) % 8
    total += pad
    new_cmd = (struct.pack("<IIIIII", INJECT_CMD, total, 24, 2, 0x00010000, 0x00010000)
               + path_bytes + b"\x00" * pad)
    free = text_start - cmd_blob_end
    if free < total:
        sys.exit(f"no header space: need {total}, have {free}")

    d[cmd_blob_end:cmd_blob_end+total] = new_cmd
    struct.pack_into("<II", d, 16, ncmds + 1, sizeofcmds + total)
    open(binpath, "wb").write(bytes(d))
    log(f"injected LC_LOAD_DYLIB → {DYLIB_INJECT_PATH.decode()}")

def zip_dir(src_dir, dst_ipa, compresslevel=6):
    if os.path.exists(dst_ipa): os.remove(dst_ipa)
    with zipfile.ZipFile(dst_ipa, "w", zipfile.ZIP_DEFLATED, compresslevel=compresslevel) as z:
        for root, _dirs, files in os.walk(src_dir):
            for fn in files:
                full = os.path.join(root, fn)
                arc = os.path.relpath(full, os.path.dirname(src_dir))
                z.write(full, arc)
    log(f"packaged {dst_ipa} = {os.path.getsize(dst_ipa):,} bytes")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("orig")
    ap.add_argument("out")
    ap.add_argument("--gadget", default=os.path.join(HERE, "libnativeunity.dylib"))
    ap.add_argument("--config", default=os.path.join(HERE, "libnativeunity.config.json"))
    ap.add_argument("--script", default=os.path.join(HERE, "ff.js"))
    ap.add_argument("--compress", type=int, default=6)
    args = ap.parse_args()

    for p in (args.orig, args.gadget, args.config, args.script):
        if not os.path.exists(p): sys.exit(f"missing: {p}")

    tmp = tempfile.mkdtemp(prefix="galactica_")
    try:
        log(f"unpack {args.orig}")
        with zipfile.ZipFile(args.orig, "r") as z: z.extractall(tmp)

        payload = os.path.join(tmp, "Payload")
        apps = [a for a in os.listdir(payload) if a.endswith(".app")]
        if not apps: sys.exit("no .app in Payload")
        app = os.path.join(payload, apps[0])
        log(f"bundle: {app}")

        import plistlib
        with open(os.path.join(app, "Info.plist"), "rb") as fp:
            info = plistlib.load(fp)
        binname = info.get("CFBundleExecutable", "FreeFire")
        binpath = os.path.join(app, binname)
        if not os.path.exists(binpath): sys.exit(f"main binary missing: {binpath}")

        fw = os.path.join(app, "Frameworks"); os.makedirs(fw, exist_ok=True)
        dst_dylib = os.path.join(fw, "libnativeunity.dylib")
        shutil.copy(args.gadget, dst_dylib)
        thin_universal_to_arm64(dst_dylib)
        strip_strings(dst_dylib)

        shutil.copy(args.config, os.path.join(fw, "libnativeunity.config.json"))
        shutil.copy(args.script, os.path.join(app, "ff.js"))

        insert_lc_load_dylib(binpath)

        for junk in ("_CodeSignature", "SC_Info", "embedded.mobileprovision"):
            p = os.path.join(app, junk)
            if os.path.isdir(p): shutil.rmtree(p)
            elif os.path.isfile(p): os.remove(p)

        zip_dir(payload, args.out, args.compress)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    main()
