"""Static analysis of game_scarlett_master.exe (PE32+ x86-64 Xbox Series image).
Read-only. Emits a text report for the decompilation notes.
"""
import struct
import sys
from pathlib import Path

EXE = Path(r"<game-dir>\game_scarlett_master.exe")
OUT = Path(r"<workspace>\game_scarlett_pe_static.txt")
IMAGE_BASE = 0x140000000

data = EXE.read_bytes()
lines = []
def p(s=""):
    lines.append(str(s))

def u16(o): return struct.unpack_from("<H", data, o)[0]
def u32(o): return struct.unpack_from("<I", data, o)[0]
def u64(o): return struct.unpack_from("<Q", data, o)[0]

p("=== FILE ===")
p(f"path   : {EXE}")
p(f"size   : {len(data):,} bytes ({len(data)/1024/1024:.2f} MiB)")
p(f"mtime  : {EXE.stat().st_mtime}")

e_lfanew = u32(0x3C)
p(f"e_lfanew: 0x{e_lfanew:x}")
assert data[e_lfanew:e_lfanew+4] == b"PE\0\0"
coff = e_lfanew + 4
machine = u16(coff)
nsect = u16(coff + 2)
opt_size = u16(coff + 16)
opt = coff + 20
magic = u16(opt)
p(f"machine: 0x{machine:x} (0x8664 = AMD64)")
p(f"sections: {nsect}  optional header size: {opt_size}  magic: 0x{magic:x} (0x20b = PE32+)")

entry_rva = u32(opt + 16)
image_base = u64(opt + 24)
sect_align = u32(opt + 32)
file_align = u32(opt + 36)
size_image = u32(opt + 56)
size_headers = u32(opt + 60)
nrva = u32(opt + 108)
dd = opt + 112
p(f"entry RVA  : 0x{entry_rva:x}  -> VA 0x{image_base + entry_rva:x}")
p(f"image base : 0x{image_base:x}   size of image: 0x{size_image:x} ({size_image/1024/1024:.1f} MiB)")
p(f"section/file alignment: 0x{sect_align:x} / 0x{file_align:x}   headers: 0x{size_headers:x}")
p(f"data directories: {nrva}")

DD_NAMES = ["EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY","BASERELOC","DEBUG","ARCHITECTURE",
            "GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT","IAT","DELAY_IMPORT","COM_DESCRIPTOR","RESERVED"]
p("")
p("=== DATA DIRECTORIES ===")
dirs = {}
for i in range(min(nrva, 16)):
    rva, size = u32(dd + i*8), u32(dd + i*8 + 4)
    dirs[DD_NAMES[i]] = (rva, size)
    if rva:
        p(f"  {DD_NAMES[i]:<16} RVA 0x{rva:08x}  size 0x{size:x}")

sections = []
sh = opt + opt_size
p("")
p("=== SECTIONS ===")
for i in range(nsect):
    o = sh + i*40
    name = data[o:o+8].rstrip(b"\0").decode("ascii", "replace")
    vsize, vaddr, rawsize, rawptr = u32(o+8), u32(o+12), u32(o+16), u32(o+20)
    chars = u32(o+36)
    sections.append((name, vaddr, vsize, rawptr, rawsize, chars))
    p(f"  {name:<8} VA 0x{vaddr:08x}  VSize 0x{vsize:08x}  RawPtr 0x{rawptr:08x}  RawSize 0x{rawsize:08x}  flags 0x{chars:08x}")

def rva2off(rva):
    for name, va, vs, rp, rs, _ in sections:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

def cstr(off, wide=False):
    out = bytearray()
    step = 2 if wide else 1
    for i in range(0, 4096, step):
        ch = data[off+i:off+i+step]
        if not ch or ch == b"\0" * step:
            break
        out += ch if not wide else ch[:1]
        if len(out) > 512:
            break
    return out.decode("utf-8" if wide else "ascii", "replace")

p("")
p("=== IMPORT TABLE ===")
imp_rva, imp_size = dirs.get("IMPORT", (0, 0))
imports = {}
if imp_rva:
    off = rva2off(imp_rva)
    idx = 0
    while True:
        o = off + idx*20
        oft, tds, fwd, name_rva, ft = u32(o), u32(o+4), u32(o+8), u32(o+12), u32(o+16)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        dll = cstr(rva2off(name_rva))
        thunk = oft or ft
        names = []
        to = rva2off(thunk)
        j = 0
        while True:
            v = u64(to + j*8)
            if v == 0:
                break
            if v & (1 << 63):
                names.append(f"ordinal:{v & 0xffff}")
            else:
                names.append(cstr(rva2off(v) + 2))
            j += 1
        imports[dll] = names
        idx += 1
p(f"  {len(imports)} DLLs, {sum(len(v) for v in imports.values())} imports total")
for dll in sorted(imports):
    p(f"  {dll:<48} {len(imports[dll]):>4} imports")
p("")
p("=== SELECTED DLL IMPORTS (full) ===")
for key in ["d3d12_xs.dll", "xmem.dll", "XCRDAPI.dll", "xgameruntime.dll",
            "api-ms-win-core-file-l1-1-0.dll", "api-ms-win-core-libraryloader-l1-2-0.dll"]:
    for dll, names in imports.items():
        if key.lower() in dll.lower():
            p(f"  [{dll}]")
            for n in names:
                p(f"      {n}")

p("")
p("=== TLS DIRECTORY ===")
tls_rva, tls_size = dirs.get("TLS", (0, 0))
if tls_rva:
    to = rva2off(tls_rva)
    p(f"  RawDataStart   VA 0x{u64(to):x}")
    p(f"  RawDataEnd     VA 0x{u64(to+8):x}")
    p(f"  AddressOfIndex VA 0x{u64(to+16):x}  (-> _tls_index)")
    p(f"  CallBacks      VA 0x{u64(to+24):x}")
    p(f"  ZeroFillSize   0x{u32(to+32):x}  Characteristics 0x{u32(to+36):x}")
    cb = u64(to+24)
    if cb:
        cbo = rva2off(cb - IMAGE_BASE)
        if cbo:
            k = 0
            while True:
                v = u64(cbo + k*8)
                if v == 0: break
                p(f"    TLS callback[{k}] VA 0x{v:x} (RVA 0x{v-IMAGE_BASE:x})")
                k += 1

p("")
p("=== .pdata (RUNTIME_FUNCTION) ===")
exc_rva, exc_size = dirs.get("EXCEPTION", (0, 0))
funcs = []
if exc_rva:
    eo = rva2off(exc_rva)
    n = exc_size // 12
    p(f"  {n:,} function ranges ({exc_size:,} bytes)")
    for i in range(n):
        s, e, u = u32(eo + i*12), u32(eo + i*12 + 4), u32(eo + i*12 + 8)
        funcs.append((s, e, u))
    for target in [0x2478b30, 0x2478dc7, 0x2478dea, 0x2237178, 0x56a1ec8]:
        hit = [f for f in funcs if f[0] <= target < f[1]]
        if hit:
            s, e, u = hit[0]
            p(f"  RVA 0x{target:x} in function 0x{s:x}..0x{e:x} (size 0x{e-s:x}, unwind 0x{u:x})")
        else:
            p(f"  RVA 0x{target:x}: no .pdata range (may be data / tail)")

p("")
p("=== KEY STRINGS (ASCII + UTF-16LE, first hit) ===")
needles = [b"appdata0.rpf", b"G:\\", b"game:", b"xgameruntime.dll", b"QueryApiImpl",
           b"InitializeApiImplEx2", b"XErrorReport", b"DStorageGetFactory",
           b"XMemAllocatePhysicalPages", b"d3d12_xs.dll", b"XCRDAPI.dll",
           b"shaders.rpf", b"common.rpf", b"D3D12XboxCreateDevice", b"game_scarlett_master.exe"]
for nd in needles:
    hits = []
    a = data.find(nd)
    if a >= 0:
        for name, va, vs, rp, rs, _ in sections:
            if rp <= a < rp + rs:
                hits.append(f"ASCII VA 0x{va + (a-rp) + IMAGE_BASE:x} (file 0x{a:x}, {name})")
                break
    w = nd.decode("ascii", "replace").encode("utf-16le")
    b = data.find(w)
    if b >= 0:
        for name, va, vs, rp, rs, _ in sections:
            if rp <= b < rp + rs:
                hits.append(f"UTF16 VA 0x{va + (b-rp) + IMAGE_BASE:x} (file 0x{b:x}, {name})")
                break
    p(f"  {nd.decode('ascii','replace'):<32}: " + ("; ".join(hits) if hits else "not found"))

p("")
p("=== KEY CONSTANTS / GLOBALS (VA -> file offset -> 16 bytes) ===")
for va in [0x1461e0658, 0x1461e0668, 0x14615c190, 0x14615c1c0,
           0x148759d00, 0x1475e72a0, 0x1475e7300, 0x1498f84ac]:
    rva = va - IMAGE_BASE
    off = rva2off(rva)
    if off is None:
        p(f"  0x{va:x}: RVA 0x{rva:x} not mapped in any section")
        continue
    if off + 16 > len(data):
        p(f"  0x{va:x}  RVA 0x{rva:x}  file 0x{off:x}: beyond file (BSS / zero-fill section, no raw bytes)")
        continue
    chunk = data[off:off+16]
    hexs = " ".join(f"{b:02x}" for b in chunk)
    q0, q1 = u64(off), u64(off+8)
    p(f"  0x{va:x}  RVA 0x{rva:x}  file 0x{off:x}  bytes {hexs}  qwords 0x{q0:016x} 0x{q1:016x}")
    if va in (0x1461e0658, 0x1461e0668):
        d1, d2, d3 = u32(off), u16(off+4), u16(off+6)
        tail = "-".join(f"{b:02x}" for b in data[off+8:off+16])
        p(f"      GUID = {{{d1:08X}-{d2:04X}-{d3:04X}-{tail}}}")

OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"WROTE {OUT}  ({len(lines)} lines)")
