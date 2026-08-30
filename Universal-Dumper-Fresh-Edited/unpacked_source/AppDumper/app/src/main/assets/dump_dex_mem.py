#!/usr/bin/env python3
"""
dump_dex_mem.py  v7  —  universal no-Frida DEX dumper via /proc/PID/mem
Single source of truth for all Android protectors.

Supported: ijiami, 360 Jiagu, Tencent Legu, Tencent TPShell, Baidu Shield,
           Bangcle/SecShell, DexProtector, NetEase YiDun, NQ Shield,
           Alibaba mPaaS, ShadowSafety/JAQ, Nagapt, Appdome, and unprotected apps.

Usage:
    su -c "python3 /sdcard/dump_dex_mem.py <PID> <output_dir> [package_name]"

Examples:
    su -c "python3 /sdcard/dump_dex_mem.py 1234 /data/local/tmp/out com.example.app"
    su -c "python3 /sdcard/dump_dex_mem.py 1234 /data/local/tmp/out"

Filtering rules (when package_name is given):
    KEEP  — [anon:dalvik-DEX] regions          (ART-loaded DEX — ijiami / Legu)
    KEEP  — anonymous rwxp regions >= 50 KB    (in-memory decrypted DEX)
    KEEP  — file-backed regions whose path contains the package name
    SKIP  — file-backed APK/JAR regions containing known protector stub signatures
    SKIP  — Google/GMS/AOSP paths and .so / .oat / .vdex / .art files always
"""

import sys, os, time

# ── global: maps text saved during first successful scan ──────────────────────
g_maps_data = ''

if len(sys.argv) < 2:
    print("Usage: dump_dex_mem.py <PID> <output_dir> [package_name]")
    sys.exit(1)

PID     = int(sys.argv[1])
OUT_DIR = sys.argv[2] if len(sys.argv) >= 3 else '/data/local/tmp/dex_dump'
PKG     = sys.argv[3] if len(sys.argv) >= 4 else None

MAX_SZ      = 80 * 1024 * 1024   # 80 MB — hard cap per DEX
MIN_SZ      = 112                 # minimum valid DEX (header size)
ANON_MIN_SZ = 50 * 1024          # 50 KB — minimum for anonymous rwxp regions
CHUNK       = 4 * 1024 * 1024    # 4 MB read chunk

os.makedirs(OUT_DIR, exist_ok=True)

maps_path = f'/proc/{PID}/maps'
mem_path  = f'/proc/{PID}/mem'

DEX_MAGIC = b'dex\n'
seen  = {}   # header-sig → True, deduplication
count = 0

# ── Protector stub signatures ──────────────────────────────────────────────────
# Applied ONLY to file-backed APK/JAR regions.
# Anonymous regions (decrypted in-memory DEX) are NEVER filtered.
# ─────────────────────────────────────────────────────────────────────────────
PROTECTOR_SIGS = [
    # ── ijiami / 爱加密 / tianyu ──────────────────────────────────────────────
    b'com/stub/StubApp',
    b'com/ijiami/',
    b'com/tianyu/',
    b'com/ijm/',
    b'DtcLoader',
    b'com/ijiami/stub/',

    # ── 360 Jiagu / Qihoo / SecNeo ───────────────────────────────────────────
    b'com/qihoo/jiagu',
    b'com/qihoo/util',
    b'com/qihoo360/',
    b'com/jg/ids',
    b'com/stub/stub0',
    b'com/secneo/',

    # ── Tencent Legu ─────────────────────────────────────────────────────────
    b'com/tencent/legu',

    # ── Tencent TPShell ───────────────────────────────────────────────────────
    b'com/tencent/tpshell',
    b'com/tencent/tpss/',

    # ── Baidu Shield ─────────────────────────────────────────────────────────
    b'com/baidu/protect',
    b'com/baidu/shield',
    b'com/baidu/encrypt',

    # ── Bangcle / SecShell ───────────────────────────────────────────────────
    b'com/secshell/',
    b'com/bangcle/',

    # ── DexProtector (Guardsquare) ────────────────────────────────────────────
    b'com/guardsquare/',
    b'com/saikoa/',
    b'com/dexprotector/',

    # ── NetEase YiDun (网易易盾) ──────────────────────────────────────────────
    b'com/netease/nis/',
    b'com/yidun/',
    b'com/netease/shield',

    # ── NQ Shield ────────────────────────────────────────────────────────────
    b'com/nq/shield',
    b'com/nqmobile/',

    # ── Alibaba mPaaS / ShadowSafety / JAQ ───────────────────────────────────
    b'com/alibaba/wireless/security',
    b'com/alibaba/mobilesecurity',
    b'com/taobao/android/dex',
    b'com/alipay/security',

    # ── Nagapt ───────────────────────────────────────────────────────────────
    b'com/nagapt/',

    # ── Appdome ──────────────────────────────────────────────────────────────
    b'com/appdome/',

    # ── Tongfu Shield (通付盾) ────────────────────────────────────────────────
    b'com/tongfu/',
    b'com/wm_sdk/',

    # ── Kiro (小米加固) ───────────────────────────────────────────────────────
    b'com/kiro/shield',
]



def is_protector_dex(data):
    for sig in PROTECTOR_SIGS:
        if sig in data:
            return True
    return False

# ── Known junk anonymous region names — always skip ───────────────────────────
ANON_JUNK = (
    'scudo', '.bss', 'stack', 'signal_stack', 'guard',
    'linker_alloc', 'bionic_alloc', 'jit-cache', 'jit-data',
)

def is_junk_anon(name):
    n = name.lower()
    return any(j in n for j in ANON_JUNK)


def should_scan(pathname, perm, region_size):
    if not perm.startswith('r'):
        return False

    p = pathname.lower() if pathname else ''

    # always skip native/ART artefacts and system paths
    for skip in ('.so', '.oat', '.vdex', '.art', '.odex',
                 '/system/', '/vendor/', '/apex/', '/proc/',
                 '/sys/', '/dev/hw', '/dev/dri'):
        if skip in p:
            return False

    if PKG:
        # ── filtered mode ─────────────────────────────────────────────────────
        if not pathname:
            # truly anonymous (no name) — include if executable + big enough
            return 'x' in perm and region_size >= ANON_MIN_SZ

        if pathname.startswith('['):
            name = pathname.lower()
            if 'dalvik-dex' in name:
                return True          # always keep ART dalvik-DEX (ijiami / Legu)
            if is_junk_anon(name):
                return False
            return 'x' in perm and region_size >= ANON_MIN_SZ

        # file-backed: keep only if path contains the package name
        return PKG.lower() in p

    else:
        # ── unfiltered mode ───────────────────────────────────────────────────
        for inc in ('[', '/dev/ashmem', '/memfd:', 'dalvik', '/data/app',
                    '/data/data', '/data/user'):
            if p.startswith(inc) or inc in p:
                return True
        return not pathname


def scan_region(mem, start, end, perm, pathname):
    global count
    region_size = end - start
    buf_offset  = 0
    leftover    = b''

    while buf_offset < region_size:
        read_size = min(CHUNK, region_size - buf_offset)
        try:
            mem.seek(start + buf_offset)
            chunk = mem.read(read_size)
        except Exception:
            break
        if not chunk:
            break

        data = leftover + chunk

        search_from = 0
        while True:
            idx = data.find(DEX_MAGIC, search_from)
            if idx == -1:
                break

            abs_addr = start + buf_offset + idx - len(leftover)

            if len(data) < idx + 112:
                try:
                    mem.seek(abs_addr)
                    hdr = mem.read(112)
                except Exception:
                    search_from = idx + 1
                    continue
            else:
                hdr = data[idx:idx + 112]

            if len(hdr) < 112:
                search_from = idx + 1
                continue

            file_size  = int.from_bytes(hdr[32:36], 'little')
            endian_tag = int.from_bytes(hdr[40:44], 'little')

            if (file_size < MIN_SZ or file_size > MAX_SZ or
                    endian_tag != 0x12345678):
                search_from = idx + 1
                continue

            sig = hdr[:64]
            if sig in seen:
                search_from = idx + 1
                continue
            seen[sig] = True

            try:
                mem.seek(abs_addr)
                dex_data = mem.read(file_size)
            except Exception as e:
                print(f'[!] Read failed @ 0x{abs_addr:x}: {e}')
                search_from = idx + 1
                continue

            if len(dex_data) < file_size:
                print(f'[!] Short read @ 0x{abs_addr:x}: '
                      f'got {len(dex_data)}, want {file_size}')
                search_from = idx + 1
                continue

            # Filter protector stubs from file-backed APK regions ONLY.
            # Never filter anonymous/dalvik-DEX regions — those are always real code.
            is_file_backed = pathname and not pathname.startswith('[')
            if is_file_backed and is_protector_dex(dex_data):
                print(f'[-] Skipped protector stub @ 0x{abs_addr:x}'
                      f'  size={file_size:,}  src={pathname}')
                search_from = idx + 1
                continue

            label    = pathname.split('/')[-1] if pathname else 'anon'
            out_path = os.path.join(OUT_DIR, f'classes{count}.dex')
            try:
                with open(out_path, 'wb') as f:
                    f.write(dex_data)
                print(f'[+] #{count}  {out_path}')
                print(f'    size={file_size:,}  addr=0x{abs_addr:x}'
                      f'  perm={perm}  src={pathname or "anon"}')
                count += 1
            except Exception as e:
                print(f'[!] Write failed: {e}')

            search_from = idx + 1

        leftover   = data[-3:] if len(data) >= 3 else data
        buf_offset += read_size


# ── dump.txt helpers ──────────────────────────────────────────────────────────

def _ri(data, pos, size=4, signed=False):
    """Read little-endian integer from bytes."""
    return int.from_bytes(data[pos:pos+size], 'little', signed=signed)


# ── Protector catalogue ───────────────────────────────────────────────────────
# Each entry: (human_name, (prefix, ...))
# Used for:
#   • _is_stub_class  — filter stubs during Application/cf BFS scan
#   • _write_stubs_txt — full report of every protector class found in dumped DEX
_STUB_CATALOGUE = [
    # ── Chinese protectors ────────────────────────────────────────────────────
    ('360 Jiagu / 奇虎',
     ('com.qihoo.', 'com.qihoo360.', 'com.secneo.', 'com.stub.', 'com.jg.')),
    ('ijiami / 爱加密',
     ('com.ijiami.', 'com.ijm.', 'com.tianyu.')),
    ('Bangcle / SecShell / 梆梆',
     ('com.bangcle.', 'com.secshell.')),
    ('Tencent Legu / 乐固',
     ('com.tencent.legu', 'com.tencent.tpshell', 'com.tencent.tpss.',
      'com.tencent.ams.', 'com.tencent.mobileqq.pb.')),
    ('Baidu Protect / 百度加固',
     ('com.baidu.protect', 'com.baidu.shield', 'com.baidu.encrypt',
      'com.baidu.mobsec.')),
    ('Alibaba / mPaaS / 阿里聚安全',
     ('com.alibaba.wireless.security', 'com.alibaba.mobilesecurity',
      'com.taobao.android.dex', 'com.alipay.security',
      'com.alibaba.security.', 'com.ut.mini.')),
    ('NetEase / 易盾',
     ('com.netease.nis.', 'com.yidun.')),
    ('NQ Mobile / 网秦',
     ('com.nq.shield', 'com.nqmobile.')),
    ('TongFu / 通付盾',
     ('com.tongfu.',)),
    ('Nagapt',
     ('com.nagapt.',)),
    ('WM SDK',
     ('com.wm_sdk.',)),
    ('Kiro Shield',
     ('com.kiro.shield',)),
    ('Shimeng Shield / 诗盟',
     ('com.shimeng.shield.',)),
    ('Hanclouds / 汉云',
     ('com.hanclouds.',)),
    ('Longshine / 龙信',
     ('com.longshine.',)),
    ('Cheetah / CM Security',
     ('com.cleanmaster.security.', 'com.ksmobile.shield.')),
    ('ByteDance AppShield',
     ('com.bytedance.appshield.', 'com.ss.android.protect.')),
    # ── International / global protectors ─────────────────────────────────────
    ('GuardSquare / DexGuard / ProGuard',
     ('com.guardsquare.', 'com.saikoa.', 'com.dexprotector.')),
    ('AppDome',
     ('com.appdome.',)),
    ('Liapp (Lockin)',
     ('com.lockincomp.',)),
    ('AppSealing / INKA Entworks',
     ('com.nshield.', 'com.inka.entworks.')),
    ('Verimatrix',
     ('com.verimatrix.',)),
    ('Arxan / Digital.ai',
     ('com.arxan.', 'com.digitalai.')),
    ('Promon SHIELD',
     ('no.promon.',)),
    ('NHN AppGuard',
     ('com.nhnent.appguard.', 'com.nhn.android.appguard.')),
    ('AhnLab V3 Mobile',
     ('com.ahnlab.',)),
    ('AppSolid',
     ('com.appsolid.',)),
]

# Flat tuple for fast prefix matching
_STUB_PREFIXES = tuple(p for _, ps in _STUB_CATALOGUE for p in ps)

def _is_stub_class(name):
    nl = name.lower()
    return any(nl.startswith(s) for s in _STUB_PREFIXES)


def _list_all_dex_classes(data):
    """
    Enumerate every class *defined* in a DEX (class_defs table).
    Returns list of dotted class names, e.g. ['com.qihoo.util.StubApp', ...].
    """
    if len(data) < 112 or data[:4] != b'dex\n':
        return []
    str_ids_size    = _ri(data, 56)
    str_ids_off     = _ri(data, 60)
    type_ids_size   = _ri(data, 64)
    type_ids_off    = _ri(data, 68)
    class_defs_size = _ri(data, 96)
    class_defs_off  = _ri(data, 100)
    classes = []
    for i in range(class_defs_size):
        cd = class_defs_off + i * 32        # class_def_item = 32 bytes
        if cd + 4 > len(data):
            break
        class_idx = _ri(data, cd)
        if class_idx >= type_ids_size:
            continue
        tp = type_ids_off + class_idx * 4
        if tp + 4 > len(data):
            continue
        str_idx = _ri(data, tp)
        desc = _dex_get_string(data, str_ids_off, str_ids_size, str_idx)
        if desc:
            classes.append(_desc_to_dot(desc))
    return classes


def _list_all_dex_type_refs(data):
    """
    Enumerate ALL types *referenced* in a DEX (type_ids table).

    type_ids holds every class/type mentioned anywhere in this DEX — in method
    signatures, field types, invoke instructions, etc. — regardless of whether
    the class is *defined* here or lives in another DEX file.

    Returns list of dotted class names (object types only; primitives/arrays
    that don't start with 'L' are skipped).

    The set difference  type_refs - defined_classes  gives classes that are
    REFERENCED but NOT DEFINED here — i.e. external call-site injections.
    """
    if len(data) < 112 or data[:4] != b'dex\n':
        return []
    str_ids_size  = _ri(data, 56)
    str_ids_off   = _ri(data, 60)
    type_ids_size = _ri(data, 64)
    type_ids_off  = _ri(data, 68)
    types = []
    for i in range(type_ids_size):
        tp = type_ids_off + i * 4
        if tp + 4 > len(data):
            break
        str_idx = _ri(data, tp)
        desc = _dex_get_string(data, str_ids_off, str_ids_size, str_idx)
        # Only object types (Lsome/Class;) — skip primitives and arrays
        if desc and desc.startswith('L') and desc.endswith(';'):
            types.append(_desc_to_dot(desc))
    return types


# ── Safe framework prefixes — excluded from heuristic foreign-class scan ──────
# Covers core Android, popular open-source libs, and runtime internals.
# Keep this list minimal: unknown custom protectors deliberately avoid these.
_SAFE_PREFIXES = (
    'android.', 'androidx.', 'java.', 'javax.', 'dalvik.', 'libcore.',
    'kotlin.', 'kotlinx.',
    'com.google.',          # Firebase, GMS, Guava, Gson, gRPC …
    'io.grpc.', 'io.grpc ',
    'okhttp3.', 'okio.',
    'retrofit2.',
    'org.apache.', 'org.json.', 'org.xmlpull.',
    'org.w3c.', 'org.xml.', 'org.bouncycastle.', 'org.conscrypt.',
    'io.reactivex.', 'rx.',
    'io.flutter.',
    'com.unity3d.',
    'bolts.',
    'io.fabric.', 'com.crashlytics.',
    'com.squareup.',        # OkHttp, Retrofit, Moshi, Picasso, LeakCanary …
    'com.bumptech.',        # Glide
    'com.jakewharton.',     # Timber, ThreeTenABP …
    'io.github.',
    'net.sf.',
)

# DEX files smaller than this are almost always injected protector stubs, not
# real app code (real multidex slices are typically several MB each).
_SMALL_DEX_THRESHOLD = 200 * 1024   # 200 KB


def _write_stubs_txt(out_dir):
    """
    Two-layer scan of every dumped DEX in out_dir.

    Layer 1 — Catalogue (all DEX sizes):
        Match each class against _STUB_CATALOGUE by known prefix.
        Works for all publicly documented protectors.

    Layer 2 — Heuristic (small DEX only, < 200 KB):
        Any class that is:
          • NOT from the app's own package (PKG)
          • NOT already caught by the catalogue
          • NOT from a known safe framework (_SAFE_PREFIXES)
        → flagged as "Unknown / Custom Protector"
        Small DEX files are the injection vehicle for every protector.
        Limiting to small DEX avoids flooding the report with legitimate
        third-party library classes from large app DEX slices.
    """
    print('[*] stubs.txt: scanning dumped DEX for protector classes...')

    # {protector_name: {dex_filename: [class_name, ...]}}
    found = {}
    # Track which (fname, cls) pairs were already caught by catalogue
    catalogue_hits = set()

    try:
        dex_files = sorted(f for f in os.listdir(out_dir) if f.endswith('.dex'))
    except Exception as e:
        print(f'[!] stubs.txt: cannot list out_dir: {e}')
        return

    # ── Layer 1: catalogue scan (all DEX) ────────────────────────────────────
    for fname in dex_files:
        fpath = os.path.join(out_dir, fname)
        try:
            with open(fpath, 'rb') as f:
                data = f.read()
        except Exception:
            continue

        for cls in _list_all_dex_classes(data):
            cl = cls.lower()
            for prot_name, prefixes in _STUB_CATALOGUE:
                if any(cl.startswith(p) for p in prefixes):
                    found.setdefault(prot_name, {}).setdefault(fname, []).append(cls)
                    catalogue_hits.add((fname, cls))
                    break

    # ── Layer 2: heuristic scan (small DEX only) ──────────────────────────────
    #  Any foreign class defined in a small DEX that wasn't caught by catalogue.
    app_pkg = (PKG + '.') if PKG else None
    for fname in dex_files:
        fpath = os.path.join(out_dir, fname)
        try:
            fsize = os.path.getsize(fpath)
            if fsize > _SMALL_DEX_THRESHOLD:
                continue            # skip large DEX — real app/library code
            with open(fpath, 'rb') as f:
                data = f.read()
        except Exception:
            continue

        for cls in _list_all_dex_classes(data):
            if (fname, cls) in catalogue_hits:
                continue
            cl = cls.lower()
            if app_pkg and cl.startswith(app_pkg.lower()):
                continue
            if any(cl.startswith(s) for s in _SAFE_PREFIXES):
                continue
            label = 'Unknown / Custom Protector (heuristic)'
            found.setdefault(label, {}).setdefault(fname, []).append(cls)
            catalogue_hits.add((fname, cls))

    # ── Layer 3: call-site injection scan (all DEX, type_ids) ─────────────────
    #  Protectors like 360 Jiagu inject calls INTO real app methods:
    #    invoke-virtual {v0}, Lcom/stub/StubApp;->interface11(I)V
    #  The class Lcom/stub/StubApp; appears in the type_ids of the big app DEX
    #  even though it is NOT defined there.
    #  We detect this by: type_ids_refs - class_defs = external stub references.
    for fname in dex_files:
        fpath = os.path.join(out_dir, fname)
        try:
            with open(fpath, 'rb') as f:
                data = f.read()
        except Exception:
            continue

        defined  = set(_list_all_dex_classes(data))
        all_refs = _list_all_dex_type_refs(data)

        for cls in all_refs:
            if cls in defined:
                continue                      # defined here — Layer 1 handles it
            if (fname, cls) in catalogue_hits:
                continue                      # already reported
            cl = cls.lower()
            for prot_name, prefixes in _STUB_CATALOGUE:
                if any(cl.startswith(p) for p in prefixes):
                    label = prot_name + ' [call-site injection]'
                    found.setdefault(label, {}).setdefault(fname, []).append('→ ' + cls)
                    catalogue_hits.add((fname, cls))
                    break

    # ── Write report ──────────────────────────────────────────────────────────
    txt_path = os.path.join(out_dir, 'stubs.txt')
    try:
        with open(txt_path, 'w') as f:
            if not found:
                f.write('=== Protector Stub Classes Report ===\n\n')
                f.write('No protector stub classes found (known, heuristic, or injected).\n')
                f.write('The dumped DEX files appear clean.\n')
                print('[*] stubs.txt: no protector classes detected')
            else:
                total = sum(
                    len(cls_list)
                    for dex_map in found.values()
                    for cls_list in dex_map.values()
                )
                f.write('=== Protector Stub Classes Report ===\n')
                f.write(f'Total entries: {total}\n\n')
                f.write('Legend:\n')
                f.write('  [KNOWN]  — class *defined* in this DEX with a known protector package\n')
                f.write('  [HEUR]   — foreign class *defined* in a small (<200 KB) injected DEX\n')
                f.write('  [INJECT] — protector class *referenced* in real app DEX (injected call site)\n')
                f.write('             Lines starting with → are external refs, not defined locally\n\n')

                for prot_name, dex_map in sorted(found.items()):
                    if 'heuristic' in prot_name:
                        tag = '[HEUR]  '
                    elif 'call-site' in prot_name:
                        tag = '[INJECT]'
                    else:
                        tag = '[KNOWN] '
                    prot_total = sum(len(v) for v in dex_map.values())
                    prot_files = len(dex_map)
                    f.write(f'{tag} {prot_name}  '
                            f'({prot_total} entries in {prot_files} DEX file(s))\n')
                    for dex_file, cls_list in sorted(dex_map.items()):
                        fp2 = os.path.join(out_dir, dex_file)
                        fsize_kb = os.path.getsize(fp2) // 1024 if os.path.exists(fp2) else 0
                        f.write(f'  {dex_file}  [{fsize_kb} KB]  ({len(cls_list)} entries):\n')
                        for cls in sorted(cls_list):
                            f.write(f'    {cls}\n')
                    f.write('\n')

                print(f'[*] stubs.txt: {total} entries across {len(found)} section(s)')
    except Exception as e:
        print(f'[!] stubs.txt write failed: {e}')


def _dex_get_string(data, str_ids_off, str_ids_size, idx):
    """Read a string from DEX string pool by index."""
    if idx < 0 or idx >= str_ids_size:
        return ''
    sp = str_ids_off + idx * 4
    if sp + 4 > len(data):
        return ''
    str_off = _ri(data, sp)
    if str_off >= len(data):
        return ''
    # ULEB128 length prefix then UTF-8 bytes then \0
    pos = str_off
    shift = 0
    while pos < len(data) and (data[pos] & 0x80):
        pos += 1
    pos += 1  # skip last ULEB128 byte
    end = data.find(b'\x00', pos)
    if end == -1:
        end = len(data)
    return data[pos:end].decode('utf-8', errors='ignore')


def _scan_dex_for_subclasses(dex_data, target_type):
    """
    Find all classes in a DEX whose direct superclass == target_type.
    Returns list of raw DEX descriptors e.g. ['Lcom/example/MyApp;'].

    DEX header offsets (correct):
      56  string_ids_size    60  string_ids_off
      64  type_ids_size      68  type_ids_off
      96  class_defs_size   100  class_defs_off
    """
    if len(dex_data) < 112 or dex_data[:4] != b'dex\n':
        return []

    str_ids_size    = _ri(dex_data, 56)
    str_ids_off     = _ri(dex_data, 60)
    type_ids_size   = _ri(dex_data, 64)
    type_ids_off    = _ri(dex_data, 68)
    class_defs_size = _ri(dex_data, 96)
    class_defs_off  = _ri(dex_data, 100)

    def get_type_desc(type_idx):
        if type_idx < 0 or type_idx >= type_ids_size:
            return ''
        tp = type_ids_off + type_idx * 4
        if tp + 4 > len(dex_data):
            return ''
        return _dex_get_string(dex_data, str_ids_off, str_ids_size,
                               _ri(dex_data, tp))

    # Find type_idx for the target superclass descriptor
    target_idx = None
    for i in range(type_ids_size):
        if get_type_desc(i) == target_type:
            target_idx = i
            break
    if target_idx is None:
        return []

    results = []
    for i in range(class_defs_size):
        cd = class_defs_off + i * 32          # class_def_item = 32 bytes
        if cd + 32 > len(dex_data):
            break
        class_idx      = _ri(dex_data, cd)
        superclass_idx = _ri(dex_data, cd + 8)
        if superclass_idx == target_idx:
            results.append(get_type_desc(class_idx))  # raw e.g. Lcom/x/Y;
    return results


def _desc_to_dot(desc):
    """'Lcom/example/MyApp;'  →  'com.example.MyApp'"""
    if desc.startswith('L') and desc.endswith(';'):
        return desc[1:-1].replace('/', '.')
    return desc


def _find_in_dumped_dex(out_dir, target_type, skip_stubs=True):
    """
    Walk every dumped DEX in out_dir.
    Does a 2-level BFS so it catches:
      MyApp → MultiDexApplication → Application
    Returns first non-stub match, or None.
    """
    # Load all DEX files once
    dex_cache = {}
    try:
        for fname in sorted(os.listdir(out_dir)):
            if not fname.endswith('.dex'):
                continue
            fpath = os.path.join(out_dir, fname)
            try:
                with open(fpath, 'rb') as f:
                    dex_cache[fname] = f.read()
            except Exception:
                pass
    except Exception:
        return None

    def scan_all(super_desc):
        """Return all subclass descriptors of super_desc across all DEX."""
        hits = []
        for data in dex_cache.values():
            hits.extend(_scan_dex_for_subclasses(data, super_desc))
        return hits

    # Level 1 — direct subclasses of target_type
    level1 = scan_all(target_type)

    real = []
    intermediate = []
    for desc in level1:
        name = _desc_to_dot(desc)
        if skip_stubs and _is_stub_class(name):
            print(f'[-] dump.txt: skipped stub: {name}')
            continue
        # Heuristic: framework/library base classes have short package depth
        parts = name.split('.')
        if len(parts) <= 3:
            intermediate.append(desc)   # e.g. androidx.multidex.MultiDexApplication
        else:
            real.append(name)

    if real:
        real.sort(key=len)
        return real[0]

    # Level 2 — subclasses of intermediate base classes (e.g. MultiDexApplication)
    for base_desc in intermediate:
        for desc in scan_all(base_desc):
            name = _desc_to_dot(desc)
            if skip_stubs and _is_stub_class(name):
                print(f'[-] dump.txt: skipped stub (L2): {name}')
                continue
            real.append(name)

    if real:
        real.sort(key=len)
        return real[0]

    return None


def _cf_from_type_strings(out_dir, maps_text):
    """
    Protectors strip appComponentFactory from the manifest and the real cf
    class (e.g. CoreComponentFactory) lives in OAT/VDEX, not raw DEX — so
    the subclass scan misses it.

    However, the app's own code REFERENCES the cf class as a type string in
    its DEX string pool.  A raw byte search for the Dalvik type descriptor
    across the dumped DEX files (and the base APK stub DEX) is reliable.

    Known cf descriptors → canonical class names, ordered by preference.
    """
    KNOWN = [
        (b'Landroidx/core/app/CoreComponentFactory;',
         'androidx.core.app.CoreComponentFactory'),
        (b'Landroid/support/v4/app/CoreComponentFactory;',
         'android.support.v4.app.CoreComponentFactory'),
    ]

    def search(data):
        for sig, name in KNOWN:
            if sig in data:
                return name
        return None

    # 1. Scan every dumped DEX file
    try:
        for fname in sorted(os.listdir(out_dir)):
            if not fname.endswith('.dex'):
                continue
            try:
                with open(os.path.join(out_dir, fname), 'rb') as f:
                    hit = search(f.read())
                if hit:
                    print(f'[*] dump.txt: cf found via type-string in {fname}: {hit}')
                    return hit
            except Exception:
                pass
    except Exception:
        pass

    # 2. Also check the base APK stub DEX (classes.dex slot)
    apk_path = _get_apk_path(maps_text)
    if apk_path:
        tmp = '/data/local/tmp/_matrix_cf_chk.dex'
        try:
            os.system(f'unzip -p "{apk_path}" classes.dex > "{tmp}" 2>/dev/null')
            with open(tmp, 'rb') as f:
                hit = search(f.read())
            os.system(f'rm -f "{tmp}"')
            if hit:
                print(f'[*] dump.txt: cf found via base APK stub DEX: {hit}')
                return hit
        except Exception:
            pass

    return None


# ── Manifest parsing (fallback / AppComponentFactory) ─────────────────────────

def _get_apk_path(maps_text):
    """Find base.apk from /proc/PID/maps, fall back to pm path."""
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            p = parts[5]
            if p.endswith('.apk') and '/data/app/' in p:
                return p
    # Fallback: ask package manager directly
    if PKG:
        try:
            out = os.popen(f'pm path {PKG} 2>/dev/null').read().strip()
            if out.startswith('package:'):
                return out[8:].strip()
        except Exception:
            pass
    return None


def _parse_axml(data):
    """
    Parse Android binary XML → {'name': ..., 'appComponentFactory': ...}
    from the <application> element.
    """
    if len(data) < 8:
        return {}
    strings = []
    i = 8
    while i + 8 <= len(data):
        chunk_type = _ri(data, i, 2)
        chunk_hdr  = _ri(data, i+2, 2)
        chunk_size = _ri(data, i+4)
        if chunk_size <= 0 or i + chunk_size > len(data):
            break

        if chunk_type == 0x0001:                          # string pool
            str_count = _ri(data, i+8)
            flags     = _ri(data, i+16)
            str_start = _ri(data, i+20)
            utf8      = bool(flags & (1 << 8))
            off_base  = i + chunk_hdr
            dat_base  = i + str_start
            for k in range(str_count):
                op  = off_base + k * 4
                if op + 4 > len(data): break
                off = _ri(data, op)
                pos = dat_base + off
                try:
                    if utf8:
                        b = data[pos]; pos += 1
                        if b & 0x80: b = ((b & 0x3f) << 8) | data[pos]; pos += 1
                        b = data[pos]; pos += 1
                        if b & 0x80: b = ((b & 0x3f) << 8) | data[pos]; pos += 1
                        s = data[pos:pos+b].decode('utf-8', errors='ignore')
                    else:
                        cl = _ri(data, pos, 2); pos += 2
                        s  = data[pos:pos+cl*2].decode('utf-16-le', errors='ignore')
                    strings.append(s)
                except Exception:
                    strings.append('')

        elif chunk_type == 0x0102 and strings:             # start element
            if i + 28 > len(data): i += chunk_size; continue
            name_idx       = _ri(data, i+12)
            attr_start_off = _ri(data, i+16, 2)
            attr_size_each = _ri(data, i+18, 2)
            attr_count     = _ri(data, i+20, 2)
            el_name = strings[name_idx] if 0 <= name_idx < len(strings) else ''
            if el_name == 'application' and attr_size_each >= 20:
                attrs_base = i + 8 + attr_start_off
                result = {}
                for a in range(attr_count):
                    ap = attrs_base + a * attr_size_each
                    if ap + 20 > len(data): break
                    an_idx    = _ri(data, ap+4)
                    raw_idx   = _ri(data, ap+8)
                    data_type = data[ap+15]
                    val_data  = _ri(data, ap+16)
                    attr_name = strings[an_idx] if 0 <= an_idx < len(strings) else ''
                    attr_val  = ''
                    if data_type == 0x03 and 0 <= val_data < len(strings):
                        attr_val = strings[val_data]
                    elif raw_idx != 0xFFFFFFFF and 0 <= raw_idx < len(strings):
                        attr_val = strings[raw_idx]
                    if attr_name in ('name', 'appComponentFactory') and attr_val:
                        result[attr_name] = attr_val
                if result:
                    return result
        i += chunk_size
    return {}


def _manifest_attrs(maps_text):
    """Extract application attrs from the APK manifest. Returns dict."""
    apk_path = _get_apk_path(maps_text)
    if not apk_path:
        return {}
    tmp_mf = '/data/local/tmp/_matrix_mf_tmp.bin'
    try:
        os.system(f'unzip -p "{apk_path}" AndroidManifest.xml > "{tmp_mf}" 2>/dev/null')
        with open(tmp_mf, 'rb') as f:
            mf_data = f.read()
        os.system(f'rm -f "{tmp_mf}"')
        return _parse_axml(mf_data)
    except Exception as e:
        print(f'[!] dump.txt: manifest parse error: {e}')
        return {}


def write_dump_txt(out_dir, maps_text):
    """
    Write dump.txt.
    Application class  → scanned from dumped DEX files (real class, not stub).
    AppComponentFactory→ from manifest (or DEX scan fallback).
    Falls back to manifest / defaults if nothing found.
    """
    # ── 1. Real Application class from dumped DEX ─────────────────────────────
    print('[*] dump.txt: scanning dumped DEX for real Application class...')
    app_class = _find_in_dumped_dex(out_dir, 'Landroid/app/Application;')

    # ── 2. AppComponentFactory from dumped DEX ────────────────────────────────
    app_cf = _find_in_dumped_dex(
        out_dir, 'Landroid/app/AppComponentFactory;', skip_stubs=False)

    # ── 3. Fallback: manifest for anything still missing ──────────────────────
    if not app_class or not app_cf:
        mf = _manifest_attrs(maps_text)
        if not app_class:
            app_class = mf.get('name', None)
            if app_class and app_class.startswith('.') and PKG:
                app_class = PKG + app_class
        if not app_cf:
            app_cf = mf.get('appComponentFactory', None)

    # ── 4. Type-string search fallback for cf ─────────────────────────────────
    #  Protectors (360, ijiami …) strip appComponentFactory from the manifest.
    #  CoreComponentFactory lives in OAT/VDEX so the subclass scan misses it.
    #  But any app code that references it has its Dalvik type descriptor as a
    #  raw string in the DEX string pool — a byte search is reliable.
    if not app_cf:
        app_cf = _cf_from_type_strings(out_dir, maps_text)

    # ── 5. Write dump.txt ─────────────────────────────────────────────────────
    txt_path = os.path.join(out_dir, 'dump.txt')
    try:
        with open(txt_path, 'w') as f:
            f.write('*****Application******\n')
            f.write((app_class or 'android.app.Application') + '\n')
            f.write('******AppComponentFactory******\n')
            f.write((app_cf   or 'android.app.AppComponentFactory') + '\n')
        print(f'[*] dump.txt → app={app_class}  cf={app_cf}')
    except Exception as e:
        print(f'[!] dump.txt write failed: {e}')


# ── scanner ───────────────────────────────────────────────────────────────────

def do_scan(pass_num):
    global g_maps_data
    print(f'\n[*] === Pass {pass_num} scan (PID={PID}) ===')
    if PKG:
        print(f'[*] Filter: keeping only DEX for "{PKG}"')
    try:
        maps_data = open(maps_path, 'r').read()
    except Exception as e:
        print(f'[!] Cannot read maps: {e}')
        return

    if not g_maps_data:
        g_maps_data = maps_data

    try:
        mem = open(mem_path, 'rb')
    except Exception as e:
        print(f'[!] Cannot open mem: {e}')
        return

    regions = []
    for line in maps_data.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        perm        = parts[1]
        pathname    = parts[5] if len(parts) >= 6 else ''
        try:
            start, end = [int(x, 16) for x in parts[0].split('-')]
        except ValueError:
            continue
        region_size = end - start
        if region_size < MIN_SZ:
            continue
        if not should_scan(pathname, perm, region_size):
            continue
        regions.append((start, end, perm, pathname))

    print(f'[*] Scanning {len(regions)} regions...')
    for start, end, perm, pathname in regions:
        scan_region(mem, start, end, perm, pathname)

    mem.close()
    print(f'[*] Pass {pass_num} done. Total unique DEX so far: {count}')


do_scan(1)

if count == 0:
    print('\n[*] Nothing on first pass — waiting 3s and retrying...')
    time.sleep(3)
    do_scan(2)

print(f'\n[*] DONE. Saved {count} DEX file(s) to {OUT_DIR}')

write_dump_txt(OUT_DIR, g_maps_data)
_write_stubs_txt(OUT_DIR)

if count == 0:
    print('[!] Still nothing found.')
    print('    - Make sure the app is fully open (past any loading screen).')
    print('    - Try while any loading/anti-piracy dialog is visible.')
    print('    - Wait 10s after launch and run again.')
    print('    - Some protectors need a longer wait — check decryptWait in DumperService.')
