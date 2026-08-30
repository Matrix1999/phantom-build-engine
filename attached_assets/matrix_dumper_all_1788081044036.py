#!/data/data/com.termux/files/usr/bin/python3
"""
matrix_dumper_all.py — @matrix_dumper_bot  (ALL-IN-ONE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Single file. Copy to /sdcard/ and run — everything else
is handled automatically:
  • Installs missing packages (aapt, python-telegram-bot)
  • Writes the DEX dumper script to /sdcard/dump_dex_mem.py
  • Creates the Termux:Boot auto-start script
  • Starts the Telegram bot

Usage:
    python3 /sdcard/matrix_dumper_all.py
"""

import os
import sys
import shutil
import subprocess

# ══════════════════════════════════════════════════════════════════════════════
#  EMBEDDED: dump_dex_mem.py  (written to /sdcard/ on every startup)
# ══════════════════════════════════════════════════════════════════════════════

DUMP_SCRIPT_CONTENT = r'''#!/usr/bin/env python3
"""
dump_dex_mem.py  v7  —  universal no-Frida DEX dumper via /proc/PID/mem
Single source of truth for all Android protectors.

Supported: ijiami, 360 Jiagu, Tencent Legu, Tencent TPShell, Baidu Shield,
           Bangcle/SecShell, DexProtector, NetEase YiDun, NQ Shield,
           Alibaba mPaaS, ShadowSafety/JAQ, Nagapt, Appdome, and unprotected apps.

Usage:
    su -c "python3 /sdcard/dump_dex_mem.py <PID> <output_dir> [package_name]"

Filtering rules (when package_name is given):
    KEEP  — [anon:dalvik-DEX] regions          (ART-loaded DEX — ijiami / Legu)
    KEEP  — anonymous rwxp regions >= 50 KB    (in-memory decrypted DEX)
    KEEP  — file-backed regions whose path contains the package name
    SKIP  — file-backed APK/JAR regions containing known protector stub signatures
    SKIP  — Google/GMS/AOSP paths and .so / .oat / .vdex / .art files always
"""

import sys, os, time

g_maps_data = ''

if len(sys.argv) < 2:
    print("Usage: dump_dex_mem.py <PID> <output_dir> [package_name]")
    sys.exit(1)

PID     = int(sys.argv[1])
OUT_DIR = sys.argv[2] if len(sys.argv) >= 3 else '/data/local/tmp/dex_dump'
PKG     = sys.argv[3] if len(sys.argv) >= 4 else None

MAX_SZ      = 32 * 1024 * 1024   # 32 MB — real DEX files are never larger; cap keeps RSS low
MIN_SZ      = 112
ANON_MIN_SZ = 50 * 1024
CHUNK       = 512 * 1024         # 512 KB reads — was 4 MB; smaller = lower peak RSS

os.makedirs(OUT_DIR, exist_ok=True)

maps_path = f'/proc/{PID}/maps'
mem_path  = f'/proc/{PID}/mem'

DEX_MAGIC = b'dex\n'
seen  = {}
count = 0

PROTECTOR_SIGS = [
    b'com/stub/StubApp', b'com/ijiami/', b'com/tianyu/', b'com/ijm/',
    b'DtcLoader', b'com/ijiami/stub/',
    b'com/qihoo/jiagu', b'com/qihoo/util', b'com/qihoo360/', b'com/jg/ids',
    b'com/stub/stub0', b'com/secneo/',
    b'com/tencent/legu', b'com/tencent/tpshell', b'com/tencent/tpss/',
    b'com/baidu/protect', b'com/baidu/shield', b'com/baidu/encrypt',
    b'com/secshell/', b'com/bangcle/',
    b'com/guardsquare/', b'com/saikoa/', b'com/dexprotector/',
    b'com/netease/nis/', b'com/yidun/', b'com/netease/shield',
    b'com/nq/shield', b'com/nqmobile/',
    b'com/alibaba/wireless/security', b'com/alibaba/mobilesecurity',
    b'com/taobao/android/dex', b'com/alipay/security',
    b'com/nagapt/', b'com/appdome/', b'com/tongfu/', b'com/wm_sdk/',
    b'com/kiro/shield',
]

def is_protector_dex(data):
    for sig in PROTECTOR_SIGS:
        if sig in data:
            return True
    return False

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
    for skip in ('.so', '.oat', '.vdex', '.art', '.odex',
                 '/system/', '/vendor/', '/apex/', '/proc/',
                 '/sys/', '/dev/hw', '/dev/dri'):
        if skip in p:
            return False
    if PKG:
        if not pathname:
            return 'x' in perm and region_size >= ANON_MIN_SZ
        if pathname.startswith('['):
            name = pathname.lower()
            if 'dalvik-dex' in name:
                return True
            if is_junk_anon(name):
                return False
            return 'x' in perm and region_size >= ANON_MIN_SZ
        return PKG.lower() in p
    else:
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


def _ri(data, pos, size=4, signed=False):
    return int.from_bytes(data[pos:pos+size], 'little', signed=signed)


_STUB_CATALOGUE = [
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

_STUB_PREFIXES = tuple(p for _, ps in _STUB_CATALOGUE for p in ps)

def _is_stub_class(name):
    nl = name.lower()
    return any(nl.startswith(s) for s in _STUB_PREFIXES)


def _dex_get_string(data, str_ids_off, str_ids_size, idx):
    if idx < 0 or idx >= str_ids_size:
        return ''
    sp = str_ids_off + idx * 4
    if sp + 4 > len(data):
        return ''
    str_off = _ri(data, sp)
    if str_off >= len(data):
        return ''
    pos = str_off
    while pos < len(data) and (data[pos] & 0x80):
        pos += 1
    pos += 1
    end = data.find(b'\x00', pos)
    if end == -1:
        end = len(data)
    return data[pos:end].decode('utf-8', errors='ignore')


def _desc_to_dot(desc):
    if desc.startswith('L') and desc.endswith(';'):
        return desc[1:-1].replace('/', '.')
    return desc


def _list_all_dex_classes(data):
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
        cd = class_defs_off + i * 32
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
        if desc and desc.startswith('L') and desc.endswith(';'):
            types.append(_desc_to_dot(desc))
    return types


_SAFE_PREFIXES = (
    'android.', 'androidx.', 'java.', 'javax.', 'dalvik.', 'libcore.',
    'kotlin.', 'kotlinx.',
    'com.google.', 'io.grpc.', 'okhttp3.', 'okio.', 'retrofit2.',
    'org.apache.', 'org.json.', 'org.xmlpull.',
    'org.w3c.', 'org.xml.', 'org.bouncycastle.', 'org.conscrypt.',
    'io.reactivex.', 'rx.', 'io.flutter.', 'com.unity3d.',
    'bolts.', 'io.fabric.', 'com.crashlytics.',
    'com.squareup.', 'com.bumptech.', 'com.jakewharton.',
    'io.github.', 'net.sf.',
)

_SMALL_DEX_THRESHOLD = 200 * 1024


def _write_stubs_txt(out_dir):
    print('[*] stubs.txt: scanning dumped DEX for protector classes...')
    found = {}
    catalogue_hits = set()
    try:
        dex_files = sorted(f for f in os.listdir(out_dir) if f.endswith('.dex'))
    except Exception as e:
        print(f'[!] stubs.txt: cannot list out_dir: {e}')
        return
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
    app_pkg = (PKG + '.') if PKG else None
    for fname in dex_files:
        fpath = os.path.join(out_dir, fname)
        try:
            fsize = os.path.getsize(fpath)
            if fsize > _SMALL_DEX_THRESHOLD:
                continue
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
                continue
            if (fname, cls) in catalogue_hits:
                continue
            cl = cls.lower()
            for prot_name, prefixes in _STUB_CATALOGUE:
                if any(cl.startswith(p) for p in prefixes):
                    label = prot_name + ' [call-site injection]'
                    found.setdefault(label, {}).setdefault(fname, []).append('-> ' + cls)
                    catalogue_hits.add((fname, cls))
                    break
    txt_path = os.path.join(out_dir, 'stubs.txt')
    try:
        with open(txt_path, 'w') as f:
            if not found:
                f.write('=== Protector Stub Classes Report ===\n\n')
                f.write('No protector stub classes found.\n')
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
                f.write('  [KNOWN]  — class defined in DEX with known protector package\n')
                f.write('  [HEUR]   — foreign class defined in a small (<200 KB) injected DEX\n')
                f.write('  [INJECT] — protector class referenced in real app DEX\n\n')
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


def _scan_dex_for_subclasses(dex_data, target_type):
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
        return _dex_get_string(dex_data, str_ids_off, str_ids_size, _ri(dex_data, tp))
    target_idx = None
    for i in range(type_ids_size):
        if get_type_desc(i) == target_type:
            target_idx = i
            break
    if target_idx is None:
        return []
    results = []
    for i in range(class_defs_size):
        cd = class_defs_off + i * 32
        if cd + 32 > len(dex_data):
            break
        class_idx      = _ri(dex_data, cd)
        superclass_idx = _ri(dex_data, cd + 8)
        if superclass_idx == target_idx:
            results.append(get_type_desc(class_idx))
    return results


def _find_in_dumped_dex(out_dir, target_type, skip_stubs=True):
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
        hits = []
        for data in dex_cache.values():
            hits.extend(_scan_dex_for_subclasses(data, super_desc))
        return hits
    level1 = scan_all(target_type)
    real = []
    intermediate = []
    for desc in level1:
        name = _desc_to_dot(desc)
        if skip_stubs and _is_stub_class(name):
            print(f'[-] dump.txt: skipped stub: {name}')
            continue
        parts = name.split('.')
        if len(parts) <= 3:
            intermediate.append(desc)
        else:
            real.append(name)
    if real:
        real.sort(key=len)
        return real[0]
    for base_desc in intermediate:
        for desc in scan_all(base_desc):
            name = _desc_to_dot(desc)
            if skip_stubs and _is_stub_class(name):
                continue
            real.append(name)
    if real:
        real.sort(key=len)
        return real[0]
    return None


def _get_apk_path(maps_text):
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            p = parts[5]
            if p.endswith('.apk') and '/data/app/' in p:
                return p
    if PKG:
        try:
            out = os.popen(f'pm path {PKG} 2>/dev/null').read().strip()
            if out.startswith('package:'):
                return out[8:].strip()
        except Exception:
            pass
    return None


def _parse_axml(data):
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
        if chunk_type == 0x0001:
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
        elif chunk_type == 0x0102 and strings:
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


def _cf_from_type_strings(out_dir, maps_text):
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
    try:
        for fname in sorted(os.listdir(out_dir)):
            if not fname.endswith('.dex'):
                continue
            try:
                with open(os.path.join(out_dir, fname), 'rb') as f:
                    hit = search(f.read())
                if hit:
                    return hit
            except Exception:
                pass
    except Exception:
        pass
    apk_path = _get_apk_path(maps_text)
    if apk_path:
        tmp = '/data/local/tmp/_matrix_cf_chk.dex'
        try:
            os.system(f'unzip -p "{apk_path}" classes.dex > "{tmp}" 2>/dev/null')
            with open(tmp, 'rb') as f:
                hit = search(f.read())
            os.system(f'rm -f "{tmp}"')
            if hit:
                return hit
        except Exception:
            pass
    return None


def _manifest_attrs(maps_text):
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
    print('[*] dump.txt: scanning dumped DEX for real Application class...')
    app_class = _find_in_dumped_dex(out_dir, 'Landroid/app/Application;')
    app_cf    = _find_in_dumped_dex(out_dir, 'Landroid/app/AppComponentFactory;', skip_stubs=False)
    if not app_class or not app_cf:
        mf = _manifest_attrs(maps_text)
        if not app_class:
            app_class = mf.get('name', None)
            if app_class and app_class.startswith('.') and PKG:
                app_class = PKG + app_class
        if not app_cf:
            app_cf = mf.get('appComponentFactory', None)
    if not app_cf:
        app_cf = _cf_from_type_strings(out_dir, maps_text)
    txt_path = os.path.join(out_dir, 'dump.txt')
    try:
        with open(txt_path, 'w') as f:
            f.write('*****Application******\n')
            f.write((app_class or 'android.app.Application') + '\n')
            f.write('******AppComponentFactory******\n')
            f.write((app_cf   or 'android.app.AppComponentFactory') + '\n')
        print(f'[*] dump.txt -> app={app_class}  cf={app_cf}')
    except Exception as e:
        print(f'[!] dump.txt write failed: {e}')


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
    print('    - Some protectors need a longer wait.')
'''

# ══════════════════════════════════════════════════════════════════════════════
#  EMBEDDED: Termux:Boot auto-start script
# ══════════════════════════════════════════════════════════════════════════════

BOT_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN",
              "8591980181:AAF_jfurO08S1af26akigNpqlFiZYr09R0M")
TG_API_ID   = 23718822
TG_API_HASH = "900af7ab5ee13b80077ef3ff51b12e1a"
SELF_PATH   = os.path.abspath(__file__)

# ── Premium / access control ──────────────────────────────────────────────
ADMIN_ID         = 853645999            # only this user can run admin commands
FREE_DAILY_LIMIT       = 3              # free-tier DEX dumps per day
PAIRIP_FREE_DAILY_LIMIT = 5             # free-tier Pairip jobs per day
PREMIUM_CHANNEL  = "https://t.me/Matrix99bot"
PREMIUM_FILE     = os.path.expanduser("~/matrix_premium.json")
USAGE_FILE       = os.path.expanduser("~/matrix_usage.json")
USERS_FILE       = os.path.expanduser("~/matrix_users.json")

BOOT_SCRIPT_CONTENT = """#!/data/data/com.termux/files/usr/bin/sh
# Auto-started by Termux:Boot on every device reboot
# Uses screen to run the bot — detached native session survives Android

TERMUX_BIN=/data/data/com.termux/files/usr/bin
TERMUX_HOME=/data/data/com.termux/files/home
LOG="$TERMUX_HOME/matrix_boot.log"

echo "$(date) — [Termux:Boot] started" >> "$LOG"

# Prevent CPU sleep
"$TERMUX_BIN/termux-wake-lock"
echo "$(date) — [Termux:Boot] wake-lock acquired" >> "$LOG"

# Wait up to 60s for network
i=0
while [ $i -lt 30 ]; do
    "$TERMUX_BIN/ping" -c 1 -W 1 8.8.8.8 >/dev/null 2>&1 && break
    "$TERMUX_BIN/sleep" 2
    i=$((i+1))
done
echo "$(date) — [Termux:Boot] network ready" >> "$LOG"

# Kill any stale bot or screen session before starting fresh
"$TERMUX_BIN/pkill" -f matrix_dumper_all.py 2>/dev/null
"$TERMUX_BIN/screen" -S matrix_bot -X quit 2>/dev/null
"$TERMUX_BIN/sleep" 2

# Start bot inside a detached screen session
"$TERMUX_BIN/screen" -dmS matrix_bot "$TERMUX_BIN/python3" "$TERMUX_HOME/matrix_dumper_all.py"
echo "$(date) — [Termux:Boot] bot started in screen session" >> "$LOG"

# Watchdog loop — keeps script alive AND restarts screen if bot crashes
while true; do
    "$TERMUX_BIN/sleep" 15
    if ! "$TERMUX_BIN/screen" -ls 2>/dev/null | grep -q "matrix_bot"; then
        echo "$(date) — [Termux:Boot] bot crashed — restarting" >> "$LOG"
        "$TERMUX_BIN/screen" -dmS matrix_bot "$TERMUX_BIN/python3" "$TERMUX_HOME/matrix_dumper_all.py"
    fi
done
"""


# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP: write embedded files, install missing deps, then run bot
# ══════════════════════════════════════════════════════════════════════════════

DUMP_SCRIPT = os.path.expanduser("~/dump_dex_mem.py")
WORK_DIR    = os.path.expanduser("~/matrix_dumper_work")
BOOT_DIR    = os.path.expanduser("~/.termux/boot")
BOOT_FILE   = os.path.join(BOOT_DIR, "start_matrix_dumper.sh")
PYTHON3     = sys.executable


def run(cmd: str, timeout: int = 300) -> tuple[int, str, str]:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def step(msg: str):
    print(f"\n  {msg}")


def ensure_wake_lock(verbose: bool = False) -> bool:
    """
    Check whether termux-wake-lock is active and enable it if not.
    Detection: dumpsys power output contains a PARTIAL_WAKE_LOCK held by
    com.termux when the wake-lock is active.
    Returns True if wake-lock is (now) active, False if it couldn't be set.
    """
    try:
        rc, out, _ = run("dumpsys power 2>/dev/null | grep -i 'com.termux'", timeout=10)
        is_active = rc == 0 and "com.termux" in out.lower()
    except Exception:
        is_active = False

    if is_active:
        if verbose:
            print("      ✓ wake-lock already active")
        return True

    # Wake-lock is off — activate it
    if verbose:
        print("      ⚠ wake-lock not active — enabling now ...")
    try:
        subprocess.Popen(
            ["termux-wake-lock"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if verbose:
            print("      ✓ termux-wake-lock started")
        return True
    except Exception as e:
        if verbose:
            print(f"      ✗ could not start termux-wake-lock: {e}")
        return False


def _ping_termux_boot():
    """
    Keep Termux:Boot registered as a boot receiver.
    Method 1: am start (works when Termux:Boot is installed and not hibernated).
    Method 2: touch the boot script so Android sees the package as recently used.
    """
    try:
        rc, _, _ = run(
            'su -c "am start -n com.termux.boot/.MainActivity '
            '--activity-no-history --activity-no-animation" 2>/dev/null',
            timeout=10,
        )
        if rc == 0:
            log.info("Termux:Boot pinged via am start")
            return
        # am start failed (app hibernated or not installed) — fall through to touch
    except Exception:
        pass

    # Fallback: touch the boot script file — marks the Termux package as active
    # and resets Android's unused-app hibernation timer
    try:
        import pathlib
        boot_file = pathlib.Path(BOOT_FILE)
        if boot_file.exists():
            boot_file.touch()
            log.info("Termux:Boot re-registered via boot script touch")
        else:
            log.warning("Termux:Boot: boot script missing — recreating automatically")
            boot_file.parent.mkdir(parents=True, exist_ok=True)
            boot_file.write_text(BOOT_SCRIPT_CONTENT)
            boot_file.chmod(0o755)
            log.info("Termux:Boot boot script recreated at %s", BOOT_FILE)
    except Exception as e:
        log.warning("Termux:Boot ping fallback failed: %s", e)


def setup():
    print("\n════════════════════════════════════════")
    print("  Matrix Dumper — Auto Setup")
    print("════════════════════════════════════════")

    # 1. Write dump_dex_mem.py
    step("[1] Writing ~/dump_dex_mem.py ...")
    with open(DUMP_SCRIPT, "w") as f:
        f.write(DUMP_SCRIPT_CONTENT)
    os.chmod(DUMP_SCRIPT, 0o755)
    print("      ✓ done")

    # 2. Create work directory
    step("[2] Creating work directory ...")
    os.makedirs(WORK_DIR, exist_ok=True)
    os.chmod(WORK_DIR, 0o777)
    print("      ✓ done")

    # 3. Install aapt if missing
    step("[3] Checking aapt ...")
    if shutil.which("aapt"):
        print("      ✓ already installed")
    else:
        print("      installing aapt ...")
        run("pkg install -y aapt")
        print("      ✓ done")

    # 4. Install screen if missing
    step("[4] Checking screen ...")
    if shutil.which("screen"):
        print("      ✓ already installed")
    else:
        print("      installing screen ...")
        run("pkg install -y screen")
        print("      ✓ done")

    # 5. Install python-telegram-bot if missing
    step("[5] Checking python-telegram-bot ...")
    try:
        import telegram  # noqa: F401
        print("      ✓ already installed")
    except ImportError:
        print("      installing python-telegram-bot ...")
        subprocess.run(
            [PYTHON3, "-m", "pip", "install", "--quiet",
             "--upgrade", "python-telegram-bot>=20.0"],
            check=True,
        )
        print("      ✓ done")

    # 6. Write Termux:Boot auto-start script
    step("[6] Setting up Termux:Boot auto-start ...")
    os.makedirs(BOOT_DIR, exist_ok=True)
    with open(BOOT_FILE, "w") as f:
        f.write(BOOT_SCRIPT_CONTENT)
    os.chmod(BOOT_FILE, 0o755)
    print("      ✓ written to", BOOT_FILE)

    # 7. Install pyrogram + tgcrypto (MTProto for large files)
    step("[7] Checking pyrogram ...")
    try:
        import pyrogram  # noqa: F401
        print("      ✓ already installed")
    except ImportError:
        print("      installing pyrogram + tgcrypto ...")
        subprocess.run(
            [PYTHON3, "-m", "pip", "install", "--quiet", "pyrogram", "tgcrypto"],
            check=True,
        )
        print("      ✓ done")

    # 8. Banner image is embedded in the script (no download needed)
    step("[8] Banner image ...")
    print("      ✓ embedded in script")

    # 9. Ensure Termux wake-lock is active
    step("[9] Checking Termux wake-lock ...")
    ensure_wake_lock(verbose=True)

    print("\n════════════════════════════════════════")
    print("  Setup complete! Starting bot...\n")


# Run setup on every launch (idempotent — safe to repeat)
setup()

# After setup, python-telegram-bot must be importable now.
# If it was just installed we continue in the same process
# (pip adds it to sys.path immediately on modern pip+Python).
try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import (
        Application,
        CommandHandler,
        CallbackQueryHandler,
        MessageHandler,
        filters,
        ContextTypes,
    )
except ImportError:
    print("  Restarting to load newly installed packages...")
    os.execv(PYTHON3, [PYTHON3] + sys.argv)

# ══════════════════════════════════════════════════════════════════════════════
#  BOT CONFIG
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import functools
import logging
import re
import gc
import struct as _struct
import time
import zipfile
from pathlib import Path

logging.basicConfig(
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("matrix_dumper")

# Suppress httpx/telegram INFO logs — they print the full API URL
# which contains the bot token in plain text (visible in log files).
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)
logging.getLogger("telegram.ext").setLevel(logging.WARNING)

LAUNCH_WAIT      = 14
MAX_APK_MB       = 200
BOT_API_LIMIT_B  = 20 * 1024 * 1024   # 20 MB — Bot API download limit
BOT_UPLOAD_LIMIT = 50 * 1024 * 1024   # 50 MB — Bot API upload limit
_BANNER_B64 = (
    "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"
    "X1mIzUWdalQPWOPlm6MvWVQwbqnQVoq5iiNE5aFQqwKjpKAisfvl9IIbmKlYn3pyEbyzmAXmLtVf"
    "nP8AwX1vhgx20EEpLRvT3SyBSzthG0gdnFKDjBIu+EluBJsAlpWoaEn3/HyY+9tX1sabjEGb8wME"
    "EUBo9jlERFhGK4xOGe6CKlzWZAFdYIgbLd7glloLLQc27TAp3hyz/nrtNHZg6WhotCyIjWWBNPac"
    "lYZMjsSoCKqTIxzBUtLapub5PsEZlKXK+vW61oo6IM1LijtFRiVKirdLojMbgaBeIt3/ACcEjrHr"
    "+Qiu3U31BGUsd7ZRYd5uNAzTEqiuiKa+j5eCE47LJurj4+waWnZiHRlTFxEZETWICYwdYi/EBxKo"
    "OVmbYA8m/udib7fYScsHQajZZtQAEMUumFuIOcwhFyw7JZ0Y/wBTdHfsTjYMWKcymszhgbSrmVm8"
    "OnMZUUXxn+ygFWt193v7Gqwy7zoKVOZTLyhZl6DiI0O+3t+yFJV0TuXJ5EVu/Zu/3z//2gAMAwEA"
    "AgADAAAAEAAAAAAAAAAAAAAAAAABDCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFFNPPEPKAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAADONCCJCAEADCAAAAAAAAAAAAAAAAAAAAAAAAAAAHNOILKNBAD"
    "AACLAAAAAAAAAAAAAAAAAAAAAAAAAAEBGDHNHCOEJCEGAAAAAAAAAAAAAAAAAAAAAAAAAAIvAEME"
    "ANDBCAPAKAAAAAAAAAAAAAAAAAAAAAAAABIANKMDGKDBMGCOIAAAAAAAAAAAAAAAAAAAAAAAAEIO"
    "ACkBKKLKJEHJCAAAAAAAAAAAAAAAAAAAAAAAAENIEIFDKKEPPHAOCAAAAAAAAAAAAAAAAAAAAAAA"
    "AAHAAAIELHGAIMCOIAAAAAAAAAAAAAAAAAAAAAAAAACBEADHNDAAAAAhIAAAAAAAAAAAAAAAAAAA"
    "AAAAAEBDNPEIKMPJJOGIIAAAAAAAAAAAAAAAAAAAAAAAAEBAMICFGKBJDGCGAAAAAAAAAAAAAAAA"
    "AAAAAAAAAALJJHHGCPOBPEEEAAAAAAAAAAAAAAAAAAAAAAAAAANHGAOOGLDOMKAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAEFINEJFANEJOLAAAAAAAAAAAAAAAAAAAAAAAAAAAABDBEEHKNMMFKAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAPEGLJGOHHEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABDIEFODCJAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAICPAiIPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEMOPLIAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAJD/2gAIAQMBAT8QZj//xAAUEQEAAAAA"
    "AAAAAAAAAAAAAACQ/9oACAECAQE/EGYD/8QAKRAAAQICCQMFAAAAAAAAAAAAARFgMHAAEEFQYXGh"
    "wfAxkeEgQFGQsf/aAAgBAQABPxB6g5NcXLaJIFlayvv+2a0TPh/H7Y143dt79z9S3/H8w6VVHOEO"
    "J5H6d61s8Obf/wCv8sCv6Hzh6Yvjxieg3/8A/wD+qG7+d7f6ZL+O5S/b99XVffnPf2yTnaEz7q9f"
    "/W7/AP8A9v8Ax2/No/8AZt+/v+1+/wDb+ejRf73gUeUHtf8At/1ddZw73x7d+393+rrr9J/aEk6e"
    "v7rf/wBf3a7f+Xc36GvfX+3d929H2/f7V5u5IZrW1bvx99//AN/vNd44dv8Aq13aL1f/AL/792+m"
    "Avm9/wD/ANn7Xd+v3f8Av9vdf/Ge/vrX8+4Mb/vv7z/eZz/e33AO7/u/V9v/AIn/AGm0r+ffqbnd"
    "p5l9/df6/v359IaP/Tdz/cPxPcHxOvn72PH+1bj99n5/n/bne0nGOJv3Xf3z+3zfa4l0PKy1D1or"
    "J7K6d5In7OQ80DTuX38X9q3799+4nHPybZ49/O+3z3e4Xivnf/46B5tXjZ/D37f1+MSEbSve+Kb/"
    "AOM5H5+u3qt//Ou9o667n1f0hX/I7u/653cWKqff7567Dn76d5uTx6r+t1RjaHa/Lf8Af/8A/wDM"
    "92+/Vrspd+/71/76WO8u/wCvdx3j/wB7fnV9vPk+/wB5v3utXtv7737/AH3/AP8Af7n7MPu+/wC/"
    "3/799/uXD+r/ADf/AP57eWUDn/8A8X2t19R8lvXbGYv0m/35++9t/as/M92v6d/7z313X2+3q4f0"
    "lf8A3/8A9t36Zv8A/wDn+rb1+r8VR7/b/wCz/wDn59ez+r7993ve9/yhKn/O99/3/fa9troXrP8A"
    "n1+15kT3v+f1/AfaGvsrul//AL/9/Nnp7/f/AL96/uJ9dBZ5O79Nd+ufC/8Av97v/Mvv7WguGz/b"
    "ref7v9e119+z43fc/ehj2f11e7bl5Pdrfsk7vIfe/mcFc+/Hxiz+0/8A2qy/Vv3nAfNT435Wef7f"
    "VbM+fKv2t79+z1/+/wD/APbgpnD/AG1307P9vzr37f8An2tbRAns9rVfyV5es/6J538v996HBoL9"
    "++ted/8Aj7yni8yMnr/3+335Wf3zq/t/v/vf3+//AHN96XJzpn/9/wDeffzz/wC66qtT4//Z"
)
_banner_file_id  = None   # cached after first upload
_pyro_client     = None   # Pyrogram MTProto client (lazy-init)
CHANNEL_URL  = "https://t.me/reversemoda"
DEV_URL      = "https://t.me/Matrix99bot"

WELCOME_TEXT = """🔬 *MATRIX V8 TURBO DUMPER* 🔬

👋 Welcome, {name}\\!

💥 The most powerful DEX dumper on Android\\.
Reads directly from `/proc/PID/mem` — zero detection, zero bypass needed\\.

👤 *Your Session:*
🔹 User: {name}
🔹 ID: `{uid}`
🔹 Status: 🔓 Free

━━━━━━━━━━━━━━━━━━━━━━
🛡️ *Apps We Dump:*

🔴 360加固 — 360 Jiagu
🟠 爱加密 — ijiami Encryption
🟠 爱加密企业版 — ijiami Enterprise
🟡 梆梆安全 — Bangcle Security
🟢 腾讯乐固 — Tencent Legu
🔵 腾讯御安全 — Tencent Royal
🟣 阿里聚安全 — Alibaba Aggregate
🔵 网易易盾 — NetEase Easy Shield
⚫ 顶象技术 — Dingxiang Technology
🟤 通付盾 — Tongfu Payment Shield
⚪ 几维安全 — Jiwei Mobile Security
💜 娜迦 — Naga App Protector
🧡 海云安 — Haiyun Cloud Shield
🟡 百度加固 — Baidu Reinforcement
📱 OPPO加固 — OPPO App Shield
🌴 椰椰加固 — Yeye Reinforcement
💛 APKProtect — APKProtect Packer

✳️ And many more\\.\\.\\.

━━━━━━━━━━━━━━━━━━━━━━
🚀 *How to Use:*
Just send any \\.apk file — I will dump then zip it for you automatically\\!"""

USAGE_TEXT = """━━━━━━━━━━━━━━━━━━━━━━━
🔐 *𝗠𝗔𝗧𝗥𝗜𝗫 𝗗𝗨𝗠𝗣𝗘𝗥 𝗘𝗡𝗚𝗜𝗡𝗘 𝗩𝟴 — 𝗛𝗢𝗪 𝗧𝗢 𝗨𝗦𝗘*
━━━━━━━━━━━━━━━━━━━━━━━

*📨 Step 1 — Submit Your APK*
Send any \\.apk file directly into this chat\\.
┣ Max file size: 200 MB
┗ No preparation needed — just send it raw\\.

*⚙️ Step 2 — What The Engine Does*
1️⃣ APK is securely received & fingerprinted
2️⃣ Deployed into a fully isolated sandbox environment
3️⃣ A clean ZIP of all dumped DEX files is delivered straight to your chat
4️⃣ Sandbox is instantly wiped — zero traces left behind

*🛡️ Supported Protectors*
┣ ijiami · 360 Jiagu · Tencent Legu
┣ Bangcle · Baidu · Zeus · Oppo
┣ Shadow Safety · DexProtect & more
┗ No detection\\. No manual steps\\.

*📋 Commands*
┣ /start — Main menu & session info
┣ /checkprem — Your tier, activation & expiry
┗ /help — How to use & full command list

"""

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def sh(cmd: str, timeout: int = 120) -> tuple[int, str, str]:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def get_package_name(apk_path: str) -> str | None:
    rc, out, _ = sh(f"aapt dump badging '{apk_path}' 2>/dev/null | head -3")
    if rc == 0 and out:
        m = re.search(r"package: name='([^']+)'", out)
        if m:
            return m.group(1)
    return None


def get_launcher_activity(pkg: str) -> str | None:
    rc, out, _ = sh(
        f'su -c "cmd package resolve-activity --brief '
        f'-c android.intent.category.LAUNCHER {pkg} 2>/dev/null | tail -1"'
    )
    if rc == 0 and "/" in out:
        return out.strip()
    return None


def launch_app(pkg: str) -> bool:
    activity = get_launcher_activity(pkg)
    if activity and "/" in activity:
        rc, _, _ = sh(
            f'su -c "am start -n {activity} '
            f'-a android.intent.action.MAIN '
            f'-c android.intent.category.LAUNCHER"'
        )
        if rc == 0:
            return True
    rc, _, _ = sh(f'su -c "monkey -p {pkg} -c android.intent.category.LAUNCHER 1"')
    return rc == 0


def get_pid(pkg: str) -> str | None:
    _, out, _ = sh(f'su -c "pidof {pkg}"')
    for p in out.split():
        if p.isdigit():
            return p
    return None


def zip_dir(src_dir: str, zip_path: str) -> int:
    files = list(Path(src_dir).iterdir())
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
        for f in sorted(files):
            if f.is_file():
                zf.write(f, f.name)
    return len(files)


# ══════════════════════════════════════════════════════════════════════════════
#  ANIMATION HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _esc(t: str) -> str:
    """Escape text for MarkdownV2 (including comma — Telegram enforces it)."""
    for ch in r'\\_*[]()~`>#+-=|{}.!,':
        t = t.replace(ch, f'\\{ch}')
    return t

def _html(t: str) -> str:
    """Escape text for Telegram HTML parse mode — only &, <, > need escaping."""
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _bar(pct: int, width: int = 10) -> str:
    n = max(0, min(width, round(width * pct / 100)))
    return "🟩" * n + "⬛" * (width - n)

def _mb(n: float) -> str:
    """Format MB value escaped for MarkdownV2 (e.g. 45\\.2)."""
    return _esc(f"{n:.1f}")

SPIN = ["◐", "◓", "◑", "◒"]

DELETE_AFTER = 20 * 60   # 20 minutes — auto-delete status messages

_cancel_flags: dict = {}   # chat_id -> asyncio.Event

# ── Job queue (2 simultaneous, strict FIFO for the rest) ───────────────────
MAX_CONCURRENT = 2                         # how many dumps run at the same time
_queue_lock  = asyncio.Lock()
_user_active : set[int] = set()            # UIDs in queue or processing
_active_dex_jobs: int = 0                  # jobs currently past the queue gate (running)
# Each entry: {"uid": int, "event": asyncio.Event, "queue_msg": Message|None}
_wait_queue  : list[dict] = []

# ── Pending APK per user (saved when they send while already busy) ──────────
# Stores the latest {update, context} for a user who sent a new APK while their
# current job was still running.  Consumed in finally→auto-triggers the next job.
_pending_apk: dict = {}   # user_uid -> {"update": Update, "context": ctx}

# ── Per-package lock (prevents two users running the same APK at once) ─────
_pkg_locks:       dict = {}               # pkg_name -> asyncio.Lock
_pkg_locks_mutex: asyncio.Lock = asyncio.Lock()

# ── Global PM lock (only one pm install at a time — prevents Binder overload) ─
# pm install goes through Android's Binder IPC. Running two installs in parallel
# floods the Binder buffer → "Failed transaction" → PM crash. This lock ensures
# installs are always sequential regardless of how many jobs are active.
_pm_lock: asyncio.Lock = asyncio.Lock()

# Path to the Java installer JAR — Termux home so user can drop it there directly
_INSTALLER_JAR = "/data/data/com.termux/files/home/installer.jar"

async def _java_pm(action: str, target: str, timeout: int = 60) -> int:
    """Run install/uninstall via Java app_process (fresh SELinux context).
    Falls back to pm shell if installer.jar not present.
    Returns 0 on success, non-zero on failure. Must be called inside _pm_lock."""
    _, jar_ok, _ = await _run_sh(
        f'su -c "[ -f {_INSTALLER_JAR} ] && echo yes || echo no"', 5)
    if jar_ok.strip() == "yes":
        rc, out, err = await _run_sh(
            f'su -c "app_process -cp {_INSTALLER_JAR} / ApkInstaller {action} {target} 2>&1"',
            timeout)
        combined = (out + " " + err).strip()
        log.info("java_pm %s %s rc=%d out=%r", action, target, rc, combined[:200])
        if action == "uninstall":
            return rc
        return 0 if (rc == 0 and "Success" in combined) else 1
    # Fallback: plain pm shell
    if action == "uninstall":
        rc, _, _ = await _run_sh(f'su -c "pm uninstall {target}"', timeout)
        return rc
    # install fallback handled by caller
    return 1

async def _acquire_pkg_lock(pkg: str) -> asyncio.Lock:
    async with _pkg_locks_mutex:
        if pkg not in _pkg_locks:
            _pkg_locks[pkg] = asyncio.Lock()
        return _pkg_locks[pkg]

def _cancel_kb(chat_id: int) -> "InlineKeyboardMarkup":
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("🚫 Cancel", callback_data=f"cancel_{chat_id}")
    ]])

async def _auto_delete(bot, chat_id: int, msg_id: int, delay: int = DELETE_AFTER):
    """Delete a message after `delay` seconds — silently ignore errors."""
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id=chat_id, message_id=msg_id)
    except Exception:
        pass

async def _wipe_work(pkg, apk_path, out_dir, zip_path, tmp_apk=None):
    """Always-run cleanup: force-stop + uninstall app, delete ALL working files.

    Called from the finally block so it runs on success, cancel, AND error.
    tmp_apk is /data/local/tmp/matrix_{chat}.apk — deleted separately because
    it lives outside WORK_DIR and is only rm'd inline during the install stage,
    so a crash/cancel mid-install would otherwise leave it on disk indefinitely.
    """
    if pkg:
        await _run_sh(f'su -c "am force-stop {pkg}"')   # kill instantly on cancel
        async with _pm_lock:
            await _java_pm("uninstall", pkg)
    if out_dir:
        await _run_sh(f'su -c "rm -rf \\"{out_dir}\\""')
    # Remove all known temp files — ignore missing (already cleaned up or never created)
    shell_paths = [p for p in (tmp_apk,) if p]
    if shell_paths:
        await _run_sh('su -c "rm -f ' + ' '.join(f'\\"{p}\\"' for p in shell_paths) + '"')
    for p in (apk_path, zip_path):
        if p:
            try:
                os.remove(p)
            except FileNotFoundError:
                pass

async def _cleanup_stale_work(max_age_hours: float = 2.0) -> int:
    """Delete files/folders in WORK_DIR that are older than max_age_hours.

    Safe to call at any time — skips entries whose mtime is recent enough
    to belong to an in-progress job. Returns the number of entries removed.
    """
    if not os.path.isdir(WORK_DIR):
        return 0
    cutoff = time.time() - max_age_hours * 3600
    removed = 0
    for name in os.listdir(WORK_DIR):
        entry = os.path.join(WORK_DIR, name)
        try:
            if os.path.getmtime(entry) < cutoff:
                if os.path.isdir(entry):
                    await _run_sh(f'su -c "rm -rf \\"{entry}\\""')
                else:
                    os.remove(entry)
                log.info("Stale work entry removed: %s", name)
                removed += 1
        except Exception as _e:
            log.warning("Could not remove stale entry %s: %s", name, _e)
    if removed:
        log.info("Stale-work cleanup: removed %d item(s) from %s", removed, WORK_DIR)
    return removed


async def _animate(msg, get_text_fn, stop: asyncio.Event,
                   interval: float = 1.3, reply_markup=None):
    """Edit msg with animated frames until stop is set."""
    i = 0
    while not stop.is_set():
        try:
            await msg.edit_text(
                get_text_fn(i), parse_mode="MarkdownV2",
                reply_markup=reply_markup,
            )
        except Exception:
            pass
        i += 1
        await asyncio.sleep(interval)

async def _run_sh(cmd: str, timeout: int = 120,
                  cancel: "asyncio.Event | None" = None):
    """
    Run a shell command asynchronously.
    If `cancel` fires, the subprocess is killed instantly (SIGKILL on process
    group) so cancel is truly immediate even during long pm-install / dump runs.
    """
    import signal as _signal
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def _wait_proc():
        stdout, stderr = await proc.communicate()
        return proc.returncode, \
               (stdout or b"").decode(errors="replace").strip(), \
               (stderr or b"").decode(errors="replace").strip()

    if cancel is None:
        try:
            return await asyncio.wait_for(_wait_proc(), timeout=timeout)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            return -1, "", "timeout"

    # Race: process completion vs cancel event
    done_event = asyncio.Event()
    result_box = [None]

    async def _runner():
        result_box[0] = await _wait_proc()
        done_event.set()

    task = asyncio.create_task(_runner())
    try:
        await asyncio.wait_for(
            asyncio.wait(
                {task, asyncio.create_task(cancel.wait())},
                return_when=asyncio.FIRST_COMPLETED,
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        pass

    if cancel.is_set() or not done_event.is_set():
        # Kill the process group instantly
        try:
            os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
        except Exception:
            try: proc.kill()
            except Exception: pass
        task.cancel()
        return -1, "", "cancelled"

    return result_box[0] if result_box[0] is not None else (-1, "", "unknown")

async def _get_pyro():
    """Lazy-init Pyrogram bot client (MTProto — no file size limit).

    workers=16                  — thread-pool workers for crypto/IO (default 4)
    max_concurrent_transmissions=4 — parallel part streams per transfer (default 1)
    These two settings give ~4× real-world speed on both large downloads and uploads.
    """
    global _pyro_client
    if _pyro_client and _pyro_client.is_connected:
        return _pyro_client
    from pyrogram import Client as PyroClient
    import inspect as _inspect
    _client_kwargs = dict(
        api_id=TG_API_ID,
        api_hash=TG_API_HASH,
        bot_token=BOT_TOKEN,
        workdir=os.path.expanduser("~/"),
        workers=16,
    )
    # max_concurrent_transmissions exists in Pyrogram 2.x — add only if supported
    if "max_concurrent_transmissions" in _inspect.signature(PyroClient.__init__).parameters:
        _client_kwargs["max_concurrent_transmissions"] = 4
    _pyro_client = PyroClient("matrix_bot_session", **_client_kwargs)
    await _pyro_client.start()
    log.info("Pyrogram MTProto client connected (workers=16, parallel_tx=%s)",
             _client_kwargs.get("max_concurrent_transmissions", "default"))
    return _pyro_client

async def _download_large_pyro(msg, chat_id, message_id, dest_path, fname, total_bytes):
    """
    Download any-size file via Pyrogram MTProto with live progress bar.

    Retry policy (network-resilient):
      • Up to 5 attempts total.
      • Backoff: 5 → 15 → 30 → 60 → 120 s between retries.
      • Each attempt gets a fresh Pyrogram session and restarts from 0
        (Pyrogram streams in parallel chunks so restarts are fast).
      • Status message shows "⚠️ Download paused — retrying in Xs…" on each
        failure so the user sees something is happening.
      • After all 5 attempts are exhausted the original exception is re-raised
        so the caller can show an error and clean up.
    """
    MAX_ATTEMPTS = 5
    BACKOFF      = [5, 15, 30, 60, 120]   # seconds between retries
    total_mb     = total_bytes / 1048576
    last_pct     = [-5]

    for attempt in range(1, MAX_ATTEMPTS + 1):
        last_pct[0] = -5   # reset bar on every attempt

        # Label shown while downloading on retry attempts
        attempt_label = (
            f" \\(retry {attempt - 1}/{MAX_ATTEMPTS - 1}\\)" if attempt > 1 else ""
        )

        async def _progress(current, total, _lbl=attempt_label):
            pct = min(int(current * 100 / total), 99) if total else 0
            if pct - last_pct[0] >= 5:
                mb_done = current / 1048576
                try:
                    await msg.edit_text(
                        f"📥 *Receiving APK{_lbl}\\.\\.\\.*\n\n"
                        f"`{_bar(pct)}` {pct}%\n"
                        f"📁 {_esc(fname)} • {_mb(mb_done)} \\/ {_mb(total_mb)} MB",
                        parse_mode="MarkdownV2",
                    )
                except Exception:
                    pass
                last_pct[0] = pct

        try:
            client = await _get_pyro()
            # 30 s to fetch message info; 900 s ceiling for the actual transfer.
            # Pyrogram fetches 4 × 1 MB chunks simultaneously (max_concurrent_
            # transmissions=4) so real transfer time is much less than the ceiling.
            pyro_msg = await asyncio.wait_for(
                client.get_messages(chat_id, message_id), timeout=30
            )
            await asyncio.wait_for(
                client.download_media(pyro_msg, file_name=dest_path, progress=_progress),
                timeout=900,
            )
            return   # success

        except Exception as exc:
            log.warning("Pyro download attempt %d/%d failed (%s): %s",
                        attempt, MAX_ATTEMPTS, type(exc).__name__, exc)

            if attempt == MAX_ATTEMPTS:
                raise   # all retries exhausted

            wait = BACKOFF[attempt - 1]

            # Remove partial file so the next attempt writes fresh
            try:
                if os.path.exists(dest_path):
                    os.remove(dest_path)
            except OSError:
                pass

            try:
                await msg.edit_text(
                    f"⚠️ *Download paused — retrying in {wait}s\\.\\.\\.*\n\n"
                    f"📁 {_esc(fname)} • connection dropped, will resume…",
                    parse_mode="MarkdownV2",
                )
            except Exception:
                pass

            await asyncio.sleep(wait)

async def _upload_large_pyro(chat_id: int, zip_path: str, filename: str,
                              caption: str, status_msg=None, zip_mb: float = 0,
                              cancel: "asyncio.Event | None" = None):
    """Upload any-size file via Pyrogram MTProto with live % progress and auto-retry.

    cancel — when set the upload is aborted immediately between retry attempts.
    FloodWait is capped at MAX_FLOOD_SLEEP seconds: if Telegram demands a longer
    wait the upload fails fast so _user_active is freed and the user can retry.
    """
    from pyrogram import enums as pyro_enums

    MAX_ATTEMPTS    = 5
    BACKOFF         = [5, 10, 20, 40, 60]   # seconds between normal retries
    MAX_FLOOD_SLEEP = 60   # never sleep more than 60 s for FloodWait
    # ↑ Primary fix: Telegram can return FloodWait(3600). Without this cap the
    #   bot sleeps 1 hour inside the try block with _user_active still set,
    #   causing every subsequent send from that user to get "still being processed".

    last_pct = [-5]

    for attempt in range(1, MAX_ATTEMPTS + 1):
        # Respect cancel between retry attempts
        if cancel and cancel.is_set():
            return

        client = await _get_pyro()

        attempt_label = (
            f" \\(resuming {attempt - 1}/{MAX_ATTEMPTS - 1}\\)" if attempt > 1 else ""
        )

        async def _progress(current, total, _lbl=attempt_label):
            pct = min(int(current * 100 / total), 99) if total else 0
            if status_msg and pct - last_pct[0] >= 5:
                mb_done = current / 1048576
                try:
                    await status_msg.edit_text(
                        f"📤 *Uploading{_lbl}\\.\\.\\.*\n\n"
                        f"`{_bar(pct)}` {pct}%\n"
                        f"📦 {_esc(filename)} • {_mb(mb_done)} \\/ {_mb(zip_mb)} MB",
                        parse_mode="MarkdownV2",
                    )
                except Exception:
                    pass
                last_pct[0] = pct

        try:
            await client.send_document(
                chat_id,
                zip_path,
                file_name=filename,
                caption=caption,
                parse_mode=pyro_enums.ParseMode.MARKDOWN,
                progress=_progress,
            )
            return   # success — done

        except Exception as exc:
            err_name = type(exc).__name__
            log.warning("Upload attempt %d/%d failed (%s): %s",
                        attempt, MAX_ATTEMPTS, err_name, exc)

            if attempt == MAX_ATTEMPTS:
                raise   # exhausted all retries — let caller handle it

            wait = BACKOFF[attempt - 1]

            # FloodWait carries the required wait time from Telegram
            fw_wait = getattr(exc, "value", None) or getattr(exc, "x", None)
            if fw_wait and isinstance(fw_wait, int):
                if fw_wait > MAX_FLOOD_SLEEP:
                    # Telegram wants us to wait too long — fail fast so the user
                    # is freed from _user_active and can simply resend.
                    log.warning("FloodWait(%d s) exceeds cap — failing fast", fw_wait)
                    raise
                wait = max(wait, fw_wait)

            if status_msg:
                current_pct = max(last_pct[0], 0)
                try:
                    await status_msg.edit_text(
                        f"⚠️ *Upload paused — resuming in {wait}s\\.\\.\\.*\n\n"
                        f"`{_bar(current_pct)}` {current_pct}%\n"
                        f"📦 {_esc(filename)} • connection dropped, will resume…",
                        parse_mode="MarkdownV2",
                    )
                except Exception:
                    pass

            # Interruptible sleep — wakes immediately if cancel fires
            try:
                await asyncio.wait_for(
                    asyncio.shield(cancel.wait()) if cancel else asyncio.sleep(wait),
                    timeout=wait,
                )
                if cancel and cancel.is_set():
                    return
            except asyncio.TimeoutError:
                pass

async def _download_with_progress(msg, bot, file_id, dest_path, filename, total_bytes):
    """
    Download a ≤20 MB Telegram file (Bot API) with a live progress bar.

    Retry policy (network-resilient):
      • Up to 5 attempts total.
      • Backoff: 5 → 15 → 30 → 60 → 120 s between retries.
      • Each attempt re-fetches the Bot API download URL (they expire) and
        writes the file from byte 0 so there is no partial-file corruption.
      • Status message shows "⚠️ Download paused — retrying in Xs…" on each
        failure so the user always sees progress.
      • After all 5 attempts the original exception is re-raised.
    """
    import httpx

    MAX_ATTEMPTS = 5
    BACKOFF      = [5, 15, 30, 60, 120]
    total_mb     = total_bytes / 1048576 if total_bytes else 0

    for attempt in range(1, MAX_ATTEMPTS + 1):
        attempt_label = (
            f" \\(retry {attempt - 1}/{MAX_ATTEMPTS - 1}\\)" if attempt > 1 else ""
        )
        downloaded = 0
        last_pct   = -5

        try:
            # Re-fetch the URL on every attempt — Bot API links can expire.
            tg_file = await bot.get_file(file_id)
            url     = tg_file.file_path   # full HTTPS URL in PTB v20+

            async with httpx.AsyncClient(timeout=600) as client:
                async with client.stream("GET", url) as resp:
                    with open(dest_path, "wb") as f:
                        async for chunk in resp.aiter_bytes(65536):
                            f.write(chunk)
                            downloaded += len(chunk)
                            pct = (
                                min(int(downloaded * 100 / total_bytes), 99)
                                if total_bytes else 0
                            )
                            if pct - last_pct >= 5:
                                mb_done = downloaded / 1048576
                                try:
                                    await msg.edit_text(
                                        f"📥 *Receiving APK{attempt_label}\\.\\.\\.*\n\n"
                                        f"`{_bar(pct)}` {pct}%\n"
                                        f"📁 {_esc(filename)} • {_mb(mb_done)} \\/ {_mb(total_mb)} MB",
                                        parse_mode="MarkdownV2",
                                    )
                                except Exception:
                                    pass
                                last_pct = pct
            return   # success — file fully written

        except Exception as exc:
            log.warning("Bot-API download attempt %d/%d failed (%s): %s",
                        attempt, MAX_ATTEMPTS, type(exc).__name__, exc)

            if attempt == MAX_ATTEMPTS:
                raise   # all retries exhausted

            wait = BACKOFF[attempt - 1]

            # Remove partial file so the next attempt writes fresh
            try:
                if os.path.exists(dest_path):
                    os.remove(dest_path)
            except OSError:
                pass

            try:
                await msg.edit_text(
                    f"⚠️ *Download paused — retrying in {wait}s\\.\\.\\.*\n\n"
                    f"📁 {_esc(filename)} • connection dropped, will resume…",
                    parse_mode="MarkdownV2",
                )
            except Exception:
                pass

            await asyncio.sleep(wait)

# ══════════════════════════════════════════════════════════════════════════════
#  BOT HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#  PREMIUM DATABASE
# ══════════════════════════════════════════════════════════════════════════════
import json as _json
from datetime import datetime as _dt, timedelta as _td, timezone as _tz

def _prem_load() -> dict:
    try:
        with open(PREMIUM_FILE) as _f: return _json.load(_f)
    except Exception: return {}

def _prem_save(db: dict):
    with open(PREMIUM_FILE, "w") as _f: _json.dump(db, _f, indent=2)

def _usage_load() -> dict:
    try:
        with open(USAGE_FILE) as _f: return _json.load(_f)
    except Exception: return {}

def _usage_save(db: dict):
    with open(USAGE_FILE, "w") as _f: _json.dump(db, _f, indent=2)

def _users_load() -> dict:
    try:
        with open(USERS_FILE) as _f: return _json.load(_f)
    except Exception: return {}

def _users_save(db: dict):
    with open(USERS_FILE, "w") as _f: _json.dump(db, _f, indent=2)

def _users_register(uid: int, name: str, username: str | None) -> bool:
    """Register/update user. Returns True if this is their very first time."""
    db   = _users_load()
    uid_s = str(uid)
    is_new = uid_s not in db
    now  = _dt.now(_tz.utc).isoformat()
    if is_new:
        db[uid_s] = {"name": name, "username": username,
                     "first_seen": now, "last_seen": now}
    else:
        db[uid_s]["last_seen"] = now
        if name:     db[uid_s]["name"]     = name
        if username: db[uid_s]["username"] = username
    _users_save(db)
    return is_new

_BOT_START_TIME = _dt.now(_tz.utc)   # for /stats uptime

def is_admin(uid: int) -> bool:
    return uid == ADMIN_ID

def is_premium(uid: int) -> bool:
    if is_admin(uid): return True
    entry = _prem_load().get(str(uid))
    if not entry: return False
    exp = entry.get("expires_at")
    if exp is None: return True
    return _dt.fromisoformat(exp) > _dt.now(_tz.utc)

def get_user_status(uid: int) -> dict:
    if is_admin(uid):
        return {"tier": "admin", "expires_at": None, "added_at": None}
    entry = _prem_load().get(str(uid))
    if not entry: return {"tier": "free", "expires_at": None, "added_at": None}
    exp = entry.get("expires_at")
    if exp and _dt.fromisoformat(exp) <= _dt.now(_tz.utc):
        return {"tier": "free", "expires_at": None, "added_at": None}
    return {"tier": "premium", "expires_at": exp, "added_at": entry.get("added_at")}

def get_daily_count(uid: int) -> int:
    today = _dt.now().strftime("%Y-%m-%d")
    return _usage_load().get(str(uid), {}).get(today, 0)

def increment_daily_count(uid: int):
    db = _usage_load(); today = _dt.now().strftime("%Y-%m-%d"); uid_s = str(uid)
    if uid_s not in db: db[uid_s] = {}
    db[uid_s][today] = db[uid_s].get(today, 0) + 1
    _usage_save(db)

def parse_duration(s: str):
    import re as _re
    # support  3min / 3mins / 3m(onths) / 30d / 2h / 1w / 1y
    m = _re.fullmatch(r"(\d+)(mins?|[dhwmy])", s.lower())
    if not m: return None
    n, u = int(m.group(1)), m.group(2)
    return {
        "min": _td(minutes=n), "mins": _td(minutes=n),
        "h": _td(hours=n),     "d": _td(days=n),
        "w": _td(weeks=n),     "m": _td(days=n*30), "y": _td(days=n*365),
    }.get(u)


def _start_keyboard(tier: str = "free") -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton("📖 Usage 📖", callback_data="usage"),
            InlineKeyboardButton("📢 Channel 📢", url=CHANNEL_URL),
        ],
        [InlineKeyboardButton("👨\u200d💻 Developer", url=DEV_URL)],
    ]
    if tier == "free":
        rows.append([
            InlineKeyboardButton("💎 Subscribe to Premium ✨", url=PREMIUM_CHANNEL)
        ])
    return InlineKeyboardMarkup(rows)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global _banner_file_id
    user   = update.effective_user
    uid    = user.id
    name   = f"@{user.username}" if user.username else (user.first_name or "User")
    status = get_user_status(uid)
    tier   = status["tier"]

    # ── Build per-tier fields (HTML mode — no escaping headaches) ────────
    if tier == "admin":
        badge      = "👑 <b>𝗔𝗱𝗺𝗶𝗻 — Unlimited</b>"
        expiry_txt = "Never"
        dumps_txt  = "┗ 🎰 Jobs: ♾️ Unlimited (DEX + Pairip)"
    elif tier == "premium":
        badge      = "💎 <b>𝗣𝗿𝗲𝗺𝗶𝘂𝗺 — Unlimited</b>"
        exp        = status["expires_at"]
        expiry_txt = _html(_dt.fromisoformat(exp).strftime("%b %d, %Y")) if exp else "Lifetime"
        dumps_txt  = "┗ 🎰 Jobs: ♾️ Unlimited (DEX + Pairip)"
    else:
        badge      = "🆓 <b>𝗙𝗿𝗲𝗲 — Limited</b>"
        expiry_txt = "—"
        used        = get_daily_count(uid)
        left_dex    = max(0, FREE_DAILY_LIMIT - used)
        left_pairip = max(0, PAIRIP_FREE_DAILY_LIMIT - used)
        dumps_txt   = (
            f"┣ 🎰 DEX Dumps: <b>{left_dex} / {FREE_DAILY_LIMIT}</b> today\n"
            f"┗ 🛡️ Pairip Jobs: <b>{left_pairip} / {PAIRIP_FREE_DAILY_LIMIT}</b> today"
        )

    text = (
        f"━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔐 <b>𝗠𝗔𝗧𝗥𝗜𝗫 𝗗𝗨𝗠𝗣𝗘𝗥 𝗘𝗡𝗚𝗜𝗡𝗘 𝗩𝟴</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"👋 Welcome, <b>{_html(name)}</b>!\n\n"
        f"🚀 Advanced APK toolkit — DEX dumper + Google加固 protection remover. "
        f"Send a file and the engine does everything.\n\n"
        f"👤 <b>𝗬𝗼𝘂𝗿 𝗦𝗲𝘀𝘀𝗶𝗼𝗻:</b>\n"
        f"┣ 🔹 User: <b>{_html(name)}</b>\n"
        f"┣ 🔹 ID: <code>{uid}</code>\n"
        f"┣ 🎖 Status: {badge}\n"
        f"┣ 📅 Expiry: {expiry_txt}\n"
        f"{dumps_txt}\n\n"
        f"✨ <b>𝗖𝗼𝗿𝗲 𝗙𝗲𝗮𝘁𝘂𝗿𝗲𝘀:</b>\n"
        f"┣ 🔐 <b>DEX Dumper</b> — bypass ijiami, 360 Jiagu, Tencent Legu, Bangcle, Baidu, Zeus, Shadow Safety, Oppo, DexProtect &amp; more\n"
        f"┣ 🛡️ <b>Pairip X</b> — strip Google Play Integrity / pairip protection from any .apks bundle\n"
        f"┣ 📤 Files zipped &amp; delivered instantly\n"
        f"┣ ⚡ Parallel processing with live progress bar\n"
        f"┣ 🚫 Instant cancel — kills subprocess group immediately\n"
        f"┗ 🔒 Sandbox fully wiped after every job\n\n"
        f"📌 <b>𝗛𝗼𝘄 𝘁𝗼 𝗨𝘀𝗲:</b>\n"
        f"┣ Send a <code>.apk</code> → auto-dumps DEX\n"
        f"┣ Send a <code>.apks</code> bundle → reply with /pairipx to strip Pairip\n"
        f"┗ /help for all commands\n\n"
        f"💬 <b>Bot not responding?</b> Tap the <b>Developer</b> button below.\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━"
    )
    kb = _start_keyboard(tier)

    async def _send_text_fallback():
        await update.message.reply_text(text, parse_mode="HTML", reply_markup=kb)

    # ── Register user + alert admin on first visit ────────────────────────
    display_name = f"@{user.username}" if user.username else (user.first_name or "User")
    is_new = _users_register(uid, display_name, user.username)
    if is_new and not is_admin(uid):
        try:
            await context.bot.send_message(
                ADMIN_ID,
                f"👤 <b>New user joined!</b>\n\n"
                f"Name: <b>{_html(display_name)}</b>\n"
                f"ID: <code>{uid}</code>",
                parse_mode="HTML",
            )
        except Exception:
            pass

    if _banner_file_id:
        try:
            await update.message.reply_photo(
                photo=_banner_file_id, caption=text,
                parse_mode="HTML", reply_markup=kb,
            )
        except Exception:
            _banner_file_id = None
            await _send_text_fallback()
    else:
        try:
            import base64, io
            img_bytes = base64.b64decode(_BANNER_B64)
            sent = await update.message.reply_photo(
                photo=io.BytesIO(img_bytes), caption=text,
                parse_mode="HTML", reply_markup=kb,
            )
            _banner_file_id = sent.photo[-1].file_id
        except Exception:
            await _send_text_fallback()


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ *Admin only\\.*", parse_mode="MarkdownV2")
        return

    users_db  = _users_load()
    prem_db   = _prem_load()
    usage_db  = _usage_load()
    today     = _dt.now().strftime("%Y-%m-%d")

    total_users   = len(users_db)
    # Count valid (non-expired) premium users
    now_utc = _dt.now(_tz.utc)
    prem_count = 0
    for entry in prem_db.values():
        exp = entry.get("expires_at")
        if exp is None or _dt.fromisoformat(exp) > now_utc:
            prem_count += 1

    # Users who did at least one dump today
    active_today = sum(1 for u in usage_db.values() if today in u)
    # Total dumps today
    jobs_today   = sum(u.get(today, 0) for u in usage_db.values())

    uptime_secs  = int((now_utc - _BOT_START_TIME).total_seconds())
    h, rem       = divmod(uptime_secs, 3600)
    m, s         = divmod(rem, 60)
    uptime_str   = _esc(f"{h}h {m}m {s}s")

    await update.message.reply_text(
        f"📊 *Matrix Dumper — Stats*\n\n"
        f"👥 Total users: *{total_users}*\n"
        f"💎 Premium users: *{prem_count}*\n"
        f"🆓 Free users: *{total_users - prem_count}*\n\n"
        f"📅 Active today: *{active_today}* users\n"
        f"⚙️ Jobs today: *{jobs_today}* dumps\n\n"
        f"⏱ Uptime: `{uptime_str}`",
        parse_mode="MarkdownV2",
    )


async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ *Admin only\\.*", parse_mode="MarkdownV2")
        return
    if not context.args:
        await update.message.reply_text(
            "📢 *Usage:* `/broadcast <message>`\n\nSends your message to all registered users\\.",
            parse_mode="MarkdownV2",
        )
        return

    msg      = " ".join(context.args)
    users_db = _users_load()
    sent = failed = 0

    status_msg = await update.message.reply_text(
        f"📢 Broadcasting to {len(users_db)} users\\.\\.\\.",
        parse_mode="MarkdownV2",
    )

    for uid_s in users_db:
        try:
            await context.bot.send_message(int(uid_s), f"📢 *Announcement*\n\n{_esc(msg)}",
                                           parse_mode="MarkdownV2")
            sent += 1
        except Exception:
            failed += 1

    await status_msg.edit_text(
        f"📢 *Broadcast complete*\n\n"
        f"✅ Delivered: *{sent}*\n"
        f"❌ Failed: *{failed}* \\(blocked or never messaged bot\\)",
        parse_mode="MarkdownV2",
    )


async def cb_usage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.message.reply_text(
        USAGE_TEXT,
        parse_mode="MarkdownV2",
    )


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    loop = asyncio.get_event_loop()
    _, load, _    = await loop.run_in_executor(None, sh, "cat /proc/loadavg")
    _, mem, _     = await loop.run_in_executor(None, sh, "free -m | grep Mem")
    _, storage, _ = await loop.run_in_executor(None, sh, "df -h / | tail -1")
    parts         = load.split()
    load_1m       = parts[0] if parts else "N/A"
    mem_parts     = mem.split()
    used_mb       = mem_parts[2] if len(mem_parts) >= 3 else "N/A"
    total_mb      = mem_parts[1] if len(mem_parts) >= 2 else "N/A"
    st_parts      = storage.split()
    disk_used     = st_parts[2] if len(st_parts) >= 4 else "N/A"
    disk_total    = st_parts[1] if len(st_parts) >= 2 else "N/A"
    await update.message.reply_text(
        f"📊 *Matrix V8 — Server Status*\n\n"
        f"🖥️ CPU Load: `{_esc(load_1m)}` \\(1 min avg\\)\n"
        f"🧠 Memory: `{_esc(used_mb)} / {_esc(total_mb)} MB` used\n"
        f"💾 Storage: `{_esc(disk_used)} / {_esc(disk_total)}` used\n\n"
        f"✅ Server is online and processing",
        parse_mode="MarkdownV2",
    )


# ══════════════════════════════════════════════════════════════════════════════
#  PREMIUM ADMIN COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_addprem(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ *Admin only\\.*", parse_mode="MarkdownV2")
        return
    args = context.args
    if len(args) < 2:
        await update.message.reply_text(
            "📋 *Usage:* `/addprem <user\\_id> <duration>`\n\n"
            "Duration examples:\n"
            "`3min` — 3 minutes\n`2h` — 2 hours\n`30d` — 30 days\n"
            "`3m` — 3 months\n`1y` — 1 year\n`lifetime` — forever",
            parse_mode="MarkdownV2",
        )
        return
    try:
        target = int(args[0])
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID\\.", parse_mode="MarkdownV2")
        return
    dur_str = args[1].lower()
    if dur_str == "lifetime":
        expires_at, dur_label = None, "Lifetime"
    else:
        delta = parse_duration(dur_str)
        if not delta:
            await update.message.reply_text(
                "❌ Bad duration\\. Use `3min`, `2h`, `30d`, `3m`, `1y`, or `lifetime`\\.",
                parse_mode="MarkdownV2",
            )
            return
        expires_at = (_dt.now(_tz.utc) + delta).isoformat()
        dur_label  = dur_str
    # Try to resolve username/name from Telegram
    uname = name_str = None
    try:
        chat_obj = await context.bot.get_chat(target)
        uname    = chat_obj.username
        name_str = chat_obj.full_name or chat_obj.first_name
    except Exception:
        pass

    db = _prem_load()
    db[str(target)] = {
        "added_at":   _dt.now(_tz.utc).isoformat(),
        "expires_at": expires_at,
        "added_by":   update.effective_user.id,
        "username":   uname,
        "name":       name_str,
    }
    _prem_save(db)
    exp_txt      = _esc(expires_at[:10] if expires_at else "Lifetime")
    display_name = _esc(f"@{uname}") if uname else _esc(name_str or str(target))
    await update.message.reply_text(
        f"✅ *Premium Granted*\n\n"
        f"👤 {display_name}\n"
        f"🔹 ID: `{target}`\n"
        f"⏱ Duration: `{_esc(dur_label)}`\n"
        f"📅 Expires: {exp_txt}",
        parse_mode="MarkdownV2",
    )


async def cmd_listprem(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ *Admin only\\.*", parse_mode="MarkdownV2")
        return
    db  = _prem_load()
    now = _dt.now(_tz.utc)
    if not db:
        await update.message.reply_text(
            "📭 *No premium users yet\\.*", parse_mode="MarkdownV2"
        )
        return
    lines = [f"💎 *Premium Users* — {len(db)} total\n"]
    for i, (uid_s, entry) in enumerate(db.items(), 1):
        exp = entry.get("expires_at")
        if exp:
            exp_dt  = _dt.fromisoformat(exp)
            ok      = exp_dt > now
            exp_txt = _esc(exp_dt.strftime("%b %d, %Y"))
            icon    = "✅" if ok else "❌ expired"
        else:
            icon, exp_txt = "♾️", "Lifetime"

        # Resolve display name: stored → live fetch → fallback to ID
        uname    = entry.get("username")
        name_str = entry.get("name")
        if not uname and not name_str:
            try:
                chat_obj = await context.bot.get_chat(int(uid_s))
                uname    = chat_obj.username
                name_str = chat_obj.full_name or chat_obj.first_name
                # Cache it for next time
                entry["username"] = uname
                entry["name"]     = name_str
            except Exception:
                pass

        if uname:
            who = f"@{_esc(uname)} \\(`{uid_s}`\\)"
        elif name_str:
            who = f"{_esc(name_str)} \\(`{uid_s}`\\)"
        else:
            who = f"`{uid_s}`"

        lines.append(f"{i}\\. {icon} {who} — {exp_txt}")

    _prem_save(db)   # persist any newly resolved usernames
    await update.message.reply_text("\n".join(lines), parse_mode="MarkdownV2")


async def cmd_listusers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ *Admin only\\.*", parse_mode="MarkdownV2")
        return

    users_db = _users_load()
    usage_db = _usage_load()
    today    = _dt.now().strftime("%Y-%m-%d")

    if not users_db:
        await update.message.reply_text(
            "📭 *No users registered yet\\.*", parse_mode="MarkdownV2"
        )
        return

    # Build rows: (uid_str, display, today_count, total_count, last_seen, tier)
    rows = []
    for uid_s, info in users_db.items():
        uid_i       = int(uid_s)
        uname       = info.get("username") or ""
        name        = info.get("name") or ""
        last_seen   = info.get("last_seen", "")[:10]   # YYYY-MM-DD
        today_count = usage_db.get(uid_s, {}).get(today, 0)
        total_count = sum(usage_db.get(uid_s, {}).values())
        if is_admin(uid_i):
            tier = "admin"
        elif is_premium(uid_i):
            tier = "premium"
        else:
            tier = "free"
        rows.append((uid_s, uname, name, today_count, total_count, last_seen, tier))

    # Sort by total usage descending, then by last_seen descending
    rows.sort(key=lambda r: (r[4], r[5]), reverse=True)

    total_users   = len(rows)
    total_today   = sum(r[3] for r in rows)
    total_alltime = sum(r[4] for r in rows)

    header = (
        f"👥 *User List* — {total_users} registered\n"
        f"📊 Today: *{total_today}* jobs  •  All\\-time: *{total_alltime}* jobs\n"
        f"{'─' * 28}\n"
    )

    lines = [header]
    for i, (uid_s, uname, name, today_c, total_c, last_seen, tier) in enumerate(rows, 1):
        icon = "👑" if tier == "admin" else ("💎" if tier == "premium" else "👤")
        if uname:
            who = f"@{_esc(uname)}"
        elif name:
            who = _esc(name)
        else:
            who = f"uid `{uid_s}`"
        tier_tag = {"admin": " \\[Admin\\]", "premium": " \\[💎\\]", "free": ""}.get(tier, "")
        last = _esc(last_seen) if last_seen else "—"
        lines.append(
            f"{i}\\. {icon} {who}{tier_tag}\n"
            f"    `{uid_s}` • Today: *{today_c}* • Total: *{total_c}* • Last: {last}"
        )

    # Split into chunks that fit inside Telegram's 4096-char limit
    chunks, current = [], header
    for line in lines[1:]:  # skip header — already in current
        candidate = current + "\n" + line
        if len(candidate) > 3800:
            chunks.append(current)
            current = line
        else:
            current = candidate
    chunks.append(current)

    for chunk in chunks:
        await update.message.reply_text(chunk, parse_mode="MarkdownV2")


async def cmd_delprem(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ *Admin only\\.*", parse_mode="MarkdownV2")
        return
    if not context.args:
        await update.message.reply_text(
            "📋 *Usage:* `/delprem <user\\_id>`", parse_mode="MarkdownV2"
        )
        return
    try:
        target = str(int(context.args[0]))
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID\\.", parse_mode="MarkdownV2")
        return
    db = _prem_load()
    if target not in db:
        await update.message.reply_text(
            f"❌ `{target}` is not a premium user\\.", parse_mode="MarkdownV2"
        )
        return
    del db[target]
    _prem_save(db)
    await update.message.reply_text(
        f"🗑️ Premium removed from `{target}`\\.", parse_mode="MarkdownV2"
    )


async def cmd_checkprem(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user   = update.effective_user
    uid    = user.id
    name   = _esc(f"@{user.username}" if user.username else (user.first_name or "User"))
    status = get_user_status(uid)
    tier   = status["tier"]

    if tier == "admin":
        badge      = "👑 *𝗔𝗱𝗺𝗶𝗻*"
        expiry_txt = "Never"
        added_txt  = _esc("Since the beginning")
        dumps_txt  = "┗ 🎰 Jobs: ♾️ Unlimited \\(DEX \\+ Pairip\\)"
    elif tier == "premium":
        badge      = "💎 *𝗣𝗿𝗲𝗺𝗶𝘂𝗺*"
        exp        = status["expires_at"]
        expiry_txt = _esc(_dt.fromisoformat(exp).strftime("%b %d, %Y — %H:%M UTC")) if exp else "Lifetime"
        raw_add    = status.get("added_at")
        added_txt  = _esc(_dt.fromisoformat(raw_add).strftime("%b %d, %Y")) if raw_add else "Unknown"
        dumps_txt  = "┗ 🎰 Jobs: ♾️ Unlimited \\(DEX \\+ Pairip\\)"
    else:
        badge      = "🆓 *𝗙𝗿𝗲𝗲*"
        expiry_txt = "—"
        added_txt  = "—"
        used        = get_daily_count(uid)
        left_dex    = max(0, FREE_DAILY_LIMIT - used)
        left_pairip = max(0, PAIRIP_FREE_DAILY_LIMIT - used)
        dumps_txt   = (
            f"┣ 🎰 DEX Dumps: *{left_dex} \\/ {FREE_DAILY_LIMIT}* today\n"
            f"┗ 🛡️ Pairip Jobs: *{left_pairip} \\/ {PAIRIP_FREE_DAILY_LIMIT}* today"
        )

    text = (
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"🔍 *𝗔𝗰𝗰𝗼𝘂𝗻𝘁 𝗦𝘁𝗮𝘁𝘂𝘀*\n"
        f"━━━━━━━━━━━━━━━━━━━\n\n"
        f"👤 User: *{name}*\n"
        f"🔹 ID: `{uid}`\n"
        f"🎖 Tier: {badge}\n"
        f"📅 Activated: {added_txt}\n"
        f"⏳ Expires: {expiry_txt}\n"
        f"{dumps_txt}\n\n"
        f"━━━━━━━━━━━━━━━━━━━"
    )
    kb = None
    if tier == "free":
        kb = InlineKeyboardMarkup([[
            InlineKeyboardButton("💎 Upgrade to Premium ✨", url=PREMIUM_CHANNEL)
        ]])
    await update.message.reply_text(text, parse_mode="MarkdownV2", reply_markup=kb)



async def handle_apk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global _active_dex_jobs
    doc  = update.message.document
    chat = update.effective_chat.id

    if not doc.file_name.lower().endswith(".apk"):
        await update.message.reply_text(
            "⚠️ Please send an \\.apk file\\.", parse_mode="MarkdownV2"
        )
        return

    fname    = doc.file_name or "app.apk"
    total_b  = doc.file_size or 0
    total_mb = total_b / 1048576

    if total_mb > MAX_APK_MB:
        await update.message.reply_text(
            f"❌ APK is {total_mb:.0f} MB — limit is {MAX_APK_MB} MB\\.",
            parse_mode="MarkdownV2",
        )
        return

    # ── Per-user lock: ignore duplicate sends while job is running/queued ──
    user_uid = update.effective_user.id
    async with _queue_lock:
        already_busy = user_uid in _user_active
        if not already_busy:
            _user_active.add(user_uid)

    if already_busy:
        # Save this APK so the finally block auto-triggers it when the current
        # job finishes.  Overwrites any previously pending APK (last one wins).
        _pending_apk[user_uid] = {"update": update, "context": context}

        # Tell the user whether their current job is still queued or running
        async with _queue_lock:
            pos = next(
                (i + 1 for i, e in enumerate(_wait_queue) if e["uid"] == user_uid),
                None,
            )
        if pos is not None:
            pos_txt = (
                f"📥 *Got it\\! Your new APK is saved\\.*\n\n"
                f"Your current APK is still \\#{pos} in the queue\\.\n"
                f"Once it finishes\\, your new one will start automatically — "
                f"no need to resend\\."
            )
        else:
            pos_txt = (
                f"📥 *Got it\\! Your new APK is saved\\.*\n\n"
                f"Your current APK is still processing\\.\n"
                f"Once it finishes\\, your new one will start automatically — "
                f"no need to resend\\."
            )
        await update.message.reply_text(pos_txt, parse_mode="MarkdownV2")
        return

    # ── Daily limit for free users ─────────────────────────────────────────
    if not is_admin(user_uid) and not is_premium(user_uid):
        used = get_daily_count(user_uid)
        if used >= FREE_DAILY_LIMIT:
            async with _queue_lock:
                _user_active.discard(user_uid)
            kb_lim = InlineKeyboardMarkup([[
                InlineKeyboardButton("💎 Subscribe to Premium ✨", url=PREMIUM_CHANNEL)
            ]])
            await update.message.reply_text(
                f"🚫 *Daily Limit Reached*\n\n"
                f"🆓 Free users get *{FREE_DAILY_LIMIT} successful dumps per day*\\.\n"
                f"You've used all {FREE_DAILY_LIMIT} slots today\\.\n\n"
                f"⏰ Resets at midnight — or upgrade for *unlimited* access\\!",
                parse_mode="MarkdownV2",
                reply_markup=kb_lim,
            )
            return

    # ── FIFO queue gate (1 job at a time) ────────────────────────────────
    my_event  = asyncio.Event()
    my_entry  = {"uid": user_uid, "event": my_event, "queue_msg": None}
    queue_msg = None

    async with _queue_lock:
        _wait_queue.append(my_entry)
        queue_pos = len(_wait_queue)
        if queue_pos <= MAX_CONCURRENT:
            my_event.set()                    # free slot — start immediately

    # Initialise ALL vars here so the finally block can always clean up,
    # even if an exception fires before we enter the try body.
    cancel     = asyncio.Event()
    _held_slot = False   # True only after we actually acquire a running slot
    apk_path = None
    out_dir  = None
    zip_path = None
    tmp_apk  = None   # /data/local/tmp/matrix_{chat}.apk — set when copied for install
    pkg      = None
    pkg_lock = None   # asyncio.Lock acquired when same-package serialisation starts
    msg      = None

    # ── Global job watchdog: activity-based, not flat-timer ─────────────────
    # Fires if NO stage has made progress for INACTIVITY_SECS (10 min), OR the
    # total job exceeds ABSOLUTE_CAP_SECS (30 min).  Each major stage calls
    # _touch() to reset the inactivity clock.  A flat 10-min timer would cancel
    # a legitimately slow dump/upload on a large APK.
    import time as _time_mod
    INACTIVITY_SECS  = 600   # cancel if silent for 10 min
    ABSOLUTE_CAP_SECS = 1800  # cancel unconditionally after 30 min
    _last_activity = [_time_mod.monotonic()]
    def _touch():
        """Reset the inactivity clock — call at every major stage boundary."""
        _last_activity[0] = _time_mod.monotonic()

    async def _job_watchdog():
        start = _time_mod.monotonic()
        while True:
            await asyncio.sleep(30)   # check every 30 s
            if cancel.is_set():
                return
            elapsed   = _time_mod.monotonic() - start
            inactive  = _time_mod.monotonic() - _last_activity[0]
            if elapsed >= ABSOLUTE_CAP_SECS:
                log.warning("Watchdog: absolute cap %ds hit for chat %s", ABSOLUTE_CAP_SECS, chat)
                cancel.set(); return
            if inactive >= INACTIVITY_SECS:
                log.warning("Watchdog: %ds inactivity for chat %s — forcing cancel", inactive, chat)
                cancel.set(); return
    _watchdog_task = asyncio.create_task(_job_watchdog())

    try:
        # ── Send queue-position card (if beyond the concurrent slots) ─────
        if queue_pos > MAX_CONCURRENT:
            ahead = queue_pos - MAX_CONCURRENT   # number waiting ahead
            try:
                queue_msg = await update.message.reply_text(
                    f"⏳ *You're \\#{ahead} in the queue*\n\n"
                    f"{'1 APK' if ahead == 1 else f'{ahead} APKs'} finishing before your turn\\.\n"
                    f"You'll start automatically — no need to resend\\.",
                    parse_mode="MarkdownV2",
                )
                async with _queue_lock:
                    my_entry["queue_msg"] = queue_msg
            except Exception as _qe:
                log.warning("Could not send queue card: %s", _qe)

        # Register cancel flag NOW — before waiting — so Cancel button works while queued
        _cancel_flags[chat] = cancel

        # Race: queue slot vs Cancel button press — user can abort at any point
        _slot_t   = asyncio.create_task(my_event.wait())
        _cancel_t = asyncio.create_task(cancel.wait())
        await asyncio.wait({_slot_t, _cancel_t}, return_when=asyncio.FIRST_COMPLETED)
        _cancel_t.cancel()

        if cancel.is_set():
            # Cancelled while still queued — no slot was held, just show message and exit
            if queue_msg:
                try:
                    await queue_msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2")
                except Exception:
                    pass
            return

        # Slot acquired — mark as actively running
        _held_slot = True
        _active_dex_jobs += 1

        # ── Stage 1: Download with real progress bar ───────────────────────
        # If the user was queued, reuse that message as the status message
        # so the queue card smoothly transforms into the live progress bar.
        # Cancel button shown from Stage 1 onwards — user can abort at any time.
        kb_cancel = _cancel_kb(chat)
        init_text = (
            f"📥 *Receiving APK\\.\\.\\.*\n\n"
            f"`{_bar(0)}` 0%\n"
            f"📁 {_esc(fname)} • 0\\.0 \\/ {_mb(total_mb)} MB"
        )
        if queue_msg:
            try:
                await queue_msg.edit_text(
                    f"✅ *Your turn\\!* Grabbing your APK now\\.\\.\\.  🔄\n\n"
                    f"`{_bar(0)}` 0%\n"
                    f"📁 {_esc(fname)} • 0\\.0 \\/ {_mb(total_mb)} MB",
                    parse_mode="MarkdownV2",
                    reply_markup=kb_cancel,
                )
                msg = queue_msg
            except Exception:
                msg = None   # fall through to fresh message below

        if msg is None:
            msg = await update.message.reply_text(
                init_text, parse_mode="MarkdownV2", reply_markup=kb_cancel,
            )
        asyncio.create_task(
            _auto_delete(context.bot, chat, msg.message_id)
        )

        apk_path = os.path.join(WORK_DIR, f"incoming_{chat}.apk")
        if total_b > BOT_API_LIMIT_B:
            await _download_large_pyro(
                msg, chat, update.message.message_id, apk_path, fname, total_b
            )
        else:
            try:
                await _download_with_progress(
                    msg, context.bot, doc.file_id, apk_path, fname, total_b
                )
            except Exception:
                tg_file = await context.bot.get_file(doc.file_id)
                await tg_file.download_to_drive(apk_path)

        _touch()   # Stage 1 done — reset inactivity clock
        if cancel.is_set():
            return

        await msg.edit_text(
            f"📥 *APK Received* ✅\n\n"
            f"`{_bar(100)}` 100%\n"
            f"📁 {_esc(fname)} • {_mb(total_mb)} MB",
            parse_mode="MarkdownV2",
        )
        gc.collect()   # free download buffers before heavy install/dump stages
        await asyncio.sleep(0.6)

        # ── Stage 2: Read package info ─────────────────────────────────────
        loop = asyncio.get_event_loop()
        pkg = await loop.run_in_executor(None, get_package_name, apk_path)
        if not pkg:
            await msg.edit_text(
                "❌ Could not read package info\\. Is it a valid APK?",
                parse_mode="MarkdownV2",
            )
            return

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2")
            return

        # ── Per-package lock: serialise same-package jobs ──────────────────
        # pkg_lock is stored in the outer scope so finally can always release it
        # even after pkg is set to None during Stage 5 uninstall.
        pkg_lock = await _acquire_pkg_lock(pkg)
        if pkg_lock.locked():
            await msg.edit_text(
                f"⚠️ *Same package detected*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"Another user is currently processing this exact package\\.\n"
                f"Waiting for them to finish before starting yours\\.\\.\\.",
                parse_mode="MarkdownV2",
            )
        await pkg_lock.acquire()
        # ↑ From this point pkg_lock is held — finally MUST release it

        if cancel.is_set():
            pkg_lock.release()
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2")
            return

        # ── Stage 3: Process — install + launch + wait (animated) ─────────
        PROC_FRAMES = [
            "🧬 Analyzing protection structure\\.\\.\\.",
            "🔐 Preparing sandbox environment\\.\\.\\.",
            "⚙️  Executing decryption engine\\.\\.\\.",
            "🔬 Scanning runtime memory\\.\\.\\.",
            "🛡️  Bypassing protection layers\\.\\.\\.",
            "💉 Injecting extraction hooks\\.\\.\\.",
            "📡 Monitoring process signals\\.\\.\\.",
            "🗂️  Mapping memory regions\\.\\.\\.",
        ]

        stop1 = asyncio.Event()
        kb    = _cancel_kb(chat)

        def proc_frame(i):
            sp = SPIN[i % len(SPIN)]
            fr = PROC_FRAMES[(i // 2) % len(PROC_FRAMES)]
            return (
                f"⚙️ *Processing* {sp}\n\n"
                f"📦 `{_esc(pkg)}`\n\n"
                f"{fr}"
            )

        anim1 = asyncio.create_task(_animate(msg, proc_frame, stop1, reply_markup=kb))

        tmp_apk = f"/data/local/tmp/matrix_{chat}.apk"   # tracked for finally cleanup
        await _run_sh(f'su -c "cp \\"{apk_path}\\" {tmp_apk} && chmod 644 {tmp_apk}"', cancel=cancel)

        # Pre-install uninstall is inside the PM lock — prevents collision with
        # another job's pm install running at the same time on a parallel slot.
        async with _pm_lock:
            await _java_pm("uninstall", pkg, 30)

        # Force-stop the app first so pm install isn't blocked by a running process
        await _run_sh(f'su -c "am force-stop {pkg}"', 10, cancel=cancel)

        # Clear page cache before install — gives PM the best chance of responding
        await _run_sh("su -c 'echo 3 > /proc/sys/vm/drop_caches'", 10, cancel=cancel)

        # Global PM lock — only one install runs at a time to prevent Binder overload
        if _pm_lock.locked():
            log.info("PM lock busy — queuing install for %s", pkg)
            await msg.edit_text(
                "⏳ *Installer busy\\.\\.\\.*\n\n"
                "Another APK is being installed right now\\. "
                "Yours will start automatically in a moment — no need to resend\\.",
                parse_mode="MarkdownV2",
                reply_markup=kb_cancel,
            )
        async with _pm_lock:
            log.info("PM lock acquired — starting install for %s", pkg)

            # Path to the Java installer JAR (built once on device via build_installer.sh)
            INSTALLER_JAR = "/data/local/tmp/installer.jar"

            # ── Shared pm-shell helper (setenforce + flag fallback) ───────────────
            # Root cause of "Failed transaction": after Java runs as root, su shells
            # get degraded SELinux context u:r:shell:s0 → PM rejects the Binder call.
            async def _do_pm_shell(apk: str) -> "tuple[int, str]":
                await _run_sh('su -c "setenforce 0 2>/dev/null; true"', 5, cancel=cancel)
                rc_i, o_i, e_i = await _run_sh(
                    f'su -c "pm install -r -g -t -d --bypass-low-target-sdk-block {apk} 2>&1"',
                    180, cancel=cancel)
                combined = (o_i + " " + e_i).strip()
                if "Unknown option" in combined or (
                    "error" in combined.lower() and "Success" not in combined
                ):
                    rc_i, o_i, e_i = await _run_sh(
                        f'su -c "pm install -r -g -t -d {apk} 2>&1"', 180, cancel=cancel)
                    combined = (o_i + " " + e_i).strip()
                await _run_sh('su -c "setenforce 1 2>/dev/null; true"', 5, cancel=cancel)
                return rc_i, combined

            rc, out, err = -1, "", ""

            # ── Method 0: Java installer via app_process (PREFERRED) ─────────────
            # app_process always starts with a FRESH SELinux context — not degraded
            # by any previous Java run — so pm install called from inside it works
            # correctly without setenforce tricks.
            _, jar_check, _ = await _run_sh(
                f'su -c "[ -f {INSTALLER_JAR} ] && echo yes || echo no"', 5, cancel=cancel)
            if jar_check.strip() == "yes":
                log.info("Using Java installer (app_process) for %s", pkg)
                rc, out, err = await _run_sh(
                    f'su -c "app_process -cp {INSTALLER_JAR} / ApkInstaller install {tmp_apk} 2>&1"',
                    180, cancel=cancel)
                combined = (out + " " + err).strip()
                log.info("java install rc=%d out=%r", rc, combined[:300])
                if rc == 0 and "Success" in combined:
                    log.info("PM lock released for %s (java install OK)", pkg)
                    # skip all fallback methods
                    rc = 0; out = combined; err = ""
                else:
                    log.warning("Java installer failed (%r) — falling through to shell methods", combined[:200])
                    rc = 1; out = combined; err = ""
            else:
                log.info("installer.jar not found — using shell pm install (run build_installer.sh to enable Java path)")
                rc = 1  # force fallthrough to Method 1

            # ── Method 1: setenforce + direct pm install ──────────────────────────
            if rc != 0 and "Success" not in (out + err):
                combined = out
                rc, combined = await _do_pm_shell(tmp_apk)
                out, err = combined, ""
                log.info("pm install#1 rc=%d out=%r", rc, combined[:300])

            # ── Method 2: su -mm (Magisk mount-master — correct SELinux namespace) ─
            if rc != 0 and "Failed transaction" in (out + err):
                log.warning("Binder failure — trying su -mm (Magisk mount-master)")
                await _run_sh('su -c "setenforce 0 2>/dev/null; true"', 5, cancel=cancel)
                rc, o2, e2 = await _run_sh(
                    f'su -mm -c "pm install -r -g -t -d --bypass-low-target-sdk-block {tmp_apk} 2>&1"',
                    180, cancel=cancel)
                combined = (o2 + " " + e2).strip()
                out, err = combined, ""
                await _run_sh('su -c "setenforce 1 2>/dev/null; true"', 5, cancel=cancel)
                log.info("pm install#2 (su -mm) rc=%d out=%r", rc, combined[:300])

            # ── Method 3: session-based install (different Binder path) ───────────
            if rc != 0 and "Failed transaction" in (out + err):
                log.warning("Binder failure — trying session-based install")
                await asyncio.sleep(3)
                _, sz_out, _ = await _run_sh(f'su -c "wc -c < {tmp_apk}"', 10, cancel=cancel)
                apk_size = sz_out.strip() or "0"
                await _run_sh('su -c "setenforce 0 2>/dev/null; true"', 5, cancel=cancel)
                _, sess_out, _ = await _run_sh(
                    f'su -c "pm install-create -r -g -t -d -S {apk_size}"', 30, cancel=cancel)
                m = re.search(r'\[(\d+)\]', sess_out)
                if m:
                    sid = m.group(1)
                    log.info("session id=%s size=%s", sid, apk_size)
                    await _run_sh(
                        f'su -c "pm install-write -S {apk_size} {sid} base.apk {tmp_apk}"',
                        120, cancel=cancel)
                    rc, out, err = await _run_sh(
                        f'su -c "pm install-commit {sid}"', 60, cancel=cancel)
                    log.info("session commit rc=%d out=%r err=%r", rc, out[:200], err[:200])
                await _run_sh('su -c "setenforce 1 2>/dev/null; true"', 5, cancel=cancel)

            # ── Method 4: adb install via localhost ───────────────────────────────
            if rc != 0 and "Failed transaction" in (out + err):
                log.warning("Trying adb install via localhost")
                await _run_sh('adb start-server 2>&1', 10, cancel=cancel)
                await _run_sh('adb connect localhost:5555 2>&1', 10, cancel=cancel)
                rc, out, err = await _run_sh(f'adb install -r -g {tmp_apk} 2>&1', 180, cancel=cancel)
                log.info("adb install rc=%d out=%r", rc, out[:300])

            # ── Method 5: final — wait for PM self-heal then retry ────────────────
            if rc != 0 and "Failed transaction" in (out + err):
                log.warning("All methods failed — waiting 20s for PM self-heal")
                await asyncio.sleep(20)
                rc, combined = await _do_pm_shell(tmp_apk)
                out, err = combined, ""
                log.info("pm install#5 (recovery) rc=%d out=%r", rc, combined[:300])

            log.info("PM lock released for %s", pkg)

        await _run_sh(f'su -c "rm -f {tmp_apk}"', cancel=cancel)
        _touch()   # Stage 3 done — install complete, reset inactivity clock

        if cancel.is_set():
            stop1.set(); await anim1
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2")
            return

        if rc != 0:
            stop1.set(); await anim1
            log.error("Install failed for %s: %s", pkg, (err or out)[:300])
            binder_dead = "Failed transaction" in (out + err)
            if binder_dead:
                await msg.edit_text(
                    f"⚠️ *Engine temporarily unavailable*\n\n"
                    f"`{_esc(pkg)}`\n\n"
                    f"The sandbox service needs a restart\\. Please try again in a moment\\.",
                    parse_mode="MarkdownV2",
                )
            else:
                await msg.edit_text(
                    f"❌ *Processing failed*\n\n"
                    f"`{_esc(pkg)}`\n\n"
                    f"The APK could not be processed by our engine\\.",
                    parse_mode="MarkdownV2",
                )
            return

        loop = asyncio.get_event_loop()
        # Keep screen alive for the full dump — some apps (e.g. AOD apps)
        # intentionally turn the screen off when launched which makes the
        # phone appear to "shut down". Set timeout to 10 min then wake it.
        await loop.run_in_executor(
            None, lambda: run("su -c 'settings put system screen_off_timeout 600000'", timeout=5)
        )
        await loop.run_in_executor(None, functools.partial(launch_app, pkg))
        # Push the launched app to background immediately — this is the key:
        # any app (AOD, fullscreen, overlay) that takes the foreground can
        # turn the screen off or hijack the display. HOME removes it from
        # foreground so it has zero display control while its DEX is in memory.
        await asyncio.sleep(1)   # 1 s so the app has time to actually start
        await loop.run_in_executor(
            None, lambda: run("su -c 'input keyevent KEYCODE_HOME'", timeout=5)
        )
        # Also wake the screen in case it went off during that 1 s
        await loop.run_in_executor(
            None, lambda: run("su -c 'input keyevent KEYCODE_WAKEUP'", timeout=5)
        )
        await asyncio.sleep(LAUNCH_WAIT)

        if cancel.is_set():
            stop1.set(); await anim1
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2")
            return

        pid = await loop.run_in_executor(None, get_pid, pkg)
        if not pid:
            await asyncio.sleep(5)
            pid = await loop.run_in_executor(None, get_pid, pkg)

        if not pid:
            stop1.set(); await anim1
            # App never started — uninstall before giving up so nothing is left on device
            _failed_pkg = pkg
            await _run_sh(f'su -c "am force-stop {pkg}"')
            async with _pm_lock:
                await _java_pm("uninstall", pkg)
            pkg = None   # tell wipe_work to skip (already done)
            await msg.edit_text(
                f"❌ *App did not launch*\n\n"
                f"`{_esc(_failed_pkg)}`\n\n"
                f"The app failed to start after install\\. "
                f"This usually means the protection layer has a hard crash at init\\.\n\n"
                f"📋 Sandbox has been wiped\\.",
                parse_mode="MarkdownV2",
            )
            return

        # ── Crash guard: verify app is still alive 3 s after we got the PID ──
        # Apps with SIGABRT / memory corruption (e.g. Scudo invalid-chunk) crash
        # within a few seconds of launch — the PID vanishes immediately.
        # Without this check the dump script would run for its full 180 s timeout
        # producing nothing, leaving the app installed the whole time.
        await asyncio.sleep(3)
        pid_check = await loop.run_in_executor(None, get_pid, pkg)
        if not pid_check:
            stop1.set(); await anim1
            # Grab last crash line from logcat for the user
            _, crash_log, _ = await _run_sh(
                f'su -c "logcat -d -t 60 2>/dev/null | grep -E \'FATAL|signal [0-9]|SIGABRT|{pkg}\' | tail -6"',
                timeout=10,
            )
            crash_snippet = crash_log.strip()[:600] if crash_log.strip() else "No crash log captured."
            await _run_sh(f'su -c "am force-stop {pkg}"')
            async with _pm_lock:
                await _java_pm("uninstall", pkg)
            pkg = None
            crash_esc = _esc(crash_snippet)
            await msg.edit_text(
                f"💥 *App crashed at launch*\n\n"
                f"The app crashed immediately after start — "
                f"likely a native SIGABRT or memory corruption inside the protection layer\\.\n\n"
                f"📋 *Last crash log:*\n"
                f"`{crash_esc}`\n\n"
                f"Sandbox wiped\\.",
                parse_mode="MarkdownV2",
            )
            return

        # ── Stage 4: Dump DEX ──────────────────────────────────────────────
        out_dir = os.path.join(WORK_DIR, f"dex_{chat}")
        await _run_sh(f'su -c "rm -rf \\"{out_dir}\\""', cancel=cancel)
        await _run_sh(f'su -c "mkdir -p \\"{out_dir}\\" && chmod 777 \\"{out_dir}\\""', cancel=cancel)
        rc_dump, out_dump, err_dump = await _run_sh(
            f'su -c "{PYTHON3} {DUMP_SCRIPT} {pid} \\"{out_dir}\\" {pkg}"', 180, cancel=cancel
        )
        await _run_sh(f'su -c "chmod 644 \\"{out_dir}\\"/* 2>/dev/null"', cancel=cancel)
        _touch()   # Stage 4 done — DEX dump complete, reset inactivity clock
        gc.collect()   # release any leftover dump subprocess output buffers

        stop1.set(); await anim1

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2")
            return

        dex_files = list(Path(out_dir).glob("*.dex"))
        if not dex_files:
            # Nothing dumped — uninstall immediately before sending error
            await _run_sh(f'su -c "am force-stop {pkg}"')
            async with _pm_lock:
                await _java_pm("uninstall", pkg)
            pkg = None
            # Include the dump script's own error output so the user sees exactly what failed
            dump_err = (err_dump or out_dump or "").strip()[:400]
            err_detail = f"\n\n📋 *Engine output:*\n`{_esc(dump_err)}`" if dump_err else ""
            await msg.edit_text(
                f"❌ *Dump failed — no DEX captured*\n\n"
                f"The app may have crashed mid\\-dump\\, re\\-encrypted itself\\, "
                f"or the protection layer uses a method our engine does not yet support\\."
                f"{err_detail}\n\n"
                f"📋 Sandbox wiped\\.",
                parse_mode="MarkdownV2",
            )
            return

        # ── Free RAM immediately: kill + uninstall the app now that we have its DEX ──
        # Doing this before zip/upload drops the running-app's RSS before we do
        # any more heavy work, which is critical on a memory-constrained device.
        pkg_name = pkg   # keep the name for messages; pkg→None tells _wipe_work to skip
        await _run_sh(f'su -c "am force-stop {pkg_name}"', cancel=cancel)
        async with _pm_lock:
            await _java_pm("uninstall", pkg_name)
        pkg = None

        # ── Stage 5: Zip ───────────────────────────────────────────────────
        dex_count = len(dex_files)
        zip_path  = os.path.join(WORK_DIR, f"dex_{chat}.zip")

        await msg.edit_text(
            f"📦 *Packaging Results\\.\\.\\.*\n\n"
            f"`{_esc(pkg_name)}`\n\n"
            f"📁 Compressing {dex_count} DEX files\\.\\.\\.",
            parse_mode="MarkdownV2",
        )
        n_zipped = await loop.run_in_executor(
            None, functools.partial(zip_dir, out_dir, zip_path)
        )
        zip_mb   = os.path.getsize(zip_path) / 1048576
        _touch()   # Stage 5 done — zip ready, reset inactivity clock
        await asyncio.sleep(0.4)

        # ── Stage 6: Upload ────────────────────────────────────────────────
        zip_fname = f"dex_{pkg_name}.zip"
        zip_size  = os.path.getsize(zip_path)

        caption_md2 = (
            f"✅ *Extraction Complete\\!*\n\n"
            f"`{_esc(pkg_name)}`\n\n"
            f"📁 {n_zipped} DEX files  •  💾 {_mb(zip_mb)} MB\n"
            f"🧹 Sandbox wiped\\."
        )
        caption_md = (
            f"✅ **Extraction Complete!**\n\n"
            f"`{pkg_name}`\n\n"
            f"📁 {n_zipped} DEX files  •  💾 {zip_mb:.1f} MB\n"
            f"🧹 Sandbox wiped."
        )

        # Always upload via Pyrogram so progress % shows regardless of file size
        await msg.edit_text(
            f"📤 *Uploading\\.\\.\\.*\n\n"
            f"`{_bar(0)}` 0%\n"
            f"📦 {_esc(zip_fname)} • 0\\.0 \\/ {_mb(zip_mb)} MB",
            parse_mode="MarkdownV2",
        )
        await _upload_large_pyro(
            chat, zip_path, zip_fname, caption_md,
            status_msg=msg, zip_mb=zip_mb, cancel=cancel,
        )

        log.info("Sent %d DEX (%.1f MB) for %s to chat %s",
                 n_zipped, zip_mb, pkg, chat)

        # Count only successful dumps toward the free daily limit
        if not is_admin(user_uid) and not is_premium(user_uid):
            increment_daily_count(user_uid)

        try:
            await msg.edit_text(
                f"✅ *Complete\\!*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"📁 {n_zipped} DEX files  •  💾 {_mb(zip_mb)} MB\n"
                f"🧹 Sandbox wiped \\— ZIP delivered above ↑",
                parse_mode="MarkdownV2",
            )
        except Exception:
            pass


    except Exception as exc:
        log.exception("handle_apk crashed for chat %s: %s", chat, exc)
        if msg:
            try:
                await msg.edit_text(
                    "❌ *Internal error*\n\nSomething went wrong\\. Please try again\\.",
                    parse_mode="MarkdownV2",
                )
            except Exception:
                pass
    finally:
        # Stop the watchdog — job finished (success, cancel, or error)
        _watchdog_task.cancel()
        # Release per-package lock so the next user with the same APK can go.
        # Use pkg_lock directly — NOT via _pkg_locks.get(pkg) — because pkg is
        # set to None at Stage 5 before finally runs, which previously caused
        # the lock to never be released (permanent "Same package detected" deadlock).
        if pkg_lock and pkg_lock.locked():
            try:
                pkg_lock.release()
            except RuntimeError:
                pass
        # Always remove from queue and clear user-active — regardless of _held_slot
        async with _queue_lock:
            _wait_queue[:] = [e for e in _wait_queue if e["event"] is not my_event]
            _user_active.discard(user_uid)
        _cancel_flags.pop(chat, None)
        if _held_slot:
            # Held a running slot — free it and wake the next waiter
            next_to_wake = None
            still_waiting = []
            async with _queue_lock:
                for e in _wait_queue:
                    if not e["event"].is_set():
                        if next_to_wake is None:
                            next_to_wake = e
                        else:
                            still_waiting.append(e)
            if next_to_wake:
                next_to_wake["event"].set()
            for idx, entry in enumerate(still_waiting):
                qm = entry.get("queue_msg")
                if not qm:
                    continue
                new_pos = idx + 1
                try:
                    await qm.edit_text(
                        f"⏳ *You're \\#{new_pos} in the queue*\n\n"
                        f"{'1 APK' if new_pos == 1 else f'{new_pos} APKs'} finishing before your turn\\.\n"
                        f"You'll start automatically — no need to resend\\.",
                        parse_mode="MarkdownV2",
                    )
                except Exception:
                    pass
            _active_dex_jobs = max(0, _active_dex_jobs - 1)
            if _active_dex_jobs == 0:
                try:
                    await _run_sh("su -c 'settings put system screen_off_timeout 120000'")
                except Exception:
                    pass
            await _wipe_work(pkg, apk_path, out_dir, zip_path, tmp_apk)
            await asyncio.sleep(15)
            pending = _pending_apk.pop(user_uid, None)
            if pending:
                log.info("Auto-triggering pending APK for user %s", user_uid)
                asyncio.create_task(
                    handle_apk(pending["update"], pending["context"])
                )
        else:
            # Cancelled while queued — never held a slot, so don't free one or cooldown
            await _wipe_work(pkg, apk_path, out_dir, zip_path, tmp_apk)


async def handle_cancel_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Inline 🚫 Cancel button pressed during processing."""
    query   = update.callback_query
    chat_id = query.message.chat_id
    try:
        await query.answer("Cancelling…", show_alert=False)
    except Exception:
        pass   # TimedOut / already answered — not critical
    ev = _cancel_flags.get(chat_id)
    if ev:
        ev.set()
    else:
        try:
            await query.edit_message_text(
                "ℹ️ Nothing is running right now\\.", parse_mode="MarkdownV2"
            )
        except Exception:
            pass


async def handle_other(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "━━━━━━━━━━━━━━━━━━━━━━━\n"
        "🔐 <b>𝗠𝗔𝗧𝗥𝗜𝗫 𝗗𝗨𝗠𝗣𝗘𝗥 𝗘𝗡𝗚𝗜𝗡𝗘 𝗩𝟴</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📦 Send me any protected <code>.apk</code> file and I'll dump its DEX classes instantly.\n\n"
        "🛡️ Got a <code>.apks</code> <b>Google加固</b> bundle too?\n"
        "Send it here, then <b>reply</b> to it with /pairipx to strip out the <b>Google加固</b> protection — fully automated.\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━",
        parse_mode="HTML",
    )


# ══════════════════════════════════════════════════════════════════════════════
#  PAIRIPX — Google Pairip / Play Integrity protection remover
#  Triggered automatically when a user sends a .apks Split APK bundle.
#  Mirrors handle_apk exactly: same queue, cancel, watchdog, cleanup patterns.
#  Independent queue from DEX dump — up to PAIRIP_MAX_CONCURRENT parallel jobs.
# ══════════════════════════════════════════════════════════════════════════════

PAIRIP_JAR            = os.path.expanduser("~/Pairip.jar")
PAIRIP_MAX_CONCURRENT = 2        # independent of DEX MAX_CONCURRENT
PAIRIP_POLL_SECS      = 120      # max seconds to wait for pairip.json

_LD_PATH = (
    "/data/data/com.termux/files/usr/lib"
    ":/data/local/tmp/matrix_java/usr/lib"
    ":/system/lib64"
)

# ── Pairip-specific queue structures (separate from DEX queue) ──────────────
_pairip_user_active: set[int]  = set()
_pairip_wait_queue:  list[dict] = []
_pending_apks:       dict       = {}   # uid -> {update, context}
# Override injected by cmd_pairipx so handle_pairip uses the right doc + msg_id
_pairip_src_override: dict      = {}   # uid -> {doc, source_msg_id}


def _pairip_heap_mb() -> int:
    """75 % of physical RAM, clamped 512–4096 MB."""
    try:
        pages     = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        total_mb  = pages * page_size // (1024 * 1024)
        return max(512, min(4096, total_mb * 75 // 100))
    except Exception:
        return 1024


def _pairip_jvm_flags() -> str:
    heap = _pairip_heap_mb()
    try:
        cores = os.cpu_count() or 2
    except Exception:
        cores = 2
    gc_threads = max(1, cores // 2)
    return (
        f"-server -Xmx{heap}m -Xms{max(256, heap // 4)}m "
        f"-XX:+UseG1GC -XX:ConcGCThreads={gc_threads} "
        f"-XX:+TieredCompilation -XX:+OptimizeStringConcat"
    )


async def _find_java() -> "str | None":
    """
    Scan all known Java binary locations and return the first working path.
    Does NOT install anything — call _ensure_java() for auto-install.
    """
    candidates = [
        "/data/local/tmp/matrix_java/usr/bin/java",
        "/data/local/tmp/matrix_java/usr/lib/jvm/java-17-openjdk/bin/java",
        "/data/local/tmp/matrix_java/usr/lib/jvm/java-21-openjdk/bin/java",
        "/data/local/tmp/matrix_java/usr/lib/jvm/java-11-openjdk/bin/java",
        "/data/data/com.termux/files/usr/bin/java",
    ]
    for p in candidates:
        rc, _, _ = await _run_sh(f'su -c "test -x \\"{p}\\""', timeout=5)
        if rc == 0:
            return p
    rc, out, _ = await _run_sh(
        "which java 2>/dev/null || command -v java 2>/dev/null", timeout=5
    )
    if rc == 0 and out.strip():
        return out.strip()
    return None


async def _ensure_java(msg, kb_cancel) -> "str | None":
    """
    Return a working Java binary path, auto-installing openjdk-17 via
    Termux pkg if not already present.  Skips installation instantly when
    Java is already there (idempotent — safe to call on every job).

    Flow:
      1. _find_java()  →  found? return immediately (fast path, no install)
      2. Not found     →  update status msg, run: pkg install openjdk-17 -y
      3. _find_java()  →  found? return path
      4. Still missing →  return None (caller shows error)
    """
    # ── Fast path: already installed ────────────────────────────────────────
    java = await _find_java()
    if java:
        log.info("Java found (reusing): %s", java)
        return java

    # ── Not found — auto-install openjdk-17 via Termux pkg ──────────────────
    log.info("Java not found — auto-installing openjdk-17 via pkg…")
    try:
        await msg.edit_text(
            "☕ *Java 17 not found — installing automatically\\.\\.\\.*\n\n"
            "This is a one\\-time setup \\(~60 s\\)\\. Please wait\\.",
            parse_mode="MarkdownV2", reply_markup=kb_cancel,
        )
    except Exception:
        pass

    # pkg install is interactive by default; -y answers yes to all prompts.
    # DEBIAN_FRONTEND=noninteractive silences any remaining prompts.
    rc, out, err = await _run_sh(
        "DEBIAN_FRONTEND=noninteractive pkg install openjdk-17 -y 2>&1",
        timeout=300,
    )
    combined = (out + err).strip()
    log.info("pkg install openjdk-17 rc=%d out=%s", rc, combined[:300])

    # ── Re-check after install ────────────────────────────────────────────────
    java = await _find_java()
    if java:
        log.info("Java installed successfully: %s", java)
        try:
            await msg.edit_text(
                "☕ *Java 17 installed successfully* ✅\n\n"
                "Continuing with Pairip pipeline\\.\\.\\.",
                parse_mode="MarkdownV2", reply_markup=kb_cancel,
            )
        except Exception:
            pass
        await asyncio.sleep(1)
        return java

    log.error("Java still not found after pkg install. output: %s", combined[:500])
    return None


async def _run_pairip_jar(java_bin: str, jar_args: str,
                          cancel: "asyncio.Event", timeout: int = 480
                          ) -> "tuple[int, str]":
    """
    Run Pairip.jar via su with the correct LD_LIBRARY_PATH and JVM flags
    (mirrors PatchEngine.kt runJarStreaming).  Returns (exit_code, combined_log).
    Pairip.jar sometimes never closes stdout after finishing — the timeout
    kills it; the caller checks for output files regardless of exit code.
    """
    jvm = _pairip_jvm_flags()
    cmd = (
        f"LD_LIBRARY_PATH='{_LD_PATH}' "
        f"'{java_bin}' {jvm} -jar '{PAIRIP_JAR}' {jar_args}"
    )
    rc, out, err = await _run_sh(f'su -c "{cmd}"', timeout=timeout, cancel=cancel)
    return rc, (out + "\n" + err).strip()


def _pick_pass1_apks(dir_path: str) -> "tuple[str | None, str | None]":
    """
    From Pass-1 output dir identify:
      pairip_apk — the bypass-install APK  → install this on device
      merged_apk — all-splits-merged APK   → feed to Pass 2

    Pairip.jar produces two files whose names contain both the input stem
    and either '_pairip' or '_merged':
        <stem>_pairip.apk   ← sig-bypass patched, pairip lib INTACT → install
        <stem>_merged.apk   ← raw merge, pairip lib INTACT          → Pass 2

    IMPORTANT: both filenames contain the string "pairip" (it's also in the
    stem prefix like "pairip_853645999_pairip.apk").  Naively matching on
    "pairip" would pick _merged first (alphabetically earlier).  We must
    prefer the file whose name ends with '_pairip.apk', i.e. the suffix token
    (last underscore-word) is 'pairip'.
    """
    try:
        apks = sorted(
            os.path.join(dir_path, f)
            for f in os.listdir(dir_path)
            if f.lower().endswith(".apk")
        )
    except Exception:
        return None, None
    if not apks:
        return None, None

    def _suffix(p: str) -> str:
        """Last token before .apk, e.g. 'pairip_853645999_pairip' → 'pairip'."""
        return os.path.basename(p).lower().rsplit(".", 1)[0].rsplit("_", 1)[-1]

    # Prefer file whose last underscore-token is exactly 'pairip' (not 'merged')
    pairip_apk = next((p for p in apks if _suffix(p) == "pairip"), None)
    if not pairip_apk:
        # Fallback: has 'pairip' anywhere but not 'merged' suffix
        pairip_apk = next(
            (p for p in apks
             if "pairip" in os.path.basename(p).lower() and _suffix(p) != "merged"),
            None,
        )
    if not pairip_apk:
        # Last resort: any file with 'pairip' in name
        pairip_apk = next(
            (p for p in apks if "pairip" in os.path.basename(p).lower()), None
        )

    # merged_apk: last token is 'merged', or fall back to any non-pairip file
    merged_apk = next((p for p in apks if _suffix(p) == "merged"), None)
    if not merged_apk:
        merged_apk = next(
            (p for p in apks if "merged" in os.path.basename(p).lower()), None
        )

    if not pairip_apk:
        pairip_apk = apks[0]
    if not merged_apk:
        merged_apk = next((p for p in apks if p != pairip_apk), apks[0])
    return pairip_apk, merged_apk


def _find_apk_in_dir(dir_path: str, hint: "str | None") -> "str | None":
    """Return first APK in dir_path whose name contains hint (or any APK)."""
    try:
        apks = sorted(f for f in os.listdir(dir_path) if f.lower().endswith(".apk"))
    except Exception:
        return None
    if not apks:
        return None
    if hint:
        match = next((f for f in apks if hint.lower() in f.lower()), None)
        if match:
            return os.path.join(dir_path, match)
    return os.path.join(dir_path, apks[0])


def _pairip_json_candidates(pkg: str, sys_pid: str) -> "list[str]":
    """
    All locations where pairip.json might appear.
    proc/<sys_pid>/root/... paths are listed FIRST — they use system_server's
    mount namespace and work reliably on all Android versions (the mount
    namespace fix documented in PatchEngine.kt).
    """
    c = []
    if sys_pid:
        c += [
            f"/proc/{sys_pid}/root/data/user/0/{pkg}/dictionary/pairip.json",
            f"/proc/{sys_pid}/root/data/user/0/{pkg}/pairip.json",
            f"/proc/{sys_pid}/root/data/user/0/{pkg}/files/pairip.json",
            f"/proc/{sys_pid}/root/data/data/{pkg}/dictionary/pairip.json",
            f"/proc/{sys_pid}/root/data/data/{pkg}/pairip.json",
        ]
    c += [
        f"/data/user/0/{pkg}/dictionary/pairip.json",
        f"/data/data/{pkg}/dictionary/pairip.json",
        f"/data/user/0/{pkg}/pairip.json",
        f"/data/data/{pkg}/pairip.json",
        f"/data/user/0/{pkg}/files/pairip.json",
        "/storage/emulated/0/pairip.json",
        "/sdcard/pairip.json",
        f"/storage/emulated/0/Android/data/{pkg}/pairip.json",
    ]
    return c


async def _wipe_pairip(pkg: "str | None", work_dir: "str | None",
                       apks_path: "str | None",
                       tmp_pairip: "str | None" = None):
    """
    Always-run cleanup for Pairip jobs — runs on success, cancel, AND error.

    Cleans up every artefact the pipeline can create:
      • force-stop + pm uninstall the test package
      • rm -rf the entire work_dir  (covers pass1/, pass2/, extracted APKs,
        pairip.json, patched output APK — everything inside the work dir)
      • remove the original .apks the user sent (Termux home)
      • remove tmp_pairip (/data/local/tmp/pairip_<chat>.apk) — the copy
        used for pm install; only deleted inline on the happy path so the
        finally block is the safety-net for crashes / cancels mid-install
    """
    # Always re-enable SELinux — the pipeline leaves it permissive during
    # the swap→launch→poll→collect stages and relies on cleanup to restore it.
    await _run_sh('su -c "setenforce 1 2>/dev/null; true"')
    if pkg:
        await _run_sh(f'su -c "am force-stop {pkg}"')
        await _run_sh(f'su -c "pm uninstall {pkg}"')
    if work_dir:
        await _run_sh(f'su -c "rm -rf \\"{work_dir}\\""')
    # Remove /data/local/tmp staging copy (safety-net — also deleted inline)
    if tmp_pairip:
        await _run_sh(f'su -c "rm -f \\"{tmp_pairip}\\""')
    # Remove the user's original .apks from Termux home
    for p in (apks_path,):
        if p:
            try:
                os.remove(p)
            except FileNotFoundError:
                pass


async def handle_pairip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Full Pairip pipeline triggered when the user sends a .apks bundle.

    Steps (mirrors PatchEngine.kt exactly):
      0  Find Java binary
      1  Download .apks from Telegram
      2  Read package name (extract base.apk → aapt)
      3  Pass 1 — Pairip.jar -i bundle.apks  → pairip_apk + merged_apk
      4  pm install pairip_apk via root
      5  Locate installed path (pm path)
      6  Swap original base.apk into installed slot (dd + chmod)
      7  Get system_server PID (mount namespace fix for pairip.json polling)
      8  setenforce 0 + launch app (monkey) → app writes pairip.json
      9  Poll for pairip.json across all candidate paths (90 s)
     10  Collect pairip.json, kill app
     11  Pass 2 — Pairip.jar -i merged_apk -t pairip.json → patched APK
     12  Upload patched APK to Telegram, cleanup
    """
    # Support being called from cmd_pairipx (reply to an .apks message)
    _ov      = _pairip_src_override.pop(update.effective_user.id, None)
    doc      = (_ov["doc"] if _ov else None) or update.message.document
    _src_msg_id = (_ov["source_msg_id"] if _ov else None) or update.message.message_id

    chat     = update.effective_chat.id
    user_uid = update.effective_user.id

    fname    = doc.file_name or "bundle.apks"
    total_b  = doc.file_size or 0
    total_mb = total_b / 1048576

    if total_mb > MAX_APK_MB:
        await update.message.reply_text(
            f"❌ Bundle is {total_mb:.0f} MB — limit is {MAX_APK_MB} MB\\.",
            parse_mode="MarkdownV2",
        )
        return

    # ── Per-user lock: ignore duplicate sends while already queued ──────────
    async with _queue_lock:
        already_busy = user_uid in _pairip_user_active
        if not already_busy:
            _pairip_user_active.add(user_uid)

    if already_busy:
        _pending_apks[user_uid] = {"update": update, "context": context}
        async with _queue_lock:
            pos = next(
                (i + 1 for i, e in enumerate(_pairip_wait_queue)
                 if e["uid"] == user_uid),
                None,
            )
        _pos_txt = f"\\#{pos} in the queue" if pos is not None else "processing"
        txt = (
            f"📥 *Got it\\! Your new bundle is saved\\.*\n\n"
            f"Your current Pairip job is still {_pos_txt}\\.\n"
            f"Once it finishes\\, your new one starts automatically — no need to resend\\."
        )
        await update.message.reply_text(txt, parse_mode="MarkdownV2")
        return

    # ── Daily limit ─────────────────────────────────────────────────────────
    if not is_admin(user_uid) and not is_premium(user_uid):
        used = get_daily_count(user_uid)
        if used >= PAIRIP_FREE_DAILY_LIMIT:
            async with _queue_lock:
                _pairip_user_active.discard(user_uid)
            kb_lim = InlineKeyboardMarkup([[
                InlineKeyboardButton("💎 Subscribe to Premium ✨", url=PREMIUM_CHANNEL)
            ]])
            await update.message.reply_text(
                f"🚫 *Daily Limit Reached*\n\n"
                f"🆓 Free users get *{PAIRIP_FREE_DAILY_LIMIT} Pairip jobs per day*\\.\n"
                f"You've used all {PAIRIP_FREE_DAILY_LIMIT} slots today\\.\n\n"
                f"⏰ Resets at midnight — or upgrade for *unlimited* access\\!",
                parse_mode="MarkdownV2",
                reply_markup=kb_lim,
            )
            return

    # ── FIFO queue gate ──────────────────────────────────────────────────────
    my_event = asyncio.Event()
    my_entry = {"uid": user_uid, "event": my_event, "queue_msg": None}
    queue_msg = None

    async with _queue_lock:
        _pairip_wait_queue.append(my_entry)
        queue_pos = len(_pairip_wait_queue)
        if queue_pos <= PAIRIP_MAX_CONCURRENT:
            my_event.set()

    # Initialise ALL cleanup vars before the try so finally always runs clean
    cancel     = asyncio.Event()
    _held_slot = False   # True only after we actually acquire a running slot
    apks_path  = None
    work_dir   = None
    pkg        = None
    pkg_lock   = None
    msg        = None
    tmp_pairip = None   # /data/local/tmp/pairip_<chat>.apk — set before pm install

    import time as _time_mod
    INACTIVITY_SECS   = 600
    ABSOLUTE_CAP_SECS = 2400   # 2 Java passes — allow 40 min max
    _last_activity    = [_time_mod.monotonic()]

    def _touch():
        _last_activity[0] = _time_mod.monotonic()

    async def _job_watchdog():
        start = _time_mod.monotonic()
        while True:
            await asyncio.sleep(30)
            if cancel.is_set():
                return
            elapsed  = _time_mod.monotonic() - start
            inactive = _time_mod.monotonic() - _last_activity[0]
            if elapsed >= ABSOLUTE_CAP_SECS:
                log.warning("Pairip watchdog: absolute cap hit chat=%s", chat)
                cancel.set(); return
            if inactive >= INACTIVITY_SECS:
                log.warning("Pairip watchdog: %ds inactivity chat=%s", inactive, chat)
                cancel.set(); return

    _watchdog_task = asyncio.create_task(_job_watchdog())

    try:
        # ── Queue position card ──────────────────────────────────────────────
        if queue_pos > PAIRIP_MAX_CONCURRENT:
            ahead = queue_pos - PAIRIP_MAX_CONCURRENT
            try:
                queue_msg = await update.message.reply_text(
                    f"⏳ *You're \\#{ahead} in the Pairip queue*\n\n"
                    f"{'1 job' if ahead == 1 else f'{ahead} jobs'} finishing before your turn\\.\n"
                    f"You'll start automatically — no need to resend\\.",
                    parse_mode="MarkdownV2",
                )
                async with _queue_lock:
                    my_entry["queue_msg"] = queue_msg
            except Exception as _qe:
                log.warning("Could not send pairip queue card: %s", _qe)

        # Register cancel flag NOW — before waiting — so Cancel button works while queued
        _cancel_flags[chat] = cancel

        # Race: queue slot vs Cancel button press — user can abort at any point
        _slot_t   = asyncio.create_task(my_event.wait())
        _cancel_t = asyncio.create_task(cancel.wait())
        await asyncio.wait({_slot_t, _cancel_t}, return_when=asyncio.FIRST_COMPLETED)
        _cancel_t.cancel()

        if cancel.is_set():
            # Cancelled while still queued — no slot was held, just show message and exit
            if queue_msg:
                try:
                    await queue_msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2")
                except Exception:
                    pass
            return

        # Slot acquired — mark as actively running
        _held_slot = True

        # ── Stage 0: Find Java + verify Pairip.jar ───────────────────────────
        kb_cancel = _cancel_kb(chat)
        if queue_msg:
            try:
                await queue_msg.edit_text(
                    "⚡ *Initialising engine\\.\\.\\.*",
                    parse_mode="MarkdownV2", reply_markup=kb_cancel,
                )
                msg = queue_msg
            except Exception:
                msg = None
        if msg is None:
            msg = await update.message.reply_text(
                "⚡ *Initialising engine\\.\\.\\.*",
                parse_mode="MarkdownV2", reply_markup=kb_cancel,
            )
        asyncio.create_task(_auto_delete(context.bot, chat, msg.message_id))

        java_bin = await _ensure_java(msg, kb_cancel)
        if not java_bin:
            await msg.edit_text(
                "❌ *Java 17 could not be installed*\n\n"
                "Automatic install via `pkg install openjdk-17` failed\\.\n\n"
                "Run this manually in Termux and retry:\n"
                "`pkg install openjdk-17 -y`",
                parse_mode="MarkdownV2",
            )
            return

        if not os.path.isfile(PAIRIP_JAR):
            await msg.edit_text(
                f"❌ *Pairip\\.jar not found*\n\n"
                f"Expected: `{_esc(PAIRIP_JAR)}`\n\n"
                f"Copy Pairip\\.jar to the Termux home directory and retry\\.",
                parse_mode="MarkdownV2",
            )
            return

        _touch()
        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        # ── Stage 1: Download .apks ──────────────────────────────────────────
        await msg.edit_text(
            f"📥 *Receiving bundle\\.\\.\\.*\n\n"
            f"`{_bar(0)}` 0%\n"
            f"📁 {_esc(fname)} • 0\\.0 \\/ {_mb(total_mb)} MB",
            parse_mode="MarkdownV2", reply_markup=kb_cancel,
        )

        apks_path = os.path.join(WORK_DIR, f"pairip_{chat}.apks")
        if total_b > BOT_API_LIMIT_B:
            await _download_large_pyro(
                msg, chat, _src_msg_id, apks_path, fname, total_b
            )
        else:
            try:
                await _download_with_progress(
                    msg, context.bot, doc.file_id, apks_path, fname, total_b
                )
            except Exception:
                tg_file = await context.bot.get_file(doc.file_id)
                await tg_file.download_to_drive(apks_path)

        _touch()
        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        await msg.edit_text(
            f"📥 *Bundle Received* ✅\n\n"
            f"`{_bar(100)}` 100%\n"
            f"📁 {_esc(fname)} • {_mb(total_mb)} MB",
            parse_mode="MarkdownV2",
        )
        gc.collect()
        await asyncio.sleep(0.6)

        # ── Stage 2: Read package name ───────────────────────────────────────
        await msg.edit_text(
            "🔬 *Reading bundle info\\.\\.\\.*",
            parse_mode="MarkdownV2", reply_markup=kb_cancel,
        )

        loop          = asyncio.get_event_loop()
        base_apk_tmp  = apks_path + ".base.apk"

        def _extract_base_apk():
            try:
                import zipfile as _zf
                with _zf.ZipFile(apks_path, "r") as z:
                    entries = [e for e in z.namelist() if e.lower().endswith(".apk")]
                    base_e  = next(
                        (e for e in entries
                         if os.path.basename(e).lower() == "base.apk"),
                        entries[0] if entries else None,
                    )
                    if not base_e:
                        return False
                    import shutil as _sh
                    with z.open(base_e) as src, open(base_apk_tmp, "wb") as dst:
                        _sh.copyfileobj(src, dst)
                return True
            except Exception as _e:
                log.warning("extract_base_apk failed: %s", _e)
                return False

        ok = await loop.run_in_executor(None, _extract_base_apk)
        if not ok:
            await msg.edit_text(
                "❌ *Invalid bundle*\n\n"
                "Could not find any APK inside the \\`.apks\\` file\\.\n"
                "Make sure you send a valid Split APK bundle\\.",
                parse_mode="MarkdownV2",
            )
            return

        pkg = await loop.run_in_executor(None, get_package_name, base_apk_tmp)
        try:
            os.remove(base_apk_tmp)
        except FileNotFoundError:
            pass

        if not pkg:
            await msg.edit_text(
                "❌ *Could not read package info*\\. Is it a valid APK bundle?",
                parse_mode="MarkdownV2",
            )
            return

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        # ── Per-package lock ─────────────────────────────────────────────────
        pkg_lock = await _acquire_pkg_lock(f"pairip_{pkg}")
        if pkg_lock.locked():
            await msg.edit_text(
                f"⚠️ *Same package detected*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"Another user is patching this exact package\\.\n"
                f"Waiting for them to finish\\.\\.\\.",
                parse_mode="MarkdownV2",
            )
        await pkg_lock.acquire()

        if cancel.is_set():
            pkg_lock.release()
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        # ── Work directory ───────────────────────────────────────────────────
        work_dir  = os.path.join(WORK_DIR, f"pairip_{chat}")
        pass1_dir = os.path.join(work_dir, "pass1")
        pass2_dir = os.path.join(work_dir, "pass2")
        await _run_sh(f'su -c "rm -rf \\"{work_dir}\\""', cancel=cancel)
        await _run_sh(
            f'su -c "mkdir -p \\"{pass1_dir}\\" \\"{pass2_dir}\\" && chmod 777 \\"{pass1_dir}\\" \\"{pass2_dir}\\""',
            cancel=cancel,
        )

        # ── Stage 3: Pass 1 ──────────────────────────────────────────────────
        stop1 = asyncio.Event()
        PASS1_FRAMES = [
            "🔍 Mapping guard layers\\.\\.\\.",
            "⚡ Neutralising verification hooks\\.\\.\\.",
            "🧬 Decoding protection signatures\\.\\.\\.",
            "🛠️ Forging bypass payload\\.\\.\\.",
        ]

        def pass1_frame(i):
            sp = SPIN[i % len(SPIN)]
            fr = PASS1_FRAMES[(i // 2) % len(PASS1_FRAMES)]
            return (
                f"🔓 *Cracking Protection* {sp}\n\n"
                f"📦 `{_esc(pkg)}`\n\n"
                f"{fr}"
            )

        anim1 = asyncio.create_task(
            _animate(msg, pass1_frame, stop1, reply_markup=kb_cancel)
        )

        # Clear any leftover install before Pass 1
        await _run_sh(
            f'su -c "pm uninstall {pkg} 2>/dev/null || true"', 30, cancel=cancel
        )

        rc1, out1 = await _run_pairip_jar(
            java_bin,
            f"-i '{apks_path}' -o '{pass1_dir}'",
            cancel, timeout=480,
        )
        _touch()
        stop1.set(); await anim1

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        pairip_apk, merged_apk = await loop.run_in_executor(
            None, _pick_pass1_apks, pass1_dir
        )

        if not pairip_apk or not merged_apk:
            log.error("Pass 1 no APK output for %s — log: %s", pkg, out1[:500])
            short = _esc(out1.strip()[-400:]) if out1.strip() else "\\(no output\\)"
            await msg.edit_text(
                f"❌ *Analysis Failed*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"Could not process this bundle\\.\n\n"
                f"📋 *Log:*\n`{short}`",
                parse_mode="MarkdownV2",
            )
            return

        # Log every APK produced by Pairip.jar so we can confirm the picker chose right
        try:
            _all_pass1 = sorted(
                f for f in os.listdir(pass1_dir) if f.lower().endswith(".apk")
            )
        except Exception:
            _all_pass1 = []
        log.info("Pass 1 APKs in dir: %s", _all_pass1)
        log.info("Pass 1 OK — pairip=%s  merged=%s",
                 os.path.basename(pairip_apk), os.path.basename(merged_apk))

        # ── Stage 4: Install pairip APK ──────────────────────────────────────
        await msg.edit_text(
            f"⚙️ *Deploying analysis agent\\.\\.\\.*\n\n"
            f"`{_esc(pkg)}`",
            parse_mode="MarkdownV2", reply_markup=kb_cancel,
        )

        tmp_pairip = f"/data/local/tmp/pairip_{chat}.apk"
        await _run_sh(f'su -c "cp \\"{pairip_apk}\\" {tmp_pairip} && chmod 644 {tmp_pairip}"', cancel=cancel)
        await _run_sh(f'su -c "pm uninstall {pkg} 2>/dev/null; true"', 30, cancel=cancel)
        await _run_sh(f'su -c "am force-stop {pkg} 2>/dev/null; true"', 10, cancel=cancel)

        # Root-cause (Android 16 + Magisk/KernelSU): after running a Java process as root,
        # the SELinux context of new su shells can degrade to u:r:shell:s0 instead of
        # u:r:su:s0, causing PackageManagerService to reject the Binder call with
        # "Failed transaction (2147483646)".
        #
        # Fix A: setenforce 0 → pm install → setenforce 1  (works on KernelSU LKM)
        # Fix B: su -mm (Magisk --mount-master flag) forces correct namespace + SELinux ctx
        # Fix C: session-based install-create/write/commit (different Binder path)

        # App source flags: pm install -r -t -d --bypass-low-target-sdk-block
        #   -t  allow test APKs  -d  allow downgrade  --bypass-low-target-sdk-block Android 14+
        # setenforce 0 fixes SELinux context degradation after Java process on Android 16

        async def _do_pm_install(apk: str) -> "tuple[int, str]":
            """Run pm install with all flags the app uses; return (rc, combined_out)."""
            await _run_sh('su -c "setenforce 0 2>/dev/null; true"', 5, cancel=cancel)
            rc, o, e = await _run_sh(
                f'su -c "pm install -r -t -d --bypass-low-target-sdk-block {apk} 2>&1"',
                180, cancel=cancel)
            out = (o + " " + e).strip()
            # Fallback without --bypass-low-target-sdk-block for older Android
            if "Unknown option" in out or ("error" in out.lower() and "Success" not in out):
                rc, o, e = await _run_sh(
                    f'su -c "pm install -r -t -d {apk} 2>&1"', 180, cancel=cancel)
                out = (o + " " + e).strip()
            await _run_sh('su -c "setenforce 1 2>/dev/null; true"', 5, cancel=cancel)
            return rc, out

        # Try 1: plain install with correct flags
        rc_inst, inst_out = await _do_pm_install(tmp_pairip)
        log.info("pairip install#1 rc=%d out=%r", rc_inst, inst_out[:300])

        # Try 2: su -mm (Magisk mount-master — correct SELinux namespace)
        if rc_inst != 0 and "Failed transaction" in inst_out:
            log.warning("Pairip install#1 Binder fail — trying su -mm")
            await _run_sh('su -c "setenforce 0 2>/dev/null; true"', 5, cancel=cancel)
            rc_inst, o, e = await _run_sh(
                f'su -mm -c "pm install -r -t -d --bypass-low-target-sdk-block {tmp_pairip} 2>&1"',
                180, cancel=cancel)
            inst_out = (o + " " + e).strip()
            await _run_sh('su -c "setenforce 1 2>/dev/null; true"', 5, cancel=cancel)
            log.info("pairip install#2 (su -mm) rc=%d out=%r", rc_inst, inst_out[:300])

        # Try 3: session-based install (different Binder path)
        if rc_inst != 0 and "Failed transaction" in inst_out:
            log.warning("Pairip install#2 Binder fail — trying session install")
            await asyncio.sleep(3)
            _, sz_out, _ = await _run_sh(f'su -c "wc -c < {tmp_pairip}"', 10, cancel=cancel)
            apk_size = sz_out.strip() or "0"
            await _run_sh('su -c "setenforce 0 2>/dev/null; true"', 5, cancel=cancel)
            _, sess_out, _ = await _run_sh(
                f'su -c "pm install-create -r -t -d -S {apk_size} 2>&1"', 30, cancel=cancel)
            m = re.search(r'\[(\d+)\]', sess_out)
            if m:
                sid = m.group(1)
                log.info("pairip session id=%s", sid)
                await _run_sh(
                    f'su -c "pm install-write -S {apk_size} {sid} base.apk {tmp_pairip} 2>&1"',
                    120, cancel=cancel)
                rc_inst, o, e = await _run_sh(
                    f'su -c "pm install-commit {sid} 2>&1"', 60, cancel=cancel)
                inst_out = (o + " " + e).strip()
                log.info("pairip install#3 (session) rc=%d out=%r", rc_inst, inst_out[:200])
            else:
                log.warning("pairip session-create got no ID: %r", sess_out[:200])
            await _run_sh('su -c "setenforce 1 2>/dev/null; true"', 5, cancel=cancel)

        await _run_sh(f'su -c "rm -f {tmp_pairip}"', cancel=cancel)
        _touch()

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        install_ok = "success" in inst_out.lower() or rc_inst == 0
        if not install_ok:
            short_err = _esc(inst_out[:400])
            await msg.edit_text(
                f"❌ *Agent deployment failed*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"📋 `{short_err}`\n\n"
                f"Ensure the device is unlocked and try again\\.",
                parse_mode="MarkdownV2",
            )
            return

        await asyncio.sleep(1.5)

        # ── Stage 5: Locate installed path ───────────────────────────────────
        await msg.edit_text(
            f"🎯 *Locking onto target\\.\\.\\.*\n\n"
            f"`{_esc(pkg)}`",
            parse_mode="MarkdownV2", reply_markup=kb_cancel,
        )

        # Keep SELinux permissive from here through to pairip.json collection.
        # The swap (dd to /data/app/…/base.apk) requires it; re-enable in cleanup.
        await _run_sh('su -c "setenforce 0 2>/dev/null; true"', 5, cancel=cancel)
        rc_path, pm_path_out, _ = await _run_sh(
            f"su -c \"pm path {pkg} 2>/dev/null | sed 's/^package://'\"",
            20, cancel=cancel,
        )
        installed_base = pm_path_out.strip()
        if not installed_base or not installed_base.startswith("/"):
            await msg.edit_text(
                f"❌ *Target not found*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"Could not locate the agent on device\\. Please try again\\.",
                parse_mode="MarkdownV2",
            )
            return

        installed_dir = os.path.dirname(installed_base)
        log.info("Pairip installed at: %s", installed_base)

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        # ── Stage 6: Swap original base.apk into installed slot ──────────────
        await msg.edit_text(
            f"🔬 *Loading protected binary\\.\\.\\.*\n\n"
            f"`{_esc(pkg)}`",
            parse_mode="MarkdownV2", reply_markup=kb_cancel,
        )

        # Extract base.apk from the .apks bundle into WORK_DIR (root can read it)
        swap_base_tmp = os.path.join(WORK_DIR, f"pairip_{chat}_base_swap.apk")

        def _extract_base_for_swap():
            try:
                import zipfile as _zf
                import shutil as _sh
                with _zf.ZipFile(apks_path, "r") as z:
                    entries = [e for e in z.namelist() if e.lower().endswith(".apk")]
                    base_e  = next(
                        (e for e in entries
                         if os.path.basename(e).lower() == "base.apk"),
                        entries[0] if entries else None,
                    )
                    if not base_e:
                        return False
                    with z.open(base_e) as src, open(swap_base_tmp, "wb") as dst:
                        _sh.copyfileobj(src, dst)
                return True
            except Exception as _e:
                log.warning("extract_base_for_swap failed: %s", _e)
                return False

        ok_swap = await loop.run_in_executor(None, _extract_base_for_swap)
        if not ok_swap:
            await msg.edit_text(
                "❌ *Could not extract base\\.apk from bundle for swap*",
                parse_mode="MarkdownV2",
            )
            return

        # Verify the swap source exists and has size > 0
        swap_size = os.path.getsize(swap_base_tmp) if os.path.isfile(swap_base_tmp) else 0
        log.info("pairip swap: source base.apk size=%d bytes", swap_size)

        swap_cmd = (
            f"mount -o remount,rw '{installed_dir}' 2>/dev/null || true && "
            f"dd if='{swap_base_tmp}' of='{installed_base}' bs=1048576 && "
            f"chmod 644 '{installed_base}' && "
            f"chown system:system '{installed_base}' 2>/dev/null || true && "
            f"sync"
        )
        rc_swap, _, err_swap = await _run_sh(
            f'su -c "{swap_cmd}"', 60, cancel=cancel
        )

        # Verify installed base.apk now matches expected size
        _, installed_sz_out, _ = await _run_sh(
            f"su -c \"wc -c < '{installed_base}' 2>/dev/null\"", 10, cancel=cancel
        )
        installed_sz = int(installed_sz_out.strip()) if installed_sz_out.strip().isdigit() else 0
        log.info("pairip swap: rc=%d installed_base size after=%d expected=%d err=%s",
                 rc_swap, installed_sz, swap_size, err_swap[:200])

        # Remove swap temp — no longer needed
        try:
            os.remove(swap_base_tmp)
        except FileNotFoundError:
            pass

        _touch()

        # FATAL — without the swap the installed slot has the bypass dex (not original),
        # pairip never initialises and pairip.json is never written.
        if rc_swap != 0 or (swap_size > 0 and abs(installed_sz - swap_size) > 1024):
            await msg.edit_text(
                f"❌ *base\\.apk swap failed*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"Could not write original base\\.apk into the installed slot \\(`rc={rc_swap}`\\)\\.\n"
                f"Source: `{swap_size // 1024} KB`  Installed: `{installed_sz // 1024} KB`\n\n"
                f"This is required for pairip to initialise\\. "
                f"Check that the device is unlocked and try again\\.",
                parse_mode="MarkdownV2",
            )
            return

        # Log installed dir so we can confirm oat/ state (mirrors PatchEngine.kt [DBG])
        _, dir_ls, _ = await _run_sh(
            f"su -c \"ls -la '{installed_dir}' 2>/dev/null\"", 10, cancel=cancel
        )
        log.info("pairip: installed dir after swap:\n%s", dir_ls[:500])

        # ── CRITICAL: restore libpairipcore.so into the installed lib dir ────────
        # Pass 1 produces _pairip.apk with libpairipcore.so INTACT (only Pass 2
        # strips it).  But extractNativeLibs behaviour or installd version may
        # leave lib/arm64-v8a/ incomplete.  Explicitly copy it from pairip_apk
        # (which is still on disk) as a safety net so System.loadLibrary succeeds.
        # NOTE: swap_base_tmp was already removed above — use pairip_apk instead.
        #
        # SELinux must be permissive BEFORE the dd write to /data/app — set it now.
        await _run_sh('su -c "setenforce 0 2>/dev/null || true"', 5, cancel=cancel)
        _pairip_so_tmp = os.path.join(WORK_DIR, f"pairip_{chat}_libpairipcore.so")
        _so_entry = None
        try:
            import zipfile as _zf2
            with _zf2.ZipFile(pairip_apk, "r") as _z2:
                _ents = _z2.namelist()
                _so_entry = next(
                    (e for e in _ents if e.endswith("libpairipcore.so")), None
                )
                if _so_entry:
                    with _z2.open(_so_entry) as _src2, open(_pairip_so_tmp, "wb") as _dst2:
                        _dst2.write(_src2.read())
                    log.info("pairip: extracted %s → %s (%d bytes)",
                             _so_entry, _pairip_so_tmp, os.path.getsize(_pairip_so_tmp))
                else:
                    _lib_ents = [e for e in _ents if "lib" in e.lower()]
                    log.warning("pairip: libpairipcore.so not found in base.apk; lib entries: %s",
                                _lib_ents[:20])
        except Exception as _ze:
            log.error("pairip: zip extract libpairipcore.so failed: %s", _ze)

        if _so_entry and os.path.exists(_pairip_so_tmp):
            # ABI subdir is the parent component of the zip entry: lib/<abi>/libpairipcore.so
            _abi = _so_entry.split("/")[-2]   # e.g. "arm64-v8a"
            _lib_dir = f"{installed_dir}/lib/{_abi}"
            _lib_dst = f"{_lib_dir}/libpairipcore.so"
            # Show what's currently in the ABI lib dir
            _, _lib_ls_before, _ = await _run_sh(
                f"su -c \"ls -la '{_lib_dir}/' 2>/dev/null || echo '(empty)'\"", 8, cancel=cancel
            )
            log.info("pairip: lib/%s before copy:\n%s", _abi, _lib_ls_before[:400])
            rc_so, _, err_so = await _run_sh(
                f"su -c \""
                f"mkdir -p '{_lib_dir}' && "
                f"chmod 755 '{_lib_dir}' && "
                f"chown system:system '{_lib_dir}' && "
                f"dd if='{_pairip_so_tmp}' of='{_lib_dst}' bs=1048576 && "
                f"chmod 755 '{_lib_dst}' && "
                f"chown system:system '{_lib_dst}' && "
                f"restorecon '{_lib_dst}' 2>/dev/null; "
                f"sync"
                f"\"",
                20, cancel=cancel,
            )
            log.info("pairip: libpairipcore.so → %s rc=%d err=%s",
                     _lib_dst, rc_so, err_so[:200])
        else:
            log.warning("pairip: libpairipcore.so not copied — see above for reason")

        # ── DO NOT run pm compile after the swap ─────────────────────────────
        # Manual process ground truth: MT Manager swaps base.apk then launches
        # immediately — no pm compile.  Here is why that works and why pm compile
        # BREAKS it:
        #
        #   _pairip.apk (Pass 1 output) contains InitContextProvider in its dex
        #   AND libpairipcore.so in lib/.  `pm install _pairip.apk` causes ART/
        #   installd to compile an OAT (base.odex + base.vdex) that includes
        #   InitContextProvider.
        #
        #   After the dd-swap the APK checksum changes, so ART falls back to the
        #   dex embedded in base.vdex — which is still the pairip-modified dex
        #   WITH InitContextProvider.  libpairipcore.so then reads the raw APK
        #   file directly (its own ZIP parser), so it sees the original code we
        #   swapped in and writes pairip.json.
        #
        #   If we call `pm compile -f` it regenerates BOTH vdex AND odex from the
        #   CURRENT base.apk (now the original — no pairip classes).  That DELETES
        #   InitContextProvider from the OAT → ClassNotFoundException → instant
        #   crash → pairip.json never written.
        #
        # Solution: leave the OAT files untouched.  Only apply restorecon on the
        # swapped base.apk so SELinux labels are correct on Android 12–16.
        await _run_sh(
            f"su -c \"restorecon '{installed_base}' 2>/dev/null || true\"",
            8, cancel=cancel,
        )
        log.info("pairip: OAT preserved (no pm compile) — restorecon applied")

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        # ── Stage 7: Get system_server PID (mount namespace fix) ─────────────
        # su -c spawns in the init mount namespace where /data/user/0/ is NOT
        # bind-mounted.  Accessing pairip.json via /proc/<sysPid>/root/data/...
        # uses system_server's namespace where user storage IS visible.
        _, ss_out, _ = await _run_sh(
            "su -c \""
            "pidof system_server 2>/dev/null || "
            "ps -A 2>/dev/null | grep system_server | awk '{print $2}' | head -1 || "
            "ps 2>/dev/null | grep system_server | awk '{print $2}' | head -1"
            "\"",
            10, cancel=cancel,
        )
        sys_pid = ss_out.strip().split()[0] if ss_out.strip() else ""
        log.info("system_server PID: %s", sys_pid or "NOT FOUND")

        # ── Stage 8: SELinux permissive + launch app ──────────────────────────
        await msg.edit_text(
            f"⚡ *Triggering extraction\\.\\.\\.*\n\n"
            f"`{_esc(pkg)}`\n\n"
            f"_Intercepting runtime keys — stand by\\.\\.\\._",
            parse_mode="MarkdownV2", reply_markup=kb_cancel,
        )

        await _run_sh('su -c "setenforce 0 2>/dev/null || true"', 5, cancel=cancel)

        # Wake screen + dismiss keyguard BEFORE launch.
        # On Android 12–16 monkey sends no events when the display is inactive —
        # the command returns exit:0 but the Activity never starts (pid stays '').
        # Matches the DEX pipeline pattern: screen_off_timeout=600000 + WAKEUP.
        await _run_sh(
            'su -c "'
            'settings put system screen_off_timeout 600000 2>/dev/null; '
            'input keyevent KEYCODE_WAKEUP 2>/dev/null; '
            'wm dismiss-keyguard 2>/dev/null || true; '
            'input keyevent KEYCODE_MENU 2>/dev/null || true'
            '"',
            10, cancel=cancel,
        )
        await asyncio.sleep(0.5)

        await _run_sh(f'su -c "am force-stop {pkg} 2>/dev/null"', 5, cancel=cancel)
        await asyncio.sleep(1)

        # ── Resolve launcher Activity then start with am start ────────────────
        # monkey is unreliable from a root shell on Android 12-16 — it fires the
        # intent but the process never gets a PID (Background Activity Launch
        # restrictions block it silently).  am start is the correct tool:
        # it runs inside the ActivityManagerService context, honours
        # --allow-background-activity-starts, and returns a meaningful exit code.
        #
        # Strategy:
        #   1. resolve the component via `cmd package resolve-activity`
        #   2. am start -n <component>  (most reliable path)
        #   3. fallback: am start -a MAIN -c LAUNCHER -p <pkg>
        _, _resolve_out, _ = await _run_sh(
            f'su -c "cmd package resolve-activity --brief'
            f' -c android.intent.category.LAUNCHER'
            f' -a android.intent.action.MAIN {pkg} 2>/dev/null | tail -1"',
            10, cancel=cancel,
        )
        _component = _resolve_out.strip()
        log.info("pairip launch: resolved component=%r", _component)

        if _component and "/" in _component and not _component.startswith("No activity"):
            _am_cmd = (
                f"am start -n '{_component}' 2>&1; echo exit:$?"
            )
        else:
            # Fallback: let am resolve MAIN/LAUNCHER itself
            _am_cmd = (
                f"am start"
                f" -a android.intent.action.MAIN"
                f" -c android.intent.category.LAUNCHER"
                f" -p {pkg} 2>&1; echo exit:$?"
            )

        _, _am_out, _ = await _run_sh(f'su -c "{_am_cmd}"', 15, cancel=cancel)
        log.info("pairip launch am start: %r", _am_out[:300])

        # Brief logcat snapshot to see any immediate crash reason
        await asyncio.sleep(1)
        _, _lc, _ = await _run_sh(
            f'su -c "logcat -d -t 40 --pid=$(pidof {pkg} 2>/dev/null | head -c 10)'
            f' *:E 2>/dev/null | tail -30"',
            8, cancel=cancel,
        )
        if _lc.strip():
            log.info("pairip logcat (errors, last 30 lines):\n%s", _lc[:800])

        # Push to background so the app's background services keep running
        await asyncio.sleep(0.5)
        await _run_sh('su -c "input keyevent KEYCODE_HOME 2>/dev/null"', 5, cancel=cancel)
        await _run_sh('su -c "input keyevent KEYCODE_WAKEUP 2>/dev/null"', 5, cancel=cancel)
        _touch()

        # ── Stage 9: Poll for pairip.json ─────────────────────────────────────
        poll_start         = _time_mod.monotonic()
        json_path          = None
        last_edit_t        = 0.0
        last_diag_t        = 0.0
        already_relaunched = False
        candidates         = _pairip_json_candidates(pkg, sys_pid)
        _last_pid          = ""   # track PID changes → app crash → dump logcat

        # Paths to ls for diagnostics (mirrors PatchEngine dataDiag)
        _diag_dirs = [
            f"/data/user/0/{pkg}",
            f"/data/data/{pkg}",
        ]
        if sys_pid:
            _diag_dirs = [
                f"/proc/{sys_pid}/root/data/user/0/{pkg}",
                f"/proc/{sys_pid}/root/data/data/{pkg}",
            ] + _diag_dirs

        while True:
            if cancel.is_set():
                break
            elapsed = int(_time_mod.monotonic() - poll_start)
            if elapsed >= PAIRIP_POLL_SECS:
                break

            now = _time_mod.monotonic()

            # Rate-limited message update (~every 5 s)
            if now - last_edit_t >= 5:
                try:
                    await msg.edit_text(
                        f"🔑 *Intercepting keys\\.\\.\\.*\n\n"
                        f"`{_esc(pkg)}`\n\n"
                        f"⏱ {elapsed}s elapsed",
                        parse_mode="MarkdownV2", reply_markup=kb_cancel,
                    )
                    last_edit_t = now
                except Exception:
                    pass

            # Data-dir snapshot every 20 s (mirrors PatchEngine dataDiag)
            if now - last_diag_t >= 20:
                last_diag_t = now
                for _dd in _diag_dirs:
                    _, _ls, _ = await _run_sh(
                        f"su -c \"ls '{_dd}/' 2>&1 | head -20\"", 5)
                    log.info("pairip diag [%ds] ls %s → %r", elapsed, _dd, _ls[:300])
                _, _dict_ls, _ = await _run_sh(
                    f"su -c \"ls '{_diag_dirs[0]}/dictionary/' 2>&1\"", 5)
                log.info("pairip diag [%ds] ls …/dictionary/ → %r", elapsed, _dict_ls[:300])
                _, _pid_out, _ = await _run_sh(
                    f"su -c \"pidof {pkg} 2>/dev/null\"", 5)
                _cur_pid = _pid_out.strip()
                log.info("pairip diag [%ds] app pid=%r", elapsed, _cur_pid)

                # PID changed → app crashed → dump pairip-tagged logcat to diagnose
                if _last_pid and _cur_pid != _last_pid:
                    log.info("pairip: PID changed %r→%r (app crashed/respawned) — capturing logcat",
                             _last_pid, _cur_pid)
                    _, _lc2, _ = await _run_sh(
                        f'su -c "logcat -d -b crash -b main -v brief'
                        f' pairipcore:V InitContextProvider:V'
                        f' AndroidRuntime:E art:E zygote:E'
                        f' DEBUG:V *:S 2>/dev/null | tail -60"',
                        10, cancel=cancel,
                    )
                    log.info("pairip logcat@crash:\n%s", _lc2[:2000] or "(empty)")
                    # Also search for any tombstone/crash file
                    _, _tomb, _ = await _run_sh(
                        f'su -c "ls -t /data/tombstones/ 2>/dev/null | head -3"',
                        5, cancel=cancel,
                    )
                    if _tomb.strip():
                        log.info("pairip tombstones: %s", _tomb.strip())
                        _, _t1, _ = await _run_sh(
                            f'su -c "head -40 /data/tombstones/{_tomb.splitlines()[0].strip()} 2>/dev/null"',
                            5, cancel=cancel,
                        )
                        log.info("pairip tombstone[0]:\n%s", _t1[:800])
                _last_pid = _cur_pid or _last_pid

            # Check every candidate path
            for candidate in candidates:
                rc_chk, chk_out, _ = await _run_sh(
                    f"su -c \"test -f '{candidate}' && echo 1 || echo 0\"",
                    timeout=5,
                )
                if chk_out.strip() == "1":
                    json_path = candidate
                    break

            if json_path:
                break

            # At 20 s: broad recursive find to catch any unexpected path
            if elapsed >= 20 and not already_relaunched:
                already_relaunched = True
                search_parts = []
                if sys_pid:
                    search_parts += [
                        f"/proc/{sys_pid}/root/data/user/0/{pkg}",
                        f"/proc/{sys_pid}/root/data/data/{pkg}",
                    ]
                search_parts += [f"/data/user/0/{pkg}", f"/data/data/{pkg}"]
                sp = " ".join(f"'{p}'" for p in search_parts)
                _, find_out, _ = await _run_sh(
                    f"su -c \"find {sp} -name '*.json' 2>/dev/null\"",
                    15, cancel=cancel,
                )
                log.info("pairip find *.json at %ds → %r", elapsed, find_out[:600])
                if "pairip.json" in find_out:
                    for line in find_out.splitlines():
                        if "pairip.json" in line.strip():
                            json_path = line.strip()
                            break
                    if json_path:
                        break
                # Do NOT re-launch — pairip native lib initialises during the FIRST
                # launch.  Re-launching kills a running pairip init and restarts from
                # scratch, resetting the timer.  Wait for the json from the first launch.

            await asyncio.sleep(2)

        _touch()

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        if not json_path:
            _, pc_out, _ = await _run_sh(
                f'su -c "pidof {pkg} 2>/dev/null"', 5
            )
            pid_str = _esc(pc_out.strip() or "DEAD")
            await msg.edit_text(
                f"❌ *Key extraction timed out*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"Waited {PAIRIP_POLL_SECS}s with no result\\.\n\n"
                f"Possible causes:\n"
                f"• App requires a screen tap to initialise\n"
                f"• App crashed before keys could be captured\n"
                f"• Keys written to an unexpected location",
                parse_mode="MarkdownV2",
            )
            return

        log.info("pairip.json found at: %s", json_path)

        # ── Stage 10: Collect pairip.json, kill app ───────────────────────────
        await msg.edit_text(
            f"📥 *Securing extracted keys\\.\\.\\.*\n\n"
            f"`{_esc(pkg)}`",
            parse_mode="MarkdownV2", reply_markup=kb_cancel,
        )

        local_json = os.path.join(work_dir, "pairip.json")
        await _run_sh(
            f"su -c \"dd if='{json_path}' of='{local_json}'"
            f" bs=1048576 && chmod 644 '{local_json}'\"",
            30, cancel=cancel,
        )
        await _run_sh(f'su -c "am force-stop {pkg}"', 5, cancel=cancel)

        if not os.path.isfile(local_json) or os.path.getsize(local_json) == 0:
            await msg.edit_text(
                "❌ *Key data lost*\n\n"
                "Keys were detected but could not be secured\\. Please try again\\.",
                parse_mode="MarkdownV2",
            )
            return

        log.info("pairip.json collected: %d bytes", os.path.getsize(local_json))
        _touch()

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        # ── Stage 11: Pass 2 ─────────────────────────────────────────────────
        stop2 = asyncio.Event()
        PASS2_FRAMES = [
            "🧬 Rewriting guard logic\\.\\.\\.",
            "🔓 Severing verification chains\\.\\.\\.",
            "✂️  Cutting protection threads\\.\\.\\.",
            "🛠️ Forging clean APK\\.\\.\\.",
        ]

        def pass2_frame(i):
            sp = SPIN[i % len(SPIN)]
            fr = PASS2_FRAMES[(i // 2) % len(PASS2_FRAMES)]
            return (
                f"⚡ *Applying Bypass* {sp}\n\n"
                f"📦 `{_esc(pkg)}`\n\n"
                f"{fr}"
            )

        anim2 = asyncio.create_task(
            _animate(msg, pass2_frame, stop2, reply_markup=kb_cancel)
        )

        rc2, out2 = await _run_pairip_jar(
            java_bin,
            f"-i '{merged_apk}' -t '{local_json}' -o '{pass2_dir}'",
            cancel, timeout=480,
        )
        _touch()
        stop2.set(); await anim2

        if cancel.is_set():
            await msg.edit_text("🚫 *Cancelled*", parse_mode="MarkdownV2"); return

        patched_apk = await loop.run_in_executor(
            None,
            lambda: (
                _find_apk_in_dir(pass2_dir, "patched")
                or _find_apk_in_dir(pass2_dir, None)
            ),
        )

        if not patched_apk:
            log.error("Pass 2 no APK output for %s — log: %s", pkg, out2[:500])
            short2 = _esc(out2.strip()[-400:]) if out2.strip() else "\\(no output\\)"
            await msg.edit_text(
                f"❌ *Bypass build failed*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"Could not produce the final clean APK\\.\n\n"
                f"📋 *Log:*\n`{short2}`",
                parse_mode="MarkdownV2",
            )
            return

        # ── Stage 12: Zip then upload ─────────────────────────────────────────
        patched_apk_name = f"{pkg}_pairipx_patched.apk"
        zip_name         = f"{pkg}_pairipx_patched.zip"
        zip_path         = os.path.join(pass2_dir, zip_name)

        # Wrap the patched APK in a zip so Telegram delivers it as a proper file
        import zipfile as _zf
        def _make_zip():
            with _zf.ZipFile(zip_path, "w", _zf.ZIP_DEFLATED) as _z:
                _z.write(patched_apk, patched_apk_name)
        await loop.run_in_executor(None, _make_zip)

        zip_mb = os.path.getsize(zip_path) / 1048576
        caption_md = (
            f"✅ **Done. Protection removed.**\n\n"
            f"`{pkg}`\n\n"
            f"💾 {zip_mb:.1f} MB  •  Guards stripped. Ready to sign & install.\n"
            f"🧹 Traces cleared."
        )

        await msg.edit_text(
            f"📤 *Delivering clean build\\.\\.\\.*\n\n"
            f"`{_bar(0)}` 0%\n"
            f"📦 {_esc(zip_name)} • 0\\.0 \\/ {_mb(zip_mb)} MB",
            parse_mode="MarkdownV2",
        )
        await _upload_large_pyro(
            chat, zip_path, zip_name, caption_md,
            status_msg=msg, zip_mb=zip_mb, cancel=cancel,
        )

        log.info("Pairip done — sent %s (%.1f MB) to chat %s",
                 zip_name, zip_mb, chat)

        if not is_admin(user_uid) and not is_premium(user_uid):
            increment_daily_count(user_uid)

        try:
            await msg.edit_text(
                f"✅ *Protection Stripped\\!*\n\n"
                f"`{_esc(pkg)}`\n\n"
                f"💾 {_mb(zip_mb)} MB — clean ZIP ready above ↑\n"
                f"🧹 All traces cleared\\.",
                parse_mode="MarkdownV2",
            )
        except Exception:
            pass

    except Exception as exc:
        log.exception("handle_pairip crashed for chat %s: %s", chat, exc)
        if msg:
            try:
                await msg.edit_text(
                    "❌ *Internal error*\n\nSomething went wrong\\. Please try again\\.",
                    parse_mode="MarkdownV2",
                )
            except Exception:
                pass

    finally:
        _watchdog_task.cancel()
        # Release per-package lock
        if pkg_lock and pkg_lock.locked():
            try:
                pkg_lock.release()
            except RuntimeError:
                pass
        # Always remove from queue and clear user-active — regardless of _held_slot
        async with _queue_lock:
            _pairip_wait_queue[:] = [
                e for e in _pairip_wait_queue if e["event"] is not my_event
            ]
            _pairip_user_active.discard(user_uid)
        _cancel_flags.pop(chat, None)
        if _held_slot:
            # Held a running slot — free it and wake the next waiter
            next_to_wake  = None
            still_waiting = []
            async with _queue_lock:
                for e in _pairip_wait_queue:
                    if not e["event"].is_set():
                        if next_to_wake is None:
                            next_to_wake = e
                        else:
                            still_waiting.append(e)
            if next_to_wake:
                next_to_wake["event"].set()
            for idx, entry in enumerate(still_waiting):
                qm = entry.get("queue_msg")
                if not qm:
                    continue
                new_pos = idx + 1
                try:
                    await qm.edit_text(
                        f"⏳ *You're \\#{new_pos} in the Pairip queue*\n\n"
                        f"{'1 job' if new_pos == 1 else f'{new_pos} jobs'}"
                        f" finishing before your turn\\.\n"
                        f"You'll start automatically — no need to resend\\.",
                        parse_mode="MarkdownV2",
                    )
                except Exception:
                    pass
            await _wipe_pairip(pkg, work_dir, apks_path, tmp_pairip)
            await asyncio.sleep(15)
            pending = _pending_apks.pop(user_uid, None)
            if pending:
                log.info("Auto-triggering pending .apks for user %s", user_uid)
                asyncio.create_task(
                    handle_pairip(pending["update"], pending["context"])
                )
        else:
            # Cancelled while queued — never held a slot, so don't free one or cooldown
            await _wipe_pairip(pkg, work_dir, apks_path, tmp_pairip)


async def cmd_pairipx(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /pairipx — must be sent as a reply to a .apks document message.
    Injects the replied-to document into _pairip_src_override and calls
    handle_pairip so the full pipeline runs against the correct file.
    """
    reply = update.message.reply_to_message if update.message else None

    if not reply or not reply.document:
        await update.message.reply_text(
            "━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🛡️ <b>𝗣𝗔𝗜𝗥𝗜𝗣 𝗫 — Google加固 𝗥𝗲𝗺𝗼𝘃𝗲𝗿</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "🚀 Strips <b>Google Play Integrity</b> / pairip protection from any "
            "<code>.apks</code> split-APK bundle — delivering a clean, unshielded APK.\n\n"
            "⚙️ <b>𝗛𝗼𝘄 𝗶𝘁 𝘄𝗼𝗿𝗸𝘀:</b>\n"
            "┣ Analyses the APKs on our server\n"
            "┣ Applies protection removal automatically\n"
            "┣ Ships you the <b>final patched APK</b> — no extra steps\n"
            "┗ Just <b>sign it</b> or kill signature verification, then install\n\n"
            "📌 <b>𝗛𝗼𝘄 𝘁𝗼 𝗨𝘀𝗲:</b>\n"
            "┣ 1. Send your <code>.apks</code> bundle to this chat\n"
            "┣ 2. <b>Reply</b> to that file message with <code>/pairipx</code>\n"
            "┗ The engine does everything automatically\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━",
            parse_mode="HTML",
        )
        return

    doc   = reply.document
    fname = (doc.file_name or "").lower()

    if not fname.endswith(".apks"):
        await update.message.reply_text(
            f"❌ That file is <code>{_html(doc.file_name or 'unknown')}</code>\n\n"
            "Please reply to a <code>.apks</code> Split APK bundle.",
            parse_mode="HTML",
        )
        return

    # Inject override so handle_pairip grabs the right document + message ID
    _pairip_src_override[update.effective_user.id] = {
        "doc":           doc,
        "source_msg_id": reply.message_id,
    }
    await handle_pairip(update, context)


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Router for incoming documents.
    .apks → hint to use /pairipx
    .apk  → DEX dump pipeline (handle_apk)
    other → ignored
    """
    doc = update.message.document if update.message else None
    if not doc:
        return
    fname = (doc.file_name or "").lower()
    if fname.endswith(".apks"):
        await update.message.reply_text(
            "📦 <b>Split APK bundle received!</b>\n\n"
            "Reply to this file with <code>/pairipx</code> to strip Pairip protection.",
            parse_mode="HTML",
        )
    elif fname.endswith(".apk"):
        await handle_apk(update, context)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if not BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set.")

    app = Application.builder().token(BOT_TOKEN).concurrent_updates(True).build()
    app.add_handler(CommandHandler("start",     cmd_start))
    app.add_handler(CommandHandler("status",    cmd_status))
    app.add_handler(CommandHandler("stats",     cmd_stats))
    app.add_handler(CommandHandler("broadcast", cmd_broadcast))
    app.add_handler(CommandHandler("addprem",   cmd_addprem))
    app.add_handler(CommandHandler("listprem",   cmd_listprem))
    app.add_handler(CommandHandler("listusers",  cmd_listusers))
    app.add_handler(CommandHandler("delprem",    cmd_delprem))
    app.add_handler(CommandHandler("checkprem", cmd_checkprem))
    app.add_handler(CommandHandler("pairipx",   cmd_pairipx))
    app.add_handler(CallbackQueryHandler(cb_usage,        pattern="^usage$"))
    app.add_handler(CallbackQueryHandler(handle_cancel_cb, pattern=r"^cancel_\d+$"))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.ALL, handle_other))

    # Background task: keep wake-lock alive + keep Termux:Boot registered
    async def _wake_lock_watcher():
        loop = asyncio.get_event_loop()
        last_boot_ping   = 0.0
        last_chrome_kill = 0.0
        last_stale_clean = 0.0

        # Ping Termux:Boot immediately at startup
        await loop.run_in_executor(None, _ping_termux_boot)

        # Stale-work cleanup immediately on startup
        await _cleanup_stale_work(max_age_hours=2.0)

        while True:
            await asyncio.sleep(300)  # check every 5 minutes

            # ── Page cache purge (always — even during active processing) ─
            # Drops file-system cache to reclaim RAM without touching swap.
            # Safe to run anytime — kernel re-caches on next read.
            try:
                await loop.run_in_executor(
                    None,
                    lambda: run("su -c 'echo 3 > /proc/sys/vm/drop_caches'", timeout=10),
                )
                mem_free = await loop.run_in_executor(
                    None,
                    lambda: run("awk '/MemFree/{print $2}' /proc/meminfo", timeout=5)[1].strip(),
                )
                log.info("Page cache purged — MemFree now %s kB", mem_free)
            except Exception as _pe:
                log.warning("Page cache purge failed: %s", _pe)

            # ── Stuck job counter recovery ────────────────────────────────
            # If tasks were destroyed without cleanup, _active_dex_jobs can
            # get stuck > 0 forever blocking all future installs.
            # Safe to reset when both queues are empty (nothing is running).
            if not _wait_queue and not _pairip_wait_queue and _active_dex_jobs > 0:
                log.warning(
                    "_active_dex_jobs stuck at %d with empty queues — resetting to 0",
                    _active_dex_jobs,
                )
                _active_dex_jobs = 0

            # ── Wake-lock check ───────────────────────────────────────────
            try:
                rc, out, _ = await loop.run_in_executor(
                    None,
                    lambda: run("dumpsys power 2>/dev/null | grep -i 'com.termux'", timeout=10),
                )
                is_active = rc == 0 and "com.termux" in out.lower()
            except Exception:
                is_active = False
            if not is_active:
                log.warning("Wake-lock dropped — re-enabling termux-wake-lock")
                await loop.run_in_executor(None, lambda: ensure_wake_lock(verbose=False))

            # ── Swap clear (only when idle — no dump running) ────────────
            # Reclaims swap that piled up from previous heavy jobs so the
            # next dump starts with a clean slate.
            if not _wait_queue:
                # ── Force-stop known RAM hogs when idle ───────────────────
                # These apps re-launch themselves when you actually open them,
                # so killing them in the background costs nothing.
                RAM_HOGS = [
                    "com.google.android.as",            # Google Assistant
                    "com.google.android.gm",            # Gmail
                    "com.google.android.googlequicksearchbox",
                    "com.liuzh.deviceinfo",
                    "com.google.android.apps.photos",
                    "com.logistics.rider.talabat",
                    "com.google.android.apps.tips",
                    "com.google.android.apps.wellbeing", # Digital Wellbeing — 389 MB
                    "com.android.vending",               # Play Store
                    "com.android.settings",              # Settings app
                ]
                # Each package gets its own su -c call — chaining many am
                # commands in one su invocation overflows the Binder buffer.
                _stopped = 0
                for _pkg in RAM_HOGS:
                    try:
                        await loop.run_in_executor(
                            None,
                            lambda p=_pkg: run(f"su -c 'am force-stop {p}'", timeout=10),
                        )
                        _stopped += 1
                    except Exception:
                        pass
                log.info("RAM hogs force-stopped (%d/%d apps)", _stopped, len(RAM_HOGS))

                # ── Swap clear ────────────────────────────────────────────
                try:
                    swap_line = await loop.run_in_executor(
                        None,
                        lambda: run("free -m | awk 'NR==3{print $3}'", timeout=5)[1].strip(),
                    )
                    swap_used_mb = int(swap_line) if swap_line.isdigit() else 0
                    if swap_used_mb > 512:   # only bother if >512 MB is in swap
                        log.info("Swap at %d MB — clearing (idle)", swap_used_mb)
                        await loop.run_in_executor(
                            None,
                            lambda: run(
                                r"su -c 'for s in $(awk \"NR>1{print \$1}\" /proc/swaps); do swapoff \"$s\" && swapon \"$s\"; done'",
                                timeout=60,
                            ),
                        )
                        log.info("Swap cleared")
                except Exception as _se:
                    log.warning("Swap clear failed: %s", _se)

            # ── Chrome: kill once every 24 hours (not every 10 min) ──────
            now = asyncio.get_event_loop().time()
            if now - last_chrome_kill >= 86400:  # 24 hours
                try:
                    await loop.run_in_executor(
                        None,
                        lambda: run("su -c 'am force-stop com.android.chrome'", timeout=10),
                    )
                    log.info("Chrome force-stopped (24-hour cycle)")
                except Exception as _ce:
                    log.warning("Chrome kill failed: %s", _ce)
                last_chrome_kill = now

            # ── Hourly stale-work cleanup ─────────────────────────────────
            if now - last_stale_clean >= 3600:  # every 1 hour
                await _cleanup_stale_work(max_age_hours=2.0)
                last_stale_clean = now

            # ── Daily Termux:Boot ping + boot log rotation ───────────────
            if now - last_boot_ping >= 86400:  # 24 hours
                await loop.run_in_executor(None, _ping_termux_boot)
                last_boot_ping = now

                # Rotate matrix_boot.log — keep only the last 50 lines
                boot_log = os.path.join(os.path.expanduser("~"), "matrix_boot.log")
                try:
                    if os.path.exists(boot_log):
                        with open(boot_log, "r") as _f:
                            lines = _f.readlines()
                        if len(lines) > 50:
                            with open(boot_log, "w") as _f:
                                _f.writelines(lines[-50:])
                            log.info("matrix_boot.log rotated — kept last 50 lines")
                except Exception as _e:
                    log.warning("boot log rotation failed: %s", _e)

                # ── Premium expiry reminders ──────────────────────────────
                try:
                    prem_db  = _prem_load()
                    now_u    = _dt.now(_tz.utc)
                    in_24h   = now_u + _td(hours=24)
                    changed  = False
                    for uid_s, entry in prem_db.items():
                        exp = entry.get("expires_at")
                        if not exp:
                            continue  # lifetime — skip
                        exp_dt = _dt.fromisoformat(exp)
                        if exp_dt <= now_u:
                            continue  # already expired
                        if exp_dt > in_24h:
                            continue  # more than 24h left
                        if entry.get("expiry_notified"):
                            continue  # already sent reminder
                        # Send the reminder
                        exp_str = exp_dt.strftime("%b %d, %Y %H:%M UTC")
                        try:
                            await app.bot.send_message(
                                int(uid_s),
                                f"⏰ *Premium Expiring Soon\\!*\n\n"
                                f"Your premium access expires on:\n"
                                f"`{_esc(exp_str)}`\n\n"
                                f"Renew now to keep unlimited dumps\\.",
                                parse_mode="MarkdownV2",
                            )
                            prem_db[uid_s]["expiry_notified"] = True
                            changed = True
                            log.info("Expiry reminder sent to uid=%s", uid_s)
                        except Exception as _ex:
                            log.warning("Could not send expiry reminder to %s: %s", uid_s, _ex)
                    if changed:
                        _prem_save(prem_db)
                except Exception as _e:
                    log.warning("Expiry reminder check failed: %s", _e)

    asyncio.get_event_loop().create_task(_wake_lock_watcher())

    log.info("@matrix_dumper_bot is running")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
