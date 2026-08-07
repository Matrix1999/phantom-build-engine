"""
dex_bridge.py - on-device DEX→C bridge for Dex2c -+-
Called via Chaquopy from Java.

KEY FORMAT  "Lcom/pkg/Cls;->methodName(Larg/Type;I)V"  — dexlib2 has NO spaces.
Androguard's get_descriptor() may have SPACES between params: "(Ljava/lang/String; I)V"

FIX: we build a lookup dict  (cls, name, desc_no_spaces) → EncodedMethod
     then look up each Java key by parsing it into components and stripping spaces.
     No regex. No format assumptions. Completely immune to space differences.

MULTI-DEX FIX (per-DEX compiler):
     invokecommon() in opcode_ins.py resolves the super-call class via
     ins.cm.get_method_ref(ins.BBBB). cm is the ConstantPool Manager of the
     *specific DEX owning that instruction*. If the Dex2C compiler's vm is from
     a different DEX, the index BBBB resolves against the wrong method table →
     wrong class descriptor (e.g. Build$VERSION instead of android/app/Activity).

     Fix: one DalvikVMFormat per DEX, all added to one shared Analysis for
     cross-DEX type info, and one Dex2C compiler per DEX keyed by id(vm_owner)
     so ins.cm always matches the right constant pool.

     Same fix applied to get_dex_methods() — previously single-DEX only, so
     method scanning for multi-DEX APKs would miss classes in secondary DEX files.
"""
import sys, os, logging, traceback, zipfile, io

logging.basicConfig(level=logging.WARNING)
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _debug_log(path, msg):
    """Append a line to a debug log file (best-effort, never raises)."""
    try:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(msg + '\n')
    except Exception:
        pass


def _load_dex_files(path, load_bytecode=True):
    """
    Load all DEX files from an APK or a single DEX file.

    Returns list of (name, DalvikVMFormat) tuples — one per DEX file.
    All are added to a single shared Analysis so cross-DEX type resolution works.

    load_bytecode=False — parse headers only (fast scan, no m.load()).
    load_bytecode=True  — force-load every method's bytecode (needed for
                          transpilation; only use after filtering so we can
                          call m.load() on selected methods only).
    """
    from androguard.core import androconf
    from androguard.core.bytecodes import dvm
    from androguard.util import read as ag_read

    kind = androconf.is_android(path)
    raw_list = []  # list of (name, bytes)

    if kind == 'APK':
        with zipfile.ZipFile(path, 'r') as zf:
            for name in sorted(n for n in zf.namelist()
                               if n.endswith('.dex') and '/' not in n):
                raw_list.append((name, zf.read(name)))
    elif kind in ('DEX', 'DEY'):
        raw_list.append((os.path.basename(path), ag_read(path)))
    else:
        raise ValueError('Not a DEX or APK: %s' % path)

    result = []
    for name, data in raw_list:
        print('Loading DEX: %s (%.1f KB)…' % (name, len(data) / 1024))
        sys.stdout.flush()
        vm = dvm.DalvikVMFormat(data)
        if load_bytecode:
            # Force-load every EncodedMethod BEFORE building Analysis.
            methods_list = list(vm.get_methods())
            print('  Indexing %d methods in %s…' % (len(methods_list), name))
            sys.stdout.flush()
            for i, m in enumerate(methods_list):
                try:
                    m.load()
                except Exception:
                    pass
                if (i + 1) % 5000 == 0:
                    print('  Indexed %d / %d…' % (i + 1, len(methods_list)))
                    sys.stdout.flush()
            print('  Done indexing %s' % name)
            sys.stdout.flush()
        result.append((name, vm))

    return result


def transpile_dex(dex_path, method_keys, output_dir):
    """
    Transpile selected DEX methods to C source files.

    Args:
        dex_path:    str - path to classes.dex OR path to the APK.
                     Passing the APK is preferred: all DEX files are loaded into
                     one shared Analysis so cross-DEX type info is complete AND
                     each DEX gets its own Dex2C compiler so ins.cm always
                     resolves against the right constant pool.
        method_keys: list of str - "Lcom/pkg/Cls;->methodName(sig)V" (no spaces — dexlib2 format)
        output_dir:  str - where to write .c files

    Returns:
        dict: {'compiled': {key: {'c_file': path, 'prototype': str}},
               'errors': [str], 'error': str or None}
    """
    log_path = os.path.join(output_dir, 'dex_bridge_debug.log')
    os.makedirs(output_dir, exist_ok=True)

    try:
        from androguard.core.analysis import analysis
        from dex2c.compiler import Dex2C
        from dex2c.util import JniLongName
    except Exception as e:
        return {'error': 'import_failed: ' + str(e), 'compiled': {}, 'errors': []}

    results = {}
    errors  = []

    # ── 1. Parse all DEX files ───────────────────────────────────────────────
    try:
        dex_list = _load_dex_files(dex_path)  # list of (name, DalvikVMFormat)

        # One shared Analysis for cross-DEX type resolution
        dx = analysis.Analysis()
        for _, vm in dex_list:
            dx.add(vm)

        # One Dex2C compiler per DEX — keyed by id(vm_owner) so ins.cm always
        # matches the right constant pool (fixes Build$VERSION / wrong-class bug)
        dex_to_compiler = {}
        for _, vm in dex_list:
            dex_to_compiler[id(vm)] = Dex2C(vm, dx, obfus=True, dynamic_register=True)

    except Exception as e:
        return {'error': 'parse_failed: ' + str(e) + '\n' + traceback.format_exc(),
                'compiled': {}, 'errors': []}

    # ── 2. Build lookup dict across ALL DEX files ────────────────────────────
    # Key = (class_name, method_name, descriptor_NO_spaces)
    method_lookup = {}  # key → (DalvikVMFormat owner, EncodedMethod)
    for _, vm in dex_list:
        for m in vm.get_methods():
            try:
                cls  = m.get_class_name()
                name = m.get_name()
                desc = m.get_descriptor().replace(' ', '')
                method_lookup[(cls, name, desc)] = (vm, m)
            except Exception as e:
                errors.append('lookup_err: ' + str(e))

    _debug_log(log_path, 'Input: ' + dex_path)
    _debug_log(log_path, 'DEX files loaded: ' + str(len(dex_list)))
    _debug_log(log_path, 'Methods in lookup: ' + str(len(method_lookup)))
    _debug_log(log_path, 'Java keys requested: ' + str(len(method_keys) if method_keys else 0))

    # Log first 5 Java keys and first 5 Python keys for diagnosis
    if method_keys:
        for k in list(method_keys)[:5]:
            _debug_log(log_path, 'JAVA_KEY: ' + k)
    sample_keys = [('%s->%s%s' % (c, n, d)) for (c, n, d) in list(method_lookup.keys())[:5]]
    for k in sample_keys:
        _debug_log(log_path, 'PY_KEY:   ' + k)

    # ── 3. Compile each requested method ────────────────────────────────────
    key_list = list(method_keys) if method_keys else []
    compile_all = not key_list   # empty list = compile everything
    _total_to_compile = len(key_list) if not compile_all else len(method_lookup)
    _done = 0
    print('Compiling %d method(s) to C++…' % _total_to_compile)
    sys.stdout.flush()

    for java_key in (key_list if not compile_all else ['__all__']):
        if compile_all:
            targets = [(cls + '->' + name + desc, vm, method)
                       for (cls, name, desc), (vm, method) in method_lookup.items()]
        else:
            # Parse java_key into (cls, name, desc)
            try:
                arrow = java_key.index('->')
                cls   = java_key[:arrow]
                rest  = java_key[arrow + 2:]
                paren = rest.index('(')
                name  = rest[:paren]
                desc  = rest[paren:]              # already no spaces (dexlib2 format)
            except Exception as pe:
                errors.append('key_parse_err: ' + java_key + ': ' + str(pe))
                continue

            entry = method_lookup.get((cls, name, desc))
            if entry is None:
                errors.append('not_found: ' + java_key)
                _debug_log(log_path, 'NOT_FOUND: ' + java_key)
                continue
            vm, method = entry
            targets = [(cls + '->' + name + desc, vm, method)]

        for key, vm, method in targets:
            try:
                # Skip abstract / native / no-code
                flags = method.get_access_flags()
                if flags & 0x400 or flags & 0x100:
                    if not compile_all:
                        errors.append('skip_flags: ' + key)
                    continue
                if not method.get_code():
                    if not compile_all:
                        errors.append('skip_nocode: ' + key)
                    continue

                # Rebuild proper key for output
                out_cls  = method.get_class_name()
                out_name = method.get_name()
                out_desc = method.get_descriptor().replace(' ', '')

                # ART forbids native constructors — skip <init> entirely so
                # JNI_OnLoad never tries to RegisterNatives for a constructor.
                if out_name == '<init>':
                    continue
                out_key  = out_cls + '->' + out_name + out_desc

                jni_name = JniLongName(out_cls, out_name, out_desc)
                if len(jni_name) > 220:
                    continue

                # Use the compiler for THIS method's DEX (per-DEX compiler fix)
                compiler = dex_to_compiler.get(id(vm))
                if compiler is None:
                    errors.append('no_compiler: ' + out_key)
                    continue

                try:
                    code_tuple = compiler.get_source_method(method)
                except Exception as ce:
                    errors.append('dcc_exception: ' + out_key + ': ' + str(ce))
                    _debug_log(log_path, 'DCC_EXC: ' + out_key + ': ' + str(ce))
                    continue

                c_source  = code_tuple[0] if code_tuple else None
                prototype = code_tuple[1] if code_tuple and len(code_tuple) > 1 else ''
                irmethod  = code_tuple[2] if code_tuple and len(code_tuple) > 2 else None

                if not c_source:
                    errors.append('dcc_nosource: ' + out_key)
                    _debug_log(log_path, 'NOSOURCE: ' + out_key)
                    continue

                safe_name  = jni_name[:180]
                out_file   = os.path.join(output_dir, safe_name + '.cpp')
                vm_success = False

                # ── Try VM compilation: hides method body inside AES-256-CBC ──
                # If eligible, the entire method body is replaced by an opaque
                # lvm_method_exec() call. Ghidra sees only argument packing and
                # a single interpreter dispatch — zero ARM64 method logic.
                if irmethod is not None:
                    try:
                        from dex2c.vm_writer import VmMethodCompiler
                        vm_comp = VmMethodCompiler()
                        if vm_comp.can_compile(irmethod):
                            sym_prefix = ('VM_' + safe_name[:60]).upper().replace('-', '_').replace('.', '_')
                            bytecode   = vm_comp.compile(irmethod)
                            vm_proto   = vm_comp.generate_prototype(irmethod, jni_name)
                            shell_cpp  = vm_comp.generate_shell(irmethod, jni_name, bytecode, sym_prefix)
                            with open(out_file, 'w', encoding='utf-8') as fp:
                                fp.write('#include "Dex2C.h"\n')
                                fp.write(shell_cpp)
                            prototype  = vm_proto
                            vm_success = True
                            _debug_log(log_path, 'VM_OK (%d bytes): ' % len(bytecode) + out_key)
                    except Exception as vm_err:
                        _debug_log(log_path, 'VM_FALLBACK: ' + out_key + ': ' + str(vm_err))

                # ── Fallback: standard dex2c C++ output ───────────────────────
                if not vm_success:
                    with open(out_file, 'w', encoding='utf-8') as fp:
                        fp.write('#include "Dex2C.h"\n')
                        fp.write(c_source)

                results[out_key] = {
                    'c_file':      out_file,
                    'prototype':   prototype or '',
                    'jni_name':    jni_name,
                    'cls':         out_cls,
                    'method_name': out_name,
                    'desc':        out_desc,
                    'vm_protected': vm_success,
                }
                _done += 1
                if _done % 10 == 0 or _done == _total_to_compile:
                    print('  Compiled %d / %d…' % (_done, _total_to_compile))
                    sys.stdout.flush()
                _debug_log(log_path, 'OK: ' + out_key)

            except Exception as e:
                errors.append('method_exc: ' + traceback.format_exc()[:300])

    _debug_log(log_path, 'Compiled: ' + str(len(results)) + '  Errors: ' + str(len(errors)))
    return {'compiled': results, 'errors': errors, 'error': None}


def get_dex_methods(dex_path):
    """
    List all non-abstract, non-native methods in a DEX file or APK.

    APK-aware: scans ALL DEX files (classes.dex, classes2.dex, …) so
    multi-DEX apps don't silently miss methods in secondary DEX files.

    Returns list of method key strings (no spaces — matches dexlib2 format).
    """
    try:
        dex_list = _load_dex_files(dex_path)
    except Exception as e:
        return {'error': str(e), 'methods': []}

    methods = []
    for dex_name, vm in dex_list:
        all_m = list(vm.get_methods())
        print('Scanning %s (%d methods)…' % (dex_name, len(all_m)))
        sys.stdout.flush()
        for m in all_m:
            try:
                flags = m.get_access_flags()
                if flags & 0x400 or flags & 0x100:
                    continue
                if not m.get_code():
                    continue
                cls  = m.get_class_name()
                name = m.get_name()
                if name == '<init>':
                    continue
                desc = m.get_descriptor().replace(' ', '')
                methods.append(cls + '->' + name + desc)
            except Exception:
                pass
        print('Scan complete — %d eligible methods so far' % len(methods))
        sys.stdout.flush()

    return {'methods': methods, 'error': None}


if __name__ == '__main__':
    import argparse, json

    parser = argparse.ArgumentParser(description='Dex2c bridge: transpile DEX methods to C')
    parser.add_argument('--apk',    required=True,  help='Path to input APK or DEX file')
    parser.add_argument('--filter', required=True,  help='Path to filter file (class names, one per line)')
    parser.add_argument('--outdir', required=True,  help='Directory to write .c output files')
    parser.add_argument('--result', required=True,  help='Path to write JSON result file')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    log_path = os.path.join(args.outdir, 'dex_bridge_debug.log')

    # ── 1. Read filter file ───────────────────────────────────────────────────
    with open(args.filter, 'r', encoding='utf-8') as _f:
        _lines = [_l.strip() for _l in _f if _l.strip()]

    _filter_classes = set()   # DEX class descriptors  e.g. "Lcom/example/Foo;"
    _filter_methods = set()   # exact dex_keys          e.g. "Lcom/example/Foo;->bar(I)V"

    for _line in _lines:
        _semi = _line.find(';')
        if _semi != -1 and _semi < len(_line) - 1:
            _cls_part    = _line[:_semi]
            _method_part = _line[_semi + 1:]
            _dex_key     = 'L' + _cls_part + ';->' + _method_part
            _filter_methods.add(_dex_key)
        else:
            _n = _line.rstrip(';')
            if _n.startswith('L'):
                _n = _n[1:]
            _filter_classes.add('L' + _n.replace('.', '/') + ';')

    _has_filter = bool(_filter_classes or _filter_methods)
    print('dex_bridge.py loaded OK')
    print('Filter classes: %d  Filter methods: %d' % (len(_filter_classes), len(_filter_methods)))

    # Build unified set of target class descriptors (from both filter sets).
    _target_cls_set = set(_filter_classes)
    for _mk in _filter_methods:
        _target_cls_set.add(_mk.split('->')[0])   # "Lcom/example/Foo;"

    # Pre-encode each descriptor to bytes for fast raw search.
    _target_cls_bytes = [_d.encode('utf-8') for _d in _target_cls_set]

    # ── 2. Raw bytes pre-filter — no androguard yet ───────────────────────────
    # Read each DEX entry from the APK as raw bytes and search for the target
    # class descriptor strings BEFORE calling dvm.DalvikVMFormat().
    # Searching 26 MB of bytes takes ~0.1 s; parsing with androguard takes 59 s.
    # Non-target DEX files are dropped entirely — no Analysis, no compiler, no cost.
    from androguard.core.bytecodes import dvm as _dvm
    from androguard.core.analysis import analysis as _ag_analysis
    from dex2c.compiler import Dex2C as _Dex2C
    from dex2c.util import JniLongName as _JniLongName

    _raw_target = []   # (dex_name, raw_bytes) for DEX files that contain target classes
    _n_total    = 0

    with zipfile.ZipFile(args.apk, 'r') as _zf:
        _dex_names = sorted(n for n in _zf.namelist()
                            if n.endswith('.dex') and '/' not in n)
        _n_total = len(_dex_names)
        for _dname in _dex_names:
            _data = _zf.read(_dname)
            if _has_filter:
                if not any(_cb in _data for _cb in _target_cls_bytes):
                    print('Skip %s (%.0f KB) — target classes absent' % (_dname, len(_data) / 1024))
                    sys.stdout.flush()
                    continue
            print('Target DEX: %s (%.0f KB)' % (_dname, len(_data) / 1024))
            sys.stdout.flush()
            _raw_target.append((_dname, _data))

    print('DEX to parse: %d / %d' % (len(_raw_target), _n_total))
    sys.stdout.flush()

    # ── 3. Parse ONLY the target DEX files with androguard ───────────────────
    _dex_list = []
    for _dname, _data in _raw_target:
        print('Parsing %s…' % _dname)
        sys.stdout.flush()
        _vm = _dvm.DalvikVMFormat(_data)
        _dex_list.append((_dname, _vm))

    # ── 4. Scan methods — no m.load() yet ────────────────────────────────────
    _selected_triples = []   # (vm, EncodedMethod, dex_key)
    _total_scanned    = 0

    for _dex_name, _vm in _dex_list:
        _all_m = list(_vm.get_methods())
        print('Scanning %s (%d methods)…' % (_dex_name, len(_all_m)))
        sys.stdout.flush()
        _total_scanned += len(_all_m)
        for _m in _all_m:
            try:
                _flags = _m.get_access_flags()
                if _flags & 0x400 or _flags & 0x100:   # abstract | native
                    continue
                _cls  = _m.get_class_name()
                _name = _m.get_name()
                if _name == '<init>':
                    continue
                _desc = _m.get_descriptor().replace(' ', '')
                _key  = _cls + '->' + _name + _desc
                if _has_filter and _cls not in _filter_classes and _key not in _filter_methods:
                    continue
                _selected_triples.append((_vm, _m, _key))
            except Exception:
                pass

    print('Total methods scanned: %d  After filter: %d' % (_total_scanned, len(_selected_triples)))
    sys.stdout.flush()

    # Diagnostic: nothing matched
    if _has_filter and not _selected_triples:
        _sample_cls = sorted(set(
            _c.get_name()
            for _, _vm in _dex_list
            for _c in _vm.get_classes()
        ))
        print('DIAG filter sample : %s' % list(_target_cls_set)[:5])
        print('DIAG dex cls sample: %s' % _sample_cls[:5])
        _lower_map = {_c.lower(): _c for _c in _sample_cls}
        for _fc in list(_target_cls_set)[:5]:
            _hit = _lower_map.get(_fc.lower())
            if _hit:
                print('DIAG case mismatch: filter=%r  dex=%r' % (_fc, _hit))
        _out = {'success': 0, 'methods': [], 'errors': ['no methods matched filter']}
        with open(args.result, 'w', encoding='utf-8') as _f:
            json.dump(_out, _f)
        sys.exit(0)

    # ── 5. m.load() ONLY the selected methods — not the entire DEX ───────────
    print('Loading bytecode for %d selected method(s)…' % len(_selected_triples))
    sys.stdout.flush()
    for _, _m, _ in _selected_triples:
        try:
            _m.load()
        except Exception:
            pass

    # ── 6. Build Analysis + per-DEX compilers (target DEX only) ──────────────
    _dx = _ag_analysis.Analysis()
    for _, _vm in _dex_list:
        _dx.add(_vm)

    _dex_to_compiler = {}
    for _, _vm in _dex_list:
        _dex_to_compiler[id(_vm)] = _Dex2C(_vm, _dx, obfus=True, dynamic_register=True)

    # ── 7. Compile each selected method ───────────────────────────────────────
    _compiled = {}
    _errors   = []

    print('Compiling %d method(s) to C++…' % len(_selected_triples))
    sys.stdout.flush()

    for _i, (_vm, _method, _key) in enumerate(_selected_triples):
        try:
            _out_cls  = _method.get_class_name()
            _out_name = _method.get_name()
            _out_desc = _method.get_descriptor().replace(' ', '')
            _out_key  = _out_cls + '->' + _out_name + _out_desc

            _jni_name = _JniLongName(_out_cls, _out_name, _out_desc)
            if len(_jni_name) > 220:
                continue

            if not _method.get_code():
                _errors.append('skip_nocode: ' + _out_key)
                continue

            _compiler = _dex_to_compiler.get(id(_vm))
            if _compiler is None:
                _errors.append('no_compiler: ' + _out_key)
                continue

            try:
                _code_tuple = _compiler.get_source_method(_method)
            except Exception as _ce:
                _errors.append('dcc_exception: ' + _out_key + ': ' + str(_ce))
                _debug_log(log_path, 'DCC_EXC: ' + _out_key + ': ' + str(_ce))
                continue

            _c_source  = _code_tuple[0] if _code_tuple else None
            _prototype = _code_tuple[1] if _code_tuple and len(_code_tuple) > 1 else ''
            _irmethod  = _code_tuple[2] if _code_tuple and len(_code_tuple) > 2 else None

            if not _c_source:
                _errors.append('dcc_nosource: ' + _out_key)
                continue

            _safe_name  = _jni_name[:180]
            _out_file   = os.path.join(args.outdir, _safe_name + '.cpp')
            _vm_success = False

            # ── Try VM compilation ──────────────────────────────────────
            if _irmethod is not None:
                try:
                    from dex2c.vm_writer import VmMethodCompiler
                    _vm_comp = VmMethodCompiler()
                    if _vm_comp.can_compile(_irmethod):
                        _sym_prefix = ('VM_' + _safe_name[:60]).upper().replace('-', '_').replace('.', '_')
                        _bytecode   = _vm_comp.compile(_irmethod)
                        _vm_proto   = _vm_comp.generate_prototype(_irmethod, _jni_name)
                        _shell_cpp  = _vm_comp.generate_shell(_irmethod, _jni_name, _bytecode, _sym_prefix)
                        with open(_out_file, 'w', encoding='utf-8') as _fp:
                            _fp.write('#include "Dex2C.h"\n')
                            _fp.write(_shell_cpp)
                        _prototype  = _vm_proto
                        _vm_success = True
                        _debug_log(log_path, 'VM_OK (%d bytes): ' % len(_bytecode) + _out_key)
                except Exception as _vm_err:
                    _debug_log(log_path, 'VM_FALLBACK: ' + _out_key + ': ' + str(_vm_err))

            # ── Fallback: standard dex2c output ────────────────────────
            if not _vm_success:
                with open(_out_file, 'w', encoding='utf-8') as _fp:
                    _fp.write('#include "Dex2C.h"\n')
                    _fp.write(_c_source)

            _compiled[_out_key] = {
                'c_file':      _out_file,
                'prototype':   _prototype or '',
                'jni_name':    _jni_name,
                'cls':         _out_cls,
                'method_name': _out_name,
                'desc':        _out_desc,
                'vm_protected': _vm_success,
            }
            _debug_log(log_path, 'OK: ' + _out_key)

        except Exception:
            _errors.append('method_exc: ' + traceback.format_exc()[:300])

    # ── 5. Write jni_onload.cpp ───────────────────────────────────────────────
    # NdkBuilder scans sourceDir for "jni_onload.cpp". When found → hasJniOnload=true:
    #   • uses fonts_jniload_prebuilt.o  (no JNI_OnLoad — avoids duplicate symbol)
    #   • adds -DD2C_HAS_JNILOAD so Dex2C_impl.cpp exposes d2c_init_runtime instead
    #   • patchJniOnload() injects classloader capture + fonts_register_natives(env)
    # Without this file → fonts_nojniload_prebuilt.o AND Dex2C_impl.cpp both define
    # JNI_OnLoad → duplicate symbol linker error.
    _jni_onload = os.path.join(args.outdir, 'jni_onload.cpp')
    with open(_jni_onload, 'w', encoding='utf-8') as _f:
        _f.write(
            '#include "Dex2C.h"\n'
            '#include "DynamicRegister.h"\n'
            '\n'
            'extern "C" void d2c_init_runtime(JNIEnv *env);\n'
            '\n'
            'JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {\n'
            '    JNIEnv *env = nullptr;\n'
            '    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {\n'
            '        return JNI_ERR;\n'
            '    }\n'
            '    d2c_init_runtime(env);\n'
            '    const char *err = dynamic_register_compile_methods(env);\n'
            '    if (err) {\n'
            '        return JNI_ERR;\n'
            '    }\n'
            '    return JNI_VERSION_1_6;\n'
            '}\n'
        )
    print('dex_bridge.py: wrote jni_onload.cpp')

    # ── 6. Write DynamicRegister.cpp ─────────────────────────────────────────
    # This file DEFINES dynamic_register_compile_methods(JNIEnv*) — called from
    # jni_onload.cpp to RegisterNatives for every transpiled method.
    # Template mirrors dcc.py's generate_dynamic_register_code() exactly.
    _export_list = {}   # class_path (e.g. "com/example/Foo") → list of (name, desc, jni_name, prototype)
    for _dex_key, _info in _compiled.items():
        _raw_cls = _info['cls']                          # "Lcom/example/Foo;"
        _class_path = _raw_cls[1:-1]                     # "com/example/Foo"
        _entry = (
            _info['method_name'],                        # short name  e.g. "bar"
            _info['desc'],                               # JNI descriptor e.g. "(I)V"
            _info['jni_name'],                           # JNI long name e.g. "Java_com_example_Foo_bar"
            _info['prototype'],                          # full prototype for extern decl
        )
        _export_list.setdefault(_class_path, []).append(_entry)

    _dynreg_lines = ['#include "DynamicRegister.h"\n']

    # extern declarations
    for _class_path in sorted(_export_list):
        for _m in _export_list[_class_path]:
            _proto = _m[3].strip()
            if _proto:
                _dynreg_lines.append('extern %s;\n' % _proto)

    _dynreg_lines.append('\nconst char *dynamic_register_compile_methods(JNIEnv *env) {\n')
    _dynreg_lines.append('    jclass clazz;\n')

    for _idx, _class_path in enumerate(sorted(_export_list)):
        _methods = _export_list[_class_path]
        _dynreg_lines.append(
            '    clazz = env->FindClass("%s");\n'
            '    if (clazz == nullptr)\n'
            '        return "Class not found: %s";\n'
            % (_class_path, _class_path)
        )
        _entries = ',\n        '.join(
            '{"%s", "%s", (void *)%s}' % (_m[0], _m[1], _m[2])
            for _m in _methods
        )
        _dynreg_lines.append(
            '    const JNINativeMethod export_method_%d[] = {\n        %s\n    };\n'
            % (_idx, _entries)
        )
        _dynreg_lines.append(
            '    env->RegisterNatives(clazz, export_method_%d, %d);\n'
            '    env->DeleteLocalRef(clazz);\n'
            % (_idx, len(_methods))
        )

    _dynreg_lines.append('    return nullptr;\n}\n')

    _dynreg_path = os.path.join(args.outdir, 'DynamicRegister.cpp')
    with open(_dynreg_path, 'w', encoding='utf-8') as _f:
        _f.writelines(_dynreg_lines)
    print('dex_bridge.py: wrote DynamicRegister.cpp (%d class(es))' % len(_export_list))

    # ── 7. Build result JSON ──────────────────────────────────────────────────
    # Java expects: {"success": N, "methods": [{"dex_key": "...", "file": "foo.cpp"}], "errors": [...]}
    # jni_onload.cpp is NOT listed here — NdkBuilder picks it up via listFiles().
    _methods_list = []
    for _dex_key, _info in _compiled.items():
        _fname = os.path.basename(_info['c_file'])
        _methods_list.append({'dex_key': _dex_key, 'file': _fname})

    _result_json = {
        'success': len(_methods_list),
        'methods': _methods_list,
        'errors':  _errors,
    }

    with open(args.result, 'w', encoding='utf-8') as _f:
        json.dump(_result_json, _f, indent=2)

    print('dex_bridge.py: compiled %d method(s), %d error(s)' % (len(_methods_list), len(_errors)))
