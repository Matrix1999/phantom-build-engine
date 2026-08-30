package com.ultra.dex2cvmp.engine.vmp.converter;

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.util.MethodUtil;
import com.ultra.dex2cvmp.engine.AesCrypto;
import com.ultra.dex2cvmp.engine.vmp.util.ModifiedUtf8;

import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UTFDataFormatException;
import java.io.Writer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * 根据dex生成符号解析代码,比如字符串常量池,类型常量池这些
 */

public class ResolverCodeGenerator {

    private final References references;

    // Encryption context — populated by generateStringPool(), consumed by generateResolver()
    private byte[] _vmpXorKey;
    private byte[] _vmpCc20Key;
    private byte[] _vmpNonce;
    private int    _vmpBlobSize;
    // 8 independent gates — each masks 4 bytes of _vbs_ck (all 32 bytes gate-protected)
    private int[][] _vmpGc;  // [8][5] gate constants
    private int[]   _vmpGv;  // [8]   gate output values (computed at build time)
    // HI/LO splits for .rodata arrays — no single array is the real key material
    private byte[] _vmpCkHi, _vmpCkLo;   // _vbs_ck = HI ^ LO (32 bytes each)
    private byte[] _vmpX0Hi, _vmpX0Lo;   // _vbs_x0 = HI ^ LO (16 bytes each)
    private byte[] _vmpX1Hi, _vmpX1Lo;   // _vbs_x1 = HI ^ LO (16 bytes each)

    public ResolverCodeGenerator(DexBackedDexFile dexFile,
                                 @Nonnull ClassAnalyzer analyzer
    ) {

        references = new References(dexFile, analyzer);
    }

    public References getReferences() {
        return references;
    }

    public void generate(Writer writer) throws IOException {
        writer.write("#include \"GlobalCache.h\"\n");
        writer.write("#include \"ConstantPool.h\"\n");
        writer.write("#include \"vm.h\"\n\n");       // vmField, vmMethod types
        writer.write("#include <pthread.h>\n");
        writer.write("#include \"ph_aes_impl.h\"\n\n"); // ChaCha20 — string blob decrypt

        generateStringPool(writer);
        generateTypePool(writer);

        //额外添加的,方便生成结构体
        generateClassNamePool(writer);
        generateSignaturePool(writer);

        generateFieldPool(writer);

        generateMethodPool(writer);

        generateStringConstants(writer);

        //生成初始化函数及符号解析器结构体
        generateResolver(writer);
    }

    //产生const-string*指令对应的缓存
    private void generateStringConstants(Writer writer) throws IOException {
        final References references = this.references;
        final List<String> constantStringPool = references.getConstantStringPool();

        final int[] constStringIds = new int[constantStringPool.size()];
        for (int i = 0; i < constantStringPool.size(); i++) {
            //把得到字符串索引
            constStringIds[i] = references.getStringItemIndex(constantStringPool.get(i));
        }

        //
        writer.write(
                "\n//字符串常量索引缓存,const-string指令索引被重写，直接根据索引得到字符串索引，然后创建jstring\n" +
                        "typedef struct {\n" +
                        "    u4 idx;\n" +
                        "} ConstStringId;\n"
        );

        writer.write("static const ConstStringId gStringConstantIds[] = {\n");
        for (int offset : constStringIds) {
            writer.write(String.format("    {.idx=0x%04x},\n", offset));
        }
        writer.write("};\n");

        writer.write(String.format("static jstring gStringConstants[%d];\n\n", constStringIds.length));
    }

    private void generateResolver(Writer writer) throws IOException {
        // ── 8 independent gate functions — each unmasks 4 bytes of _vbs_ck ────
        // volatile locals prevent constant-folding at compile time (replaces optnone).
        // noinline keeps each gate as a discrete call target under OLLVM.
        for (int _g = 0; _g < 8; _g++) {
            writer.write(String.format(
                "static __attribute__((noinline,optnone)) uint32_t _vbs_gate%d(void){\n" +
                "    volatile uint32_t _a=0x%08XU,_b=0x%08XU,_c=0x%08XU,_d=0x%08XU,_e=0x%08XU;\n" +
                "    uint32_t _v=(uint32_t)_a; _v^=(uint32_t)_b;\n" +
                "    _v=(_v<<13)|(_v>>19); _v+=(uint32_t)_c; _v^=(uint32_t)_d;\n" +
                "    _v=(_v>>7)|(_v<<25);  _v*=(uint32_t)_e; return _v;\n" +
                "}\n",
                _g,
                _vmpGc[_g][0], _vmpGc[_g][1], _vmpGc[_g][2],
                _vmpGc[_g][3], _vmpGc[_g][4]));
        }
        writer.write("\n");

        // ── resolver_init: recover all 32 key bytes via 8 gates + HI^LO ───────
        StringBuilder ri = new StringBuilder(2048);
        ri.append("static void resolver_init(JNIEnv *env) {\n");
        ri.append("    /* Recover ChaCha20 key: HI^LO then unmask via 8 gates */\n");
        ri.append("    u1 _rk[32];\n");
        ri.append("    const volatile u1 *_chi=_vbs_ck_hi, *_clo=_vbs_ck_lo;\n");
        ri.append("    for(int _qi=0;_qi<32;_qi++) _rk[_qi]=_chi[_qi]^_clo[_qi];\n");
        for (int _g = 0; _g < 8; _g++) {
            ri.append(String.format(
                "    {const uint32_t _gv=_vbs_gate%d();\n" +
                "     _rk[%d]^=(u1)((_gv>>24)&0xFF); _rk[%d]^=(u1)((_gv>>16)&0xFF);\n" +
                "     _rk[%d]^=(u1)((_gv>>8)&0xFF);  _rk[%d]^=(u1)(_gv&0xFF);}\n",
                _g, _g*4, _g*4+1, _g*4+2, _g*4+3));
        }
        ri.append(String.format(
                "    /* Decrypt string blob: ChaCha20 then XOR-layer */\n" +
                "    memcpy(gStrDecBuf, gBaseStrPtr, %d);\n" +
                "    _pha_cc20_dec(_rk, _vbs_n, gStrDecBuf, %d);\n" +
                "    memset(_rk, 0, 32);\n" +
                "    const volatile u1 *_h0=_vbs_x0_hi,*_l0=_vbs_x0_lo;\n" +
                "    const volatile u1 *_h1=_vbs_x1_hi,*_l1=_vbs_x1_lo;\n" +
                "    for (int _i = 0; _i < %d; _i++) {\n" +
                "        const u1 _k = (_i < 16\n" +
                "            ? (u1)(_h0[_i&15]^_l0[_i&15])\n" +
                "            : (u1)(_h1[_i&15]^_l1[_i&15]))\n" +
                "            ^ (u1)(_i * 0x1D);\n" +
                "        gStrDecBuf[_i] ^= _k;\n" +
                "    }\n" +
                "    if(sizeof(gFields)>0) memset(gFields,0,sizeof(gFields));\n" +
                "    if(sizeof(gMethods)>0) memset(gMethods,0,sizeof(gMethods));\n" +
                "    if(sizeof(gStringConstants)>0) memset(gStringConstants,0,sizeof(gStringConstants));\n" +
                "}\n",
                _vmpBlobSize, _vmpBlobSize, _vmpBlobSize));
        writer.write(ri.toString());
        writer.write(
                "\n" +
                // STRING_BY_ID now reads from the decrypted mutable buffer, not the encrypted .rodata blob
                "#define STRING_BY_ID(_idx) ((const char *) (gStrDecBuf + gStringIds[_idx].off))\n" +
                "\n" +
                "#define STRING_BY_TYPE_ID(_idx) (STRING_BY_ID(gTypeIds[_idx].idx))\n" +
                "\n" +
                "#define STRING_BY_CLASS_ID(_idx) (STRING_BY_ID(gClassIds[_idx].idx))\n" +
                "\n" +
                "#define STRING_BY_SIGNATURE_ID(_idx) (STRING_BY_ID(gSignatureIds[_idx].idx))\n" +
                "\n" +
                "#define FIND_CLASS_BY_NAME(_className)                          \\\n" +
                "    clazz = (*env)->FindClass(env, _className);                 \\\n" +
                "    if (clazz == NULL) {                                        \\\n" +
                "        /*转换异常类型,保持和正常java抛一样异常*/                   \\\n" +
                "        (*env)->ExceptionClear(env);                            \\\n" +
                "        vmThrowNoClassDefFoundError(env, _className);           \\\n" +
                "        return NULL;                                            \\\n" +
                "    }\n" +
                "\n" +
                "\n" +
                "static void vmThrowNoClassDefFoundError(JNIEnv *env, const char *msg) {\n" +
                "    (*env)->ThrowNew(env, gVm.exNoClassDefFoundError, msg);\n" +
                "}\n" +
                "\n" +
                "static void vmThrowNoSuchFieldError(JNIEnv *env, const char *msg) {\n" +
                "    (*env)->ThrowNew(env, gVm.exNoSuchFieldError, msg);\n" +
                "}\n" +
                "\n" +
                "static void vmThrowNoSuchMethodError(JNIEnv *env, const char *msg) {\n" +
                "    (*env)->ThrowNew(env, gVm.exNoSuchMethodError, msg);\n" +
                "}\n" +
                "\n" +
                "static const vmField *dvmResolveField(JNIEnv *env, u4 idx, bool isStatic) {\n" +
                "    vmField *field = &gFields[idx];\n" +
                "    if (field->fieldId == NULL) {\n" +
                "        FieldId fieldId = gFieldIds[idx];\n" +
                "\n" +
                "        jclass clazz;\n" +
                "        const char *clsName = STRING_BY_CLASS_ID(fieldId.classIdx);\n" +
                "        FIND_CLASS_BY_NAME(clsName);\n" +
                "\n" +
                "        const char *type = STRING_BY_TYPE_ID(fieldId.typeIdx);\n" +
                "        const char *name = STRING_BY_ID(fieldId.nameIdx);\n" +
                "\n" +
                "        field->classIdx = fieldId.classIdx;\n" +
                "        field->type = (*type == '[') ? 'L' : *type;\n" +
                "\n" +
                "        //和方法解析同理,最后赋值fieldId\n" +
                "        jfieldID fid;\n" +
                "        if (isStatic) {\n" +
                "            fid = (*env)->GetStaticFieldID(env, clazz, name, type);\n" +
                "        } else {\n" +
                "            fid = (*env)->GetFieldID(env, clazz, name, type);\n" +
                "        }\n" +
                "        if (fid == NULL) {\n" +
                "            (*env)->DeleteLocalRef(env, clazz);\n" +
                "\n" +
                "            (*env)->ExceptionClear(env);\n" +
                "            vmThrowNoSuchFieldError(env, name);\n" +
                "            return NULL;\n" +
                "        }\n" +
                "        (*env)->DeleteLocalRef(env, clazz);\n" +
                "\n" +
                "\n" +
                "        field->fieldId = fid;\n" +
                "    }\n" +
                "    return field;\n" +
                "}\n" +
                "\n" +
                "static const vmMethod *dvmResolveMethod(JNIEnv *env, u4 idx, bool isStatic) {\n" +
                "    vmMethod *method = &gMethods[idx];\n" +
                "    if (method->methodId == NULL) {\n" +
                "        MethodId methodId = gMethodIds[idx];\n" +
                "\n" +
                "        jclass clazz;\n" +
                "        const char *clsName = STRING_BY_CLASS_ID(methodId.classIdx);\n" +
                "        FIND_CLASS_BY_NAME(clsName);\n" +
                "\n" +
                "        method->shorty = STRING_BY_ID(methodId.shortyIdx);\n" +
                "\n" +
                "        method->classIdx = methodId.classIdx;\n" +
                "\n" +
                "        const char *name = STRING_BY_ID(methodId.nameIdx);\n" +
                "        const char *sig = STRING_BY_SIGNATURE_ID(methodId.sigIdx);\n" +
                "\n" +
                "        jmethodID mid;\n" +
                "        if (isStatic) {\n" +
                "            mid = (*env)->GetStaticMethodID(env, clazz, name, sig);\n" +
                "        } else {\n" +
                "            mid = (*env)->GetMethodID(env, clazz, name, sig);\n" +
                "        }\n" +
                "        if (mid == NULL) {\n" +
                "            (*env)->DeleteLocalRef(env, clazz);\n" +
                "\n" +
                "            (*env)->ExceptionClear(env);\n" +
                "            vmThrowNoSuchMethodError(env, name);\n" +
                "            return NULL;\n" +
                "        }\n" +
                "        (*env)->DeleteLocalRef(env, clazz);\n" +
                "\n" +
                "        //只根据method->methodId判断是否需要解析,最后赋值为了防止结构体解析一半被其他线程使用从而导致错误\n" +
                "        //todo 赋值需为原子操作\n" +
                "\n" +
                "        method->methodId = mid;\n" +
                "    }\n" +
                "    return method;\n" +
                "}\n" +
                "\n" +
                "static pthread_mutex_t str_mutex = PTHREAD_MUTEX_INITIALIZER;\n" +

                "static jstring dvmConstantString(JNIEnv *env, u4 idx) {\n" +
                "    //先查找索引位置是否存在缓存,不用频繁创建string对象\n" +
                "    if (gStringConstants[idx] == NULL) {\n" +
                "        pthread_mutex_lock(&str_mutex);\n" +
                "        jstring str;\n" +
                "        if (gStringConstants[idx] == NULL) {\n" +
                "            str = (*env)->NewStringUTF(env, STRING_BY_ID(gStringConstantIds[idx].idx));\n" +
                "            gStringConstants[idx] = (*env)->NewGlobalRef(env, str);\n" +
                "        } else {\n" +
                "            str = (*env)->NewLocalRef(env, gStringConstants[idx]);\n" +
                "        }\n" +
                "        pthread_mutex_unlock(&str_mutex);\n" +
                "\n" +
                "        return str;\n" +
                "    } else {\n" +
                "        return (*env)->NewLocalRef(env, gStringConstants[idx]);\n" +
                "    }\n" +
                "}\n" +
                "\n" +
                "\n" +
                "static const char *dvmResolveTypeUtf(JNIEnv *env, u4 idx) {\n" +
                "    return STRING_BY_TYPE_ID(idx);\n" +
                "}\n" +
                "\n" +
                "static jclass dvmResolveClass(JNIEnv *env, u4 idx) {\n" +
                "    const char *typeName = STRING_BY_TYPE_ID(idx);\n" +
                "    jclass clazz = getCacheClass(env, typeName);\n" +
                "    if (clazz != NULL) {\n" +
                "        return (jclass) (*env)->NewLocalRef(env, clazz);\n" +
                "    }\n" +
                "    FIND_CLASS_BY_NAME(STRING_BY_CLASS_ID(idx));\n" +
                "    return clazz;\n" +
                "}\n\n");

        //因为类型需要去掉开头的'L'和结尾的';',所以最大最大class名不需要再加1表示字符串结尾
        writer.write(String.format(
                "static jclass dvmFindClass(JNIEnv *env, const char *type) {\n" +
                        "    jclass clazz = getCacheClass(env, type);\n" +
                        "    if (clazz != NULL) {\n" +
                        "        return (jclass) (*env)->NewLocalRef(env, clazz);\n" +
                        "    }\n" +
                        "    if (*type == 'L') {\n" +
                        "        char clazzName[%d];\n" +
                        "        size_t len = strlen(type);\n" +
                        "        strncpy(clazzName, type + 1, len - 2);\n" +
                        "        clazzName[len - 2] = 0;\n" +
                        "\n" +
                        "        FIND_CLASS_BY_NAME(clazzName);\n" +
                        "\n" +
                        "        return clazz;\n" +
                        "    }\n" +
                        "\n" +
                        "    FIND_CLASS_BY_NAME(type);\n" +
                        "\n" +
                        "    return clazz;\n" +
                        "}\n\n", references.getMaxTypeLen()));
        writer.write(
                "static const vmResolver dvmResolver = {\n" +
                        "        .dvmResolveField = dvmResolveField,\n" +
                        "        .dvmResolveMethod = dvmResolveMethod,\n" +
                        "        .dvmResolveTypeUtf = dvmResolveTypeUtf,\n" +
                        "        .dvmResolveClass = dvmResolveClass,\n" +
                        "        .dvmFindClass = dvmFindClass,\n" +
                        "        .dvmConstantString = dvmConstantString,\n" +
                        "};\n" +
                        "\n");
    }

    private void generateMethodPool(Writer writer) throws IOException {
        final References references = this.references;
        writer.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u2 classIdx;\n" +
                        "    u4 nameIdx;\n" +
                        "    u4 shortyIdx;\n" +
                        "    u4 sigIdx;\n" +
                        "} MethodId;\n\n");
        writer.write("static const MethodId gMethodIds[] = {\n");

        final List<MethodReference> methodPool = references.getMethodPool();
        for (MethodReference methodReference : methodPool) {
            String definingClass = methodReference.getDefiningClass();
            String className;
            if (definingClass.charAt(0) == 'L') {
                className = definingClass.substring(1, definingClass.length() - 1);
            } else {
                className = definingClass;
            }
            int classNameIdx = references.getClassNameItemIndex(className);
            if (classNameIdx < 0) {
                throw new RuntimeException("unknown class name" + definingClass);
            }
            String name = methodReference.getName();
            int nameIdx = references.getStringItemIndex(name);
            if (nameIdx < 0) {
                throw new RuntimeException("unknown method name");
            }
            int shortyIdx = references.getStringItemIndex(MethodUtil.getShorty(methodReference.getParameterTypes(), methodReference.getReturnType()));
            if (shortyIdx < 0) {
                throw new RuntimeException("unknown method shorty");
            }
            String signature = MyMethodUtil.getMethodSignature(methodReference.getParameterTypes(), methodReference.getReturnType());
            int sigIdx = references.getSignatureItemIndex(signature);
            if (sigIdx < 0) {
                throw new RuntimeException("unknown method signature");
            }

            writer.write(String.format(
                    "    {.classIdx=%d, .nameIdx=%d, .shortyIdx=%d, .sigIdx=%d},\n",
                    classNameIdx, nameIdx, shortyIdx, sigIdx));
        }
        writer.write("};\n");
        writer.write("//ends method data\n\n");
        writer.write(String.format("static vmMethod gMethods[%d];\n", methodPool.size()));
        writer.write("\n");
    }

    private void generateFieldPool(Writer writer) throws IOException {
        final References references = this.references;
        writer.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u2 classIdx;\n" +
                        "    u4 nameIdx;\n" +
                        "    u2 typeIdx;\n" +
                        "} FieldId;\n\n");
        writer.write("static const FieldId gFieldIds[] = {\n");

        final List<FieldReference> fieldPool = references.getFieldPool();
        for (FieldReference reference : fieldPool) {
            String definingClass = reference.getDefiningClass();
            String className;
            if (definingClass.charAt(0) == 'L') {
                className = definingClass.substring(1, definingClass.length() - 1);
            } else {
                className = definingClass;
            }
            int classNameIdx = references.getClassNameItemIndex(className);
            if (classNameIdx < 0) {
                throw new RuntimeException("unknown class name");
            }
            int nameIdx = references.getStringItemIndex(reference.getName());
            if (nameIdx < 0) {
                throw new RuntimeException("unknown field name");
            }
            int typeIdx = references.getTypeItemIndex(reference.getType());
            if (typeIdx < 0) {
                throw new RuntimeException("unknown field type");
            }

            writer.write(String.format(
                    "    {.classIdx=%d, .nameIdx=%d, .typeIdx=%d},\n",
                    classNameIdx, nameIdx, typeIdx));
        }
        writer.write("};\n");
        writer.write("//ends field id\n\n");
        writer.write(String.format("static vmField gFields[%d];\n", fieldPool.size()));
    }


    // String blob encrypted with ChaCha20+XOR — plaintext never lands in .rodata
    private void generateStringPool(Writer writer) throws IOException {
        // 1. Collect all strings into a flat blob (modified-UTF8 + null terminator per string)
        final List<String> stringPool = references.getStringPool();
        ArrayList<Long> strOffsets = new ArrayList<>();
        ByteArrayOutputStream blobStream = new ByteArrayOutputStream();
        long strOffset = 0;
        for (String string : stringPool) {
            byte[] bytes = ModifiedUtf8.encode(string);
            strOffsets.add(strOffset);
            blobStream.write(bytes);
            blobStream.write(0);
            strOffset += bytes.length + 1;
        }
        byte[] plainBlob = blobStream.toByteArray();

        // 2. Fresh keys per protection run
        SecureRandom rng = new SecureRandom();
        _vmpXorKey  = new byte[32];
        _vmpCc20Key = new byte[32];
        _vmpNonce   = new byte[12];
        rng.nextBytes(_vmpXorKey);
        rng.nextBytes(_vmpCc20Key);
        rng.nextBytes(_vmpNonce);
        _vmpBlobSize = plainBlob.length;

        // Save REAL key before masking — blob must be encrypted with K, not _vbs_ck.
        byte[] _realVmpCc20Key = _vmpCc20Key.clone();

        // ── 8 gates × 4 bytes — all 32 bytes of _vbs_ck gate-protected ────────
        _vmpGc = new int[8][5];
        _vmpGv = new int[8];
        for (int _g = 0; _g < 8; _g++) {
            for (int _k = 0; _k < 5; _k++) _vmpGc[_g][_k] = rng.nextInt();
            _vmpGc[_g][4] |= 1;
            int _v = _vmpGc[_g][0] ^ _vmpGc[_g][1];
            _v = Integer.rotateLeft(_v, 13); _v += _vmpGc[_g][2];
            _v ^= _vmpGc[_g][3]; _v = Integer.rotateRight(_v, 7); _v *= _vmpGc[_g][4];
            _vmpGv[_g] = _v;
            _vmpCc20Key[_g*4+0] ^= (byte)((_v >>> 24) & 0xFF);
            _vmpCc20Key[_g*4+1] ^= (byte)((_v >>> 16) & 0xFF);
            _vmpCc20Key[_g*4+2] ^= (byte)((_v >>>  8) & 0xFF);
            _vmpCc20Key[_g*4+3] ^= (byte)( _v         & 0xFF);
        }

        // ── HI/LO splits — no single .rodata array is the real key/xor material ─
        _vmpCkHi = new byte[32]; _vmpCkLo = new byte[32];
        rng.nextBytes(_vmpCkHi);
        for (int i = 0; i < 32; i++) _vmpCkLo[i] = (byte)(_vmpCc20Key[i] ^ _vmpCkHi[i]);

        _vmpX0Hi = new byte[16]; _vmpX0Lo = new byte[16];
        _vmpX1Hi = new byte[16]; _vmpX1Lo = new byte[16];
        rng.nextBytes(_vmpX0Hi); rng.nextBytes(_vmpX1Hi);
        for (int i = 0; i < 16; i++) {
            _vmpX0Lo[i] = (byte)(_vmpXorKey[i]      ^ _vmpX0Hi[i]);
            _vmpX1Lo[i] = (byte)(_vmpXorKey[16 + i] ^ _vmpX1Hi[i]);
        }

        // Encrypt with real key K (not the gated _vmpCc20Key / _vbs_ck)
        byte[] encBlob = (plainBlob.length == 0) ? new byte[]{0}
                       : AesCrypto.encrypt(plainBlob, _vmpXorKey, _realVmpCc20Key, _vmpNonce);

        // 3. Write HI/LO split key arrays + nonce (nonce is not secret)
        writeByteArr(writer, "static const u1 _vbs_ck_hi[32]", _vmpCkHi, 32);
        writeByteArr(writer, "static const u1 _vbs_ck_lo[32]", _vmpCkLo, 32);
        writeByteArr(writer, "static const u1 _vbs_x0_hi[16]", _vmpX0Hi, 16);
        writeByteArr(writer, "static const u1 _vbs_x0_lo[16]", _vmpX0Lo, 16);
        writeByteArr(writer, "static const u1 _vbs_x1_hi[16]", _vmpX1Hi, 16);
        writeByteArr(writer, "static const u1 _vbs_x1_lo[16]", _vmpX1Lo, 16);
        writer.write("static const u1 _vbs_n[12]={");
        for (int i=0;i<12;i++){if(i>0)writer.write(",");writer.write(String.format("0x%02X",_vmpNonce[i]&0xFF));}
        writer.write("};\n\n");

        // 4. Encrypted blob (in .rodata — no plaintext strings)
        writer.write(String.format("static const u1 gBaseStrPtr[%d]={\n", encBlob.length));
        int col = 0;
        for (byte b : encBlob) {
            if (col == 0) writer.write("    ");
            writer.write(String.format("0x%02x,", b & 0xFF));
            if (++col == 16) { writer.write("\n"); col = 0; }
        }
        if (col > 0) writer.write("\n");
        writer.write("};\n");

        // 5. Mutable decrypt buffer — same size, in .bss (zero-initialised)
        writer.write(String.format("static u1 gStrDecBuf[%d];\n\n", Math.max(_vmpBlobSize, 1)));

        // 6. StringId offset table (offsets into the plaintext layout, valid after decrypt)
        writer.write(
                "\ntypedef struct {\n" +
                "    u4 off;\n" +
                "} StringId;\n");
        writer.write("static const StringId gStringIds[] = {\n");
        for (Long offset : strOffsets) {
            if (offset > 0xFFFFFFFFL) throw new RuntimeException("string offset too long");
            writer.write(String.format("    {.off=0x%04x},\n", offset));
        }
        writer.write("};\n");
        writer.write("//ends string ids\n\n");
        writer.flush();
    }

    private static final char[] _HEX = "0123456789ABCDEF".toCharArray();

    /** Emit a C byte-array declaration. Uses char-lookup instead of String.format for speed. */
    private static void writeByteArr(Writer w, String decl, byte[] data, int len) throws IOException {
        w.write(decl);
        w.write("={");
        for (int i = 0; i < len; i++) {
            if (i > 0) w.write(",");
            int b = data[i] & 0xFF;
            w.write("0x");
            w.write(_HEX[b >> 4]);
            w.write(_HEX[b & 0xF]);
        }
        w.write("};\n");
    }

    static String stringEsc(String str) throws UTFDataFormatException {
        byte[] bytes = ModifiedUtf8.encode(str);
        StringBuilder sb = new StringBuilder(4 * bytes.length);
        for (byte b : bytes) {
            sb.append(String.format("\\x%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private void generateTypePool(Writer writer) throws IOException {

        writer.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u4 idx;\n" +
                        "} TypeId;\n");

        writer.write("static const TypeId gTypeIds[] = {\n");
        final References references = this.references;
        for (String type : references.getTypePool()) {
            writer.write(String.format("    {.idx=%d},\n", references.getStringItemIndex(type)));
        }
        writer.write("};\n");
        writer.write("//ends type ids\n\n");
        writer.flush();
    }

    //根据类型池,去掉L开头和;得到class name,其他则不变
    private void generateClassNamePool(Writer writer) throws IOException {
        writer.write(
                "\n" +
                        "typedef struct {\n" +
                        "    u4 idx;\n" +
                        "} ClassId;\n");


        writer.write("static const ClassId gClassIds[] = {\n");

        final References references = this.references;
        for (String className : references.getClassNamePool()) {
            int classNameIdx = references.getStringItemIndex(className);
            if (classNameIdx < 0) {
                throw new RuntimeException("string not contain");
            }
            writer.write(String.format("    {.idx=%d},\n", classNameIdx));

        }
        writer.write("};\n");
        writer.write("//ends class name ids\n\n");
    }

    private void generateSignaturePool(Writer writer) throws IOException {
        writer.write(
                "typedef struct {\n" +
                        "    u4 idx;\n" +
                        "} SignatureId;\n");

        writer.write("static const SignatureId gSignatureIds[] = {\n");

        final References references = this.references;
        for (String sig : references.getSignaturePool()) {
            int sigIdx = references.getStringItemIndex(sig);
            if (sigIdx < 0) {
                throw new RuntimeException("string not contain");
            }
            writer.write(String.format("    {.idx=%d},\n", sigIdx));
        }
        writer.write("};\n");
        writer.write("//ends method signature pool\n\n");
    }
}