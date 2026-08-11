# encoding=utf-8
"""
vm_writer.py — Compile dex2c SSA IR into lvm_method_exec() bytecode.

This implements the "thin JNI shell + VM-protected core" pipeline:

  Java method
      ↓  dex2c (existing)
  SSA IR (IrMethod)
      ↓  VmMethodCompiler (this file)
  AES-256-CBC encrypted bytecode + JNI shell C++ source
      ↓  lvm_method_exec() at runtime
  Pure ARM64-invisible execution

──────────────────────────────────────────────────────────────────────────────
ELIGIBLE METHODS (can_compile returns True):
  • All parameters AND results are primitive types: I J F D Z B S C
  • No InvokeInstruction (any variant)
  • No object creation: NewInstance, NewArrayExpression, FilledArrayExpression
  • No array/field/object: ArrayLoad, ArrayStore, InstanceExpression,
    StaticExpression, InstanceInstruction, StaticInstruction
  • No exception handling: ThrowExpression, MonitorEnter/Exit, MoveException,
    LandingPads, FillArrayExpression
  • No String/Class constants (require JNI env)
  • No SwitchExpression (table/sparse switch)
  • ≤ MVM_MAX_REGS (16) distinct SSA variable slots
──────────────────────────────────────────────────────────────────────────────
BYTECODE FORMAT:
  [n_consts:1][pad:3][const_0:8LE]…[const_N:8LE][instructions…]
  Each instruction: [op:1][b1:1][b2:1][b3:1]  (4 bytes, always 4-byte aligned)
  Jump targets in b2:b3 = 16-bit absolute byte offset (big-endian)
──────────────────────────────────────────────────────────────────────────────
PARAMETER CONVENTION:
  JNI args are packed by generate_shell() into ctx->args[vm_slot] where
  vm_slot = irmethod.ra(param_variable).  lvm_method_exec() pre-loads ALL
  MVM_MAX_REGS register slots from ctx->args before executing.  This means
  parameters arrive at their correct VM registers with zero bytecode overhead.
──────────────────────────────────────────────────────────────────────────────
"""

import struct
import logging

from dex2c import util
from dex2c.opcode_ins import Op
from dex2c.instruction import (
    LoadConstant, MoveParam, MoveExpression, MoveResultExpression,
    BinaryExpression, BinaryExpression2Addr, BinaryExpressionLit,
    BinaryCompExpression, UnaryExpression, CastExpression,
    ConditionalExpression, ConditionalZExpression, GotoInst,
    ReturnInstruction, NopExpression, Phi, Constant, Variable,
    InvokeInstruction, NewInstance, ArrayStoreInstruction,
    ArrayLoadExpression, NewArrayExpression, FilledArrayExpression,
    FillArrayExpression, InstanceExpression, StaticExpression,
    InstanceInstruction, StaticInstruction, CheckCastExpression,
    InstanceOfExpression, ThrowExpression, MonitorEnterExpression,
    MonitorExitExpression, MoveExceptionExpression, ArrayLengthExpression,
    SwitchExpression,
)

logger = logging.getLogger('dex2c.vm_writer')

# ── Register limit (matches MVM_MAX_REGS in guard.cpp) ────────────────────
MAX_VM_REGS   = 16
MAX_VM_CONSTS = 32
MAX_PROG_PLAIN = 3800   # safety margin below MVM_PROG_MAX (4096)

# ── Instruction types that always disqualify a method from VM compilation ──
_DISQUALIFYING_TYPES = (
    InvokeInstruction,
    NewInstance, NewArrayExpression, FilledArrayExpression, FillArrayExpression,
    ArrayLoadExpression, ArrayStoreInstruction, ArrayLengthExpression,
    InstanceExpression, StaticExpression,
    InstanceInstruction, StaticInstruction,
    CheckCastExpression, InstanceOfExpression,
    ThrowExpression, MonitorEnterExpression, MonitorExitExpression,
    MoveExceptionExpression,
    SwitchExpression,       # packed/sparse switch needs a table — not emittable
)

# ── Primitive-type predicate ───────────────────────────────────────────────
def _is_primitive(vtype):
    return vtype is not None and vtype in 'IJFDZBS C'

# ── Opcode tables ──────────────────────────────────────────────────────────
# Integer / long (both stored as int64 in the VM)
_ARITH_INT = {
    Op.ADD:    0xA0,
    Op.SUB:    0xA1,
    Op.MUL:    0xA2,
    Op.DIV:    0xA3,
    Op.MOD:    0xA4,
    Op.AND:    0xA5,
    Op.OR:     0xA6,
    Op.XOR:    0xA7,
    Op.INTSHL: 0xA8,
    Op.INTSHR: 0xA9,
    Op.INTUSHR:0xAA,
    Op.LONGSHL: 0xAB,
    Op.LONGSHR: 0xAC,
    Op.LONGUSHR:0xAD,
    # Comparisons → 0 or 1
    Op.EQUAL:  0xAE,
    Op.NEQUAL: 0xAF,
    Op.LOWER:  0xB0,
    Op.LEQUAL: 0xB1,
    Op.GREATER:0xB2,
    Op.GEQUAL: 0xB3,
    # long-cmp → -1/0/+1
    Op.CMP:    0xB4,
}

# Float arithmetic (IEEE-754 bits stored as int64 low 32)
_ARITH_FLOAT = {
    Op.ADD:  0xD1,
    Op.SUB:  0xD2,
    Op.MUL:  0xD3,
    Op.DIV:  0xD4,
    Op.MODF: 0xD5,
    Op.CMPL: 0xD6,   # cmpl: NaN → -1
    Op.CMPG: 0xD7,   # cmpg: NaN → +1
}

# Double arithmetic (IEEE-754 bits stored as int64)
_ARITH_DOUBLE = {
    Op.ADD:  0xD8,
    Op.SUB:  0xD9,
    Op.MUL:  0xDA,
    Op.DIV:  0xDB,
    Op.MODD: 0xDC,
    Op.CMPL: 0xDD,
    Op.CMPG: 0xDE,
}

# Condz op → VM jump opcode (jump if condition is TRUE, i.e., r[src] OP 0)
_CONDZ_JUMP = {
    '==': 0x82,   # MVJZ
    '!=': 0x83,   # MVJNZ
    '<':  0x84,   # MVJLTZ
    '<=': 0x85,   # MVJLEZ
    '>':  0x86,   # MVJGTZ
    '>=': 0x87,   # MVJGEZ
}

# Conditional comparison (two operands) → CMP opcode, then MVJNZ to reach true target
_COND_CMP = {
    '==': 0xAE,
    '!=': 0xAF,
    '<':  0xB0,
    '<=': 0xB1,
    '>':  0xB2,
    '>=': 0xB3,
}

# CastExpression (src_type, dst_type) → VM opcode
# Verified against opcode_ins.py lines 1160-1300 CastExpression call sites
_CAST_OP = {
    ('I', 'J'): 0xC0,  # MVI2L (sign-extend int32 → int64)
    ('J', 'I'): 0xC1,  # MVL2I (truncate int64 → int32)
    ('I', 'F'): 0xC2,  # MVI2F
    ('F', 'I'): 0xC3,  # MVF2I (with Dalvik NaN clamping)
    ('I', 'D'): 0xC4,  # MVI2D
    ('D', 'I'): 0xC5,  # MVD2I
    ('J', 'F'): 0xC6,  # MVL2F
    ('F', 'J'): 0xC7,  # MVF2L
    ('J', 'D'): 0xC8,  # MVL2D
    ('D', 'J'): 0xC9,  # MVD2L
    ('F', 'D'): 0xCA,  # MVF2D
    ('D', 'F'): 0xCB,  # MVD2F
    ('I', 'B'): 0xCC,  # MVI2B (int → byte, sign-extend)
    ('I', 'C'): 0xCD,  # MVI2C (int → char, zero-extend 16)
    ('I', 'S'): 0xCE,  # MVI2S (int → short, sign-extend)
}


class VmMethodCompiler:
    """
    Compiles a dex2c IrMethod into lvm_method_exec() bytecode + JNI shell C++.

    Usage:
        comp = VmMethodCompiler()
        if comp.can_compile(irmethod):
            bytecode = comp.compile(irmethod)
            shell_cpp = comp.generate_shell(irmethod, jni_name, bytecode, sym_prefix)
    """

    # ── Eligibility check ──────────────────────────────────────────────────

    def can_compile(self, irmethod) -> bool:
        """Return True iff the method body is fully VM-compilable."""
        try:
            # No exception handlers (landing pads)
            if irmethod.landing_pads:
                return False

            # Return type must be primitive or void
            rtype = irmethod.rtype
            if rtype and rtype not in 'VIJFDZBS C':
                return False

            # All explicit parameter types must be primitive
            # (note: irmethod.params_type excludes 'this')
            for pt in (irmethod.params_type or []):
                if not _is_primitive(pt):
                    return False

            # Also check move_param_insns — catches 'this' (object type)
            # which is NOT in params_type but would be referenced as a Variable
            entry = irmethod.entry
            for mp in getattr(entry, 'move_param_insns', []):
                val = mp.get_param().get_value()
                vtype = val.get_type()
                if vtype and not _is_primitive(vtype):
                    # Only disqualify if 'this' is USED (method isn't isolated)
                    # If all uses of 'this' are via disqualifying instructions
                    # (InstanceInstruction etc.) those will be caught below.
                    # A method that references 'this' at all is disqualified here.
                    return False

            # All instructions must be handleable
            for block in irmethod.irblocks:
                for ins in block.get_instr_list():
                    if isinstance(ins, _DISQUALIFYING_TYPES):
                        return False

                    # String/Class constants need JNI env — not available in VM
                    if isinstance(ins, LoadConstant):
                        cst = ins.get_cst()
                        ctype = cst.get_type() if cst else None
                        if ctype and (ctype[0] == 'L' or ctype[0] == '['):
                            return False

                    # All result variables must be primitive
                    val = ins.get_value()
                    if val is not None:
                        vtype = val.get_type()
                        if vtype and not _is_primitive(vtype):
                            return False

            # SSA register slot count must fit in MAX_VM_REGS
            if self._max_slot(irmethod) >= MAX_VM_REGS:
                return False

            # Scratch registers: we need at least 2 above the max used slot
            if self._max_slot(irmethod) + 2 >= MAX_VM_REGS:
                return False

            return True

        except Exception as e:
            logger.debug('can_compile error: %s', e)
            return False

    def _max_slot(self, irmethod) -> int:
        """Return the highest VM register slot used, or -1 if empty."""
        try:
            ra = irmethod.ra
            max_s = -1
            for v in irmethod.entry.var_to_declare:
                try:
                    s = ra(v)
                    if s > max_s:
                        max_s = s
                except Exception:
                    pass
            return max_s
        except Exception:
            return MAX_VM_REGS  # safe: disqualify

    # ── Compilation ────────────────────────────────────────────────────────

    def compile(self, irmethod) -> bytes:
        """
        Compile IrMethod → raw VM bytecode bytes.
        Raises ValueError if any unsupported instruction is encountered.

        MoveParam is NOT processed here — arguments are pre-loaded by
        lvm_method_exec() directly into their VM registers (see generate_shell).
        """
        ra    = irmethod.ra
        graph = irmethod.graph

        # ── Scratch registers ────────────────────────────────────────────
        max_slot    = self._max_slot(irmethod)
        scratch_reg = max_slot + 1   # for temp const loads and cmp results
        scratch2    = max_slot + 2   # for second operand when both are constants

        # ── Constant table ───────────────────────────────────────────────
        const_table  = []   # list of int64 values (insertion order)
        const_index  = {}   # int64 value → index

        def add_const(raw_int: int) -> int:
            v = raw_int & 0xFFFFFFFFFFFFFFFF
            if v > 0x7FFFFFFFFFFFFFFF:
                v -= 0x10000000000000000
            if v not in const_index:
                if len(const_table) >= MAX_VM_CONSTS:
                    raise ValueError('Too many constants (max %d)' % MAX_VM_CONSTS)
                const_index[v] = len(const_table)
                const_table.append(v)
            return const_index[v]

        def float_bits(raw, vtype):
            """Convert a Python constant value to int64 bits for the VM."""
            if vtype == 'F':
                bits = struct.unpack('<I', struct.pack('<f', float(raw)))[0]
            elif vtype == 'D':
                bits = struct.unpack('<Q', struct.pack('<d', float(raw)))[0]
            else:
                bits = int(raw) if raw is not None else 0
            return bits

        def resolve_val(value, instrs, force_reg=None):
            """
            Return a register number that holds `value`.
            If value is a Constant, emit MVCONST into force_reg (or scratch_reg).
            """
            if isinstance(value, Constant):
                raw   = value.constant
                vtype = value.get_type()
                bits  = float_bits(raw, vtype)
                idx   = add_const(bits)
                dst   = force_reg if force_reg is not None else scratch_reg
                instrs.append([0x91, dst, (idx >> 8) & 0xFF, idx & 0xFF])
                return dst
            else:
                return ra(value)

        # ── First pass: collect instructions per block, collect constants ─
        block_instrs = {}   # block → list of [op, b1, b2, b3]
        block_jumps  = {}   # block → list of (instr_idx, kind, target_info)
        # jump kinds: 'goto' / 'condz_true' / 'condz_false'
        #             'cond_true' / 'cond_false'

        for block in irmethod.irblocks:
            instrs = []
            jumps  = []

            for ins in block.get_instr_list():

                # ── NOP ──────────────────────────────────────────────────
                if isinstance(ins, NopExpression):
                    continue

                # ── MoveParam: args are pre-loaded; skip entirely ─────────
                elif isinstance(ins, MoveParam):
                    continue

                # ── LoadConstant ──────────────────────────────────────────
                elif isinstance(ins, LoadConstant):
                    val  = ins.get_value()
                    cst  = ins.get_cst()
                    dst  = ra(val)
                    bits = float_bits(cst.constant, val.get_type())
                    idx  = add_const(bits)
                    instrs.append([0x91, dst, (idx >> 8) & 0xFF, idx & 0xFF])

                # ── Move / MoveResult ─────────────────────────────────────
                elif isinstance(ins, (MoveExpression, MoveResultExpression)):
                    lhs = ins.get_value()
                    rhs = ins.operands[0]
                    dst = ra(lhs)
                    if isinstance(rhs, Constant):
                        resolve_val(rhs, instrs, force_reg=dst)
                    else:
                        src = ra(rhs)
                        if dst != src:
                            instrs.append([0x90, dst, src, 0])  # MVMOV

                # ── UnaryExpression ───────────────────────────────────────
                elif isinstance(ins, UnaryExpression):
                    val    = ins.get_value()
                    arg    = ins.operands[0]
                    dst    = ra(val)
                    vtype  = val.get_type()
                    op_str = ins.op
                    src    = resolve_val(arg, instrs, force_reg=scratch_reg) \
                             if isinstance(arg, Constant) else ra(arg)
                    if op_str == Op.NEG:   # '-' for negate
                        if vtype == 'F':
                            instrs.append([0xCF, dst, src, 0])  # MVFNEG
                        elif vtype == 'D':
                            instrs.append([0xDF, dst, src, 0])  # MVDNEG
                        else:
                            instrs.append([0x92, dst, src, 0])  # MVNEG
                    elif op_str == Op.NOT:  # '~'
                        instrs.append([0x93, dst, src, 0])      # MVNOT
                    else:
                        if dst != src:
                            instrs.append([0x90, dst, src, 0])  # unknown → mov

                # ── CastExpression ────────────────────────────────────────
                elif isinstance(ins, CastExpression):
                    lhs   = ins.get_value()
                    arg   = ins.operands[0]
                    dst   = ra(lhs)
                    src   = resolve_val(arg, instrs, force_reg=scratch_reg) \
                            if isinstance(arg, Constant) else ra(arg)
                    # ins.type = dest_type, ins.src_type = source_type
                    opc = _CAST_OP.get((ins.src_type, ins.type))
                    if opc is not None:
                        instrs.append([opc, dst, src, 0])
                    else:
                        # Unknown cast — emit mov (may lose precision)
                        if dst != src:
                            instrs.append([0x90, dst, src, 0])

                # ── BinaryExpression (and all 2-addr / lit / comp variants) ─
                elif isinstance(ins, (BinaryExpression, BinaryExpression2Addr,
                                      BinaryExpressionLit, BinaryCompExpression)):
                    val    = ins.get_value()
                    arg1   = ins.operands[0]
                    arg2   = ins.operands[1]
                    dst    = ra(val)
                    op_str = ins.op
                    # For BinaryCompExpression the value is typed 'I' (result
                    # is -1/0/+1) but the *operand* type is ins.op_type.
                    op_type = ins.op_type  # type of the operation (I J F D …)

                    s1 = resolve_val(arg1, instrs, force_reg=scratch_reg) \
                         if isinstance(arg1, Constant) else ra(arg1)
                    s2 = resolve_val(arg2, instrs, force_reg=scratch2) \
                         if isinstance(arg2, Constant) else ra(arg2)

                    # Choose opcode table based on operand type
                    if op_type == 'F':
                        opc = _ARITH_FLOAT.get(op_str)
                    elif op_type == 'D':
                        opc = _ARITH_DOUBLE.get(op_str)
                    else:
                        opc = _ARITH_INT.get(op_str)

                    if opc is None:
                        raise ValueError(
                            'Unsupported binary op %r for type %s' % (op_str, op_type))
                    instrs.append([opc, dst, s1, s2])

                # ── GotoInst ──────────────────────────────────────────────
                elif isinstance(ins, GotoInst):
                    # target is a signed half-word offset in instruction units
                    tgt_off = (ins.offset // 2 + ins.target) * 2
                    tgt_blk = irmethod.offset_to_node.get(tgt_off)
                    if tgt_blk is None:
                        raise ValueError(
                            'GotoInst: unmapped target offset 0x%x' % tgt_off)
                    ji = len(instrs)
                    instrs.append([0x81, 0, 0xFF, 0xFF])  # MVJMP placeholder
                    jumps.append((ji, 'goto', (tgt_blk,)))

                # ── ConditionalZExpression ────────────────────────────────
                elif isinstance(ins, ConditionalZExpression):
                    src_val  = ins.operands[0]
                    op_str   = ins.op
                    true_off = (ins.offset // 2 + ins.target) * 2
                    false_off = ins.next_offset
                    true_blk  = irmethod.offset_to_node.get(true_off)
                    false_blk = irmethod.offset_to_node.get(false_off)
                    if true_blk is None or false_blk is None:
                        raise ValueError('CondZ: unmapped target block')

                    src = resolve_val(src_val, instrs, force_reg=scratch_reg) \
                          if isinstance(src_val, Constant) else ra(src_val)

                    jmp_opc = _CONDZ_JUMP.get(op_str)
                    if jmp_opc is None:
                        raise ValueError('Unknown condz op: %r' % op_str)

                    ji1 = len(instrs)
                    instrs.append([jmp_opc, src, 0xFF, 0xFF])   # cond → true
                    ji2 = len(instrs)
                    instrs.append([0x81, 0, 0xFF, 0xFF])         # fallthrough → false
                    jumps.append((ji1, 'condz_true',  (true_blk,)))
                    jumps.append((ji2, 'condz_false', (false_blk,)))

                # ── ConditionalExpression (two-operand branch) ────────────
                elif isinstance(ins, ConditionalExpression):
                    arg1     = ins.operands[0]
                    arg2     = ins.operands[1]
                    op_str   = ins.op
                    true_off = (ins.offset // 2 + ins.target) * 2
                    false_off = ins.next_offset
                    true_blk  = irmethod.offset_to_node.get(true_off)
                    false_blk = irmethod.offset_to_node.get(false_off)
                    if true_blk is None or false_blk is None:
                        raise ValueError('Cond: unmapped target block')

                    s1 = resolve_val(arg1, instrs, force_reg=scratch_reg) \
                         if isinstance(arg1, Constant) else ra(arg1)
                    s2 = resolve_val(arg2, instrs, force_reg=scratch2) \
                         if isinstance(arg2, Constant) else ra(arg2)

                    cmp_opc = _COND_CMP.get(op_str)
                    if cmp_opc is None:
                        raise ValueError('Unknown cond op: %r' % op_str)

                    # MVCMPEQ scratch, s1, s2  → then MVJNZ to true
                    instrs.append([cmp_opc, scratch_reg, s1, s2])
                    ji1 = len(instrs)
                    instrs.append([0x83, scratch_reg, 0xFF, 0xFF])  # MVJNZ → true
                    ji2 = len(instrs)
                    instrs.append([0x81, 0, 0xFF, 0xFF])             # MVJMP → false
                    jumps.append((ji1, 'cond_true',  (true_blk,)))
                    jumps.append((ji2, 'cond_false', (false_blk,)))

                # ── ReturnInstruction ─────────────────────────────────────
                elif isinstance(ins, ReturnInstruction):
                    retval = ins.retval   # None for void
                    if retval is None:
                        instrs.append([0x80, 0, 0, 0])  # MVHALT r0 (void)
                    else:
                        if isinstance(retval, Constant):
                            ret_reg = resolve_val(retval, instrs,
                                                  force_reg=scratch_reg)
                        else:
                            ret_reg = ra(retval)
                        instrs.append([0x80, ret_reg, 0, 0])  # MVHALT

                else:
                    raise ValueError(
                        'Unhandled IR instruction: %s' % type(ins).__name__)

            # ── Phi elimination ──────────────────────────────────────────
            # For each normal successor, for each phi that takes a value from
            # this block, emit MVMOV at the end of this block (before any jump).
            phi_copies = []
            for succ in graph.sucs(block):
                for phi in getattr(succ, 'phis', set()):
                    ops = phi.get_operands()   # dict {pred_block: Value}
                    if block in ops:
                        src_val = ops[block]
                        phi_dst = ra(phi)
                        if isinstance(src_val, Constant):
                            bits = float_bits(src_val.constant, src_val.get_type())
                            idx  = add_const(bits)
                            phi_copies.append(
                                [0x91, phi_dst, (idx >> 8) & 0xFF, idx & 0xFF])
                        else:
                            phi_src = ra(src_val)
                            if phi_dst != phi_src:
                                phi_copies.append([0x90, phi_dst, phi_src, 0])

            # Insert phi copies before the first jump instruction
            if phi_copies and jumps:
                first_jump_pos = min(j[0] for j in jumps)
                # Shift stored jump indices up by the number of copies inserted
                jumps = [(ji + len(phi_copies), jk, jt) for ji, jk, jt in jumps]
                for ci, copy_ins in enumerate(phi_copies):
                    instrs.insert(first_jump_pos + ci, copy_ins)
            elif phi_copies:
                # Tail block (return): insert copies before MVHALT
                insert_at = max(0, len(instrs) - 1)
                for ci, copy_ins in enumerate(phi_copies):
                    instrs.insert(insert_at + ci, copy_ins)

            block_instrs[block] = instrs
            block_jumps[block]  = jumps

        # ── Second pass: assign byte offsets, patch jumps ────────────────
        n_consts    = len(const_table)
        header_size = 4 + n_consts * 8   # [n:1][pad:3] + N×8-byte constants
        # header_size is always 4-byte aligned (4 + N*8 = 4(1+2N))

        block_offset = {}
        cur_off = header_size
        for block in irmethod.irblocks:
            block_offset[block] = cur_off
            cur_off += len(block_instrs[block]) * 4

        if cur_off > MAX_PROG_PLAIN:
            raise ValueError('Program too large: %d bytes' % cur_off)

        # Patch placeholder jump targets
        for block in irmethod.irblocks:
            instrs = block_instrs[block]
            for (ji, jk, jt) in block_jumps[block]:
                tgt_off = block_offset.get(jt[0])
                if tgt_off is None:
                    raise ValueError('Jump to unmapped block (%s)' % jk)
                instrs[ji][2] = (tgt_off >> 8) & 0xFF
                instrs[ji][3] = tgt_off & 0xFF

        # ── Assemble output ───────────────────────────────────────────────
        out = bytearray()

        # Header
        out.append(n_consts & 0xFF)
        out.extend(b'\x00\x00\x00')
        for cv in const_table:
            out.extend(struct.pack('<Q', cv & 0xFFFFFFFFFFFFFFFF))

        # Instructions
        for block in irmethod.irblocks:
            for instr in block_instrs[block]:
                out.extend(bytes(instr))

        return bytes(out)

    # ── JNI shell generation ───────────────────────────────────────────────

    def generate_shell(self, irmethod, jni_name: str,
                       bytecode: bytes, sym_prefix: str) -> str:
        """
        Generate complete C++ source for one protected method:
          - AES-256-CBC encrypted bytecode blobs (C array declarations)
          - Thin JNI shell that packs args → ctx → lvm_method_exec → return

        Each JNI arg is packed at its VM register index (derived from
        entry.move_param_insns + irmethod.ra), so lvm_method_exec pre-loads
        them at the right slots with zero bytecode overhead.
        """
        from dex2c.vm_encryptor import VmEncryptor
        enc = VmEncryptor()
        c_blobs, cs, enc_len = enc.generate_c_blobs(bytecode, sym_prefix)

        method  = irmethod.method
        access  = util.get_access_method(method.get_access_flags())
        rtype   = irmethod.rtype or 'V'   # default void
        is_static = 'static' in access

        # ── Parameter → VM register mapping ─────────────────────────────
        # Walk entry.move_param_insns to find each param's VM slot.
        # MoveParam for 'this' is skipped (its type is an object type).
        entry = irmethod.entry
        param_slots = []   # list of (jni_param_name, vm_slot, type_char)
        for mp in getattr(entry, 'move_param_insns', []):
            param = mp.get_param()
            val   = param.get_value()
            vtype = val.get_type()
            if not _is_primitive(vtype):
                continue   # skip 'this' or any object param
            vm_slot  = irmethod.ra(val)
            reg_num  = val.get_register()
            jni_name_param = 'p%s' % reg_num
            param_slots.append((jni_name_param, vm_slot, vtype))

        # ── Build JNI parameter declaration list ─────────────────────────
        param_decls = ', '.join(
            '%s %s' % (util.get_native_type(pt), pn)
            for pn, _, pt in param_slots
        )

        lines = []
        lines.append('\n/* VM-protected: %s->%s%s  (%d bytes plain, %d encrypted) */\n'
                     % (method.get_class_name(), method.get_name(),
                        method.get_descriptor(), len(bytecode), enc_len))
        lines.append(c_blobs)

        # JNI function signature
        ret_native = util.get_native_type(rtype)
        if param_decls:
            lines.append('%s %s(JNIEnv *env, jobject thiz, %s) {\n'
                         % (ret_native, jni_name, param_decls))
        else:
            lines.append('%s %s(JNIEnv *env, jobject thiz) {\n'
                         % (ret_native, jni_name))

        lines.append('    vm_method_ctx_t _ctx;\n')
        lines.append('    memset(&_ctx, 0, sizeof(_ctx));\n')

        # Pack each JNI arg into ctx->args at its VM register slot
        for pn, vm_slot, pt in param_slots:
            if pt == 'J':
                lines.append('    _ctx.args[%d] = (int64_t)%s;\n'
                             % (vm_slot, pn))
            elif pt == 'F':
                lines.append(
                    '    { float _fv = (float)%s; uint32_t _fb;'
                    ' memcpy(&_fb, &_fv, 4);'
                    ' _ctx.args[%d] = (int64_t)_fb; }\n' % (pn, vm_slot))
            elif pt == 'D':
                lines.append(
                    '    { double _dv = (double)%s; uint64_t _db;'
                    ' memcpy(&_db, &_dv, 8);'
                    ' _ctx.args[%d] = (int64_t)_db; }\n' % (pn, vm_slot))
            else:
                # Z B S C I → cast to int64
                lines.append('    _ctx.args[%d] = (int64_t)%s;\n'
                             % (vm_slot, pn))

        # Dispatch into interpreter
        lines.append('    lvm_method_exec(\n')
        lines.append('        %s_KHI, %s_KLO,\n' % (sym_prefix, sym_prefix))
        lines.append('        %s_IHI, %s_ILO,\n' % (sym_prefix, sym_prefix))
        lines.append('        %s_ENC, %s_LEN, %s_CS, &_ctx);\n'
                     % (sym_prefix, sym_prefix, sym_prefix))

        # Unpack return value
        if rtype in ('V', None):
            lines.append('}\n')
        elif rtype == 'J':
            lines.append('    return (jlong)_ctx.ret_val;\n}\n')
        elif rtype == 'F':
            lines.append('    { float _rf; uint32_t _ru = (uint32_t)_ctx.ret_val;'
                         ' memcpy(&_rf, &_ru, 4); return _rf; }\n}\n')
        elif rtype == 'D':
            lines.append('    { double _rd; uint64_t _ru = (uint64_t)_ctx.ret_val;'
                         ' memcpy(&_rd, &_ru, 8); return _rd; }\n}\n')
        elif rtype == 'Z':
            lines.append('    return (jboolean)(_ctx.ret_val & 1);\n}\n')
        else:
            # I B S C
            lines.append('    return (%s)_ctx.ret_val;\n}\n' % ret_native)

        return ''.join(lines)

    def generate_prototype(self, irmethod, jni_name: str) -> str:
        """Return the JNI function prototype (for DynamicRegister.cpp extern decl)."""
        access    = util.get_access_method(irmethod.method.get_access_flags())
        rtype     = irmethod.rtype or 'V'
        ret_native = util.get_native_type(rtype)

        entry = irmethod.entry
        param_decls_parts = []
        for mp in getattr(entry, 'move_param_insns', []):
            param = mp.get_param()
            val   = param.get_value()
            vtype = val.get_type()
            if not _is_primitive(vtype):
                continue
            pn = 'p%s' % val.get_register()
            param_decls_parts.append('%s %s' % (util.get_native_type(vtype), pn))

        param_decls = ', '.join(param_decls_parts)
        if param_decls:
            return '%s %s(JNIEnv *env, jobject thiz, %s)' % (ret_native, jni_name, param_decls)
        else:
            return '%s %s(JNIEnv *env, jobject thiz)' % (ret_native, jni_name)
