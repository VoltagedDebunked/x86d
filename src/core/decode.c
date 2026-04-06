#include <string.h>
#include <stdio.h>
#include <core/decode.h>
#include <core/opcodes.h>

#define REX_W(r) (((r) >> 3) & 1)
#define REX_R(r) (((r) >> 2) & 1)
#define REX_X(r) (((r) >> 1) & 1)
#define REX_B(r) (((r) >> 0) & 1)

#define MODRM_MOD(b) (((b) >> 6) & 0x03)
#define MODRM_REG(b) (((b) >> 3) & 0x07)
#define MODRM_RM(b)  (((b) >> 0) & 0x07)

#define SIB_SCALE(b) (((b) >> 6) & 0x03)
#define SIB_INDEX(b) (((b) >> 3) & 0x07)
#define SIB_BASE(b)  (((b) >> 0) & 0x07)

#define NEED(n) do { if (!can_read(c, (n))) return X86D_ERR_TRUNCATED; } while(0)

typedef struct {
    const uint8_t *buf;
    size_t         buf_len;
    size_t         off;
    x86d_mode_t    mode;
    uint8_t        rex;
    int            opsz;
    int            addrsz;
    uint8_t        prefix_66;
    uint8_t        prefix_67;
    uint8_t        prefix_f2;
    uint8_t        prefix_f3;
    uint8_t        prefix_seg;
} dec_ctx_t;

static x86d_reg_t gpr(dec_ctx_t *c, int idx, int ext_bit, int size);

static int can_read(dec_ctx_t *c, size_t n)
{
    return (c->off + n) <= c->buf_len;
}

static uint8_t read8(dec_ctx_t *c)
{
    return c->buf[c->off++];
}

static uint16_t read16(dec_ctx_t *c)
{
    uint16_t v = (uint16_t)(c->buf[c->off] | (c->buf[c->off+1] << 8));
    c->off += 2;
    return v;
}

static uint32_t read32(dec_ctx_t *c)
{
    uint32_t v = (uint32_t)(c->buf[c->off]           |
                            ((uint32_t)c->buf[c->off+1] << 8)  |
                            ((uint32_t)c->buf[c->off+2] << 16) |
                            ((uint32_t)c->buf[c->off+3] << 24));
    c->off += 4;
    return v;
}

static uint64_t read64(dec_ctx_t *c)
{
    uint64_t lo = read32(c);
    uint64_t hi = read32(c);
    return lo | (hi << 32);
}

static x86d_reg_t gpr(dec_ctx_t *c, int idx, int ext_bit, int size)
{
    (void)c;
    int full = (idx & 7) | (ext_bit << 3);
    switch (size) {
        case 1:  return (x86d_reg_t)(X86D_REG_AL  + full);
        case 2:  return (x86d_reg_t)(X86D_REG_AX  + full);
        case 4:  return (x86d_reg_t)(X86D_REG_EAX + full);
        case 8:  return (x86d_reg_t)(X86D_REG_RAX + full);
        default: return X86D_REG_NONE;
    }
}

static int decode_modrm(dec_ctx_t *c,
                         x86d_operand_t *rm_op,
                         x86d_operand_t *reg_op,
                         int opsz,
                         int reg_ext,
                         int rm_ext)
{
    if (!can_read(c, 1)) return -1;
    uint8_t modrm = read8(c);
    int mod = MODRM_MOD(modrm);

    if (reg_op) {
        reg_op->type = X86D_OT_REG;
        reg_op->size = opsz;
        reg_op->reg  = gpr(c, MODRM_REG(modrm), reg_ext, opsz);
    }

    if (mod == 3) {
        rm_op->type = X86D_OT_REG;
        rm_op->size = opsz;
        rm_op->reg  = gpr(c, MODRM_RM(modrm), rm_ext, opsz);
        return 0;
    }

    rm_op->type      = X86D_OT_MEM;
    rm_op->size      = opsz;
    rm_op->base      = X86D_REG_NONE;
    rm_op->index     = X86D_REG_NONE;
    rm_op->scale     = 1;
    rm_op->disp      = 0;
    rm_op->disp_size = 0;

    int rm_idx = MODRM_RM(modrm) | (rm_ext << 3);

    if (c->addrsz >= 4) {
        int use_sib = ((rm_idx & 7) == 4);

        if (mod == 0 && (rm_idx & 7) == 5) {
            if (!can_read(c, 4)) return -1;
            rm_op->disp      = (int32_t)read32(c);
            rm_op->disp_size = 4;
            if (c->mode == X86D_MODE_64) rm_op->base = X86D_REG_RIP;
            return 0;
        }

        if (use_sib) {
            if (!can_read(c, 1)) return -1;
            uint8_t sib   = read8(c);
            int scale_exp = SIB_SCALE(sib);
            int idx       = SIB_INDEX(sib) | (REX_X(c->rex) << 3);
            int base      = SIB_BASE(sib)  | (REX_B(c->rex) << 3);
            rm_op->scale  = 1 << scale_exp;
            if ((idx & 7) != 4)
                rm_op->index = (x86d_reg_t)(X86D_REG_RAX + idx);
            if (mod == 0 && (base & 7) == 5) {
                if (!can_read(c, 4)) return -1;
                rm_op->disp      = (int32_t)read32(c);
                rm_op->disp_size = 4;
            } else {
                rm_op->base = (x86d_reg_t)(X86D_REG_RAX + base);
            }
        } else {
            rm_op->base = (x86d_reg_t)(X86D_REG_RAX + rm_idx);
        }

        if (mod == 1) {
            if (!can_read(c, 1)) return -1;
            rm_op->disp      = (int8_t)read8(c);
            rm_op->disp_size = 1;
        } else if (mod == 2) {
            if (!can_read(c, 4)) return -1;
            rm_op->disp      = (int32_t)read32(c);
            rm_op->disp_size = 4;
        }
    } else {
        /* 16-bit addressing */
        static const x86d_reg_t base16[8] = {
            X86D_REG_BX, X86D_REG_BX, X86D_REG_BP, X86D_REG_BP,
            X86D_REG_SI, X86D_REG_DI, X86D_REG_BP, X86D_REG_BX
        };
        static const x86d_reg_t idx16[8] = {
            X86D_REG_SI,   X86D_REG_DI,   X86D_REG_SI,   X86D_REG_DI,
            X86D_REG_NONE, X86D_REG_NONE, X86D_REG_NONE, X86D_REG_NONE
        };
        if (mod == 0 && (rm_idx & 7) == 6) {
            if (!can_read(c, 2)) return -1;
            rm_op->disp      = (int16_t)read16(c);
            rm_op->disp_size = 2;
        } else {
            rm_op->base  = base16[rm_idx & 7];
            rm_op->index = idx16[rm_idx & 7];
            rm_op->scale = 1;
            if (mod == 1) {
                if (!can_read(c, 1)) return -1;
                rm_op->disp      = (int8_t)read8(c);
                rm_op->disp_size = 1;
            } else if (mod == 2) {
                if (!can_read(c, 2)) return -1;
                rm_op->disp      = (int16_t)read16(c);
                rm_op->disp_size = 2;
            }
        }
    }
    return 0;
}

static void fmt_reg(x86d_reg_t r, char *buf, size_t sz)
{
    if (r >= X86D_REG_RAX && r <= X86D_REG_R15)
        snprintf(buf, sz, "%s", x86d_reg64_names[r - X86D_REG_RAX]);
    else if (r >= X86D_REG_EAX && r <= X86D_REG_EDI)
        snprintf(buf, sz, "%s", x86d_reg32_names[r - X86D_REG_EAX]);
    else if (r >= X86D_REG_AX && r <= X86D_REG_DI)
        snprintf(buf, sz, "%s", x86d_reg16_names[r - X86D_REG_AX]);
    else if (r >= X86D_REG_AL && r <= X86D_REG_BH)
        snprintf(buf, sz, "%s", x86d_reg8_names[r - X86D_REG_AL]);
    else if (r >= X86D_REG_ES && r <= X86D_REG_GS)
        snprintf(buf, sz, "%s", x86d_sreg_names[r - X86D_REG_ES]);
    else if (r == X86D_REG_RIP)
        snprintf(buf, sz, "rip");
    else if (r >= X86D_REG_ST0 && r <= X86D_REG_ST7)
        snprintf(buf, sz, "st%d", r - X86D_REG_ST0);
    else
        snprintf(buf, sz, "r?");
}

static void fmt_operand(dec_ctx_t *c, const x86d_operand_t *op,
                         char *buf, size_t bufsz, uint64_t next_pc)
{
    (void)c;

    if (op->type == X86D_OT_REG) {
        fmt_reg(op->reg, buf, bufsz);
        return;
    }

    if (op->type == X86D_OT_IMM) {
        switch (op->size) {
            case 1:  snprintf(buf, bufsz, "0x%02x",            (uint8_t)op->imm);  break;
            case 2:  snprintf(buf, bufsz, "0x%04x",            (uint16_t)op->imm); break;
            case 4:  snprintf(buf, bufsz, "0x%08x",            (uint32_t)op->imm); break;
            default: snprintf(buf, bufsz, "0x%016llx", (unsigned long long)op->imm); break;
        }
        return;
    }

    if (op->type == X86D_OT_REL) {
        uint64_t target = (uint64_t)((int64_t)next_pc + op->imm);
        snprintf(buf, bufsz, "0x%llx", (unsigned long long)target);
        return;
    }

    if (op->type == X86D_OT_MOFFSET) {
        snprintf(buf, bufsz, "[0x%llx]", (unsigned long long)op->imm);
        return;
    }

    if (op->type == X86D_OT_MEM) {
        static const char *sz_pfx[] = {
            "","byte ptr ","word ptr ","","dword ptr ","","","","qword ptr ","","tbyte ptr "
        };
        const char *pfx = (op->size >= 1 && op->size <= 10) ? sz_pfx[op->size] : "";
        char inner[80] = {0};
        char tmp[32];
        int  first = 1;

        if (op->base != X86D_REG_NONE) {
            fmt_reg(op->base, inner, sizeof(inner));
            first = 0;
        }

        if (op->index != X86D_REG_NONE) {
            char ireg[16];
            fmt_reg(op->index, ireg, sizeof(ireg));
            if (op->scale > 1)
                snprintf(tmp, sizeof(tmp), "%s%s*%d", first ? "" : "+", ireg, op->scale);
            else
                snprintf(tmp, sizeof(tmp), "%s%s", first ? "" : "+", ireg);
            strncat(inner, tmp, sizeof(inner) - strlen(inner) - 1);
            first = 0;
        }

        if (op->disp != 0 || first) {
            if (op->disp < 0)
                snprintf(tmp, sizeof(tmp), "-0x%llx", (unsigned long long)(-op->disp));
            else
                snprintf(tmp, sizeof(tmp), "%s0x%llx",
                         first ? "" : "+", (unsigned long long)op->disp);
            strncat(inner, tmp, sizeof(inner) - strlen(inner) - 1);
        }

        snprintf(buf, bufsz, "%s[%s]", pfx, inner);
        return;
    }

    snprintf(buf, bufsz, "?");
}

static void build_text(dec_ctx_t *c, x86d_insn_t *out, uint64_t pc)
{
    char hexbuf[X86D_MAX_INSN_LEN * 3 + 1] = {0};
    for (int i = 0; i < out->size; i++) {
        char tmp[4];
        snprintf(tmp, sizeof(tmp), "%02x ", out->bytes[i]);
        strncat(hexbuf, tmp, sizeof(hexbuf) - strlen(hexbuf) - 1);
    }

    char ops[128] = {0};
    uint64_t next_pc = pc + (uint64_t)out->size;
    for (int i = 0; i < out->operand_count; i++) {
        char op_str[96] = {0};
        fmt_operand(c, &out->operands[i], op_str, sizeof(op_str), next_pc);
        if (i > 0) strncat(ops, ", ", sizeof(ops) - strlen(ops) - 1);
        strncat(ops, op_str, sizeof(ops) - strlen(ops) - 1);
    }

    snprintf(out->text, X86D_LINE_MAX, "%016llx:  %-24s %-11s%s",
             (unsigned long long)out->address, hexbuf, out->mnemonic, ops);
}

static void set_mnem(x86d_insn_t *out, const char *m)
{
    strncpy(out->mnemonic, m, X86D_MNEM_MAX - 1);
    out->mnemonic[X86D_MNEM_MAX - 1] = '\0';
}

static x86d_operand_t *next_op(x86d_insn_t *out)
{
    if (out->operand_count >= X86D_MAX_OPERANDS)
        return &out->operands[X86D_MAX_OPERANDS - 1];
    return &out->operands[out->operand_count++];
}

static void add_reg_op(x86d_insn_t *out, x86d_reg_t reg, int size)
{
    x86d_operand_t *op = next_op(out);
    op->type = X86D_OT_REG;
    op->reg  = reg;
    op->size = size;
}

static void add_imm_op(x86d_insn_t *out, int64_t imm, int size)
{
    x86d_operand_t *op = next_op(out);
    op->type = X86D_OT_IMM;
    op->imm  = imm;
    op->size = size;
}

static void add_rel_op(x86d_insn_t *out, int64_t rel, int size)
{
    x86d_operand_t *op = next_op(out);
    op->type = X86D_OT_REL;
    op->imm  = rel;
    op->size = size;
}

static void add_moff_op(x86d_insn_t *out, int64_t addr, int size)
{
    x86d_operand_t *op = next_op(out);
    op->type = X86D_OT_MOFFSET;
    op->imm  = addr;
    op->size = size;
}

static const x86d_op_entry_t *find_entry(uint16_t opc)
{
    for (int i = 0; i < x86d_op_table_len; i++) {
        if (x86d_op_table[i].opc == opc)
            return &x86d_op_table[i];
    }
    return NULL;
}

/* peek at modrm.reg without consuming */
static int peek_modrm_reg(dec_ctx_t *c)
{
    if (!can_read(c, 1)) return -1;
    return MODRM_REG(c->buf[c->off]);
}

static int decode_fpu(dec_ctx_t *c, x86d_insn_t *out, uint8_t esc)
{
    if (!can_read(c, 1)) return -1;
    uint8_t modrm = c->buf[c->off];
    int mod = MODRM_MOD(modrm);
    int reg = MODRM_REG(modrm);
    int rm  = MODRM_RM(modrm);

    if (mod != 3) {
        /* memory form: mnemonic from group table, operand from modrm */
        const char *mnem = "";
        int opsz = 4;
        x86d_operand_t rm_op = {0};

        switch (esc) {
            case 0xD8: mnem = x87_d8_mem[reg]; opsz = 4; break;
            case 0xD9:
                mnem = x87_d9_mem[reg];
                opsz = (reg == 4 || reg == 6) ? 0  /* env/state, no size prefix */
                     : (reg == 5 || reg == 7) ? 2  /* fldcw/fstcw: word */
                     : 4;
                break;
            case 0xDA: mnem = x87_da_mem[reg]; opsz = 4; break;
            case 0xDB:
                mnem = x87_db_mem[reg];
                opsz = (reg == 5 || reg == 7) ? 10 /* 80-bit */
                     : 4;
                break;
            case 0xDC: mnem = x87_dc_mem[reg]; opsz = 8; break;
            case 0xDD:
                mnem = x87_dd_mem[reg];
                opsz = (reg == 7) ? 2    /* fstsw: word */
                     : 8;                /* everything else: qword for fld/fst/fstp, 0 would suppress frstor/fsave */
                break;
            case 0xDE: mnem = x87_de_mem[reg]; opsz = 2; break;
            case 0xDF:
                mnem = x87_df_mem[reg];
                opsz = (reg == 4 || reg == 6) ? 10 /* fbld/fbstp: 80-bit BCD */
                     : (reg == 5 || reg == 7) ? 8  /* fild/fistp qword */
                     : 2;
                break;
        }

        if (mnem[0] == '\0') {
            /* reserved/undefined */
            set_mnem(out, ".byte");
            c->off++; /* consume the modrm */
            return 0;
        }

        set_mnem(out, mnem);
        if (decode_modrm(c, &rm_op, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
        if (opsz != 0) *next_op(out) = rm_op;
        return 0;
    }

    /* mod == 3: register forms, second opcode = modrm byte */
    c->off++; /* consume modrm */
    uint8_t second = (uint8_t)((reg << 3) | rm); /* low 6 bits used */

    switch (esc) {
        case 0xD8:
            /* D8 C0+i: fadd st0,sti  D8 C8+i: fmul  D8 D0+i: fcom
               D8 D8+i: fcomp  D8 E0+i: fsub  D8 E8+i: fsubr
               D8 F0+i: fdiv   D8 F8+i: fdivr */
            switch (reg) {
                case 0: set_mnem(out, "fadd");  goto st0_sti;
                case 1: set_mnem(out, "fmul");  goto st0_sti;
                case 2: set_mnem(out, "fcom");  goto st0_sti;
                case 3: set_mnem(out, "fcomp"); goto st0_sti;
                case 4: set_mnem(out, "fsub");  goto st0_sti;
                case 5: set_mnem(out, "fsubr"); goto st0_sti;
                case 6: set_mnem(out, "fdiv");  goto st0_sti;
                case 7: set_mnem(out, "fdivr"); goto st0_sti;
            }
            break;

        case 0xD9:
            switch (second) {
                case 0x00 ... 0x07: set_mnem(out, "fld");   goto sti_only;
                case 0x08 ... 0x0F: set_mnem(out, "fxch");  goto sti_only;
                case 0x10: set_mnem(out, "fnop"); break;
                case 0x20: set_mnem(out, "fchs"); break;
                case 0x21: set_mnem(out, "fabs"); break;
                case 0x24: set_mnem(out, "ftst"); break;
                case 0x25: set_mnem(out, "fxam"); break;
                case 0x28: set_mnem(out, "fld1"); break;
                case 0x29: set_mnem(out, "fldl2t"); break;
                case 0x2A: set_mnem(out, "fldl2e"); break;
                case 0x2B: set_mnem(out, "fldpi"); break;
                case 0x2C: set_mnem(out, "fldlg2"); break;
                case 0x2D: set_mnem(out, "fldln2"); break;
                case 0x2E: set_mnem(out, "fldz"); break;
                case 0x30: set_mnem(out, "f2xm1"); break;
                case 0x31: set_mnem(out, "fyl2x"); break;
                case 0x32: set_mnem(out, "fptan"); break;
                case 0x33: set_mnem(out, "fpatan"); break;
                case 0x34: set_mnem(out, "fxtract"); break;
                case 0x35: set_mnem(out, "fprem1"); break;
                case 0x36: set_mnem(out, "fdecstp"); break;
                case 0x37: set_mnem(out, "fincstp"); break;
                case 0x38: set_mnem(out, "fprem"); break;
                case 0x39: set_mnem(out, "fyl2xp1"); break;
                case 0x3A: set_mnem(out, "fsqrt"); break;
                case 0x3B: set_mnem(out, "fsincos"); break;
                case 0x3C: set_mnem(out, "frndint"); break;
                case 0x3D: set_mnem(out, "fscale"); break;
                case 0x3E: set_mnem(out, "fsin"); break;
                case 0x3F: set_mnem(out, "fcos"); break;
                default:   set_mnem(out, ".byte"); break;
            }
            break;

        case 0xDA:
            switch (second) {
                case 0x00 ... 0x07: set_mnem(out, "fcmovb");  goto st0_sti;
                case 0x08 ... 0x0F: set_mnem(out, "fcmove");  goto st0_sti;
                case 0x10 ... 0x17: set_mnem(out, "fcmovbe"); goto st0_sti;
                case 0x18 ... 0x1F: set_mnem(out, "fcmovu");  goto st0_sti;
                case 0x29:          set_mnem(out, "fucompp"); break;
                default:            set_mnem(out, ".byte");   break;
            }
            break;

        case 0xDB:
            switch (second) {
                case 0x00 ... 0x07: set_mnem(out, "fcmovnb");  goto st0_sti;
                case 0x08 ... 0x0F: set_mnem(out, "fcmovne");  goto st0_sti;
                case 0x10 ... 0x17: set_mnem(out, "fcmovnbe"); goto st0_sti;
                case 0x18 ... 0x1F: set_mnem(out, "fcmovnu");  goto st0_sti;
                case 0x22:          set_mnem(out, "fnclex");   break;
                case 0x23:          set_mnem(out, "fninit");   break;
                case 0x28 ... 0x2F: set_mnem(out, "fucomi");   goto st0_sti;
                case 0x30 ... 0x37: set_mnem(out, "fcomi");    goto st0_sti;
                default:            set_mnem(out, ".byte");    break;
            }
            break;

        case 0xDC:
            switch (reg) {
                case 0: set_mnem(out, "fadd");  goto sti_st0;
                case 1: set_mnem(out, "fmul");  goto sti_st0;
                case 2: set_mnem(out, "fcom");  goto sti_only;
                case 3: set_mnem(out, "fcomp"); goto sti_only;
                case 4: set_mnem(out, "fsubr"); goto sti_st0;
                case 5: set_mnem(out, "fsub");  goto sti_st0;
                case 6: set_mnem(out, "fdivr"); goto sti_st0;
                case 7: set_mnem(out, "fdiv");  goto sti_st0;
            }
            break;

        case 0xDD:
            switch (reg) {
                case 0: set_mnem(out, "ffree");  goto sti_only;
                case 1: set_mnem(out, "fisttp"); goto sti_only;
                case 2: set_mnem(out, "fst");    goto sti_only;
                case 3: set_mnem(out, "fstp");   goto sti_only;
                case 4: set_mnem(out, "fucom");  goto sti_only;
                case 5: set_mnem(out, "fucomp"); goto sti_only;
                default: set_mnem(out, ".byte"); break;
            }
            break;

        case 0xDE:
            switch (reg) {
                case 0: set_mnem(out, "faddp");  goto sti_st0;
                case 1: set_mnem(out, "fmulp");  goto sti_st0;
                case 2: set_mnem(out, "fcomp");  goto sti_only;
                case 3:
                    if (rm == 1) { set_mnem(out, "fcompp"); break; }
                    set_mnem(out, ".byte"); break;
                case 4: set_mnem(out, "fsubrp"); goto sti_st0;
                case 5: set_mnem(out, "fsubp");  goto sti_st0;
                case 6: set_mnem(out, "fdivrp"); goto sti_st0;
                case 7: set_mnem(out, "fdivp");  goto sti_st0;
            }
            break;

        case 0xDF:
            switch (second) {
                case 0x00 ... 0x07: set_mnem(out, "ffreep");  goto sti_only;
                case 0x10 ... 0x17: set_mnem(out, "fisttp");  goto sti_only;
                case 0x18 ... 0x1F: set_mnem(out, "fstp");    goto sti_only;
                case 0x20:          set_mnem(out, "fnstsw");
                    add_reg_op(out, X86D_REG_AX, 2);
                    break;
                case 0x28 ... 0x2F: set_mnem(out, "fucomip"); goto st0_sti;
                case 0x30 ... 0x37: set_mnem(out, "fcomip");  goto st0_sti;
                default:            set_mnem(out, ".byte");   break;
            }
            break;
    }
    return 0;

st0_sti:
    add_reg_op(out, X86D_REG_ST0, 10);
    add_reg_op(out, (x86d_reg_t)(X86D_REG_ST0 + rm), 10);
    return 0;

sti_st0:
    add_reg_op(out, (x86d_reg_t)(X86D_REG_ST0 + rm), 10);
    add_reg_op(out, X86D_REG_ST0, 10);
    return 0;

sti_only:
    add_reg_op(out, (x86d_reg_t)(X86D_REG_ST0 + rm), 10);
    return 0;
}

static int dispatch(dec_ctx_t *c, x86d_insn_t *out,
                     const x86d_op_entry_t *e, uint16_t raw_opc)
{
    int opsz  = c->opsz;
    int R8    = 1;

    set_mnem(out, e->mnemonic);

    switch (e->enc) {
        case ENC_NONE:
            /* handle mnemonic variants that depend on opsz/prefix */
            if (raw_opc == 0x98)
                set_mnem(out, c->opsz == 2 ? "cbw"  : REX_W(c->rex) ? "cdqe" : "cwde");
            else if (raw_opc == 0x99)
                set_mnem(out, c->opsz == 2 ? "cwd"  : REX_W(c->rex) ? "cqo"  : "cdq");
            else if (raw_opc == 0xA4)
                set_mnem(out, "movsb");
            else if (raw_opc == 0xA5)
                set_mnem(out, opsz == 2 ? "movsw" : opsz == 8 ? "movsq" : "movsd");
            else if (raw_opc == 0xA6)
                set_mnem(out, "cmpsb");
            else if (raw_opc == 0xA7)
                set_mnem(out, opsz == 2 ? "cmpsw" : opsz == 8 ? "cmpsq" : "cmpsd");
            else if (raw_opc == 0xAA)
                set_mnem(out, "stosb");
            else if (raw_opc == 0xAB)
                set_mnem(out, opsz == 2 ? "stosw" : opsz == 8 ? "stosq" : "stosd");
            else if (raw_opc == 0xAC)
                set_mnem(out, "lodsb");
            else if (raw_opc == 0xAD)
                set_mnem(out, opsz == 2 ? "lodsw" : opsz == 8 ? "lodsq" : "lodsd");
            else if (raw_opc == 0xAE)
                set_mnem(out, "scasb");
            else if (raw_opc == 0xAF)
                set_mnem(out, opsz == 2 ? "scasw" : opsz == 8 ? "scasq" : "scasd");
            /* bswap short form */
            else if ((raw_opc & 0xFFF8) == 0x0FC8) {
                int reg = (raw_opc & 7) | (REX_B(c->rex) << 3);
                int bsz = REX_W(c->rex) ? 8 : 4;
                add_reg_op(out, gpr(c, reg, 0, bsz), bsz);
            }
            /* push/pop fs/gs */
            else if (raw_opc == 0x0FA0) { set_mnem(out, "push"); add_reg_op(out, X86D_REG_FS, 2); }
            else if (raw_opc == 0x0FA1) { set_mnem(out, "pop");  add_reg_op(out, X86D_REG_FS, 2); }
            else if (raw_opc == 0x0FA8) { set_mnem(out, "push"); add_reg_op(out, X86D_REG_GS, 2); }
            else if (raw_opc == 0x0FA9) { set_mnem(out, "pop");  add_reg_op(out, X86D_REG_GS, 2); }
            break;

        case ENC_RM8_R8: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, R8, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            *next_op(out) = rm; *next_op(out) = reg;
            break;
        }
        case ENC_RM_R: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, opsz, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            *next_op(out) = rm; *next_op(out) = reg;
            break;
        }
        case ENC_R8_RM8: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, R8, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            *next_op(out) = reg; *next_op(out) = rm;
            break;
        }
        case ENC_R_RM: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, opsz, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            *next_op(out) = reg; *next_op(out) = rm;
            break;
        }
        case ENC_R_RM8: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, R8, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            reg.size = opsz; reg.reg = gpr(c, (int)reg.reg - X86D_REG_AL, REX_R(c->rex), opsz);
            *next_op(out) = reg; *next_op(out) = rm;
            break;
        }
        case ENC_R_RM16: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, 2, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            reg.size = opsz; reg.reg = gpr(c, (int)reg.reg - X86D_REG_AX, REX_R(c->rex), opsz);
            *next_op(out) = reg; *next_op(out) = rm;
            break;
        }
        case ENC_AL_IMM8:
            add_reg_op(out, X86D_REG_AL, 1);
            NEED(1); add_imm_op(out, (int8_t)read8(c), 1);
            break;
        case ENC_RAX_IMM:
            add_reg_op(out, gpr(c, 0, 0, opsz), opsz);
            NEED(4); add_imm_op(out, (int32_t)read32(c), 4);
            break;
        case ENC_REG:
            if (raw_opc >= 0x50 && raw_opc <= 0x57) {
                int sz = (c->mode == X86D_MODE_64) ? 8 : opsz;
                add_reg_op(out, gpr(c, raw_opc & 7, REX_B(c->rex), sz), sz);
            } else if (raw_opc >= 0x58 && raw_opc <= 0x5F) {
                int sz = (c->mode == X86D_MODE_64) ? 8 : opsz;
                add_reg_op(out, gpr(c, raw_opc & 7, REX_B(c->rex), sz), sz);
            }
            break;
        case ENC_REG_IMM8:
            add_reg_op(out, gpr(c, raw_opc & 7, REX_B(c->rex), 1), 1);
            NEED(1); add_imm_op(out, read8(c), 1);
            break;
        case ENC_REG_IMM: {
            int sz = REX_W(c->rex) ? 8 : 4;
            add_reg_op(out, gpr(c, raw_opc & 7, REX_B(c->rex), sz), sz);
            if (sz == 8) { NEED(8); add_imm_op(out, (int64_t)read64(c), 8); }
            else         { NEED(4); add_imm_op(out, (int32_t)read32(c), 4); }
            break;
        }
        case ENC_RM8: {
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, R8, 0, REX_B(c->rex)) < 0) return -1;
            *next_op(out) = rm;
            break;
        }
        case ENC_RM_R_IMM8: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, opsz, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            NEED(1); int8_t imm = (int8_t)read8(c);
            *next_op(out) = rm; *next_op(out) = reg;
            add_imm_op(out, imm, 1);
            break;
        }
        case ENC_RM_R_CL: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, opsz, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            *next_op(out) = rm; *next_op(out) = reg;
            add_reg_op(out, X86D_REG_CL, 1);
            break;
        }
        case ENC_RM: {
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
            *next_op(out) = rm;
            break;
        }
        case ENC_REL8:
            NEED(1); add_rel_op(out, (int8_t)read8(c), 1);
            break;
        case ENC_REL32:
            NEED(4); add_rel_op(out, (int32_t)read32(c), 4);
            break;
        case ENC_IMM8:
            NEED(1); add_imm_op(out, read8(c), 1);
            break;
        case ENC_IMM16:
            NEED(2); add_imm_op(out, read16(c), 2);
            break;
        case ENC_IMM16_IMM8:
            NEED(3);
            add_imm_op(out, read16(c), 2);
            add_imm_op(out, read8(c),  1);
            break;
        case ENC_R_RM_IMM8: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, opsz, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            NEED(1); int8_t imm = (int8_t)read8(c);
            *next_op(out) = reg; *next_op(out) = rm;
            add_imm_op(out, imm, 1);
            break;
        }
        case ENC_R_RM_IMM: {
            x86d_operand_t rm = {0}, reg = {0};
            if (decode_modrm(c, &rm, &reg, opsz, REX_R(c->rex), REX_B(c->rex)) < 0) return -1;
            NEED(4); int32_t imm = (int32_t)read32(c);
            *next_op(out) = reg; *next_op(out) = rm;
            add_imm_op(out, imm, 4);
            break;
        }
        case ENC_AL_DX:
            add_reg_op(out, X86D_REG_AL,  1);
            add_reg_op(out, X86D_REG_DX,  2);
            break;
        case ENC_RAX_DX:
            add_reg_op(out, gpr(c, 0, 0, opsz), opsz);
            add_reg_op(out, X86D_REG_DX, 2);
            break;
        case ENC_DX_AL:
            add_reg_op(out, X86D_REG_DX, 2);
            add_reg_op(out, X86D_REG_AL, 1);
            break;
        case ENC_DX_RAX:
            add_reg_op(out, X86D_REG_DX, 2);
            add_reg_op(out, gpr(c, 0, 0, opsz), opsz);
            break;
        case ENC_AL_MOFF: {
            int asz = c->addrsz;
            uint64_t addr = (asz == 8) ? read64(c) : (asz == 4) ? read32(c) : read16(c);
            add_reg_op(out, X86D_REG_AL, 1);
            add_moff_op(out, (int64_t)addr, 1);
            break;
        }
        case ENC_RAX_MOFF: {
            int asz = c->addrsz;
            uint64_t addr = (asz == 8) ? read64(c) : (asz == 4) ? read32(c) : read16(c);
            add_reg_op(out, gpr(c, 0, 0, opsz), opsz);
            add_moff_op(out, (int64_t)addr, opsz);
            break;
        }
        case ENC_MOFF_AL: {
            int asz = c->addrsz;
            uint64_t addr = (asz == 8) ? read64(c) : (asz == 4) ? read32(c) : read16(c);
            add_moff_op(out, (int64_t)addr, 1);
            add_reg_op(out, X86D_REG_AL, 1);
            break;
        }
        case ENC_MOFF_RAX: {
            int asz = c->addrsz;
            uint64_t addr = (asz == 8) ? read64(c) : (asz == 4) ? read32(c) : read16(c);
            add_moff_op(out, (int64_t)addr, opsz);
            add_reg_op(out, gpr(c, 0, 0, opsz), opsz);
            break;
        }
        case ENC_RAX_REG:
            add_reg_op(out, gpr(c, 0, 0, opsz), opsz);
            add_reg_op(out, gpr(c, raw_opc & 7, REX_B(c->rex), opsz), opsz);
            break;
        case ENC_RM_SREG: {
            x86d_operand_t rm = {0};
            int sreg_idx = peek_modrm_reg(c);
            if (decode_modrm(c, &rm, NULL, 2, 0, REX_B(c->rex)) < 0) return -1;
            *next_op(out) = rm;
            if (sreg_idx >= 0 && sreg_idx < 6) add_reg_op(out, (x86d_reg_t)(X86D_REG_ES + sreg_idx), 2);
            break;
        }
        case ENC_SREG_RM: {
            x86d_operand_t rm = {0};
            int sreg_idx = peek_modrm_reg(c);
            if (decode_modrm(c, &rm, NULL, 2, 0, REX_B(c->rex)) < 0) return -1;
            if (sreg_idx >= 0 && sreg_idx < 6) add_reg_op(out, (x86d_reg_t)(X86D_REG_ES + sreg_idx), 2);
            *next_op(out) = rm;
            break;
        }

        /* groups */
        case ENC_GRP1_RM8: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, R8, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp1_names[ext]);
            NEED(1); *next_op(out) = rm; add_imm_op(out, (int8_t)read8(c), 1);
            break;
        }
        case ENC_GRP1_RM: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp1_names[ext]);
            NEED(4); *next_op(out) = rm; add_imm_op(out, (int32_t)read32(c), 4);
            break;
        }
        case ENC_GRP1_RM_S8: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp1_names[ext]);
            NEED(1); *next_op(out) = rm; add_imm_op(out, (int8_t)read8(c), 1);
            break;
        }
        case ENC_GRP2_RM8_1: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, R8, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp2_names[ext]);
            *next_op(out) = rm; add_imm_op(out, 1, 1);
            break;
        }
        case ENC_GRP2_RM_1: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp2_names[ext]);
            *next_op(out) = rm; add_imm_op(out, 1, 1);
            break;
        }
        case ENC_GRP2_RM8_CL: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, R8, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp2_names[ext]);
            *next_op(out) = rm; add_reg_op(out, X86D_REG_CL, 1);
            break;
        }
        case ENC_GRP2_RM_CL: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp2_names[ext]);
            *next_op(out) = rm; add_reg_op(out, X86D_REG_CL, 1);
            break;
        }
        case ENC_GRP2_RM8_IMM8: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, R8, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp2_names[ext]);
            NEED(1); *next_op(out) = rm; add_imm_op(out, read8(c), 1);
            break;
        }
        case ENC_GRP2_RM_IMM8: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp2_names[ext]);
            NEED(1); *next_op(out) = rm; add_imm_op(out, read8(c), 1);
            break;
        }
        case ENC_GRP3_RM8: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, R8, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp3_names[ext]);
            if (ext <= 1) { NEED(1); *next_op(out) = rm; add_imm_op(out, read8(c), 1); }
            else { *next_op(out) = rm; }
            break;
        }
        case ENC_GRP3_RM: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0) set_mnem(out, x86d_grp3_names[ext]);
            if (ext <= 1) { NEED(4); *next_op(out) = rm; add_imm_op(out, (int32_t)read32(c), 4); }
            else { *next_op(out) = rm; }
            break;
        }
        case ENC_GRP4_RM8: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, R8, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 0 && ext < 2) set_mnem(out, x86d_grp4_names[ext]);
            *next_op(out) = rm;
            break;
        }
        case ENC_GRP5_RM: {
            int ext = peek_modrm_reg(c);
            /* for 8F pop, grp5 is reused */
            x86d_operand_t rm = {0};
            if (raw_opc == 0x8F) {
                if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
                set_mnem(out, "pop");
            } else {
                if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
                if (ext >= 0) set_mnem(out, x86d_grp5_names[ext]);
            }
            *next_op(out) = rm;
            break;
        }
        case ENC_GRP8_RM: {
            int ext = peek_modrm_reg(c);
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
            if (ext >= 4) set_mnem(out, x86d_grp8_names[ext]);
            NEED(1); *next_op(out) = rm; add_imm_op(out, read8(c), 1);
            break;
        }
        case ENC_GRP11_RM8: {
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, R8, 0, REX_B(c->rex)) < 0) return -1;
            NEED(1); *next_op(out) = rm; add_imm_op(out, read8(c), 1);
            break;
        }
        case ENC_GRP11_RM: {
            x86d_operand_t rm = {0};
            if (decode_modrm(c, &rm, NULL, opsz, 0, REX_B(c->rex)) < 0) return -1;
            NEED(4); *next_op(out) = rm; add_imm_op(out, (int32_t)read32(c), 4);
            break;
        }

        /* fpu */
        case ENC_FPU_M32:
        case ENC_FPU_M32I:
        case ENC_FPU_M64:
        case ENC_FPU_M64I:
        case ENC_FPU_M80:
        case ENC_FPU_M16:
        case ENC_FPU_M2BYTE:
        case ENC_FPU_ST:
        case ENC_FPU_STI:
        case ENC_FPU_ST_STI:
        case ENC_FPU_STI_ST:
        case ENC_FPU_NONE:
            if (decode_fpu(c, out, (uint8_t)raw_opc) < 0) return -1;
            break;

        default:
            return -1;
    }
    return 0;
}

int decode_insn(x86d_mode_t mode, const uint8_t *buf, size_t buf_len,
                uint64_t pc, x86d_insn_t *out)
{
    if (!buf || !out)  return X86D_ERR_NULLPTR;
    if (buf_len == 0)  return X86D_ERR_TRUNCATED;

    memset(out, 0, sizeof(*out));
    out->address = pc;

    dec_ctx_t c = {0};
    c.buf    = buf;
    c.buf_len = buf_len;
    c.mode   = mode;
    c.opsz   = (mode == X86D_MODE_16) ? 2 : 4;
    c.addrsz = (mode == X86D_MODE_16) ? 2 : (mode == X86D_MODE_32) ? 4 : 8;

    /* legacy prefixes */
    while (c.off < buf_len) {
        uint8_t b = buf[c.off];
        if      (b == 0x66) { c.prefix_66 = 1; c.opsz   = (c.opsz   == 4) ? 2 : 4; c.off++; }
        else if (b == 0x67) { c.prefix_67 = 1; c.addrsz = (c.addrsz == 4) ? 2 : 4; c.off++; }
        else if (b == 0xF2) { c.prefix_f2 = 1; c.off++; }
        else if (b == 0xF3) { c.prefix_f3 = 1; c.off++; }
        else if (b == 0x2E || b == 0x36 || b == 0x3E ||
                 b == 0x26 || b == 0x64 || b == 0x65) { c.prefix_seg = b; c.off++; }
        else break;
    }

    /* REX prefix */
    if (mode == X86D_MODE_64 && c.off < buf_len) {
        uint8_t b = buf[c.off];
        if (b >= 0x40 && b <= 0x4F) {
            c.rex = b;
            c.off++;
            if (REX_W(c.rex)) c.opsz = 8;
        }
    }

    if (c.off >= buf_len) return X86D_ERR_TRUNCATED;

    uint8_t  opc  = read8(&c);
    uint16_t full_opc = opc;

    /* two-byte escape */
    if (opc == 0x0F) {
        if (!can_read(&c, 1)) return X86D_ERR_TRUNCATED;
        full_opc = (uint16_t)(0x0F00 | read8(&c));
    }

    /* 32/64-bit inc/dec short form */
    if (mode != X86D_MODE_64 && full_opc >= 0x40 && full_opc <= 0x4F) {
        set_mnem(out, full_opc <= 0x47 ? "inc" : "dec");
        add_reg_op(out, gpr(&c, full_opc & 7, 0, c.opsz), c.opsz);
        goto done;
    }

    /* rep/repe/repne prefix handling for string ops */
    if (c.prefix_f3 || c.prefix_f2) {
        const char *rep = c.prefix_f3 ? "rep " : "repne ";
        /* will be prepended to mnemonic below after lookup */
        (void)rep;
    }

    {
        const x86d_op_entry_t *e = find_entry(full_opc);
        if (!e) {
            /* unknown */
            snprintf(out->mnemonic, X86D_MNEM_MAX, ".byte");
            out->size = (int)c.off;
            memcpy(out->bytes, buf, (size_t)out->size);
            snprintf(out->text, X86D_LINE_MAX,
                     "%016llx:  %02x                        .byte  0x%02x",
                     (unsigned long long)pc, buf[0], buf[0]);
            return 1;
        }

        if (dispatch(&c, out, e, full_opc) < 0)
            return X86D_ERR_TRUNCATED;

        /* prepend rep if string op */
        if (c.prefix_f3 || c.prefix_f2) {
            static const char *str_ops[] = {
                "movs","cmps","stos","lods","scas",NULL
            };
            int is_str = 0;
            for (int i = 0; str_ops[i]; i++) {
                if (strncmp(out->mnemonic, str_ops[i], 4) == 0) { is_str = 1; break; }
            }
            if (is_str) {
                char tmp[X86D_MNEM_MAX];
                snprintf(tmp, sizeof(tmp), "%s%s",
                         c.prefix_f3 ? "rep " : "repne ", out->mnemonic);
                strncpy(out->mnemonic, tmp, X86D_MNEM_MAX - 1);
            }
        }
    }

done:
    out->size = (int)c.off;
    if (out->size > X86D_MAX_INSN_LEN) out->size = X86D_MAX_INSN_LEN;
    memcpy(out->bytes, buf, (size_t)out->size);

    out->rex        = c.rex;
    out->prefix_66  = c.prefix_66;
    out->prefix_67  = c.prefix_67;
    out->prefix_f2  = c.prefix_f2;
    out->prefix_f3  = c.prefix_f3;
    out->prefix_seg = c.prefix_seg;

    build_text(&c, out, pc);
    return out->size;

#undef NEED
}
