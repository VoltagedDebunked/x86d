#pragma once

#include <stdint.h>

/* operand encoding kinds */
typedef enum {
    ENC_NONE,       /* no operands */
    ENC_RM8_R8,     /* r/m8, r8 */
    ENC_RM_R,       /* r/m16/32/64, r16/32/64 */
    ENC_R8_RM8,     /* r8, r/m8 */
    ENC_R_RM,       /* r16/32/64, r/m16/32/64 */
    ENC_RM8_IMM8,   /* r/m8, imm8 */
    ENC_RM_IMM,     /* r/m16/32/64, imm16/32 */
    ENC_RM_IMM8,    /* r/m16/32/64, imm8 (sign extended) */
    ENC_AL_IMM8,    /* AL, imm8 */
    ENC_RAX_IMM,    /* rAX, imm16/32 */
    ENC_REG_IMM8,   /* reg from opcode low 3 bits, imm8 */
    ENC_REG_IMM,    /* reg from opcode low 3 bits, imm16/32/64 */
    ENC_REG,        /* reg from opcode low 3 bits */
    ENC_RM8,        /* r/m8 */
    ENC_RM,         /* r/m16/32/64 */
    ENC_R_RM8,      /* r16/32/64, r/m8 (movzx/movsx) */
    ENC_R_RM16,     /* r16/32/64, r/m16 (movzx/movsx) */
    ENC_REL8,       /* rel8 */
    ENC_REL32,      /* rel32 */
    ENC_IMM8,       /* imm8 */
    ENC_IMM16,      /* imm16 */
    ENC_IMM16_IMM8, /* imm16, imm8 (enter) */
    ENC_R_RM_IMM8,  /* r, r/m, imm8 (imul) */
    ENC_R_RM_IMM,   /* r, r/m, imm32 (imul) */
    ENC_RM8_CL,     /* r/m8, CL */
    ENC_RM_CL,      /* r/m, CL */
    ENC_RM_R_CL,    /* r/m, r, cl (shld/shrd cl form) */
    ENC_RM8_1,      /* r/m8, 1 */
    ENC_RM_1,       /* r/m, 1 */
    ENC_AL_DX,      /* AL, DX */
    ENC_RAX_DX,     /* rAX, DX */
    ENC_DX_AL,      /* DX, AL */
    ENC_DX_RAX,     /* DX, rAX */
    ENC_AL_MOFF,    /* AL, moffset */
    ENC_RAX_MOFF,   /* rAX, moffset */
    ENC_MOFF_AL,    /* moffset, AL */
    ENC_MOFF_RAX,   /* moffset, rAX */
    ENC_RM_SREG,    /* r/m16, sreg */
    ENC_SREG_RM,    /* sreg, r/m16 */
    ENC_RAX_REG,    /* rAX, reg (xchg short form) */
    ENC_RM_R_IMM8,  /* r/m, r, imm8 (shld/shrd immediate form) */
    /* group encodings (opcode extension in modrm.reg) */
    ENC_GRP1_RM8,   /* group1 r/m8, imm8 */
    ENC_GRP1_RM,    /* group1 r/m, imm */
    ENC_GRP1_RM_S8, /* group1 r/m, imm8 sign extended */
    ENC_GRP2_RM8_1, /* group2 r/m8, 1 */
    ENC_GRP2_RM_1,  /* group2 r/m, 1 */
    ENC_GRP2_RM8_CL,
    ENC_GRP2_RM_CL,
    ENC_GRP2_RM8_IMM8,
    ENC_GRP2_RM_IMM8,
    ENC_GRP3_RM8,   /* group3: test/not/neg/mul/imul/div/idiv r/m8 */
    ENC_GRP3_RM,
    ENC_GRP4_RM8,   /* group4: inc/dec r/m8 */
    ENC_GRP5_RM,    /* group5: inc/dec/call/jmp/push r/m */
    ENC_GRP11_RM8,  /* mov r/m8, imm8 */
    ENC_GRP11_RM,   /* mov r/m, imm */
    ENC_GRP8_RM,    /* group8: bt/bts/btr/btc r/m, imm8 */
    /* fpu */
    ENC_FPU_M32,    /* x87 mem operand, 32-bit float */
    ENC_FPU_M64,    /* x87 mem operand, 64-bit float */
    ENC_FPU_M80,    /* x87 mem operand, 80-bit float */
    ENC_FPU_M16,    /* x87 mem operand, 16-bit int */
    ENC_FPU_M32I,   /* x87 mem operand, 32-bit int */
    ENC_FPU_M64I,   /* x87 mem operand, 64-bit int */
    ENC_FPU_M2BYTE, /* x87 mem operand, 2-byte (fldcw/fstcw etc) */
    ENC_FPU_ST,     /* st0, sti */
    ENC_FPU_STI,    /* sti only */
    ENC_FPU_ST_STI, /* st0, sti */
    ENC_FPU_STI_ST, /* sti, st0 */
    ENC_FPU_NONE,   /* no operands (register form) */
} x86d_enc_t;

/* two-byte (0F) flag */
#define OPC_2BYTE 0x100

typedef struct {
    uint16_t    opc;      /* opcode byte; OPC_2BYTE set if 0F prefix */
    x86d_enc_t  enc;
    const char *mnemonic;
} x86d_op_entry_t;

extern const x86d_op_entry_t x86d_op_table[];
extern const int              x86d_op_table_len;

/* group mnemonic tables */
extern const char *x86d_grp1_names[8];
extern const char *x86d_grp2_names[8];
extern const char *x86d_grp3_names[8];
extern const char *x86d_grp4_names[8];
extern const char *x86d_grp5_names[8];
extern const char *x86d_grp8_names[8];

/* condition code names */
extern const char *x86d_cc_names[16];

/* register name tables */
extern const char *x86d_reg8_names[16];
extern const char *x86d_reg16_names[16];
extern const char *x86d_reg32_names[16];
extern const char *x86d_reg64_names[16];
extern const char *x86d_sreg_names[6];

/* fpu */
extern const char *x87_d8_mem[8];
extern const char *x87_d9_mem[8];
extern const char *x87_da_mem[8];
extern const char *x87_db_mem[8];
extern const char *x87_dc_mem[8];
extern const char *x87_dd_mem[8];
extern const char *x87_de_mem[8];
extern const char *x87_df_mem[8];
