#pragma once

#include <stdint.h>
#include <stddef.h>

#define X86D_MNEM_MAX  16
#define X86D_OP_MAX    32
#define X86D_LINE_MAX  100
#define X86D_MAX_OPERANDS 3
#define X86D_MAX_INSN_LEN 15

typedef enum {
    X86D_OK            =  0,
    X86D_ERR_NULLPTR   = -1,
    X86D_ERR_TRUNCATED = -2,
    X86D_ERR_BADINSN   = -3
} x86d_status_t;

typedef enum {
    X86D_MODE_16 = 16,
    X86D_MODE_32 = 32,
    X86D_MODE_64 = 64
} x86d_mode_t;

typedef enum {
    X86D_OT_NONE = 0,
    X86D_OT_REG,
    X86D_OT_MEM,
    X86D_OT_IMM,
    X86D_OT_REL,
    X86D_OT_MOFFSET
} x86d_optype_t;

typedef enum {
    X86D_REG_NONE = -1,
    /* 8-bit */
    X86D_REG_AL, X86D_REG_CL, X86D_REG_DL, X86D_REG_BL,
    X86D_REG_AH, X86D_REG_CH, X86D_REG_DH, X86D_REG_BH,
    /* 16-bit */
    X86D_REG_AX, X86D_REG_CX, X86D_REG_DX, X86D_REG_BX,
    X86D_REG_SP, X86D_REG_BP, X86D_REG_SI, X86D_REG_DI,
    /* 32-bit */
    X86D_REG_EAX, X86D_REG_ECX, X86D_REG_EDX, X86D_REG_EBX,
    X86D_REG_ESP, X86D_REG_EBP, X86D_REG_ESI, X86D_REG_EDI,
    /* 64-bit */
    X86D_REG_RAX, X86D_REG_RCX, X86D_REG_RDX, X86D_REG_RBX,
    X86D_REG_RSP, X86D_REG_RBP, X86D_REG_RSI, X86D_REG_RDI,
    X86D_REG_R8,  X86D_REG_R9,  X86D_REG_R10, X86D_REG_R11,
    X86D_REG_R12, X86D_REG_R13, X86D_REG_R14, X86D_REG_R15,
    /* segment */
    X86D_REG_ES, X86D_REG_CS, X86D_REG_SS, X86D_REG_DS,
    X86D_REG_FS, X86D_REG_GS,
    /* ip */
    X86D_REG_RIP,
    /* x87 */
    X86D_REG_ST0, X86D_REG_ST1, X86D_REG_ST2, X86D_REG_ST3,
    X86D_REG_ST4, X86D_REG_ST5, X86D_REG_ST6, X86D_REG_ST7,
} x86d_reg_t;

typedef struct {
    x86d_optype_t type;
    int           size;       /* operand size in bytes */
    x86d_reg_t    reg;
    /* memory: [base + index*scale + disp] */
    x86d_reg_t    base;
    x86d_reg_t    index;
    int           scale;
    int64_t       disp;
    int           disp_size;  /* 0, 1, 4 */
    int64_t       imm;
} x86d_operand_t;

typedef struct {
    uint64_t       address;
    uint8_t        bytes[X86D_MAX_INSN_LEN];
    int            size;
    char           mnemonic[X86D_MNEM_MAX];
    x86d_operand_t operands[X86D_MAX_OPERANDS];
    int            operand_count;
    /* prefix flags */
    uint8_t        rex;
    uint8_t        prefix_66;
    uint8_t        prefix_67;
    uint8_t        prefix_f2;
    uint8_t        prefix_f3;
    uint8_t        prefix_seg;
    char           text[X86D_LINE_MAX];
} x86d_insn_t;

typedef struct x86d_ctx x86d_ctx_t;

typedef void (*x86d_insn_cb_t)(const x86d_insn_t *insn, void *userdata);

x86d_ctx_t   *x86d_create(x86d_mode_t mode);
void          x86d_destroy(x86d_ctx_t *ctx);

int           x86d_decode(x86d_ctx_t *ctx,
                          const uint8_t *buf,
                          size_t buf_len,
                          uint64_t pc,
                          x86d_insn_t *out);

x86d_status_t x86d_disasm_buf(x86d_ctx_t *ctx,
                               const uint8_t *buf,
                               size_t buf_len,
                               uint64_t base_addr,
                               x86d_insn_cb_t cb,
                               void *userdata);

const char   *x86d_format(x86d_insn_t *insn);
const char   *x86d_strerror(x86d_status_t status);
