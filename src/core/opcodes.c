#include <core/opcodes.h>

const char *x86d_cc_names[16] = {
    "o","no","b","nb","e","ne","be","a",
    "s","ns","p","np","l","ge","le","g"
};

const char *x86d_reg8_names[16] = {
    "al","cl","dl","bl","ah","ch","dh","bh",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};
const char *x86d_reg16_names[16] = {
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};
const char *x86d_reg32_names[16] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};
const char *x86d_reg64_names[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};
const char *x86d_sreg_names[6] = {
    "es","cs","ss","ds","fs","gs"
};

const char *x86d_grp1_names[8] = {
    "add","or","adc","sbb","and","sub","xor","cmp"
};
const char *x86d_grp2_names[8] = {
    "rol","ror","rcl","rcr","shl","shr","shl","sar"
};
const char *x86d_grp3_names[8] = {
    "test","test","not","neg","mul","imul","div","idiv"
};
const char *x86d_grp4_names[8] = {
    "inc","dec","","","","","",""
};
const char *x86d_grp5_names[8] = {
    "inc","dec","call","callf","jmp","jmpf","push","?"
};
const char *x86d_grp8_names[8] = {
    "","","","","bt","bts","btr","btc"
};

/* x87: for each D8-DF opcode, two sub-tables:
   [0] = mem form mnemonic (modrm.mod != 3)
   [1] = reg form handled inline */

const char *x87_d8_mem[8] = {
    "fadd","fmul","fcom","fcomp","fsub","fsubr","fdiv","fdivr"
};

const char *x87_d9_mem[8] = {
    "fld","","fst","fstp","fldenv","fldcw","fstenv","fstcw"
};

const char *x87_da_mem[8] = {
    "fiadd","fimul","ficom","ficomp","fisub","fisubr","fidiv","fidivr"
};

const char *x87_db_mem[8] = {
    "fild","fisttp","fist","fistp","","fld","","fstp"
};

const char *x87_dc_mem[8] = {
    "fadd","fmul","fcom","fcomp","fsub","fsubr","fdiv","fdivr"
};

const char *x87_dd_mem[8] = {
    "fld","fisttp","fst","fstp","frstor","","fsave","fstsw"
};

const char *x87_de_mem[8] = {
    "fiadd","fimul","ficom","ficomp","fisub","fisubr","fidiv","fidivr"
};

const char *x87_df_mem[8] = {
    "fild","fisttp","fist","fistp","fbld","fild","fbstp","fistp"
};

const x86d_op_entry_t x86d_op_table[] = {
    /* one-byte opcodes */
    { 0x00, ENC_RM8_R8,       "add"    },
    { 0x01, ENC_RM_R,         "add"    },
    { 0x02, ENC_R8_RM8,       "add"    },
    { 0x03, ENC_R_RM,         "add"    },
    { 0x04, ENC_AL_IMM8,      "add"    },
    { 0x05, ENC_RAX_IMM,      "add"    },
    { 0x08, ENC_RM8_R8,       "or"     },
    { 0x09, ENC_RM_R,         "or"     },
    { 0x0A, ENC_R8_RM8,       "or"     },
    { 0x0B, ENC_R_RM,         "or"     },
    { 0x0C, ENC_AL_IMM8,      "or"     },
    { 0x0D, ENC_RAX_IMM,      "or"     },
    { 0x10, ENC_RM8_R8,       "adc"    },
    { 0x11, ENC_RM_R,         "adc"    },
    { 0x12, ENC_R8_RM8,       "adc"    },
    { 0x13, ENC_R_RM,         "adc"    },
    { 0x14, ENC_AL_IMM8,      "adc"    },
    { 0x15, ENC_RAX_IMM,      "adc"    },
    { 0x18, ENC_RM8_R8,       "sbb"    },
    { 0x19, ENC_RM_R,         "sbb"    },
    { 0x1A, ENC_R8_RM8,       "sbb"    },
    { 0x1B, ENC_R_RM,         "sbb"    },
    { 0x1C, ENC_AL_IMM8,      "sbb"    },
    { 0x1D, ENC_RAX_IMM,      "sbb"    },
    { 0x20, ENC_RM8_R8,       "and"    },
    { 0x21, ENC_RM_R,         "and"    },
    { 0x22, ENC_R8_RM8,       "and"    },
    { 0x23, ENC_R_RM,         "and"    },
    { 0x24, ENC_AL_IMM8,      "and"    },
    { 0x25, ENC_RAX_IMM,      "and"    },
    { 0x28, ENC_RM8_R8,       "sub"    },
    { 0x29, ENC_RM_R,         "sub"    },
    { 0x2A, ENC_R8_RM8,       "sub"    },
    { 0x2B, ENC_R_RM,         "sub"    },
    { 0x2C, ENC_AL_IMM8,      "sub"    },
    { 0x2D, ENC_RAX_IMM,      "sub"    },
    { 0x30, ENC_RM8_R8,       "xor"    },
    { 0x31, ENC_RM_R,         "xor"    },
    { 0x32, ENC_R8_RM8,       "xor"    },
    { 0x33, ENC_R_RM,         "xor"    },
    { 0x34, ENC_AL_IMM8,      "xor"    },
    { 0x35, ENC_RAX_IMM,      "xor"    },
    { 0x38, ENC_RM8_R8,       "cmp"    },
    { 0x39, ENC_RM_R,         "cmp"    },
    { 0x3A, ENC_R8_RM8,       "cmp"    },
    { 0x3B, ENC_R_RM,         "cmp"    },
    { 0x3C, ENC_AL_IMM8,      "cmp"    },
    { 0x3D, ENC_RAX_IMM,      "cmp"    },
    /* 0x40-0x4F: REX in 64-bit, inc/dec in 32-bit (handled in decoder) */
    { 0x50, ENC_REG,          "push"   },
    { 0x51, ENC_REG,          "push"   },
    { 0x52, ENC_REG,          "push"   },
    { 0x53, ENC_REG,          "push"   },
    { 0x54, ENC_REG,          "push"   },
    { 0x55, ENC_REG,          "push"   },
    { 0x56, ENC_REG,          "push"   },
    { 0x57, ENC_REG,          "push"   },
    { 0x58, ENC_REG,          "pop"    },
    { 0x59, ENC_REG,          "pop"    },
    { 0x5A, ENC_REG,          "pop"    },
    { 0x5B, ENC_REG,          "pop"    },
    { 0x5C, ENC_REG,          "pop"    },
    { 0x5D, ENC_REG,          "pop"    },
    { 0x5E, ENC_REG,          "pop"    },
    { 0x5F, ENC_REG,          "pop"    },
    { 0x60, ENC_NONE,         "pusha"  },
    { 0x61, ENC_NONE,         "popa"   },
    { 0x63, ENC_R_RM,         "movsxd" },
    { 0x68, ENC_IMM16,        "push"   },
    { 0x69, ENC_R_RM_IMM,     "imul"   },
    { 0x6A, ENC_IMM8,         "push"   },
    { 0x6B, ENC_R_RM_IMM8,    "imul"   },
    { 0x6C, ENC_NONE,         "insb"   },
    { 0x6D, ENC_NONE,         "insd"   },
    { 0x6E, ENC_NONE,         "outsb"  },
    { 0x6F, ENC_NONE,         "outsd"  },
    { 0x70, ENC_REL8,         "jo"     },
    { 0x71, ENC_REL8,         "jno"    },
    { 0x72, ENC_REL8,         "jb"     },
    { 0x73, ENC_REL8,         "jnb"    },
    { 0x74, ENC_REL8,         "je"     },
    { 0x75, ENC_REL8,         "jne"    },
    { 0x76, ENC_REL8,         "jbe"    },
    { 0x77, ENC_REL8,         "ja"     },
    { 0x78, ENC_REL8,         "js"     },
    { 0x79, ENC_REL8,         "jns"    },
    { 0x7A, ENC_REL8,         "jp"     },
    { 0x7B, ENC_REL8,         "jnp"    },
    { 0x7C, ENC_REL8,         "jl"     },
    { 0x7D, ENC_REL8,         "jge"    },
    { 0x7E, ENC_REL8,         "jle"    },
    { 0x7F, ENC_REL8,         "jg"     },
    { 0x80, ENC_GRP1_RM8,     ""       },
    { 0x81, ENC_GRP1_RM,      ""       },
    { 0x83, ENC_GRP1_RM_S8,   ""       },
    { 0x84, ENC_RM8_R8,       "test"   },
    { 0x85, ENC_RM_R,         "test"   },
    { 0x86, ENC_RM8_R8,       "xchg"   },
    { 0x87, ENC_RM_R,         "xchg"   },
    { 0x88, ENC_RM8_R8,       "mov"    },
    { 0x89, ENC_RM_R,         "mov"    },
    { 0x8A, ENC_R8_RM8,       "mov"    },
    { 0x8B, ENC_R_RM,         "mov"    },
    { 0x8C, ENC_RM_SREG,      "mov"    },
    { 0x8D, ENC_R_RM,         "lea"    },
    { 0x8E, ENC_SREG_RM,      "mov"    },
    { 0x8F, ENC_GRP5_RM,      ""       },
    { 0x90, ENC_NONE,         "nop"    },
    { 0x91, ENC_RAX_REG,      "xchg"   },
    { 0x92, ENC_RAX_REG,      "xchg"   },
    { 0x93, ENC_RAX_REG,      "xchg"   },
    { 0x94, ENC_RAX_REG,      "xchg"   },
    { 0x95, ENC_RAX_REG,      "xchg"   },
    { 0x96, ENC_RAX_REG,      "xchg"   },
    { 0x97, ENC_RAX_REG,      "xchg"   },
    { 0x98, ENC_NONE,         "cwde"   },  /* cbw with 66 prefix */
    { 0x99, ENC_NONE,         "cdq"    },  /* cwd with 66 prefix */
    { 0x9B, ENC_NONE,         "fwait"  },
    { 0x9C, ENC_NONE,         "pushf"  },
    { 0x9D, ENC_NONE,         "popf"   },
    { 0x9E, ENC_NONE,         "sahf"   },
    { 0x9F, ENC_NONE,         "lahf"   },
    { 0xA0, ENC_AL_MOFF,      "mov"    },
    { 0xA1, ENC_RAX_MOFF,     "mov"    },
    { 0xA2, ENC_MOFF_AL,      "mov"    },
    { 0xA3, ENC_MOFF_RAX,     "mov"    },
    { 0xA4, ENC_NONE,         "movsb"  },
    { 0xA5, ENC_NONE,         "movsd"  },
    { 0xA6, ENC_NONE,         "cmpsb"  },
    { 0xA7, ENC_NONE,         "cmpsd"  },
    { 0xA8, ENC_AL_IMM8,      "test"   },
    { 0xA9, ENC_RAX_IMM,      "test"   },
    { 0xAA, ENC_NONE,         "stosb"  },
    { 0xAB, ENC_NONE,         "stosd"  },
    { 0xAC, ENC_NONE,         "lodsb"  },
    { 0xAD, ENC_NONE,         "lodsd"  },
    { 0xAE, ENC_NONE,         "scasb"  },
    { 0xAF, ENC_NONE,         "scasd"  },
    { 0xB0, ENC_REG_IMM8,     "mov"    },
    { 0xB1, ENC_REG_IMM8,     "mov"    },
    { 0xB2, ENC_REG_IMM8,     "mov"    },
    { 0xB3, ENC_REG_IMM8,     "mov"    },
    { 0xB4, ENC_REG_IMM8,     "mov"    },
    { 0xB5, ENC_REG_IMM8,     "mov"    },
    { 0xB6, ENC_REG_IMM8,     "mov"    },
    { 0xB7, ENC_REG_IMM8,     "mov"    },
    { 0xB8, ENC_REG_IMM,      "mov"    },
    { 0xB9, ENC_REG_IMM,      "mov"    },
    { 0xBA, ENC_REG_IMM,      "mov"    },
    { 0xBB, ENC_REG_IMM,      "mov"    },
    { 0xBC, ENC_REG_IMM,      "mov"    },
    { 0xBD, ENC_REG_IMM,      "mov"    },
    { 0xBE, ENC_REG_IMM,      "mov"    },
    { 0xBF, ENC_REG_IMM,      "mov"    },
    { 0xC0, ENC_GRP2_RM8_IMM8,"" },
    { 0xC1, ENC_GRP2_RM_IMM8, ""       },
    { 0xC2, ENC_IMM16,        "ret"    },
    { 0xC3, ENC_NONE,         "ret"    },
    { 0xC8, ENC_IMM16_IMM8,   "enter"  },
    { 0xC9, ENC_NONE,         "leave"  },
    { 0xCA, ENC_IMM16,        "retf"   },
    { 0xCB, ENC_NONE,         "retf"   },
    { 0xCC, ENC_NONE,         "int3"   },
    { 0xCD, ENC_IMM8,         "int"    },
    { 0xCE, ENC_NONE,         "into"   },
    { 0xCF, ENC_NONE,         "iret"   },
    { 0xD0, ENC_GRP2_RM8_1,   ""       },
    { 0xD1, ENC_GRP2_RM_1,    ""       },
    { 0xD2, ENC_GRP2_RM8_CL,  ""       },
    { 0xD3, ENC_GRP2_RM_CL,   ""       },
    { 0xD7, ENC_NONE,         "xlat"   },
    /* D8-DF: x87 FPU (future) */
    { 0xE0, ENC_REL8,         "loopne" },
    { 0xE1, ENC_REL8,         "loope"  },
    { 0xE2, ENC_REL8,         "loop"   },
    { 0xE3, ENC_REL8,         "jecxz"  },
    { 0xE4, ENC_AL_IMM8,      "in"     },
    { 0xE5, ENC_AL_IMM8,      "in"     },
    { 0xE6, ENC_IMM8,         "out"    },
    { 0xE7, ENC_IMM8,        "out"    },
    { 0xE8, ENC_REL32,        "call"   },
    { 0xE9, ENC_REL32,        "jmp"    },
    { 0xEB, ENC_REL8,         "jmp"    },
    { 0xEC, ENC_AL_DX,        "in"     },
    { 0xED, ENC_RAX_DX,       "in"     },
    { 0xEE, ENC_DX_AL,        "out"    },
    { 0xEF, ENC_DX_RAX,       "out"    },
    { 0xF1, ENC_NONE,         "int1"   },
    { 0xF4, ENC_NONE,         "hlt"    },
    { 0xF5, ENC_NONE,         "cmc"    },
    { 0xF6, ENC_GRP3_RM8,     ""       },
    { 0xF7, ENC_GRP3_RM,      ""       },
    { 0xF8, ENC_NONE,         "clc"    },
    { 0xF9, ENC_NONE,         "stc"    },
    { 0xFA, ENC_NONE,         "cli"    },
    { 0xFB, ENC_NONE,         "sti"    },
    { 0xFC, ENC_NONE,         "cld"    },
    { 0xFD, ENC_NONE,         "std"    },
    { 0xFE, ENC_GRP4_RM8,     ""       },
    { 0xFF, ENC_GRP5_RM,      ""       },

    /* two-byte opcodes (0F prefix) */
    { 0x0F00, ENC_RM,         "sldt"   },  /* grp6, handled specially */
    { 0x0F01, ENC_RM,         "sgdt"   },  /* grp7, handled specially */
    { 0x0F05, ENC_NONE,       "syscall"},
    { 0x0F06, ENC_NONE,       "clts"   },
    { 0x0F07, ENC_NONE,       "sysret" },
    { 0x0F08, ENC_NONE,       "invd"   },
    { 0x0F09, ENC_NONE,       "wbinvd" },
    { 0x0F0B, ENC_NONE,       "ud2"    },
    { 0x0F0D, ENC_RM,         "prefetchw"},
    { 0x0F1F, ENC_RM,         "nop"    },
    { 0x0F20, ENC_R_RM,       "mov"    },  /* mov r64, cr */
    { 0x0F21, ENC_R_RM,       "mov"    },  /* mov r64, dr */
    { 0x0F22, ENC_RM_R,       "mov"    },  /* mov cr, r64 */
    { 0x0F23, ENC_RM_R,       "mov"    },  /* mov dr, r64 */
    { 0x0F30, ENC_NONE,       "wrmsr"  },
    { 0x0F31, ENC_NONE,       "rdtsc"  },
    { 0x0F32, ENC_NONE,       "rdmsr"  },
    { 0x0F33, ENC_NONE,       "rdpmc"  },
    { 0x0F34, ENC_NONE,       "sysenter"},
    { 0x0F35, ENC_NONE,       "sysexit" },
    { 0x0F40, ENC_R_RM,       "cmovo"  },
    { 0x0F41, ENC_R_RM,       "cmovno" },
    { 0x0F42, ENC_R_RM,       "cmovb"  },
    { 0x0F43, ENC_R_RM,       "cmovnb" },
    { 0x0F44, ENC_R_RM,       "cmove"  },
    { 0x0F45, ENC_R_RM,       "cmovne" },
    { 0x0F46, ENC_R_RM,       "cmovbe" },
    { 0x0F47, ENC_R_RM,       "cmova"  },
    { 0x0F48, ENC_R_RM,       "cmovs"  },
    { 0x0F49, ENC_R_RM,       "cmovns" },
    { 0x0F4A, ENC_R_RM,       "cmovp"  },
    { 0x0F4B, ENC_R_RM,       "cmovnp" },
    { 0x0F4C, ENC_R_RM,       "cmovl"  },
    { 0x0F4D, ENC_R_RM,       "cmovge" },
    { 0x0F4E, ENC_R_RM,       "cmovle" },
    { 0x0F4F, ENC_R_RM,       "cmovg"  },
    { 0x0F80, ENC_REL32,      "jo"     },
    { 0x0F81, ENC_REL32,      "jno"    },
    { 0x0F82, ENC_REL32,      "jb"     },
    { 0x0F83, ENC_REL32,      "jnb"    },
    { 0x0F84, ENC_REL32,      "je"     },
    { 0x0F85, ENC_REL32,      "jne"    },
    { 0x0F86, ENC_REL32,      "jbe"    },
    { 0x0F87, ENC_REL32,      "ja"     },
    { 0x0F88, ENC_REL32,      "js"     },
    { 0x0F89, ENC_REL32,      "jns"    },
    { 0x0F8A, ENC_REL32,      "jp"     },
    { 0x0F8B, ENC_REL32,      "jnp"    },
    { 0x0F8C, ENC_REL32,      "jl"     },
    { 0x0F8D, ENC_REL32,      "jge"    },
    { 0x0F8E, ENC_REL32,      "jle"    },
    { 0x0F8F, ENC_REL32,      "jg"     },
    { 0x0F90, ENC_RM8,        "seto"   },
    { 0x0F91, ENC_RM8,        "setno"  },
    { 0x0F92, ENC_RM8,        "setb"   },
    { 0x0F93, ENC_RM8,        "setnb"  },
    { 0x0F94, ENC_RM8,        "sete"   },
    { 0x0F95, ENC_RM8,        "setne"  },
    { 0x0F96, ENC_RM8,        "setbe"  },
    { 0x0F97, ENC_RM8,        "seta"   },
    { 0x0F98, ENC_RM8,        "sets"   },
    { 0x0F99, ENC_RM8,        "setns"  },
    { 0x0F9A, ENC_RM8,        "setp"   },
    { 0x0F9B, ENC_RM8,        "setnp"  },
    { 0x0F9C, ENC_RM8,        "setl"   },
    { 0x0F9D, ENC_RM8,        "setge"  },
    { 0x0F9E, ENC_RM8,        "setle"  },
    { 0x0F9F, ENC_RM8,        "setg"   },
    { 0x0FA0, ENC_NONE,       "push"   },  /* push fs */
    { 0x0FA1, ENC_NONE,       "pop"    },  /* pop fs */
    { 0x0FA2, ENC_NONE,       "cpuid"  },
    { 0x0FA3, ENC_RM_R,       "bt"     },
    { 0x0FA5, ENC_RM_R_CL,    "shld"   },
    { 0x0FA8, ENC_NONE,       "push"   },  /* push gs */
    { 0x0FA9, ENC_NONE,       "pop"    },  /* pop gs */
    { 0x0FAA, ENC_NONE,       "rsm"    },
    { 0x0FAB, ENC_RM_R,       "bts"    },
    { 0x0FAC, ENC_RM_R_IMM8,  "shrd"   },
    { 0x0FA4, ENC_RM_R_IMM8,  "shld"   },  /* + imm8 */
    { 0x0FAD, ENC_RM_R_CL,    "shrd"   },
    { 0x0FAF, ENC_R_RM,       "imul"   },
    { 0x0FB0, ENC_RM8_R8,     "cmpxchg"},
    { 0x0FB1, ENC_RM_R,       "cmpxchg"},
    { 0x0FB3, ENC_RM_R,       "btr"    },
    { 0x0FB6, ENC_R_RM8,      "movzx"  },
    { 0x0FB7, ENC_R_RM16,     "movzx"  },
    { 0x0FB8, ENC_R_RM,       "popcnt" },  /* F3 prefix */
    { 0x0FBA, ENC_GRP8_RM,    ""       },  /* grp8: bt/bts/btr/btc r/m, imm8 */
    { 0x0FBB, ENC_RM_R,       "btc"    },
    { 0x0FBC, ENC_R_RM,       "bsf"    },
    { 0x0FBD, ENC_R_RM,       "bsr"    },
    { 0x0FBE, ENC_R_RM8,      "movsx"  },
    { 0x0FBF, ENC_R_RM16,     "movsx"  },
    { 0x0FC0, ENC_RM8_R8,     "xadd"   },
    { 0x0FC1, ENC_RM_R,       "xadd"   },
    { 0x0FC8, ENC_NONE,       "bswap"  },  /* bswap eax/rax */
    { 0x0FC9, ENC_NONE,       "bswap"  },
    { 0x0FCA, ENC_NONE,       "bswap"  },
    { 0x0FCB, ENC_NONE,       "bswap"  },
    { 0x0FCC, ENC_NONE,       "bswap"  },
    { 0x0FCD, ENC_NONE,       "bswap"  },
    { 0x0FCE, ENC_NONE,       "bswap"  },
    { 0x0FCF, ENC_NONE,       "bswap"  },
    { 0x0FBA, ENC_GRP8_RM, "" },
    { 0xD8, ENC_FPU_M32,  "" },
    { 0xD9, ENC_FPU_M32,  "" },
    { 0xDA, ENC_FPU_M32I, "" },
    { 0xDB, ENC_FPU_M32I, "" },
    { 0xDC, ENC_FPU_M64,  "" },
    { 0xDD, ENC_FPU_M64,  "" },
    { 0xDE, ENC_FPU_M16,  "" },
    { 0xDF, ENC_FPU_M16,  "" },
};

const int x86d_op_table_len =
    (int)(sizeof(x86d_op_table) / sizeof(x86d_op_table[0]));
