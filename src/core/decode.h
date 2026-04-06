#pragma once

#include <libx86d.h>
#include <core/opcodes.h>

int decode_insn(x86d_mode_t mode,
                const uint8_t *buf,
                size_t buf_len,
                uint64_t pc,
                x86d_insn_t *out);
