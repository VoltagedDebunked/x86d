#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libx86d.h>
#include <core/core.h>
#include <core/decode.h>

x86d_ctx_t *x86d_create(x86d_mode_t mode)
{
    x86d_ctx_t *ctx = calloc(1, sizeof(x86d_ctx_t));
    if (ctx) ctx->mode = mode;
    return ctx;
}

void x86d_destroy(x86d_ctx_t *ctx)
{
    free(ctx);
}

int x86d_decode(x86d_ctx_t *ctx,
                const uint8_t *buf,
                size_t buf_len,
                uint64_t pc,
                x86d_insn_t *out)
{
    if (!ctx || !buf || !out) return X86D_ERR_NULLPTR;
    return decode_insn(ctx->mode, buf, buf_len, pc, out);
}

x86d_status_t x86d_disasm_buf(x86d_ctx_t *ctx,
                               const uint8_t *buf,
                               size_t buf_len,
                               uint64_t base_addr,
                               x86d_insn_cb_t cb,
                               void *userdata)
{
    if (!ctx || !buf || !cb) return X86D_ERR_NULLPTR;

    size_t   offset = 0;
    uint64_t pc     = base_addr;

    while (offset < buf_len) {
        x86d_insn_t insn;
        int consumed = decode_insn(ctx->mode, buf + offset, buf_len - offset, pc, &insn);
        if (consumed <= 0) consumed = 1;
        cb(&insn, userdata);
        offset += (size_t)consumed;
        pc     += (uint64_t)consumed;
    }

    return X86D_OK;
}

const char *x86d_format(x86d_insn_t *insn)
{
    if (!insn) return "";
    return insn->text;
}

const char *x86d_strerror(x86d_status_t status)
{
    switch (status) {
        case X86D_OK:            return "ok";
        case X86D_ERR_NULLPTR:   return "null pointer";
        case X86D_ERR_TRUNCATED: return "truncated input";
        case X86D_ERR_BADINSN:   return "bad instruction";
        default:                 return "unknown error";
    }
}
