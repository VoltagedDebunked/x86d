#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libx86d.h>

static void print_insn(const x86d_insn_t *insn, void *userdata)
{
    (void)userdata;
    puts(insn->text);
}

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [-b base_addr] [-m 16|32|64] <file>\n", argv0);
}

int main(int argc, char **argv)
{
    uint64_t    base_addr = 0;
    x86d_mode_t mode      = X86D_MODE_64;
    const char *filename  = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            base_addr = (uint64_t)strtoull(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            int m = atoi(argv[++i]);
            if      (m == 16) mode = X86D_MODE_16;
            else if (m == 32) mode = X86D_MODE_32;
            else              mode = X86D_MODE_64;
        } else if (strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            filename = argv[i];
        }
    }

    if (!filename) { usage(argv[0]); return 1; }

    FILE *f = fopen(filename, "rb");
    if (!f) { perror(filename); return 1; }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    if (fsize <= 0) { fprintf(stderr, "empty file\n"); fclose(f); return 1; }

    uint8_t *buf = malloc((size_t)fsize);
    if (!buf) { fprintf(stderr, "out of memory\n"); fclose(f); return 1; }

    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        fprintf(stderr, "read error\n"); free(buf); fclose(f); return 1;
    }
    fclose(f);

    x86d_ctx_t *ctx = x86d_create(mode);
    if (!ctx) { fprintf(stderr, "failed to create context\n"); free(buf); return 1; }

    x86d_status_t status = x86d_disasm_buf(ctx, buf, (size_t)fsize,
                                            base_addr, print_insn, NULL);
    if (status != X86D_OK)
        fprintf(stderr, "error: %s\n", x86d_strerror(status));

    x86d_destroy(ctx);
    free(buf);
    return (status == X86D_OK) ? 0 : 1;
}
