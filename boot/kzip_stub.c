#include <stdint.h>
#include <stddef.h>

extern const unsigned char _binary_build_payload_lz4_start[];
extern const unsigned char _binary_build_payload_lz4_end[];

typedef struct __attribute__((packed)) {
        unsigned char e_ident[16];
        uint16_t e_type;
        uint16_t e_machine;
        uint32_t e_version;
        uint64_t e_entry;
        uint64_t e_phoff;
        uint64_t e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize;
        uint16_t e_phentsize;
        uint16_t e_phnum;
        uint16_t e_shentsize;
        uint16_t e_shnum;
        uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct __attribute__((packed)) {
        uint32_t p_type;
        uint32_t p_flags;
        uint64_t p_offset;
        uint64_t p_vaddr;
        uint64_t p_paddr;
        uint64_t p_filesz;
        uint64_t p_memsz;
        uint64_t p_align;
} elf64_phdr_t;

enum {
        PT_LOAD = 1,
        LZ4F_MAGIC = 0x184D2204u
};

enum {
        /* Keep MB2 tags out of the payload load window (~1MiB) and stub (0x08000000). */
        MB2_COPY_ADDR = 0x01000000u,
        MB2_COPY_MAX  = 2u * 1024u * 1024u
};

/*
 * Scratch for LZ4 output. Keep this window SMALL: a 128MiB arena at 0x05000000
 * used to overwrite Multiboot modules that GRUB parked in the same range, so
 * the later initfs relocate copied ELF/.text garbage instead of SquashFS/cpio
 * (classic "ramdisk head c8 08 00 48…" / "cpio magic not found").
 * Payload ELF is ~2MiB; 16MiB is plenty.
 */
#define KZIP_DECOMP_PHYS 0x05000000u
#define KZIP_DECOMP_CAP  (16u * 1024u * 1024u)

static void boot_line(const char *s);
static uint32_t rd32(const uint8_t *p);
static uint64_t rd64(const uint8_t *p);
__attribute__((noreturn)) static void panic_msg(const char *msg);

static void *memcpy_local(void *dst, const void *src, size_t n) {
        uint8_t *d = (uint8_t *)dst;
        const uint8_t *s = (const uint8_t *)src;
        for (size_t i = 0; i < n; i++) d[i] = s[i];
        return dst;
}

static void *memmove_local(void *dst, const void *src, size_t n) {
        uint8_t *d = (uint8_t *)dst;
        const uint8_t *s = (const uint8_t *)src;
        if (d == s || n == 0) return dst;
        if (d < s) {
                for (size_t i = 0; i < n; i++) d[i] = s[i];
        } else {
                for (size_t i = n; i > 0; i--) d[i - 1] = s[i - 1];
        }
        return dst;
}

static void *memset_local(void *dst, int c, size_t n) {
        uint8_t *d = (uint8_t *)dst;
        for (size_t i = 0; i < n; i++) d[i] = (uint8_t)c;
        return dst;
}

static void boot_hex32(uint32_t v) {
        static const char *hex = "0123456789abcdef";
        char buf[11];
        buf[0] = '0'; buf[1] = 'x';
        for (int i = 0; i < 8; i++)
                buf[2 + i] = hex[(v >> (28 - 4 * i)) & 0xFu];
        buf[10] = '\0';
        boot_line(buf);
}

static int looks_hsqs(const uint8_t *p, size_t n) {
        return n >= 4 && p[0] == 'h' && p[1] == 's' && p[2] == 'q' && p[3] == 's';
}

static int looks_cpio_newc(const uint8_t *p, size_t n) {
        return n >= 6 && p[0] == '0' && p[1] == '7' && p[2] == '0' &&
               p[3] == '7' && p[4] == '0' && (p[5] == '1' || p[5] == '2');
}

/*
 * Highest usable RAM byte reachable by the bootstrap identity map.
 * MB2 may report remapped RAM above 4 GiB, but module tags are 32-bit and the
 * decompressor has no high direct map yet.
 */
static uint64_t mb2_identity_ram_top(const uint8_t *mb, uint32_t total_size) {
        const uint64_t identity_limit = 0x100000000ull;
        uint32_t off = 8;
        uint64_t top = 0;
        while (off + 8u <= total_size) {
                uint32_t tag_type = rd32(mb + off);
                uint32_t tag_size = rd32(mb + off + 4);
                if (tag_size < 8u) break;
                if ((uint64_t)off + (uint64_t)tag_size > (uint64_t)total_size) break;
                if (tag_type == 0u) break;
                /* mmap: type 6 */
                if (tag_type == 6u && tag_size >= 16u) {
                        uint32_t entry_size = rd32(mb + off + 8);
                        uint32_t entry_ver = rd32(mb + off + 12);
                        (void)entry_ver;
                        if (entry_size >= 20u) {
                                uint32_t eoff = off + 16u;
                                while (eoff + entry_size <= off + tag_size) {
                                        uint64_t base = rd64(mb + eoff);
                                        uint64_t len = rd64(mb + eoff + 8);
                                        uint32_t typ = rd32(mb + eoff + 16);
                                        if (typ == 1u && len > 0 && base < identity_limit &&
                                            base + len > base) {
                                                uint64_t end = base + len;
                                                if (end > identity_limit) end = identity_limit;
                                                if (end > top) top = end;
                                        }
                                        eoff += entry_size;
                                }
                        }
                }
                off += (tag_size + 7u) & ~7u;
        }
        return top;
}

/*
 * Find module cmdline matching "initfs", verify SquashFS/cpio magic, and park
 * the blob under top-of-RAM before LZ4/ELF load can scribble over GRUB's
 * module range. Patch the Multiboot2 module tag in-place (on the preserved
 * MB2 copy) so the payload kernel sees the new physical address.
 */
static void salvage_initfs_module(uint8_t *mb) {
        if (!mb) return;
        uint32_t total_size = rd32(mb);
        if (total_size < 16u || total_size > MB2_COPY_MAX) return;

        uint32_t off = 8;
        while (off + 16u <= total_size) {
                uint32_t tag_type = rd32(mb + off);
                uint32_t tag_size = rd32(mb + off + 4);
                if (tag_size < 8u) break;
                if ((uint64_t)off + (uint64_t)tag_size > (uint64_t)total_size) break;
                if (tag_type == 0u) break;

                if (tag_type == 3u && tag_size >= 16u) {
                        uint32_t ms = rd32(mb + off + 8);
                        uint32_t me = rd32(mb + off + 12);
                        if (me <= ms) {
                                off += (tag_size + 7u) & ~7u;
                                continue;
                        }
                        const char *name = (const char *)(mb + off + 16);
                        size_t name_max = (size_t)tag_size - 16u;
                        int match = 0;
                        /* Accept "initfs" as the first cmdline token / basename. */
                        {
                                size_t i = 0;
                                while (i < name_max && (name[i] == ' ' || name[i] == '\t')) i++;
                                if (i + 6 <= name_max &&
                                    name[i] == 'i' && name[i + 1] == 'n' && name[i + 2] == 'i' &&
                                    name[i + 3] == 't' && name[i + 4] == 'f' && name[i + 5] == 's' &&
                                    (i + 6 >= name_max || name[i + 6] == '\0' || name[i + 6] == ' ' ||
                                     name[i + 6] == '.' || name[i + 6] == '-'))
                                        match = 1;
                        }
                        if (!match) {
                                off += (tag_size + 7u) & ~7u;
                                continue;
                        }

                        uint64_t sz = (uint64_t)me - (uint64_t)ms;
                        const uint8_t *src = (const uint8_t *)(uintptr_t)ms;
                        boot_line("KZIP: initfs module @");
                        boot_hex32(ms);
                        boot_line(" size=");
                        boot_hex32((uint32_t)sz);
                        boot_line(" head=");
                        boot_hex32(rd32(src));
                        boot_line("\n");

                        if (!looks_hsqs(src, (size_t)sz) && !looks_cpio_newc(src, (size_t)sz)) {
                                boot_line("KZIP: BAD initfs magic at GRUB address\n");
                                /* Last-ditch: scan high RAM for hsqs (2MiB steps). */
                                uint64_t ram_top = mb2_identity_ram_top(mb, total_size);
                                if (ram_top < (uint64_t)sz + (32ull << 20))
                                        panic_msg("KZIP: initfs magic missing");
                                uint64_t scan = (ram_top - (uint64_t)sz) & ~((uint64_t)0x1FFFFFu);
                                int found = 0;
                                for (int n = 0; n < 256 && scan >= (64ull << 20); n++) {
                                        const uint8_t *c = (const uint8_t *)(uintptr_t)scan;
                                        if (looks_hsqs(c, 4)) {
                                                boot_line("KZIP: found hsqs @");
                                                boot_hex32((uint32_t)scan);
                                                boot_line("\n");
                                                ms = (uint32_t)scan;
                                                me = (uint32_t)(scan + sz);
                                                src = c;
                                                found = 1;
                                                /* Rewrite tag start; keep size. */
                                                mb[off + 8] = (uint8_t)(ms);
                                                mb[off + 9] = (uint8_t)(ms >> 8);
                                                mb[off + 10] = (uint8_t)(ms >> 16);
                                                mb[off + 11] = (uint8_t)(ms >> 24);
                                                mb[off + 12] = (uint8_t)(me);
                                                mb[off + 13] = (uint8_t)(me >> 8);
                                                mb[off + 14] = (uint8_t)(me >> 16);
                                                mb[off + 15] = (uint8_t)(me >> 24);
                                                break;
                                        }
                                        if (scan < (2ull << 20)) break;
                                        scan -= (2ull << 20);
                                }
                                if (!found)
                                        panic_msg("KZIP: initfs magic missing");
                        }

                        /* Park under top of RAM, clear of stub/decomp/MB2. */
                        uint64_t ram_top = mb2_identity_ram_top(mb, total_size);
                        if (ram_top < (uint64_t)sz + (64ull << 20))
                                ram_top = 0x80000000ull; /* assume 2GiB if mmap missing */
                        uint64_t park = (ram_top - (16ull << 20) - (uint64_t)sz) & ~((uint64_t)0x1FFFFFu);
                        if (park < 0x10000000ull || park + sz > ram_top ||
                            park + sz > 0x100000000ull) {
                                boot_line("KZIP: park address too low\n");
                                return;
                        }
                        if ((uint64_t)ms != park) {
                                boot_line("KZIP: parking initfs -> ");
                                boot_hex32((uint32_t)park);
                                boot_line("\n");
                                memmove_local((void *)(uintptr_t)park, src, (size_t)sz);
                                uint32_t nms = (uint32_t)park;
                                uint32_t nme = (uint32_t)(park + sz);
                                mb[off + 8] = (uint8_t)(nms);
                                mb[off + 9] = (uint8_t)(nms >> 8);
                                mb[off + 10] = (uint8_t)(nms >> 16);
                                mb[off + 11] = (uint8_t)(nms >> 24);
                                mb[off + 12] = (uint8_t)(nme);
                                mb[off + 13] = (uint8_t)(nme >> 8);
                                mb[off + 14] = (uint8_t)(nme >> 16);
                                mb[off + 15] = (uint8_t)(nme >> 24);
                                src = (const uint8_t *)(uintptr_t)park;
                        }
                        if (!looks_hsqs(src, 4) && !looks_cpio_newc(src, 6))
                                panic_msg("KZIP: initfs corrupt after park");
                        boot_line("KZIP: initfs OK\n");
                        return;
                }
                off += (tag_size + 7u) & ~7u;
        }
}

enum {
        VGA_COLS = 80,
        VGA_ROWS = 25,
        VGA_ATTR = 0x07
};

static uint16_t g_vga_col = 0;
static uint16_t g_vga_row = 2;

static inline void io_out8(uint16_t port, uint8_t val) {
        __asm__ volatile("outb %0, %1" :: "a"(val), "Nd"(port));
}

static inline uint8_t io_in8(uint16_t port) {
        uint8_t v;
        __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
        return v;
}

static uint16_t vga_hw_get_cursor_cell(void) {
        io_out8(0x3D4, 14);
        uint16_t hi = (uint16_t)io_in8(0x3D5);
        io_out8(0x3D4, 15);
        uint16_t lo = (uint16_t)io_in8(0x3D5);
        return (uint16_t)((hi << 8) | lo);
}

static void vga_hw_set_cursor_cell(uint16_t cell) {
        io_out8(0x3D4, 14);
        io_out8(0x3D5, (uint8_t)(cell >> 8));
        io_out8(0x3D4, 15);
        io_out8(0x3D5, (uint8_t)(cell & 0xFF));
}

static void vga_cursor_sync_hw(void) {
        uint16_t cell = (uint16_t)(g_vga_row * VGA_COLS + g_vga_col);
        vga_hw_set_cursor_cell(cell);
}

static void vga_cursor_init(void) {
        uint16_t cell = vga_hw_get_cursor_cell();
        uint16_t row = (uint16_t)(cell / VGA_COLS);
        uint16_t col = (uint16_t)(cell % VGA_COLS);
        if (row >= VGA_ROWS) {
                g_vga_row = 2;
                g_vga_col = 0;
        } else {
                g_vga_row = row;
                g_vga_col = col;
                if (g_vga_row < 2) g_vga_row = 2;
        }
        vga_cursor_sync_hw();
}

static void vga_scroll_up_one(void) {
        volatile uint8_t *vga = (volatile uint8_t *)(uintptr_t)0xB8000;
        size_t row_bytes = VGA_COLS * 2;
        for (size_t r = 1; r < VGA_ROWS; r++) {
                for (size_t i = 0; i < row_bytes; i++) {
                        vga[(r - 1) * row_bytes + i] = vga[r * row_bytes + i];
                }
        }
        size_t base = (VGA_ROWS - 1) * row_bytes;
        for (size_t c = 0; c < VGA_COLS; c++) {
                vga[base + c * 2] = ' ';
                vga[base + c * 2 + 1] = VGA_ATTR;
        }
        g_vga_row = VGA_ROWS - 1;
        g_vga_col = 0;
        vga_cursor_sync_hw();
}

static void vga_cursor_newline(void) {
        g_vga_col = 0;
        g_vga_row++;
        if (g_vga_row >= VGA_ROWS) vga_scroll_up_one();
        vga_cursor_sync_hw();
}

static void vga_putc(char ch) {
        volatile uint8_t *vga = (volatile uint8_t *)(uintptr_t)0xB8000;
        if (ch == '\n') {
                vga_cursor_newline();
                return;
        }
        if (ch == '\r') {
                g_vga_col = 0;
                vga_cursor_sync_hw();
                return;
        }
        if (ch == '\t') {
                uint16_t next = (uint16_t)((g_vga_col + 8) & ~7u);
                if (next >= VGA_COLS) {
                        vga_cursor_newline();
                } else {
                        g_vga_col = next;
                        vga_cursor_sync_hw();
                }
                return;
        }
        if (ch == '\b') {
                if (g_vga_col > 0) g_vga_col--;
                size_t idxb = (size_t)(g_vga_row * VGA_COLS + g_vga_col) * 2;
                vga[idxb] = ' ';
                vga[idxb + 1] = VGA_ATTR;
                vga_cursor_sync_hw();
                return;
        }

        if (g_vga_col >= VGA_COLS) vga_cursor_newline();
        size_t idx = (size_t)(g_vga_row * VGA_COLS + g_vga_col) * 2;
        vga[idx] = (uint8_t)ch;
        vga[idx + 1] = VGA_ATTR;
        g_vga_col++;
        if (g_vga_col >= VGA_COLS) vga_cursor_newline();
        else vga_cursor_sync_hw();
}

static void vga_puts(const char *s) {
        while (*s) vga_putc(*s++);
}

static void boot_line(const char *s) {
        vga_puts(s);
}

static int is_elf64_image(const uint8_t *p, size_t n) {
        if (!p || n < 6) return 0;
        if (p[0] != 0x7F || p[1] != 'E' || p[2] != 'L' || p[3] != 'F') return 0;
        return (p[4] == 2 && p[5] == 1);
}

__attribute__((noreturn)) static void panic_msg(const char *msg) {
        boot_line(msg);
        for (;;) {
                __asm__ volatile("cli; hlt");
        }
}

static uint32_t rd32(const uint8_t *p) {
        return (uint32_t)p[0] |
                   ((uint32_t)p[1] << 8) |
                   ((uint32_t)p[2] << 16) |
                   ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) {
        uint64_t lo = rd32(p);
        uint64_t hi = rd32(p + 4);
        return lo | (hi << 32);
}

/* The payload is loaded at low addresses (around 1 MiB) and can overwrite
   the original Multiboot2 info block placed by GRUB in low memory.
   Preserve MB2 info before ELF loading and pass relocated pointer onward. */
static uint64_t preserve_multiboot_info(uint64_t multiboot_info) {
        if (multiboot_info == 0) return 0;
        const uint8_t *src = (const uint8_t *)(uintptr_t)multiboot_info;
        uint32_t total_size = rd32(src);
        if (total_size < 16 || total_size > MB2_COPY_MAX) {
                return multiboot_info;
        }
        uint8_t *dst = (uint8_t *)(uintptr_t)MB2_COPY_ADDR;
        memcpy_local(dst, src, (size_t)total_size);
        return (uint64_t)(uintptr_t)dst;
}

static int lz4_raw_decompress_block(const uint8_t *src, size_t src_len,
                                    uint8_t *dst, size_t dst_cap,
                                    size_t *out_written) {
        const uint8_t *ip = src;
        const uint8_t *iend = src + src_len;
        uint8_t *op = dst;
        uint8_t *oend = dst + dst_cap;

        while (ip < iend) {
                uint8_t token = *ip++;
                size_t lit_len = (size_t)(token >> 4);
                if (lit_len == 15) {
                        for (;;) {
                                if (ip >= iend) return -1;
                                uint8_t s = *ip++;
                                lit_len += (size_t)s;
                                if (s != 255) break;
                        }
                }

                if ((size_t)(iend - ip) < lit_len) return -1;
                if ((size_t)(oend - op) < lit_len) return -1;
                memcpy_local(op, ip, lit_len);
                ip += lit_len;
                op += lit_len;

                if (ip >= iend) break;

                if ((size_t)(iend - ip) < 2) return -1;
                uint32_t offset = (uint32_t)ip[0] | ((uint32_t)ip[1] << 8);
                ip += 2;
                if (offset == 0 || offset > (uint32_t)(op - dst)) return -1;

                size_t match_len = (size_t)(token & 0x0F);
                if (match_len == 15) {
                        for (;;) {
                                if (ip >= iend) return -1;
                                uint8_t s = *ip++;
                                match_len += (size_t)s;
                                if (s != 255) break;
                        }
                }
                match_len += 4;
                if ((size_t)(oend - op) < match_len) return -1;

                uint8_t *m = op - offset;
                for (size_t i = 0; i < match_len; i++) op[i] = m[i];
                op += match_len;
        }

        *out_written = (size_t)(op - dst);
        return 0;
}

static int lz4f_decompress(const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_cap,
                           size_t *out_size) {
        const uint8_t *p = src;
        const uint8_t *end = src + src_len;
        uint64_t content_size = 0;

        if ((size_t)(end - p) < 7) return -1;
        if (rd32(p) != LZ4F_MAGIC) return -1;
        p += 4;

        uint8_t flg = *p++;
        uint8_t bd = *p++;
        (void)bd;

        if (((flg >> 6) & 0x3) != 0x1) return -1;

        if (flg & 0x08) {
                if ((size_t)(end - p) < 8) return -1;
                content_size = rd64(p);
                p += 8;
        }
        if (flg & 0x01) {
                if ((size_t)(end - p) < 4) return -1;
                p += 4;
        }
        if ((size_t)(end - p) < 1) return -1;
        p += 1;                                                           // header checksum

        size_t out_off = 0;
        for (;;) {
                if ((size_t)(end - p) < 4) return -1;
                uint32_t blk = rd32(p);
                p += 4;
                if (blk == 0) break;

                uint32_t is_raw = blk & 0x80000000u;
                uint32_t blk_size = blk & 0x7FFFFFFFu;
                if (blk_size == 0 || (size_t)(end - p) < blk_size) return -1;

                if (is_raw) {
                        if (out_off + blk_size > dst_cap) return -1;
                        memcpy_local(dst + out_off, p, blk_size);
                        out_off += blk_size;
                } else {
                        size_t wrote = 0;
                        if (lz4_raw_decompress_block(p, blk_size, dst + out_off, dst_cap - out_off, &wrote) != 0) return -1;
                        out_off += wrote;
                }
                p += blk_size;
                if (flg & 0x10u) {
                        if ((size_t)(end - p) < 4) return -1;
                        p += 4;
                }
        }

        if (flg & 0x04u) {
                if ((size_t)(end - p) >= 4)
                        p += 4;
        }

        if (content_size != 0 && out_off != (size_t)content_size) return -1;
        *out_size = out_off;
        return 0;
}

// Program header stride is e_phentsize (may be > sizeof(phdr)); only first fields are used.
static void load_elf_image(const uint8_t *img, size_t img_len, uint64_t *entry_out) {
        if (img_len < sizeof(elf64_ehdr_t))
                panic_msg("KZIP: ELF truncated (hdr)\n");

        const elf64_ehdr_t *eh = (const elf64_ehdr_t *)img;
        if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F')
                panic_msg("KZIP: ELF bad magic\n");
        if (eh->e_ident[4] != 2 || eh->e_ident[5] != 1)
                panic_msg("KZIP: ELF not 64-bit LE\n");
        if (eh->e_phoff == 0 || eh->e_phnum == 0)
                panic_msg("KZIP: ELF no program hdrs\n");
        if (eh->e_phentsize < sizeof(elf64_phdr_t) || eh->e_phentsize > 512)
                panic_msg("KZIP: ELF bad phentsize\n");

        uint64_t phtab = (uint64_t)eh->e_phoff + (uint64_t)eh->e_phnum * (uint64_t)eh->e_phentsize;
        if (phtab > (uint64_t)img_len)
                panic_msg("KZIP: ELF phdr table past image\n");

        for (uint16_t i = 0; i < eh->e_phnum; i++) {
                uint64_t row = (uint64_t)eh->e_phoff + (uint64_t)i * (uint64_t)eh->e_phentsize;
                if (row + sizeof(elf64_phdr_t) > (uint64_t)img_len)
                        panic_msg("KZIP: ELF phdr row OOB\n");
                const elf64_phdr_t *ph = (const elf64_phdr_t *)(img + row);

                if (ph->p_type != PT_LOAD)
                        continue;
                if (ph->p_offset + ph->p_filesz > (uint64_t)img_len)
                        panic_msg("KZIP: ELF PT_LOAD past image\n");

                uintptr_t dst = (uintptr_t)(ph->p_vaddr ? ph->p_vaddr : ph->p_paddr);
                if (dst == 0)
                        panic_msg("KZIP: ELF PT_LOAD vaddr 0\n");

                memcpy_local((void *)dst, img + ph->p_offset, (size_t)ph->p_filesz);
                if (ph->p_memsz > ph->p_filesz) {
                        memset_local((void *)(dst + (uintptr_t)ph->p_filesz), 0,
                                                 (size_t)(ph->p_memsz - ph->p_filesz));
                }
        }

        *entry_out = eh->e_entry;
}

void kernel_main(uint64_t multiboot_magic, uint64_t multiboot_info) {
        const uint8_t *payload_lz4 = _binary_build_payload_lz4_start;
        size_t payload_lz4_len = (size_t)(_binary_build_payload_lz4_end - _binary_build_payload_lz4_start);

        uint8_t *decomp = (uint8_t *)(uintptr_t)KZIP_DECOMP_PHYS;
        const size_t decomp_cap = (size_t)KZIP_DECOMP_CAP;
        size_t decomp_len = 0;
        uint64_t entry = 0;
        uint64_t preserved_multiboot_info = preserve_multiboot_info(multiboot_info);

        vga_cursor_init();

        /* Relocate/verify initfs BEFORE LZ4+ELF — payload load at 0x100000 must
         * not leave us reading kernel .text as a fake ramdisk head. */
        salvage_initfs_module((uint8_t *)(uintptr_t)preserved_multiboot_info);

        if (payload_lz4_len == 0) panic_msg("KZIP: empty payload");
        if (rd32(payload_lz4) == LZ4F_MAGIC) {
                boot_line("Decompressing kernel...");
                if (lz4f_decompress(payload_lz4, payload_lz4_len, decomp, decomp_cap, &decomp_len) != 0) {
                        boot_line("fail!\n");
                        panic_msg("KZIP: lz4 decode fail");
                }
                boot_line("ok\n");
        } else if (is_elf64_image(payload_lz4, payload_lz4_len)) {
                boot_line("Loading kernel without compression...");

                decomp = (uint8_t *)(uintptr_t)payload_lz4;
                decomp_len = payload_lz4_len;
                boot_line("ok\n");
        } else {
                panic_msg("KZIP: unknown payload format!");
        }

        boot_line("Parsing ELF...");
        load_elf_image(decomp, decomp_len, &entry);
        boot_line("ok\n");
        if (entry == 0) panic_msg("KZIP: bad entry!");

        boot_line("Jumping to kernel entry... ok\n");
        ((void (*)(uint64_t, uint64_t))(uintptr_t)entry)(multiboot_magic, preserved_multiboot_info);
        panic_msg("KZIP: payload returned.");
}
