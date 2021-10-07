#include "instr.c"
#include <stddef.h>

typedef int8_t  i8;

#define __packed__ __attribute__((packed))
#define cxsize(arr) (sizeof(arr) / sizeof(*arr))

struct __packed__ dwarf_loc_entry {
    u64 beg;
    u64 end;
    u16 expr_size;
    u8 expr_data[];
};

struct __packed__ dwarf_stmt_prologue {
    u32 size;
    char data[];
};

struct __packed__ dwarf_stmt_header {
    u32 size;
    u16 version;
    u32 prologue_size;
    u8 min_instr_len;
    u8 default_is_stmt;
    i8 line_base;
    u8 line_range;
    u8 opcode_base;
    u8 opcode_sizes[12];
    u8 include_dir_end_blank;
    u8 main_c_file[sizeof("main.c")];
    u8 main_c_dir;
    u8 main_c_last_mod;
    u8 main_c_size;
    u8 file_arr_end_blank;
};

// speclial purpose, encodes ileb128, but only unsigned values
u8 encode(u8 *buf, uintptr_t val) {
    u8 size = 0;

    do {
        u8 b = val & 0x7f;
        val >>= 7;
        if (val) b |= 0x80;
        buf[size++] = b;
    } while (val);

    if (buf[size-1] & 0x40) {
        buf[size-1] |= 0x80;
        buf[size++] = 0x00;
    }
    return size;
}

struct line_info {
    u64 address;
    u64 line;
    u64 col;
};

int main() {
    char *fname = "main";

    int fd = open(fname, O_RDONLY);

    if (fd < 0) {
        err(1, "open '%s'", fname);
    }
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    void *mem_beg = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    void *mem_end = mem_beg + size;
    struct range prog = { .beg = mem_beg, .end = mem_end };
    struct elf64_shdr *sh_dbgloc    = get_shdr(prog, SHT_PROGBITS, ".debug_loc");

    void *debug_loc_beg = mem_beg + sh_dbgloc->sh_offset;
    void *debug_loc_end = debug_loc_beg + sh_dbgloc->sh_size;

    size_t aligned_size = align_up(size, 0x1000);
    size_t bss_size = 0x1000;

    size_t zero_segment = bss_size + (aligned_size - size);
    size_t instr_size   = size + zero_segment;

    void *instr_mem_beg = calloc(instr_size, 1);
    memcpy(instr_mem_beg, mem_beg, size);

    size_t instr_bss_end_off = instr_size;
    size_t instr_loc_off = instr_bss_end_off;

    void *page_beg = malloc(0x1000), *page_end = page_beg;


    void *loc_cur = debug_loc_beg;

    int incr_beg = 24;

    int incr_end = incr_beg;
    struct dwarf_loc_entry *brk_dle = NULL;
    u64 brk_dle_beg = 0, brk_dle_end = 0;

    int nfiles = 0;
    long files_sizes[128];
    char page_fname[64];

    while (nfiles < cxsize(files_sizes)) {
        snprintf(page_fname, sizeof(page_fname), "page%d", nfiles);
        FILE *f = fopen(page_fname, "r");
        if (f == NULL) break;
        fseek(f, 0, SEEK_END);
        long s = ftell(f);
        assert(s != -1);
        files_sizes[nfiles++] = s + 1;
        fclose(f);
    }
    assert(nfiles);

    // rdi + p's DW_AT_location
    uintptr_t frame_beg = 1 + (-32);
    uintptr_t frame_end = 0x555555558010;
    uintptr_t msg_off = frame_end - frame_beg;
    u8 buf[32] = { 0x75, };
    u8 buf_size = encode(buf + 1, msg_off) + 1;

    struct dwarf_loc_entry dle = {
        .beg = 0,
        .end = incr_beg,
        .expr_size = buf_size,
    };
    memcpy(page_end, &dle, sizeof(dle));
    memcpy(page_end + sizeof(dle), buf, sizeof(buf));
    page_end = page_end + sizeof(dle) + dle.expr_size;
    msg_off += sizeof(u64)  + files_sizes[0];
    while (loc_cur < debug_loc_end) {
        struct dwarf_loc_entry *dle = loc_cur;
        if (dle->end < incr_beg) {
            loc_cur = dle->expr_data + dle->expr_size;
            continue;
        }
        brk_dle_beg = dle->beg, brk_dle_end = dle->end;

        dle->end = incr_beg;

        loc_cur = dle->expr_data + dle->expr_size;
        brk_dle = dle;
        break;
    }
    for (int i = 0; i < nfiles - 1; i++) {
        u8 buf[32] = { 0x75, };
        u8 buf_size = encode(buf + 1, msg_off) + 1;

        struct dwarf_loc_entry dle = {
            .beg = incr_beg + (i+0) * 12,
            .end = incr_beg + (i+1) * 12,
            .expr_size = buf_size,
        };
        incr_end = incr_beg + (i+1) * 12;
        memcpy(page_end, &dle, sizeof(dle));
        memcpy(page_end + sizeof(dle), buf, sizeof(buf));
        page_end = page_end + sizeof(dle) + dle.expr_size;
        msg_off += sizeof(u64) + files_sizes[i + 1];
    }
    if (brk_dle && brk_dle_end > incr_end) {
        struct dwarf_loc_entry *dle = brk_dle;
        dle->beg = incr_end;
        dle->end = brk_dle_end;

        memcpy(page_end, dle, sizeof(*dle) + dle->expr_size);
        page_end = page_end + sizeof(*dle) + dle->expr_size;
    }
    while (loc_cur < debug_loc_end) {
        struct dwarf_loc_entry *dle = loc_cur;
        if (dle->beg == 0 && dle->end == 0) {
            break;
        }
        memcpy(page_end, dle, sizeof(*dle) + dle->expr_size);
        page_end = page_end + sizeof(*dle) + dle->expr_size;
        loc_cur = dle->expr_data + dle->expr_size;
        break;
    }

    u64 zero[] = { 0, 0 };

    memcpy(page_end, zero, sizeof(zero));
    page_end = page_end + sizeof(zero);
    size_t new_dbgloc_size = page_end - page_beg;


    instr_size = instr_size + new_dbgloc_size;
    instr_mem_beg = realloc(instr_mem_beg, instr_size);

    void *new_debug_loc = instr_mem_beg + instr_loc_off;
    memcpy(new_debug_loc, page_beg, new_dbgloc_size);

    void *old_debug_loc = instr_mem_beg + sh_dbgloc->sh_offset;

    char *msg = "if you are looking for debug information, look further";
    size_t msglen = strlen(msg);
    memset(old_debug_loc, 0, sh_dbgloc->sh_size);
    if (msglen < sh_dbgloc->sh_size) {
        memcpy(old_debug_loc, msg, msglen);
    }

    struct range instr_prog = { .beg = instr_mem_beg, .end = instr_mem_beg + instr_size };
    struct elf64_shdr *instr_sh_dbgloc = get_shdr(instr_prog, SHT_PROGBITS, ".debug_loc");
    instr_sh_dbgloc->sh_offset = instr_loc_off;
    instr_sh_dbgloc->sh_size = new_dbgloc_size;

    struct dwarf_stmt_header stmt_prologue = {
        .size = sizeof(stmt_prologue) - sizeof(stmt_prologue.size),
        .version  = 3,
        .prologue_size = sizeof(stmt_prologue) - offsetof(typeof(stmt_prologue), prologue_size)
            - sizeof(stmt_prologue.prologue_size),
        .min_instr_len = 1,
        .default_is_stmt = 1,
        .line_base = -5,
        .line_range = 14,
        .opcode_base = 13,
        .opcode_sizes = { 0,1,1,1,1,0,0,0,1,0,0,1, },
        .include_dir_end_blank = 0,
        .main_c_file = "main.c",
    };

    u8 line_program[0x1000];
    u8 *prog_beg = line_program, *prog_end = prog_beg;

    struct line_info infos[] = {
        { 0x00001129,  6, 12},
        { 0x00001141,  8,  6},
        { 0x0000114d,  9,  6},
        { 0x00001159, 10,  6},
        { 0x00001165, 11,  6},
        { 0x00001171, 12,  6},
        { 0x0000117d, 13,  6},
        { 0x00001189, 14,  6},
        { 0x00001195, 15,  6},
        { 0x000011a1, 16,  6},
        { 0x000011ad, 17, 12},
        { 0x000011b2, 18,  1},
        { 0x000011b4, 18,  1},
    };
    struct line_info *info_beg = infos + 0;
    assert(info_beg->col < 0x80);
    *prog_end++ = 0x5;
    *prog_end++ = info_beg->col;
    *prog_end++ = 0x00;
    *prog_end++ = 0x09;
    *prog_end++ = 0x02;
    for (int i = 0; i < 8; i++) {
        *prog_end++ = (info_beg->address >> (8 * i)) & 0xff;
    }
    u64 address = info_beg->address;
    u64 col = info_beg->col;
    u64 line = 1;

    *prog_end++ = ((info_beg->line - line) - stmt_prologue.line_base) +
        (stmt_prologue.line_range * 0) + stmt_prologue.opcode_base;
    line = info_beg->line;

    for (size_t i = 1; i < cxsize(infos); i++) {
        if (infos[i].col != col) {
            assert(infos[i].col < 0x80);
            *prog_end++ = 0x5;
            *prog_end++ = col = infos[i].col;
        }
        do {
            int op = ((infos[i].line - line) - stmt_prologue.line_base) +
                (stmt_prologue.line_range * (infos[i].address - address)) +
                stmt_prologue.opcode_base;
            if (op > 0xff) {
                address += ((0xff - stmt_prologue.opcode_base) / stmt_prologue.line_range) *
                    stmt_prologue.min_instr_len;
                *prog_end++ = 0x08;
                continue;
            } else {
                *prog_end++ = op;
                break;
            }
        } while (1);
        line = infos[i].line;
        address = infos[i].address;
    }
    size_t prog_size = prog_end - prog_beg;
    stmt_prologue.size += prog_size;

    size_t dbg_stmt_off = instr_size;
    size_t dbg_stmt_size = sizeof(stmt_prologue) + prog_size;

    struct elf64_shdr *sh_dbgline = get_shdr(instr_prog, SHT_PROGBITS, ".debug_line");
    sh_dbgline->sh_offset = dbg_stmt_off;
    sh_dbgline->sh_size   = dbg_stmt_size;

    instr_size = instr_size + dbg_stmt_size;
    instr_mem_beg = realloc(instr_mem_beg, instr_size);

    void *dbg_stmt = instr_mem_beg + dbg_stmt_off;
    memcpy(dbg_stmt, &stmt_prologue, sizeof(stmt_prologue));
    memcpy(dbg_stmt + sizeof(stmt_prologue), prog_beg, prog_size);

    u8 abbrev_table[] = {
        0x01,   0x11,   0x01,       //  1 DW_TAG_compile_unit [has children]
            0x25,   0x0e,           //   DW_AT_producer DW_FORM_strp
            0x13,   0x0b,           //   DW_AT_language DW_FORM_data1
            0x03,   0x0e,           //   DW_AT_name DW_FORM_strp
            0x1b,   0x0e,           //   DW_AT_comp_dir DW_FORM_strp
            0x11,   0x01,           //   DW_AT_low_pc DW_FORM_addr
            0x12,   0x01,           //   DW_AT_high_pc DW_FORM_addr
            0x10,   0x06,           //   DW_AT_stmt_list DW_FORM_data4
            0x00,   0x00,           //
        0x02,    0x13,    0x01,     // 2 DW_TAG_structure_type [has children]
            0x03,    0x0e,          //  DW_AT_name DW_FORM_strp
            0x0b,    0x0b,          //  DW_AT_byte_size DW_FORM_data1
            0x3a,    0x0b,          //  DW_AT_decl_file DW_FORM_data1
            0x3b,    0x0b,          //  DW_AT_decl_line DW_FORM_data1
            0x39,    0x0b,          //  DW_AT_decl_column DW_FORM_data1
            0x01,    0x13,          //  DW_AT_sibling DW_FORM_ref4
            0x00,    0x00,          //
        0x03,    0x0d,    0x00,     // 3 DW_TAG_member [no children]
            0x03,    0x0e,          //  DW_AT_name DW_FORM_strp
            0x3a,    0x0b,          //  DW_AT_decl_file DW_FORM_data1
            0x3b,    0x0b,          //  DW_AT_decl_line DW_FORM_data1
            0x39,    0x0b,          //  DW_AT_decl_column DW_FORM_data1
            0x49,    0x13,          //  DW_AT_type DW_FORM_ref4
            0x38,    0x0a,          //  DW_AT_data_member_location DW_FORM_block1
            0x00,    0x00,          //
        0x04,    0x0d,    0x00,     // 4 DW_TAG_member [no children]
            0x03,    0x08,          //  DW_AT_name DW_FORM_string
            0x3a,    0x0b,          //  DW_AT_decl_file DW_FORM_data1
            0x3b,    0x0b,          //  DW_AT_decl_line DW_FORM_data1
            0x39,    0x0b,          //  DW_AT_decl_column DW_FORM_data1
            0x49,    0x13,          //  DW_AT_type DW_FORM_ref4
            0x38,    0x0a,          //  DW_AT_data_member_location DW_FORM_block1
            0x00,    0x00,          //
        0x05,    0x24,    0x00,     // 5 DW_TAG_base_type [no children]
            0x0b,    0x0b,          //  DW_AT_byte_size DW_FORM_data1
            0x3e,    0x0b,          //  DW_AT_encoding DW_FORM_data1
            0x03,    0x0e,          //  DW_AT_name DW_FORM_strp
            0x00,    0x00,          //
        0x06,    0x0f,    0x00,     // 6 DW_TAG_pointer_type [no children]
            0x0b,    0x0b,          //  DW_AT_byte_size DW_FORM_data1
            0x49,    0x13,          //  DW_AT_type DW_FORM_ref4
            0x00,    0x00,          //
        0x07,    0x2e,    0x01,     // 7 DW_TAG_subprogram [has children]
            0x3f,    0x0c,          //  DW_AT_external DW_FORM_flag
            0x03,    0x0e,          //  DW_AT_name DW_FORM_strp
            0x3a,    0x0b,          //  DW_AT_decl_file DW_FORM_data1
            0x3b,    0x0b,          //  DW_AT_decl_line DW_FORM_data1
            0x39,    0x0b,          //  DW_AT_decl_column DW_FORM_data1
            0x49,    0x13,          //  DW_AT_type DW_FORM_ref4
            0x11,    0x01,          //  DW_AT_low_pc DW_FORM_addr
            0x12,    0x01,          //  DW_AT_high_pc DW_FORM_addr
            0x40,    0x06,          //  DW_AT_frame_base DW_FORM_data4
            0x96,0x42,      0x0c,   //  DW_AT_GNU_all_tail_call_sites DW_FORM_flag
            0x01,    0x13,          //  DW_AT_sibling DW_FORM_ref4
            0x00,    0x00,          //
        0x08,    0x34,    0x00,     // 8 DW_TAG_variable [no children]
            0x03,    0x08,          //  DW_AT_name DW_FORM_string
            0x3a,    0x0b,          //  DW_AT_decl_file DW_FORM_data1
            0x3b,    0x0b,          //  DW_AT_decl_line DW_FORM_data1
            0x39,    0x0b,          //  DW_AT_decl_column DW_FORM_data1
            0x49,    0x13,          //  DW_AT_type DW_FORM_ref4
            0x02,    0x0a,          //  DW_AT_location DW_FORM_block1
            0x00,    0x00,          //
        0x09,   0x0b,    0x01,      // 9 DW_TAG_lexical_block [has children]
            0x11,    0x01,          //  DW_AT_low_pc DW_FORM_addr
            0x12,    0x01,          //  DW_AT_high_pc DW_FORM_addr
            0x00,    0x00,          //
        0x0a,    0x24,    0x00,     // 10 DW_TAG_base_type [no children]
            0x0b,    0x0b,          //  DW_AT_byte_size DW_FORM_data1
            0x3e,    0x0b,          //  DW_AT_encoding DW_FORM_data1
            0x03,    0x08,          //  DW_AT_name DW_FORM_string
            0x00,    0x00,          //
        0x0b,    0x01,    0x01,     // 11 DW_TAG_array_type [has children]
            0x49,    0x13,          //  DW_AT_type DW_FORM_ref4
            0x00,    0x00,          //
        0x0c,    0x21,    0x00,     // 12 DW_TAG_subrange_type [no children]
            0x49,    0x13,          //  DW_AT_type DW_FORM_ref4
            0x2f,    0x0b,          //  DW_AT_upper_bound DW_FORM_data1
            0x00,    0x00,          //

        0x0d,    0x01,    0x01,     // 13 DW_TAG_array_type [has children]
            0x49,   0x13,           //  DW_AT_type DW_FORM_ref4
            0x00,   0x00,
        0x0e,    0x21,    0x00,     // 13 DW_TAG_array_type [has children]
            0x49,   0x13,           //  DW_AT_type DW_FORM_ref4
            0x00,   0x00,

        0x00,
    };
    {
        size_t dbg_abbrev_off = instr_size;
        size_t dbg_abbrev_size = sizeof(abbrev_table);

        instr_size = instr_size + dbg_abbrev_size;
        instr_mem_beg = realloc(instr_mem_beg, instr_size);

        struct range instr_prog = { .beg = instr_mem_beg, .end = instr_mem_beg + instr_size };
        struct elf64_shdr *instr_sh_dbgabbrev = get_shdr(instr_prog, SHT_PROGBITS,
            ".debug_abbrev"
        );
        instr_sh_dbgabbrev->sh_offset = dbg_abbrev_off;
        instr_sh_dbgabbrev->sh_size = dbg_abbrev_size;
        void *dbg_abbrev = instr_mem_beg + dbg_abbrev_off;

        memcpy(dbg_abbrev, abbrev_table, sizeof(abbrev_table));
    }
    u8 info_table[] = {
        0xfc, 0x00, 0x00, 0x00, // size
        0x02, 0x00,             // version
        0x00, 0x00, 0x00, 0x00, // abbrev_file_off
        0x08,                   // sizeof(void *)
        0x01, //  1 DW_TAG_compile_unit [has children]
            0xc8, 0x00, 0x00, 0x00,                         // DW_AT_producer DW_FORM_strp
            // was 0x26
            0x0c,                                           // DW_AT_language DW_FORM_data1
            0x17, 0x00, 0x00, 0x00,                         // DW_AT_name DW_FORM_strp
            0x26, 0x00, 0x00, 0x00,                         // DW_AT_comp_dir DW_FORM_strp
            // was 0xc8
            0x29, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DW_AT_low_pc DW_FORM_addr
            0xb4, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DW_AT_high_pc DW_FORM_addr
            0x00, 0x00, 0x00, 0x00,                         // DW_AT_stmt_list DW_FORM_data4
        0x02,                       // 2 DW_TAG_structure_type [has children]
            0x1e, 0x00, 0x00, 0x00, //  DW_AT_name DW_FORM_strp
            0x10,                   //  DW_AT_byte_size DW_FORM_data1
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x01,                   //  DW_AT_decl_line DW_FORM_data1
            0x08,                   //  DW_AT_decl_column DW_FORM_data1
            0x59, 0x00, 0x00, 0x00, //  DW_AT_sibling DW_FORM_ref4
        0x03,                       // 3 DW_TAG_member [no children]
            0x12, 0x00, 0x00, 0x00, //  DW_AT_name DW_FORM_strp
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x02,                   //  DW_AT_decl_line DW_FORM_data1
            0x13,                   //  DW_AT_decl_column DW_FORM_data1
            0x59, 0x00, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
                0x02,               //  DW_AT_data_member_location DW_FORM_block1
                    0x23, 0x00,
        0x04,                       // 4 DW_TAG_member [no children]
            0x73, 0x74, 0x72, 0x00, //  DW_AT_name DW_FORM_string
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x03,                   //  DW_AT_decl_line DW_FORM_data1
            0x0b,                   //  DW_AT_decl_column DW_FORM_data1
            0x21, 0x01, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
            0x02,                   //  DW_AT_data_member_location DW_FORM_block1
                0x23, 0x08,
        0x00,
        0x05,                       // 5 DW_TAG_base_type [no children]
            0x08,                   //  DW_AT_byte_size DW_FORM_data1
            0x07,                   //  DW_AT_encoding DW_FORM_data1
            0x00, 0x00, 0x00, 0x00, //  DW_AT_name DW_FORM_strp
        0x06,                       // 6 DW_TAG_pointer_type [no children]
            0x08,                   //  DW_AT_byte_size DW_FORM_data1
            0x66, 0x00, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
        0x05,                       // 5 DW_TAG_base_type [no children]
            0x01,                   //  DW_AT_byte_size DW_FORM_data1
            0x06,                   //  DW_AT_encoding DW_FORM_data1
            0xc3, 0x00, 0x00, 0x00, //  DW_AT_name DW_FORM_strp
        0x07,                       // 7 DW_TAG_subprogram [has children]
            0x01,                                           //  DW_AT_external DW_FORM_flag
            0xbe, 0x00, 0x00, 0x00,                         //  DW_AT_name DW_FORM_strp
            0x01,                                           //  DW_AT_decl_file DW_FORM_data1
            0x08,                                           //  DW_AT_decl_line DW_FORM_data1
            0x05,                                           //  DW_AT_decl_column DW_FORM_data1
            0x0e, 0x01, 0x00, 0x00,                         //  DW_AT_type DW_FORM_ref4
            0x29, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  DW_AT_low_pc DW_FORM_addr
            0xb4, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  DW_AT_high_pc DW_FORM_addr
            0x00, 0x00, 0x00, 0x00,                         //  DW_AT_frame_base DW_FORM_data4
            0x01,                   //  DW_AT_GNU_all_tail_call_sites DW_FORM_flag
            0x0e, 0x01, 0x00, 0x00,                         //  DW_AT_sibling DW_FORM_ref4
        0x08,                       // 8 DW_TAG_variable [no children]
            0x70, 0x00,             //  DW_AT_name DW_FORM_string
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x09,                   //  DW_AT_decl_line DW_FORM_data1
            0x14,                   //  DW_AT_decl_column DW_FORM_data1
            0x2d, 0x00, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
            0x02,                   //  DW_AT_location DW_FORM_block1
                0x91, 0x60,
        0x08,                       // 8 DW_TAG_variable [no children]
            0x73, 0x6c, 0x69, 0x64, 0x65, 0x0,             //  DW_AT_name DW_FORM_string
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x09,                   //  DW_AT_decl_line DW_FORM_data1
            0x14,                   //  DW_AT_decl_column DW_FORM_data1
            0x2d, 0x00, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
            0x02,                   //  DW_AT_location DW_FORM_block1
                0x91, 0x60,
        0x09,                       // 9 DW_TAG_lexical_block [has children]
            0x4d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  DW_AT_low_pc DW_FORM_addr
            0x59, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  DW_AT_high_pc DW_FORM_addr
        0x02,                       // 2 DW_TAG_structure_type [has children]
            0x17, 0x00, 0x00, 0x00, //  DW_AT_name DW_FORM_strp
            0x10,                   //  DW_AT_byte_size DW_FORM_data1
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x0e,                   //  DW_AT_decl_line DW_FORM_data1
            0x10,                   //  DW_AT_decl_column DW_FORM_data1
            0xee, 0x00, 0x00, 0x00, //  DW_AT_sibling DW_FORM_ref4
        0x03,                       // 3 DW_TAG_member [no children]
            0x12, 0x00, 0x00, 0x00, //  DW_AT_name DW_FORM_strp
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x0f,                   //  DW_AT_decl_line DW_FORM_data1
            0x12,                   //  DW_AT_decl_column DW_FORM_data1
            0x15, 0x01, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
            0x02,                   //  DW_AT_data_member_location DW_FORM_block1
                0x23, 0x00,
        0x04,                       // 4 DW_TAG_member [no children]
            0x73, 0x74, 0x72, 0x00, //  DW_AT_name DW_FORM_string
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x10,                   //  DW_AT_decl_line DW_FORM_data1
            0x13,                   //  DW_AT_decl_column DW_FORM_data1
            0x21, 0x01, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
            0x02,                   //  DW_AT_data_member_location DW_FORM_block1
                0x23, 0x08,
        0x00,
        0x08,                       // 8 DW_TAG_variable [no children]
            0x70, 0x00,             //  DW_AT_name DW_FORM_string
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x12,                   //  DW_AT_decl_line DW_FORM_data1
            0x18,                   //  DW_AT_decl_column DW_FORM_data1
            0xc2, 0x00, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
            0x02,                   //  DW_AT_location DW_FORM_block1
                0x91, 0x60,
        0x08,                       // 8 DW_TAG_variable [no children]
            0x73, 0x6c, 0x69, 0x64, 0x65, 0x0,             //  DW_AT_name DW_FORM_string
            0x01,                   //  DW_AT_decl_file DW_FORM_data1
            0x12,                   //  DW_AT_decl_line DW_FORM_data1
            0x18,                   //  DW_AT_decl_column DW_FORM_data1
            0xc2, 0x00, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
            0x02,                   //  DW_AT_location DW_FORM_block1
                0x91, 0x60,
        0x00,
        0x00,
        0x0a,                       // 10 DW_TAG_base_type [no children]
            0x04,                   //  DW_AT_byte_size DW_FORM_data1
            0x05,                   //  DW_AT_encoding DW_FORM_data1
            0x69, 0x6e, 0x74, 0x00, //  DW_AT_name DW_FORM_string
        0x0b,                       // 11 DW_TAG_array_type [has children]
            0x66, 0x00, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
        0x0c,                       // 12 DW_TAG_subrange_type [no children]
            0x59, 0x00, 0x00, 0x00, //  DW_AT_type DW_FORM_ref4
            0x07,                   //  DW_AT_upper_bound DW_FORM_data1
        0x00,
        
        0x0d,
            0x66, 0x00, 0x00, 0x00,
        0x0e,
            0x59, 0x00, 0x00, 0x00,
        0x00,
        0x00,
    };
    u32 info_table_rst_size = sizeof(info_table) - sizeof(u32);
    memcpy(info_table, &info_table_rst_size, sizeof(info_table_rst_size));
    {
        size_t dbg_info_off = instr_size;
        size_t dbg_info_size = sizeof(info_table);

        instr_size = instr_size + dbg_info_size;
        instr_mem_beg = realloc(instr_mem_beg, instr_size);

        struct range instr_prog = { .beg = instr_mem_beg, .end = instr_mem_beg + instr_size };
        struct elf64_shdr *instr_sh_dbginfo = get_shdr(instr_prog, SHT_PROGBITS,
            ".debug_info"
        );
        instr_sh_dbginfo->sh_offset = dbg_info_off;
        instr_sh_dbginfo->sh_size = dbg_info_size;
        void *dbg_info = instr_mem_beg + dbg_info_off;

        memcpy(dbg_info, info_table, sizeof(info_table));
    }
    {
        char debug_str_data[] = "long unsigned int"
            "\0page"
            "\0main.c"
            "\0present"
            "\0\x31\0sn\0tre\0four\0cinco\0shirto\0tyausen\0shomonte\0uddupunaa\0ra-kaitian\0napulog usa\0hopod om duo\0hopod om tolu\0goma sha hud'u\0tebwi ma nimaua\0-7+6*5+4-3!*2!+1"
            "\0main"
            "\0char"
            "\0data:text/plain;base64,WzYsTUFELF0/"
        ;
        extern char _binary_src_c_start;
        extern char _binary_src_c_end;
        size_t src_size = &_binary_src_c_end - &_binary_src_c_start;

        size_t debug_str_off  = instr_size;
        size_t debug_str_size = sizeof(debug_str_data);
        instr_size = instr_size + debug_str_size + src_size;
        instr_mem_beg = realloc(instr_mem_beg, instr_size);

        struct range instr_prog = { .beg = instr_mem_beg, .end = instr_mem_beg + instr_size };
        struct elf64_shdr *instr_sh_debug_str = get_shdr(instr_prog, SHT_PROGBITS,
            ".debug_str"
        );
        strncpy(instr_mem_beg + instr_sh_debug_str->sh_offset, "Oh, no! strncpy was here",
            instr_sh_debug_str->sh_size
        );
        instr_sh_debug_str->sh_offset = debug_str_off;
        instr_sh_debug_str->sh_size = debug_str_size;

        void *debug_str = instr_mem_beg + debug_str_off;
        memcpy(debug_str, debug_str_data, debug_str_size);
        memcpy(debug_str + debug_str_size, &_binary_src_c_start, src_size);
    }
    FILE *out = fopen("main.gdb", "w");
    fwrite(instr_mem_beg, 1, instr_size, out);
}
