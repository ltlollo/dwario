#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define EI_NIDENT   (16)

#define EM_X86_64   (0x3e)

#define PT_NULL     (0x00)
#define PT_LOAD     (0x01)
#define PT_DYNAMIC  (0x02)
#define PT_INTERP   (0x03)
#define PT_NOTE     (0x04)
#define PT_SHLIB    (0x05)
#define PT_PHDR     (0x06)
#define PT_TLS      (0x07)

#define SHT_NULL            (0x00)
#define SHT_PROGBITS        (0x01)
#define SHT_SYMTAB          (0x02)
#define SHT_STRTAB          (0x03)
#define SHT_RELA            (0x04)
#define SHT_HASH            (0x05)
#define SHT_DYNAMIC         (0x06)
#define SHT_NOTE            (0x07)
#define SHT_NOBITS          (0x08)
#define SHT_REL             (0x09)
#define SHT_SHLIB           (0x0a)
#define SHT_DYNSYM          (0x0b)
#define SHT_INIT_ARRAY      (0x0e)
#define SHT_FINI_ARRAY      (0x0f)
#define SHT_PREINIT_ARRAY   (0x10)
#define SHT_GROUP           (0x11)
#define SHT_SYMTAB_SHNDX    (0x12)

#define SHN_UNDEF   (0x00)

#define ELFDATA2LSB (0x01)
#define ELFCLASS64  (0x02)
#define EHMAGIC     ("\177ELF")
#define EHCLASS     (0x04)
#define EHDATA      (0x05)
#define EHVERS      (0x06)

#define PTF_EXEC  (1 << 0)
#define PTF_WRITE (1 << 1)
#define PTF_READ  (1 << 2)

#define STB_LOCAL       (0x00)
#define STB_GLIBAL      (0x01)
#define STB_WEAK        (0x02)
#define STB_NUM         (0x03)
#define STB_LOOS        (0x10)
#define STB_GNU_UNIQUE  (0x10)
#define STB_HIOS        (0x12)
#define STB_LOPROC      (0x13)
#define STB_HIPROC      (0x15)

#define STT_NOTYPE      (0x00)
#define STT_OBJECT      (0x01)
#define STT_FUNC        (0x02)
#define STT_FILE        (0x03)
#define STT_COMMON      (0x04)
#define STT_TLS         (0x05)
#define STT_NUM         (0x06)
#define STT_LOOS        (0x07)
#define STT_GNU_IFUNC   (0x10)
#define STT_HIOS        (0x10)
#define STT_LOPROC      (0x13)
#define STT_HIPROC      (0x15)

#define DT_NULL             (0x00)
#define DT_NEEDED           (0x01)
#define DT_PLTRELSZ         (0x02)
#define DT_PLTGOT           (0x03)
#define DT_HASH             (0x04)
#define DT_STRTAB           (0x05)
#define DT_SYMTAB           (0x06)
#define DT_RELA             (0x07)
#define DT_RELASZ           (0x08)
#define DT_RELAENT          (0x09)
#define DT_STRSZ            (0x0a)
#define DT_SYMENT           (0x0b)
#define DT_INIT             (0x0c)
#define DT_FINI             (0x0d)
#define DT_SONAME           (0x0e)
#define DT_RPATH            (0x0f)
#define DT_SYMBOLIC         (0x10)
#define DT_REL              (0x11)
#define DT_RELSZ            (0x12)
#define DT_RELENT           (0x13)
#define DT_PLTREL           (0x14)
#define DT_DEBUG            (0x15)
#define DT_TEXTREL          (0x16)
#define DT_JMPREL           (0x17)
#define DT_BIND_NOW         (0x18)
#define DT_INIT_ARRAY       (0x19)
#define DT_FINI_ARRAY       (0x1a)
#define DT_INIT_ARRAYSZ     (0x1b)
#define DT_FINI_ARRAYSZ     (0x1c)
#define DT_RUNPATH          (0x1d)
#define DT_FLAGS            (0x1e)
#define DT_ENCODING         (0x20)
#define DT_PREINIT_ARRAY    (0x20)
#define DT_PREINIT_ARRAYSZ  (0x21)
#define DT_NUM              (0x22)
#define DT_LOOS             (0x6000000d)
#define DT_HIOS             (0x6ffff000)
#define DT_LOPROC           (0x70000000)
#define DT_HIPROC           (0x7fffffff)
#define DT_PROCNUM          DT_MIPS_NUM

#define R_X86_64_NONE       (0x00)
#define R_X86_64_64         (0x01)
#define R_X86_64_PC32       (0x02)
#define R_X86_64_GOT32      (0x03)
#define R_X86_64_PLT32      (0x04)
#define R_X86_64_COPY       (0x05)
#define R_X86_64_GLOB_DAT   (0x06)
#define R_X86_64_JUMP_SLOT  (0x07)
#define R_X86_64_RELATIVE   (0x08)
#define R_X86_64_GOTPCREL   (0x09)

#define INSTR_MAX       (64)
#define MOVSEQ_MAX      (5)

#define NOP             (0x90)

#define __align(n)  __attribute__((aligned(n)))
#define __pack      __attribute__((packed))
#define __clean     __attribute__((cleanup(ifree)))

#define align_down(x, a) ((uintptr_t)(x) & ~((uintptr_t)(a) - 1))
#define align_up(x, a) align_down((uintptr_t)(x) + (uintptr_t)(a) - 1, a)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define xensure(s)\
    do {\
        if ((s) == 0) {\
            breakf();\
            err(1, "%s:%d: invariant violated: "#s, __FILE__, __LINE__);\
        }\
    } while(0)
#define xensurex(s)\
    do {\
        if ((s) == 0) {\
            breakf();\
            errx(1, "invariant vilated: "#s);\
        }\
    } while(0)
#define xinbound(f, r)\
    do {\
        if ((void *)(f) < (void *)((r).beg)\
            || (void *)(f) > (void *)((r).end)) {\
            errx(1, "%d: out of bounds %s, [%s]", __LINE__, ""#f, ""#r);\
        }\
    } while (0)
#define xinrange(a, prog)\
    do {\
        xinbound((a).beg, prog);\
        xinbound((a).end, prog);\
    } while (0)

typedef uintptr_t       __elf64_addr    __align(8);
typedef unsigned long   __elf64_off     __align(8);
typedef unsigned short  __elf64_half    __align(2);
typedef unsigned        __elf64_word    __align(4);
typedef int             __elf64_sword   __align(4);
typedef unsigned long   __elf64_xword   __align(8);
typedef long            __elf64_sxword  __align(8);
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

_Static_assert(sizeof(__elf64_addr  ) == 8, "incorrect size");
_Static_assert(sizeof(__elf64_off   ) == 8, "incorrect size");
_Static_assert(sizeof(__elf64_half  ) == 2, "incorrect size");
_Static_assert(sizeof(__elf64_word  ) == 4, "incorrect size");
_Static_assert(sizeof(__elf64_sword ) == 4, "incorrect size");
_Static_assert(sizeof(__elf64_xword ) == 8, "incorrect size");
_Static_assert(sizeof(__elf64_sxword) == 8, "incorrect size");

struct elf64_ehdr {
    unsigned char   e_ident[EI_NIDENT];
    __elf64_half    e_type;
    __elf64_half    e_machine;
    __elf64_word    e_version;
    __elf64_addr    e_entry;
    __elf64_off     e_phoff;
    __elf64_off     e_shoff;
    __elf64_word    e_flags;
    __elf64_half    e_ehsize;
    __elf64_half    e_phentsize;
    __elf64_half    e_phnum;
    __elf64_half    e_shentsize;
    __elf64_half    e_shnum;
    __elf64_half    e_shstrndx;
} __packed;

struct elf64_phdr {
    __elf64_word    p_type;
    __elf64_word    p_flags;
    __elf64_off     p_offset;
    __elf64_addr    p_vaddr;
    __elf64_addr    p_paddr;
    __elf64_xword   p_filesz;
    __elf64_xword   p_memsz;
    __elf64_xword   p_align;
} __pack;

struct elf64_shdr {
    __elf64_word    sh_name;
    __elf64_word    sh_type;
    __elf64_xword   sh_flags;
    __elf64_addr    sh_addr;
    __elf64_off     sh_offset;
    __elf64_xword   sh_size;
    __elf64_word    sh_link;
    __elf64_word    sh_info;
    __elf64_xword   sh_addralign;
    __elf64_xword   sh_entsize;
} __pack;

struct elf64_sym {
    __elf64_word    st_name;
    unsigned char   st_info;
    unsigned char   st_other;
    __elf64_half    st_shndx;
    __elf64_addr    st_value;
    __elf64_xword   st_size;
} __pack;

struct elf64_dyn {
    __elf64_xword       d_tag;
    union {
        __elf64_xword   d_val;
        __elf64_addr    d_ptr;
    };
} __pack;

struct elf64_rela {
    __elf64_addr    r_offset;
    __elf64_xword   r_info;
    __elf64_sxword  r_addend;
} __pack;

struct range {
    void *beg;
    void *end;
};

struct rangearr {
    void *beg;
    void *end;
    size_t esz;
};

enum jmpkind {
    JMP,
    JZ, JE = JZ,
    JNBE, JA = JNBE,
    JBE, JNA = JBE,
    JNZ, JNE = JNZ,
    JLE, JNG = JLE,
    JNL, JGE = JNL,
    JNLE, JG = JNLE,
    JL, JNGE = JL,
    JB, JNAE = JB, JC = JB,
    JNB, JAE = JNB, JNC = JNB,
    CALL,
    JO,
    JNO,
    JS,
    JNS,
    JP, JPE = JP,
    JNP, JPO = JNP,
    JECXZ, JRCXZ = JECXZ,
    INVALID_JMP, JMP_MAX = INVALID_JMP,
};

struct arr {
    size_t elesize;
    size_t size;
    size_t alloc;
    char data[];
};

struct str {
    size_t size;
    size_t alloc;
    char data[];
};

struct jmpinfo {
    uintptr_t from;
    uintptr_t into;
    size_t insnum;
    int len;
    enum jmpkind kind;
};

struct insinfo {
    u8 ins[INSTR_MAX];
    int len;
    char repr[64];
    u8 *pc;
};

struct segment {
    size_t off;
    size_t size;
    uintptr_t mmbeg;
    uintptr_t mmend;
};

struct insmap {
    uintptr_t oldloc;
    uintptr_t newloc;
    size_t oldlen;
    size_t insnum;
};

struct movableseq {
    int len;
    struct insmap seq[MOVSEQ_MAX];
};

static const char *const jmpstr[] = {
    [JO   ] = "jo",
    [JNO  ] = "jno",
    [JB   ] = "jb",
    [JAE  ] = "jae",
    [JE   ] = "je",
    [JNE  ] = "jne",
    [JBE  ] = "jbe",
    [JA   ] = "ja",
    [JS   ] = "js",
    [JNS  ] = "jns",
    [JP   ] = "jp",
    [JNP  ] = "jnp",
    [JL   ] = "jl",
    [JGE  ] = "jge",
    [JLE  ] = "jle",
    [JG   ] = "jg",
    [JECXZ] = "jecxz",
    [JMP  ] = "jmp",
    [CALL ] = "call"
};

static int verbose = 0;

void breakf(void) {
}

__attribute__ ((format (printf, 1, 2))) void
dbg(const char *fmt, ...) {
    if (verbose == 0) return;

    va_list vl;
    va_start(vl, fmt);
    vfprintf(stderr, fmt, vl);
    fputc('\n', stderr);
    va_end(vl);
}

void *
arr_get(struct arr *arr, size_t i) {
    return arr->data + i * arr->elesize;
}

struct arr *
arr_init(size_t elesize, size_t alloc) {
    struct arr *arr = malloc(sizeof(struct arr) + elesize * alloc);

    if (!arr) {
        return NULL;
    }
    arr->elesize = elesize;
    arr->alloc = alloc;
    arr->size = 0;
    return arr;
}

int
arr_push(struct arr **parr, const void *it) {
    struct arr *arr = *parr;

    if (arr->size == arr->alloc) {
        size_t alloc = (arr->alloc + 1) * 2;
        arr = realloc(arr, sizeof(struct arr) + arr->elesize * alloc);
        if (!arr) {
            return -1;
        }
        *parr = arr;
        arr->alloc = alloc;
    }
    memcpy(arr_get(arr, arr->size++), it, arr->elesize);
    return 0;
}

int
str_push(struct str **pstr, const void *it, size_t size) {
    struct str *str = *pstr;

    if (str->size + size > str->alloc) {
        size_t alloc = (str->alloc + size + 1) * 2;
        str = realloc(str, sizeof(struct str) + alloc);
        if (!str) {
            return -1;
        }
        *pstr = str;
        str->alloc = alloc;
    }
    memcpy(str->data + str->size, it, size);
    str->size += size;
    str->data[str->size] = 0;
    return 0;
}

struct str *
str_init(size_t alloc) {
    struct str *str = malloc(sizeof(struct str) + alloc);
    if (str == NULL) {
        return NULL;
    }
    str->alloc = alloc;
    str->size = 0;
    return str;
}

void
ifree(void *in) {
    void **pi = in;
    free(*pi);
}

int
range_resize(struct range *r, size_t size) {
    void *beg = realloc(r->beg, size);
    if (beg == NULL) {
        return -1;
    }
    r->beg = beg;
    r->end = beg + size;
    return 0;
}

char *
eat_until(char *s, char c) {
    while (*s && *s != c) s++;
    return s;
}

size_t
strlcpy(char *dest, const char *src, size_t size) {
    size_t len = strlen(src);
    if (len == 0 || size == 0) return 0;
    if (len > size - 1) len = size -1;
    memcpy(dest, src, len);
    dest[len] = 0;
    return len;
}

size_t
strnlcpy(char *dest, const char *src, size_t s, size_t size) {
    size_t len = strlen(src);
    if (len == 0 || size == 0) return 0;
    if (s > len) s = len;
    if (s > size - 1) s = size -1;
    memcpy(dest, src, s);
    dest[s] = 0;
    return s;
}

int
openf(char *fname, char **mm, size_t *mmsz) {
    int fd = open(fname, O_RDONLY);

    if (fd == -1) {
        return -1;
    }
    off_t off = lseek(fd, 0, SEEK_END);
    if (off == -1) {
        return -1;
    }
    off_t e = lseek(fd, 0, SEEK_SET);
    if (e == -1) {
        return -1;
    }
    *mmsz = off;
    if ((*mm = mmap(NULL, off, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        return -1;
    }
    return 0;
}

enum jmpkind
jmpclass(const char *str) {
    enum jmpkind ret = INVALID_JMP;

    for (size_t i = 0; i < JMP_MAX; i++) {
        if (strcmp(str, jmpstr[i]) == 0) {
            ret = i;
            break;
        }
    }
    return ret;
}

struct elf64_ehdr *
get_ehdr(struct range prog) {
    struct elf64_ehdr *eh = prog.beg;

    if (prog.beg + sizeof(struct elf64_ehdr) > prog.end) {
        errx(1, "corrupt header or not elf64 input");
    }
    if (memcmp(eh->e_ident, EHMAGIC, 4) != 0) {
        errx(1, "corrupt or not elf64 input");
    }
    if (eh->e_ident[EHCLASS] != ELFCLASS64) {
        errx(1, "wrong EHCLASS");
    }
    if (eh->e_ident[EHDATA] != ELFDATA2LSB) {
        errx(1, "wrong EHCLASS");
    }
    if (eh->e_machine != EM_X86_64) {
        errx(1, "wrong e_machine");
    }
    return eh;
}

struct range
get_sheader(struct range prog) {
    struct range sheader;
    struct elf64_ehdr *eh = get_ehdr(prog);
    sheader.beg = prog.beg + eh->e_shoff;
    sheader.end = sheader.beg + eh->e_shentsize;
    xinrange(sheader, prog);

    struct elf64_shdr *es = sheader.beg;
    if (eh->e_shnum == SHN_UNDEF) {
        sheader.end = sheader.beg + es->sh_size * eh->e_shentsize;
    } else {
        sheader.end = sheader.beg + eh->e_shnum * eh->e_shentsize;
    }
    xinrange(sheader, prog);
    return sheader;
}

struct range
get_shnames(struct range prog) {
    struct range sheader = get_sheader(prog);
    struct elf64_ehdr *eh = get_ehdr(prog);
    struct elf64_shdr *shstr = sheader.beg + eh->e_shstrndx * eh->e_shentsize;
    xinbound(shstr, prog);

    struct range shnames;
    shnames.beg = prog.beg + shstr->sh_offset;
    shnames.end = shnames.beg + shstr->sh_size;
    xinrange(shnames, prog);

    return shnames;
}

struct range
get_pheader(struct range prog) {
    struct elf64_ehdr *eh = get_ehdr(prog);
    struct range pheader;
    pheader.beg = prog.beg + eh->e_phoff;
    pheader.end = pheader.beg + eh->e_phnum * eh->e_phentsize;
    xinrange(pheader, prog);

    return pheader;
}

struct elf64_phdr *
get_phdr(struct range prog, unsigned type) {
    struct elf64_ehdr *eh = get_ehdr(prog);
    struct range pheader = get_pheader(prog);

    for (void *cur = pheader.beg; cur < pheader.end; cur += eh->e_phentsize) {
        struct elf64_phdr *ph = cur;
        if (ph->p_type == type) {
            return ph;
        }
    }
    return NULL;
}

struct elf64_shdr *
get_shdr(struct range prog, unsigned type, char *name) {
    struct range sheader = get_sheader(prog);
    struct range shnames = get_shnames(prog);
    struct elf64_ehdr *eh = get_ehdr(prog);

    for ( void *cur = sheader.beg; cur < sheader.end; cur += eh->e_shentsize) {
        struct elf64_shdr *es = cur;
        if (es->sh_type != type) {
            continue;
        }
        char *sh_name = shnames.beg + es->sh_name;
        xinbound(sh_name, shnames);

        if (strcmp(sh_name, name) == 0) {
            return es;
        }
    }
    return NULL;
}

struct rangearr
get_sharr(struct range prog, unsigned type, char *name) {
    struct rangearr a;

    struct elf64_shdr *sh = get_shdr(prog, type, name);
    xensurex(sh);
    a.beg = prog.beg + sh->sh_offset;
    a.end = a.beg + sh->sh_size;
    a.esz = sh->sh_entsize;
    xinrange(a, prog);

    return a;
}

struct rangearr
get_strtab(struct range prog) {
    return get_sharr(prog, SHT_STRTAB, ".strtab");
}

struct rangearr
get_symtab(struct range prog) {
    return get_sharr(prog, SHT_SYMTAB, ".symtab");
}

struct rangearr
get_dynamic(struct range prog) {
    return get_sharr(prog, SHT_DYNAMIC, ".dynamic");
}

struct elf64_sym *
get_sym(struct range prog, unsigned type, char *name) {
    struct rangearr symtab = get_symtab(prog);
    struct rangearr strtab = get_strtab(prog);

    for (void *cur = symtab.beg; cur < symtab.end; cur += symtab.esz) {
        struct elf64_sym *s = cur;
        if ((s->st_info & 0xf) != type  || s->st_name == 0) {
            continue;
        }
        char *sym_name = strtab.beg + s->st_name;
        xinbound(sym_name, strtab);
        if (strcmp(sym_name, name) == 0) {
            return s;
        }
    }
    return NULL;
}

// LICENSE
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
