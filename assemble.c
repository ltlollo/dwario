#include "instr.c"

struct data {
    u64 num;
};

char *main_pre = "struct present {"
    "\n    unsigned long page;"
    "\n    char *str;"
    "\n};"
    "\n"
    "\nint main() {"
    "\n    struct present p = { 0, };"
;

char *main_mid  = "\n    p.page++;";

char *main_post = "\n    return 0;"
    "\n};"
;

int main(int argc, char *argv[]) {
    int nfiles = argc - 1;

    if (nfiles <= 0) {
        errx(1, "not enough arguments");
        return 0;
    }

    struct arr *files = arr_init(sizeof(struct range), argc - 1);

    for (int i = 0; i < nfiles; i++) {
        int fd = open(argv[i+1], O_RDONLY);

        if (fd < 0) {
            err(1, "open '%s'", argv[i+1]);
        }
        off_t size = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        if (size == 0) {
            errx(1, "zero file");
        }
        size++;
        char *mem_beg = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        char *mem_end = mem_beg + size;

        if (mem_beg[size-1] != '\0') {
            errx(1, "unterm file");
        }
        struct range r = { .beg = mem_beg, .end = mem_end };
        arr_push(&files, &r);
    }
    
    FILE *out = fopen("table", "w");

    FILE *out_main = fopen("main.c", "w");
    fprintf(out_main, "%s", main_pre);

    for (size_t i = 0; i < files->size; i++) {
        struct range *r = arr_get(files, i);

        if (i == 2) {
            char confuse[sizeof(u64)] = "PAGE TWO";
            fwrite(confuse, sizeof(u64), 1, out);
        } else {
            fwrite(&i, sizeof(u64), 1, out);
        }
        fwrite(r->beg, r->end - r->beg, 1, out);
    }
    for (size_t i = 1; i < files->size; i++) {
        struct range *r = arr_get(files, i);
        fprintf(out_main, "%s", main_mid);
    }
    fprintf(out_main, "%s", main_post);
    return 0;
}
