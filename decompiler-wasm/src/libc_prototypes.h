// Pyre — MIT
// Standard libc declarations parsed lazily into the decompiler's type
// database on the first decompile() call. Without these, calls to
// printf/puts/malloc/etc. render as `FUN_001020(s_001050, iVar1)`
// instead of `printf("%d", iVar1)`.
//
// Kept deliberately small: only declarations that are likely to bind
// to imported PLT/IAT stubs in real binaries. Ghidra's parse_C accepts
// standard C, including varargs (`...`).
//
// Format requirement: each declaration MUST end with `;`. The bridge
// splits on `;` and feeds each chunk to parse_C independently so a
// single bad declaration can't poison the rest.

#ifndef PYRE_LIBC_PROTOTYPES_H
#define PYRE_LIBC_PROTOTYPES_H

namespace pyre {

inline constexpr const char *LIBC_PROTOTYPES = R"(
/* stdio */
int   printf(char *format, ...);
int   fprintf(void *stream, char *format, ...);
int   sprintf(char *str, char *format, ...);
int   snprintf(char *str, unsigned int size, char *format, ...);
int   puts(char *s);
int   fputs(char *s, void *stream);
int   putchar(int c);
int   putc(int c, void *stream);
int   scanf(char *format, ...);
int   fscanf(void *stream, char *format, ...);
int   sscanf(char *str, char *format, ...);
char *fgets(char *s, int size, void *stream);
int   fgetc(void *stream);
int   getchar(void);
int   getc(void *stream);
int   fwrite(void *ptr, unsigned int size, unsigned int n, void *stream);
int   fread(void *ptr, unsigned int size, unsigned int n, void *stream);
int   fclose(void *stream);
void *fopen(char *path, char *mode);
int   fflush(void *stream);
int   feof(void *stream);
int   ferror(void *stream);
void  perror(char *s);

/* string */
unsigned int strlen(char *s);
char *strcpy(char *dst, char *src);
char *strncpy(char *dst, char *src, unsigned int n);
char *strcat(char *dst, char *src);
char *strncat(char *dst, char *src, unsigned int n);
int   strcmp(char *a, char *b);
int   strncmp(char *a, char *b, unsigned int n);
int   strcasecmp(char *a, char *b);
char *strchr(char *s, int c);
char *strrchr(char *s, int c);
char *strstr(char *haystack, char *needle);
char *strdup(char *s);
char *strerror(int errnum);
void *memcpy(void *dst, void *src, unsigned int n);
void *memmove(void *dst, void *src, unsigned int n);
void *memset(void *s, int c, unsigned int n);
int   memcmp(void *a, void *b, unsigned int n);
void *memchr(void *s, int c, unsigned int n);

/* stdlib */
void *malloc(unsigned int size);
void *calloc(unsigned int nmemb, unsigned int size);
void *realloc(void *ptr, unsigned int size);
void  free(void *ptr);
void  exit(int status);
void  abort(void);
int   atoi(char *s);
long  atol(char *s);
double atof(char *s);
long  strtol(char *s, char **endptr, int base);
unsigned long strtoul(char *s, char **endptr, int base);
char *getenv(char *name);
int   setenv(char *name, char *value, int overwrite);
int   system(char *command);
int   rand(void);
void  srand(unsigned int seed);
void  qsort(void *base, unsigned int n, unsigned int size, void *cmp);
void *bsearch(void *key, void *base, unsigned int n, unsigned int size, void *cmp);

/* unistd */
int   read(int fd, void *buf, unsigned int count);
int   write(int fd, void *buf, unsigned int count);
int   open(char *path, int flags, int mode);
int   close(int fd);
int   dup(int fd);
int   dup2(int oldfd, int newfd);
int   fork(void);
int   execve(char *path, char **argv, char **envp);
int   pipe(int *pipefd);
int   getpid(void);
int   getuid(void);
int   geteuid(void);
unsigned int sleep(unsigned int seconds);
int   usleep(unsigned int usec);

/* assert / errno helpers */
void  __assert_fail(char *assertion, char *file, unsigned int line, char *function);
void  __stack_chk_fail(void);
int  *__errno_location(void);

/* hardened glibc variants */
int   __printf_chk(int flag, char *format, ...);
int   __fprintf_chk(void *stream, int flag, char *format, ...);
int   __sprintf_chk(char *str, int flag, unsigned int size, char *format, ...);
int   __snprintf_chk(char *str, unsigned int n, int flag, unsigned int size, char *format, ...);
int   __vfprintf_chk(void *stream, int flag, char *format, void *ap);
int   __fgets_chk(char *s, unsigned int size, int n, void *stream);
char *__strcpy_chk(char *dst, char *src, unsigned int dstlen);
void *__memcpy_chk(void *dst, void *src, unsigned int n, unsigned int dstlen);
void *__memset_chk(void *s, int c, unsigned int n, unsigned int dstlen);
void  __libc_start_main(void);
)";

}  // namespace pyre

#endif  // PYRE_LIBC_PROTOTYPES_H
