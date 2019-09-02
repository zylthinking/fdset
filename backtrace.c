

#include "zyl.h"
#include <stdlib.h>

#if defined(__APPLE__) || (defined(__linux__) && !defined(__ANDROID__))
#include <execinfo.h>

void backtrace_print(uintptr_t levels)
{
    void* callstack[1024];
    if (levels > 1024) {
        levels = 1024;
    }

    int frames = backtrace(callstack, (int) levels);
    char** strs = backtrace_symbols(callstack, frames);

    logmsg("callstack dump: =========================\n");
    for (int i = 0; i < frames; ++i) {
        logmsg("%s\n", strs[i]);
    }
    logmsg("=========================================\n");
    free(strs);
}

#elif defined(__ANDROID__)
#include <dlfcn.h>

typedef struct {
    uintptr_t absolute_pc;     /* absolute PC offset */
    uintptr_t stack_top;       /* top of stack for this frame */
    size_t stack_size;         /* size of this stack frame */
} backtrace_frame_t;

typedef struct {
    uintptr_t relative_pc;       /* relative frame PC offset from the start of the library,
                                  or the absolute PC if the library is unknown */
    uintptr_t relative_symbol_addr; /* relative offset of the symbol from the start of the
                                     library or 0 if the library is unknown */
    char* map_name;              /* executable or library name, or NULL if unknown */
    char* symbol_name;           /* symbol name, or NULL if unknown */
    char* demangled_name;        /* demangled symbol name, or NULL if unknown */
} backtrace_symbol_t;

static ssize_t (*backtrace) (backtrace_frame_t*, size_t, size_t) = NULL;
static void (*backtrace_symbols) (const backtrace_frame_t*, size_t, backtrace_symbol_t*) = NULL;
static void (*symbols_free) (backtrace_symbol_t*, size_t) = NULL;

void backtrace_print(uintptr_t levels)
{
    backtrace_frame_t callstack[1024];
    backtrace_symbol_t symbols[1024];
    if (levels > 1024) {
        levels = 1024;
    }

    static void* handle = NULL;
    if (handle == NULL) {
        handle = dlopen("/system/lib/libcorkscrew.so", RTLD_NOW);
    }

    if (handle == NULL) {
        return;
    }

    if (backtrace == NULL) {
        backtrace = dlsym(handle, "unwind_backtrace");
    }

    if (backtrace_symbols == NULL) {
        backtrace_symbols = dlsym(handle, "get_backtrace_symbols");
    }

    if (symbols_free == NULL) {
        symbols_free = dlsym(handle, "free_backtrace_symbols");
    }

    if (backtrace == NULL || backtrace_symbols == NULL || symbols_free == NULL) {
        return;
    }

    uintptr_t nr = backtrace(callstack, 1, levels);
    backtrace_symbols(callstack, nr, symbols);

    logmsg("call stack dump:\n");
    for (int i = 2; i < nr; i++) {
        const char* module = "unknown";
        if (symbols[i].map_name != NULL) {
            module = symbols[i].map_name;
        }

        const char* func = symbols[i].symbol_name;
        if (symbols[i].demangled_name != NULL) {
            func = symbols[i].demangled_name;
        }
        logmsg("%02d: %-18s %s\n", i - 2, fileof(module), func);
    }
    logmsg("\n");
    symbols_free(symbols, nr);
}
#endif
