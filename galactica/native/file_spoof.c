// file_spoof.c — libc path/read interception so Garena's integrity scan
// over the main FreeFire binary gets the PRISTINE bytes, not our patched
// copy (with the extra LC_LOAD_DYLIB). Hash on server side matches.
//
// Uses fishhook (vendored) to swap open/close/read/pread/lseek/fstat
// in every loaded image's __la_symbol_ptr / __got.
//
// The pristine_main_bin[] array is generated at build time from the
// upstream IPA by workflow xxd -i (see galactica/native/pristine_binary.h).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <os/log.h>

#include "fishhook.h"
#include "pristine_binary.h"   // defines pristine_main_bin[] and _len

#define GAL_LOG(fmt, ...) os_log(OS_LOG_DEFAULT, "[Galactica-spoof] " fmt, ##__VA_ARGS__)

// Fake fd range — far outside anything the game uses.
#define GAL_FD_BASE 90000
#define GAL_FD_MAX  32

struct gal_fd_slot {
    _Atomic int in_use;   // 0 = free, 1 = ours
    off_t       offset;
};

static struct gal_fd_slot gal_fds[GAL_FD_MAX];

static int     (*orig_open)   (const char *, int, ...)         = NULL;
static int     (*orig_close)  (int)                            = NULL;
static ssize_t (*orig_read)   (int, void *, size_t)            = NULL;
static ssize_t (*orig_pread)  (int, void *, size_t, off_t)     = NULL;
static off_t   (*orig_lseek)  (int, off_t, int)                = NULL;
static int     (*orig_fstat)  (int, struct stat *)             = NULL;
static int     (*orig_stat)   (const char *, struct stat *)    = NULL;

// Match any path ending in "FreeFire.app/FreeFire" — covers both
// /private/var/containers/Bundle/Application/<UUID>/FreeFire.app/FreeFire
// and a few other variants.
static int is_main_bin(const char *path) {
    if (!path) return 0;
    const char *needle = "FreeFire.app/FreeFire";
    size_t nlen = 21;
    size_t plen = strlen(path);
    if (plen < nlen) return 0;
    return strcmp(path + plen - nlen, needle) == 0;
}

static int alloc_slot(void) {
    for (int i = 0; i < GAL_FD_MAX; i++) {
        int expected = 0;
        if (__atomic_compare_exchange_n(&gal_fds[i].in_use, &expected, 1,
                                        0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            gal_fds[i].offset = 0;
            return i;
        }
    }
    return -1;
}

static inline int is_our_fd(int fd)  { return fd >= GAL_FD_BASE && fd < GAL_FD_BASE + GAL_FD_MAX; }
static inline int our_slot (int fd)  { return fd - GAL_FD_BASE; }

// --- open: if the caller wants the main binary, hand back a fake fd ---
static int gal_open(const char *path, int flags, mode_t mode) {
    if (is_main_bin(path)) {
        int s = alloc_slot();
        if (s >= 0) {
            GAL_LOG("spoof open %{public}s -> fd %d", path, GAL_FD_BASE + s);
            return GAL_FD_BASE + s;
        }
    }
    return orig_open(path, flags, mode);
}

// --- close ---
static int gal_close(int fd) {
    if (is_our_fd(fd)) {
        __atomic_store_n(&gal_fds[our_slot(fd)].in_use, 0, __ATOMIC_RELEASE);
        return 0;
    }
    return orig_close(fd);
}

// --- read: serve pristine bytes from our embedded buffer ---
static ssize_t gal_read(int fd, void *buf, size_t n) {
    if (is_our_fd(fd)) {
        int s = our_slot(fd);
        off_t off = gal_fds[s].offset;
        if ((size_t)off >= pristine_main_bin_len) return 0;
        size_t avail = pristine_main_bin_len - (size_t)off;
        size_t go = n < avail ? n : avail;
        memcpy(buf, pristine_main_bin + off, go);
        gal_fds[s].offset = off + (off_t)go;
        return (ssize_t)go;
    }
    return orig_read(fd, buf, n);
}

static ssize_t gal_pread(int fd, void *buf, size_t n, off_t off) {
    if (is_our_fd(fd)) {
        if ((size_t)off >= pristine_main_bin_len) return 0;
        size_t avail = pristine_main_bin_len - (size_t)off;
        size_t go = n < avail ? n : avail;
        memcpy(buf, pristine_main_bin + off, go);
        return (ssize_t)go;
    }
    return orig_pread(fd, buf, n, off);
}

static off_t gal_lseek(int fd, off_t off, int whence) {
    if (is_our_fd(fd)) {
        int s = our_slot(fd);
        off_t new_off = 0;
        switch (whence) {
            case SEEK_SET: new_off = off;                              break;
            case SEEK_CUR: new_off = gal_fds[s].offset + off;          break;
            case SEEK_END: new_off = (off_t)pristine_main_bin_len + off; break;
            default: errno = EINVAL; return -1;
        }
        if (new_off < 0) { errno = EINVAL; return -1; }
        gal_fds[s].offset = new_off;
        return new_off;
    }
    return orig_lseek(fd, off, whence);
}

// --- stat / fstat: report pristine size so hash-length checks match ---
static int gal_fstat(int fd, struct stat *st) {
    if (is_our_fd(fd)) {
        int r = orig_fstat(0, st);   // just to populate baseline fields
        (void)r;
        memset(st, 0, sizeof(*st));
        st->st_size = (off_t)pristine_main_bin_len;
        st->st_mode = S_IFREG | 0755;
        st->st_nlink = 1;
        return 0;
    }
    return orig_fstat(fd, st);
}

static int gal_stat(const char *path, struct stat *st) {
    int r = orig_stat(path, st);
    if (r == 0 && is_main_bin(path)) {
        st->st_size = (off_t)pristine_main_bin_len;
    }
    return r;
}

// Called from Galactica.m's +load (or from dylib constructor directly).
__attribute__((visibility("default")))
void gal_install_file_spoof(void) {
    struct rebinding binds[] = {
        { "open",  (void *)gal_open,  (void **)&orig_open  },
        { "close", (void *)gal_close, (void **)&orig_close },
        { "read",  (void *)gal_read,  (void **)&orig_read  },
        { "pread", (void *)gal_pread, (void **)&orig_pread },
        { "lseek", (void *)gal_lseek, (void **)&orig_lseek },
        { "fstat", (void *)gal_fstat, (void **)&orig_fstat },
        { "stat",  (void *)gal_stat,  (void **)&orig_stat  },
    };
    rebind_symbols(binds, sizeof(binds) / sizeof(binds[0]));
    GAL_LOG("file spoof installed — pristine bytes: %u", (unsigned)pristine_main_bin_len);
}

// Dylib constructor: hook FIRST, before anything in the game tries to read the binary.
__attribute__((constructor(101)))
static void gal_spoof_ctor(void) {
    gal_install_file_spoof();
}
