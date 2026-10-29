// libc compatibility shims for Android 10 (API 29).
//
// libmixxx is built for API 29 (minSdk), but some static libraries of the
// prebuilt vcpkg buildenv were compiled for a newer API level and reference
// bionic functions that only exist from that level on. The API 29 libc stubs
// do not export them, so the link fails (and, even if it did not, dlopen would
// fail on Android 10 with "cannot locate symbol").
//
//   copy_file_range  bionic API 34  used by zix (zix_copy_file)
//   backtrace        bionic API 33  used by abseil (stacktrace_generic)
//
// This file provides private replacements. They are only compiled when the
// native API level is below the one where bionic introduces the function, and
// they have hidden visibility: libmixxx is not exporting them, and on devices
// whose libc does have them, nothing else in the process is interposed. The
// references from the static libraries are resolved at link time against
// these definitions.
//
// Do not add declarations of functions that libc already has at API 29: a
// hidden definition here would silently replace the libc one inside libmixxx.

#if defined(__ANDROID__)

#include <android/api-level.h>

#if __ANDROID_API__ < 34
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if __ANDROID_API__ < 33
#include <stdint.h>
#include <unwind.h>
#endif

#define MIXXX_LIBC_COMPAT_HIDDEN extern "C" __attribute__((visibility("hidden")))

#if __ANDROID_API__ < 34

namespace {

constexpr size_t kCopyBufferSize = 64 * 1024;

ssize_t readChunk(int fd, void* buf, size_t count, off64_t* offset) {
    for (;;) {
        const ssize_t n = offset ? pread64(fd, buf, count, *offset)
                                 : read(fd, buf, count);
        if (n >= 0 || errno != EINTR) {
            return n;
        }
    }
}

ssize_t writeChunk(int fd, const void* buf, size_t count, off64_t* offset) {
    for (;;) {
        const ssize_t n = offset ? pwrite64(fd, buf, count, *offset)
                                 : write(fd, buf, count);
        if (n >= 0 || errno != EINTR) {
            return n;
        }
    }
}

} // namespace

// Userspace implementation of copy_file_range(2) with the same contract:
// copies up to `length` bytes, returns the number of bytes copied (0 at end
// of file, possibly fewer than requested) or -1 with errno set. When an
// offset pointer is given, it is used and advanced and the file offset of
// that descriptor is left untouched; otherwise the file offset is used and
// advanced.
//
// The raw syscall (__NR_copy_file_range) is deliberately not used: it is not
// part of bionic before API 34, so it may be missing from the seccomp
// allowlist that Android applies to app processes, and a blocked syscall
// kills the process with SIGSYS instead of returning ENOSYS. The files zix
// copies are small (LV2 state and similar), so a read/write loop is enough.
MIXXX_LIBC_COMPAT_HIDDEN ssize_t copy_file_range(int fd_in,
        off64_t* off_in,
        int fd_out,
        off64_t* off_out,
        size_t length,
        unsigned int flags) {
    if (flags != 0) {
        errno = EINVAL;
        return -1;
    }
    if ((off_in && *off_in < 0) || (off_out && *off_out < 0)) {
        errno = EINVAL;
        return -1;
    }
    if (length == 0) {
        return 0;
    }
    if (length > static_cast<size_t>(SSIZE_MAX)) {
        length = static_cast<size_t>(SSIZE_MAX);
    }

    const size_t bufferSize = length < kCopyBufferSize ? length : kCopyBufferSize;
    char* const buffer = static_cast<char*>(malloc(bufferSize));
    if (!buffer) {
        errno = ENOMEM;
        return -1;
    }

    size_t copied = 0;
    int error = 0;
    while (copied < length) {
        const size_t remaining = length - copied;
        const size_t want = remaining < bufferSize ? remaining : bufferSize;
        const ssize_t nRead = readChunk(fd_in, buffer, want, off_in);
        if (nRead < 0) {
            error = errno;
            break;
        }
        if (nRead == 0) {
            break; // end of file
        }

        size_t written = 0;
        while (written < static_cast<size_t>(nRead)) {
            const ssize_t nWritten = writeChunk(fd_out,
                    buffer + written,
                    static_cast<size_t>(nRead) - written,
                    off_out);
            if (nWritten <= 0) {
                error = nWritten < 0 ? errno : EIO;
                break;
            }
            written += static_cast<size_t>(nWritten);
            if (off_out) {
                *off_out += nWritten;
            }
        }

        // Only count (and consume from the input) what was actually written.
        if (off_in) {
            *off_in += static_cast<off64_t>(written);
        } else if (written < static_cast<size_t>(nRead)) {
            // Rewind the input past the bytes that were read but not written.
            lseek64(fd_in,
                    -static_cast<off64_t>(static_cast<size_t>(nRead) - written),
                    SEEK_CUR);
        }
        copied += written;
        if (error != 0) {
            break;
        }
    }

    free(buffer);
    if (copied > 0) {
        // Like the kernel: a partial copy is reported as success; the caller
        // gets the error on its next call.
        return static_cast<ssize_t>(copied);
    }
    if (error != 0) {
        errno = error;
        return -1;
    }
    return 0;
}

#endif // __ANDROID_API__ < 34

#if __ANDROID_API__ < 33

namespace {

struct BacktraceState {
    void** frames;
    int maxFrames;
    int count;
    int skip;
};

_Unwind_Reason_Code backtraceCallback(struct _Unwind_Context* context, void* arg) {
    BacktraceState* const state = static_cast<BacktraceState*>(arg);
    uintptr_t ip = _Unwind_GetIP(context);
    if (ip == 0) {
        return _URC_END_OF_STACK;
    }
    if (state->skip > 0) {
        --state->skip;
        return _URC_NO_REASON;
    }
#if defined(__aarch64__)
    // Strip the pointer authentication / tag bits, as bionic does.
    ip &= (uintptr_t{1} << 56) - 1;
#endif
    state->frames[state->count++] = reinterpret_cast<void*>(ip);
    return state->count >= state->maxFrames ? _URC_END_OF_STACK : _URC_NO_REASON;
}

} // namespace

// backtrace(3) (execinfo.h) on top of the unwinder that the NDK links into
// every binary (libunwind), which is also how bionic implements it from API
// 33 on. Like glibc, the first entry is the return address in the caller of
// backtrace(): the frame of backtrace() itself is skipped. Returns the number
// of frames stored, 0 if none (abseil then reports an empty stack).
MIXXX_LIBC_COMPAT_HIDDEN __attribute__((noinline)) int backtrace(void** buffer, int size) {
    if (!buffer || size <= 0) {
        return 0;
    }
    BacktraceState state = {buffer, size, 0, 1};
    _Unwind_Backtrace(backtraceCallback, &state);
    return state.count;
}

#endif // __ANDROID_API__ < 33

#endif // defined(__ANDROID__)
