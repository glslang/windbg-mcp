// The reviewer's scenario: an exception the program CATCHES, then a direct abort() called deeper
// than the throw site — so the caught exception's EXCEPTION_RECORD is still on the stack, above the
// aborting frame's stack pointer, and a scan that promotes anything self-consistent will find it.
//
// The fault is the same 0xc0000409 subcode 7 as the genuine unhandled throw, so nothing in the
// record tells them apart. What does is that no exception is being dispatched here.
#include <windows.h>
#include <stdlib.h>

struct hresult_error {
    unsigned long long vtable_placeholder;
    unsigned int sentinel;
    unsigned int code;
    hresult_error(unsigned int hr) : vtable_placeholder(0), sentinel(0xAABBCCDD), code(hr) {}
};

__declspec(noinline) void thrower() {
    throw hresult_error(0x80070005);
}

__declspec(noinline) void caught() {
    try {
        thrower();
    } catch (const hresult_error&) {
        // Handled. The record and the object stay on the stack regardless.
    }
}

__declspec(noinline) void deep(int n) {
    volatile char pad[64];
    pad[0] = (char)n;
    if (n > 0) {
        deep(n - 1);
        return;
    }
    abort();
}

int main() {
    caught();
    deep(30);
    return 0;
}
