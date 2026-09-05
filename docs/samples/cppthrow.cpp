// Same fault as throwcrash.cpp, but with a second thread parked in a recognisable place, so a
// dump of it can be asked the question a single-threaded one cannot: does a walk follow the
// session's selected thread, or the context the event was recorded with?
#include <windows.h>

struct hresult_error {
    unsigned long long vtable_placeholder;
    unsigned int sentinel;
    unsigned int code;
    hresult_error(unsigned int hr) : vtable_placeholder(0), sentinel(0xAABBCCDD), code(hr) {}
};

__declspec(noinline) void inner() {
    throw hresult_error(0x80670015);
}

__declspec(noinline) void middle() {
    inner();
}

DWORD WINAPI parked(LPVOID) {
    Sleep(INFINITE);
    return 0;
}

int main() {
    CreateThread(nullptr, 0, parked, nullptr, 0, nullptr);
    Sleep(200);
    middle();
    return 0;
}
