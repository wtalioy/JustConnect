#include "infrastructure/process/windows/identity.h"
#include <iostream>
#include <system_error>

static void check(bool value,const char *message)
{
    if (!value) throw std::runtime_error(message);
}

int main() try
{
    WindowsProcess retained(GetCurrentProcessId());
    auto identity = retained.identity();
    check(identity.alive(),"actual retained process not alive");
    ++identity.created;
    check(!identity.alive(),"PID reuse adopted another creation time");
    --identity.created;
    identity.sid=L"S-1-0-0";
    check(!identity.alive(),"different account was adopted");
    for (const auto &bad:{L"",L"S-1-05-18",L"not a SID"}) {
        identity.sid=bad;
        bool refused=false;
        try { identity.alive(); } catch (const std::system_error &error) { refused=error.code().value()==ERROR_INVALID_DATA; }
        check(refused,"noncanonical saved SID was accepted");
    }
    std::cout << "PASS: retained process object, creation time, actual SID and saved identity validation\n";
    return 0;
} catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
}
