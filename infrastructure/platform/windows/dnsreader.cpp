#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <initializer_list>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mi.h>
#include <cwchar>
#include <limits>
#endif

namespace {
constexpr size_t limit = 262144;
void append(std::string &output, const std::string &text)
{
    if (text.size() > limit || output.size() > limit - text.size()) throw std::runtime_error("snapshot size");
    output += text;
}
std::string quote(const std::string &text)
{
    std::string output("\"");
    constexpr char hex[] = "0123456789abcdef";
    for (const auto byte : text) {
        const auto ch = static_cast<unsigned char>(byte);
        if (ch == '"' || ch == '\\') append(output, std::string("\\") + char(ch));
        else if (ch < 32) append(output, std::string("\\u00") + hex[ch >> 4] + hex[ch & 15]);
        else append(output, std::string(1, char(ch)));
    }
    append(output, "\"");
    return output;
}

#ifdef _WIN32
ULONGLONG started;
struct ProviderFailure { MI_Result code; };
void trace(const char *stage)
{
    std::fprintf(stderr, "JCDNS phase=%s elapsed_ms=%llu\n", stage,
                 static_cast<unsigned long long>(GetTickCount64() - started));
    std::fflush(stderr);
}
void require(MI_Result result)
{
    if (result != MI_RESULT_OK) throw ProviderFailure{result};
}
std::string utf8(const wchar_t *text)
{
    if (!text) return {};
    const auto length = wcsnlen(text, limit + 1);
    if (length > limit) throw std::runtime_error("native string size");
    if (!length) return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, int(length), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0 || bytes > int(limit)) throw std::runtime_error("native Unicode");
    std::string output(size_t(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, int(length), output.data(), bytes, nullptr, nullptr) != bytes)
        throw std::runtime_error("native Unicode");
    return output;
}
std::string ip(const wchar_t *text)
{
    if (!text) throw std::runtime_error("native IP");
    const auto input = utf8(text);
    const auto separator = input.find('%');
    const auto host = input.substr(0, separator);
    IN6_ADDR address{};
    char canonical[INET6_ADDRSTRLEN]{};
    const int family = host.find(':') == std::string::npos ? AF_INET : AF_INET6;
    if (InetPtonA(family, host.c_str(), &address) != 1 || !InetNtopA(family, &address, canonical, sizeof(canonical)))
        throw std::runtime_error("native IP");
    std::string output(canonical);
    if (separator != std::string::npos) {
        const auto scope = input.substr(separator + 1);
        if (family != AF_INET6 || scope.empty() || scope.size() > 10 || scope.find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("native IP scope");
        const auto number = std::stoull(scope);
        if (number > 0xffffffffu) throw std::runtime_error("native IP scope");
        if (number) output += "%" + std::to_string(number);
    }
    return output;
}
struct Element {
    MI_Value value{};
    MI_Type type = MI_BOOLEAN;
    MI_Uint32 flags = MI_FLAG_NULL;
};
Element element(const MI_Instance *row, const wchar_t *name)
{
    Element item;
    const auto result = MI_Instance_GetElement(row, name, &item.value, &item.type, &item.flags, nullptr);
    if (result == MI_RESULT_NO_SUCH_PROPERTY || result == MI_RESULT_NOT_FOUND) return {};
    require(result);
    return item;
}
std::string value(const Element &item)
{
    if (item.flags & MI_FLAG_NULL) return "null";
    const auto &v = item.value;
    switch (item.type) {
    case MI_BOOLEAN: return v.boolean ? "true" : "false";
    case MI_UINT8: return std::to_string(v.uint8);
    case MI_SINT8: return std::to_string(v.sint8);
    case MI_UINT16: return std::to_string(v.uint16);
    case MI_SINT16: return std::to_string(v.sint16);
    case MI_UINT32: return std::to_string(v.uint32);
    case MI_SINT32: return std::to_string(v.sint32);
    case MI_SINT64: return std::to_string(v.sint64);
    case MI_UINT64:
        if (v.uint64 > static_cast<MI_Uint64>(std::numeric_limits<long long>::max())) throw std::runtime_error("native integer size");
        return std::to_string(v.uint64);
    case MI_STRING: return v.string ? quote(utf8(v.string)) : "null";
    case MI_STRINGA: {
        if (v.stringa.size > 4096) throw std::runtime_error("native array size");
        std::string output("[");
        for (MI_Uint32 i = 0; i < v.stringa.size; ++i) {
            if (i) append(output, ",");
            append(output, v.stringa.data[i] ? quote(utf8(v.stringa.data[i])) : "null");
        }
        append(output, "]");
        return output;
    }
    default: throw std::runtime_error("native property type");
    }
}
std::string strings(const Element &item, bool addresses)
{
    if (item.flags & MI_FLAG_NULL) return "[]";
    std::string output("[");
    bool first = true;
    const auto add = [&](const wchar_t *text) {
        if (!text) return;
        if (!first) append(output, ",");
        append(output, quote(addresses ? ip(text) : utf8(text)));
        first = false;
    };
    if (item.type == MI_STRING) add(item.value.string);
    else if (item.type == MI_STRINGA) {
        if (item.value.stringa.size > 4096) throw std::runtime_error("native array size");
        for (MI_Uint32 i = 0; i < item.value.stringa.size; ++i) add(item.value.stringa.data[i]);
    } else throw std::runtime_error("native string array");
    append(output, "]");
    return output;
}
std::string row(const MI_Instance *instance, std::initializer_list<const wchar_t *> fields)
{
    std::string output("{");
    bool first = true;
    for (const auto *name : fields) {
        if (!first) append(output, ",");
        first = false;
        append(output, quote(utf8(name)) + ":");
        const auto item = element(instance, name);
        const std::wstring field(name);
        if (field == L"Namespace" || field == L"NameServers" || field == L"DirectAccessDnsServers"
            || field == L"ServerAddresses" || field == L"ConnectionSpecificSuffixSearchList" || field == L"SuffixSearchList")
            append(output, strings(item, field == L"NameServers" || field == L"DirectAccessDnsServers"));
        else if (field == L"ConnectionSpecificSuffix" && (item.flags & MI_FLAG_NULL)) append(output, "\"\"");
        else append(output, value(item));
    }
    append(output, "}");
    return output;
}
struct Operation {
    MI_Operation handle = MI_OPERATION_NULL;
    ~Operation() { if (handle.ft) MI_Operation_Close(&handle); }
};
struct Session {
    HMODULE library = nullptr;
    MI_Application application = MI_APPLICATION_NULL;
    MI_Session handle = MI_SESSION_NULL;
    ~Session() {
        if (handle.ft) MI_Session_Close(&handle, nullptr, nullptr);
        if (application.ft) MI_Application_Close(&application);
        if (library) FreeLibrary(library);
    }
    void open() {
        trace("native");
        library = LoadLibraryExW(L"mi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) throw std::runtime_error("system MI library");
        const auto initialize = reinterpret_cast<decltype(&MI_Application_InitializeV1)>(GetProcAddress(library, "MI_Application_InitializeV1"));
        if (!initialize) throw std::runtime_error("system MI entry");
        require(initialize(0, nullptr, nullptr, &application));
        trace("local_session");
        require(MI_Application_NewSession(&application, L"WMIDCOM", nullptr, nullptr, nullptr, nullptr, &handle));
    }
};
template<typename Consume>
void consume(Operation &operation, Consume callback)
{
    MI_Boolean more = MI_TRUE;
    size_t count = 0;
    while (more) {
        const MI_Instance *instance = nullptr, *details = nullptr;
        const MI_Char *error = nullptr;
        MI_Result result = MI_RESULT_OK;
        require(MI_Operation_GetInstance(&operation.handle, &instance, &more, &result, &error, &details));
        require(result);
        if (instance) {
            if (++count > 4096) throw std::runtime_error("native result count");
            callback(instance);
        }
    }
}
std::string query(Session &session, const wchar_t *name, const char *stage, std::initializer_list<const wchar_t *> fields, bool singleton = false)
{
    trace(stage);
    Operation operation;
    const auto statement = std::wstring(L"SELECT * FROM ") + name;
    MI_Session_QueryInstances(&session.handle, 0, nullptr, L"ROOT\\StandardCimv2", L"WQL", statement.c_str(), nullptr, &operation.handle);
    std::string output("[");
    bool first = true;
    size_t count = 0;
    consume(operation, [&](const MI_Instance *instance) {
        ++count;
        if (!first) append(output, ",");
        first = false;
        append(output, row(instance, fields));
    });
    append(output, "]");
    if (singleton && count != 1) throw std::runtime_error("native global settings count");
    return singleton ? output.substr(1, output.size()-2) : output;
}
bool dohSupported(Session &session, const wchar_t *name)
{
    trace("doh_class");
    Operation operation;
    MI_Session_GetClass(&session.handle, 0, nullptr, L"ROOT\\StandardCimv2", name, nullptr, &operation.handle);
    const MI_Class *type = nullptr;
    const MI_Instance *details = nullptr;
    const MI_Char *error = nullptr;
    MI_Boolean more = MI_FALSE;
    MI_Result result = MI_RESULT_OK;
    const auto received = MI_Operation_GetClass(&operation.handle, &type, &more, &result, &error, &details);
    if (received == MI_RESULT_INVALID_CLASS || received == MI_RESULT_NOT_FOUND
        || result == MI_RESULT_INVALID_CLASS || result == MI_RESULT_NOT_FOUND) return false;
    require(received);
    require(result);
    if (!type || more) throw std::runtime_error("native DoH class");
    return true;
}
std::string nrpt(Session &session, const wchar_t *name, bool emptyFixture)
{
    trace("nrpt");
    MI_Instance *parameters = nullptr;
    require(MI_Application_NewInstance(&session.application, L"Parameters", nullptr, &parameters));
    struct Release { MI_Instance *instance; ~Release() { MI_Instance_Delete(instance); } } release{parameters};
    MI_Value effective{};
    effective.boolean = MI_TRUE;
    require(MI_Instance_AddElement(parameters, L"Effective", &effective, MI_BOOLEAN, MI_FLAG_IN));
    Operation operation;
    MI_Session_Invoke(&session.handle, 0, nullptr, L"ROOT\\Microsoft\\Windows\\DNS", name, L"Get", nullptr, parameters, nullptr, &operation.handle);
    std::string output("[");
    bool first = true, found = false;
    consume(operation, [&](const MI_Instance *instance) {
        if (found) throw std::runtime_error("native NRPT result count");
        found = true;
        if (emptyFixture) return;
        const auto policies = element(instance, L"cmdletOutput"), code = element(instance, L"ReturnValue");
        if (!(code.flags & MI_FLAG_NULL) && (code.type != MI_UINT32 || code.value.uint32 != 0))
            throw std::runtime_error("native NRPT return code");
        if (policies.flags & MI_FLAG_NULL) return;
        if (policies.type != MI_INSTANCEA || policies.value.instancea.size > 4096
            || ((code.flags & MI_FLAG_NULL) && policies.value.instancea.size)) throw std::runtime_error("native NRPT output");
        trace("nrpt_rows");
        for (MI_Uint32 i = 0; i < policies.value.instancea.size; ++i) {
            if (!first) append(output, ",");
            first = false;
            append(output, row(policies.value.instancea.data[i], {L"Namespace",L"NameServers",L"DirectAccessEnabled",L"DirectAccessDnsServers",L"DirectAccessIPsecCARestriction",L"DirectAccessProxyName",L"DirectAccessProxyType",L"DirectAccessQueryIPsecEncryption",L"DirectAccessQueryIPsecRequired",L"DnsSecIPsecCARestriction",L"DnsSecQueryIPsecEncryption",L"DnsSecQueryIPsecRequired",L"DnsSecValidationRequired",L"NameEncoding",L"QueryPolicy",L"SecureNameQueryFallback"}));
        }
    });
    append(output, "]");
    return output;
}
std::string snapshot(const wchar_t *nrptClass, const wchar_t *dohClass, bool emptyFixture)
{
    Session session;
    session.open();
    const auto policies = nrpt(session, nrptClass, emptyFixture);
    const bool supported = dohSupported(session, dohClass);
    const auto doh = supported ? query(session,dohClass,"MSFT_DNSClientDohServerAddress",{L"ServerAddress",L"DohTemplate",L"AllowFallbackToUdp",L"AutoUpgrade"}) : "[]";
    const auto interfaces = query(session,L"MSFT_DNSClientServerAddress","MSFT_DNSClientServerAddress",{L"InterfaceIndex",L"AddressFamily",L"ServerAddresses"});
    const auto clients = query(session,L"MSFT_DNSClient","MSFT_DNSClient",{L"InterfaceIndex",L"ConnectionSpecificSuffix",L"ConnectionSpecificSuffixSearchList",L"RegisterThisConnectionsAddress",L"UseSuffixWhenRegistering"});
    const auto globals = query(session,L"MSFT_DNSClientGlobalSetting","MSFT_DNSClientGlobalSetting",{L"SuffixSearchList",L"UseDevolution",L"DevolutionLevel",L"AppendParentSuffixes",L"AppendPrimarySuffixes"},true);
    std::string output("{\"interfaces\":");
    append(output,interfaces);append(output,",\"clients\":");append(output,clients);
    append(output,",\"global\":");append(output,globals);
    append(output,",\"nrpt\":");append(output,policies);
    append(output,",\"doh_supported\":");append(output,supported ? "true" : "false");
    append(output,",\"doh\":");append(output,doh);append(output,"}");
    trace("serialize");
    return output;
}
#endif
}

int main(int argc, char **argv) try
{
    const wchar_t *nrptClass = L"PS_DnsClientNrptPolicy", *dohClass = L"MSFT_DNSClientDohServerAddress";
    bool emptyFixture = false;
#ifdef JC_DNS_READER_TESTING
#ifdef _WIN32
    if (argc == 2 && std::strcmp(argv[1], "--stall") == 0) {
        started = GetTickCount64();
        trace("native");
        Sleep(INFINITE);
    }
#endif
    if (argc == 2 && std::strcmp(argv[1], "--self-test") == 0) {
        if (quote(std::string("\0\n\t\"\\",5)) != "\"\\u0000\\u000a\\u0009\\\"\\\\\""
            || quote("\xc3\xa9") != "\"\xc3\xa9\"") throw std::runtime_error("JSON escaping");
#ifdef _WIN32
        if (ip(L"2001:0DB8:0000::1%0012") != "2001:db8::1%12") throw std::runtime_error("IP normalization");
        bool rejected = false;
        try { ip(L"2001:db8::1%4294967296"); } catch (const std::exception &) { rejected = true; }
        if (!rejected) throw std::runtime_error("IP scope limit");
        const wchar_t invalid[] = {wchar_t(0xd800),0};
        rejected = false;
        try { utf8(invalid); } catch (const std::exception &) { rejected = true; }
        if (!rejected) throw std::runtime_error("Invalid Unicode");
        Element item;
        if (strings(item,false) != "[]" || value(item) != "null") throw std::runtime_error("Null property");
        wchar_t one[] = L"private.test";
        MI_Char *names[] = {one,nullptr};
        item.flags = 0; item.type = MI_STRINGA; item.value.stringa = {names,2};
        if (strings(item,false) != "[\"private.test\"]" || value(item) != "[\"private.test\",null]") throw std::runtime_error("String arrays");
#endif
        std::string output(limit, 'x');
        try { append(output,"x"); } catch (const std::runtime_error &) { std::puts("PASS: bounded DNS JSON and control/Unicode escaping"); return 0; }
        throw std::runtime_error("JSON limit");
    }
    if (argc == 2 && std::strcmp(argv[1], "--missing-doh") == 0) dohClass = L"JustConnectMissingDnsClass";
    else if (argc == 2 && std::strcmp(argv[1], "--missing-nrpt") == 0) nrptClass = L"JustConnectMissingDnsClass";
    else if (argc == 2 && std::strcmp(argv[1], "--empty-nrpt") == 0) emptyFixture = true;
    else
#endif
    if (argc != 1) throw std::runtime_error("arguments");
#ifdef _WIN32
    started = GetTickCount64();
    const auto output = snapshot(nrptClass,dohClass,emptyFixture);
    if (std::fwrite(output.data(), 1, output.size(), stdout) != output.size() || std::fflush(stdout) != 0) return 1;
    return 0;
#else
    throw std::runtime_error("Windows only");
#endif
#ifdef _WIN32
} catch (const ProviderFailure &failure) {
    std::fprintf(stderr, "Native DNS provider failed with code %u%s; no partial snapshot published.\n",
                 unsigned(failure.code), failure.code == MI_RESULT_ACCESS_DENIED ? ": permission denied" : "");
    return 1;
#endif
} catch (const std::exception &) {
    std::fputs("Native DNS snapshot failed; no partial snapshot published.\n", stderr);
    return 1;
}
