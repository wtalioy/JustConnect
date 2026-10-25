#include "infrastructure/networkhelper/windows/session.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <iostream>
#include <system_error>

using namespace winrt::Windows::Data::Json;
namespace {
void check(bool value,const char *message){if(!value)throw std::runtime_error(message);}
template<class F>void refused(F operation){bool denied=false;try{operation();}catch(const std::system_error &){denied=true;}check(denied,"invalid network configuration was accepted");}
}
int main() try
{
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    const std::string valid=R"({"address":"198.18.0.1","peer":"198.18.0.2","mtu":1400,"capture_prefixes":["198.18.0.6/32"],"dns_domains":["campus.invalid"]})";
    const auto accepted=decodeWindowsNetworkConfiguration(valid);
    check(accepted.dns && accepted.dns->valid() && accepted.captures.size()==1,"valid complete network configuration was refused");
    for(const auto &address:{L"0.0.0.0",L"127.0.0.1",L"224.0.0.1",L"198.018.0.1",L"198.18.0.2"}){
        auto value=JsonObject::Parse(winrt::to_hstring(valid));value.SetNamedValue(L"address",JsonValue::CreateStringValue(address));
        refused([&]{decodeWindowsNetworkConfiguration(winrt::to_string(value.Stringify()));});
    }
    for(const auto &prefix:{L"0.0.0.0/0",L"0.0.0.0/2",L"127.0.0.0/8",L"224.0.0.0/4",L"198.18.0.1/32",L"198.18.0.6/24",L"198.18.0.6/033"}){
        auto value=JsonObject::Parse(winrt::to_hstring(valid));JsonArray targets;targets.Append(JsonValue::CreateStringValue(prefix));value.SetNamedValue(L"capture_prefixes",targets);
        refused([&]{decodeWindowsNetworkConfiguration(winrt::to_string(value.Stringify()));});
    }
    for(const auto number:{67.0,65536.0,1400.5}){
        auto value=JsonObject::Parse(winrt::to_hstring(valid));value.SetNamedValue(L"mtu",JsonValue::CreateNumberValue(number));
        refused([&]{decodeWindowsNetworkConfiguration(winrt::to_string(value.Stringify()));});
    }
    auto value=JsonObject::Parse(winrt::to_hstring(valid));value.SetNamedValue(L"program",JsonValue::CreateStringValue(L"unowned.exe"));
    refused([&]{decodeWindowsNetworkConfiguration(winrt::to_string(value.Stringify()));});
    value=JsonObject::Parse(winrt::to_hstring(valid));JsonArray names;names.Append(JsonValue::CreateStringValue(L"localhost"));value.SetNamedValue(L"dns_domains",names);
    refused([&]{decodeWindowsNetworkConfiguration(winrt::to_string(value.Stringify()));});
    refused([&]{decodeWindowsCapturePrefixes(R"(["198.18.0.6/32","198.18.0.6/32"])");});
    refused([&]{decodeWindowsCapturePrefixes(R"([false])");});
    std::cout<<"PASS: bounded native session configuration, canonical captures, protected ranges, DNS and unknown-field rejection\n";
    return 0;
}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
