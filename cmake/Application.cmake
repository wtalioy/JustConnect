include_guard(GLOBAL)
find_package(Qt6 REQUIRED COMPONENTS Core Network Concurrent)

add_library(justconnect_application STATIC
    "${REPO}/application/coreengine.h"
    "${REPO}/application/authmethodsquery.cpp"
    "${REPO}/application/networkprotection.cpp"
    "${REPO}/application/applicationlogger.cpp"
    "${REPO}/application/commandlineoptions.cpp"
    "${REPO}/application/applicationshutdown.cpp"
    "${REPO}/application/connectionsession.cpp"
    "${REPO}/application/profileservice.cpp"
    "${REPO}/application/profileconfiguration.cpp"
    "${REPO}/application/profilecredentials.cpp"
    "${REPO}/application/settingsmigrator.cpp"
    "${REPO}/application/systemproxysession.cpp"
    "${REPO}/application/coexistencenetworkaccess.cpp"
    "${REPO}/application/networkpolicysession.cpp"
    "${REPO}/application/defaultsettings.cpp"
    "${REPO}/core/connectionsessionstate.cpp")
set_target_properties(justconnect_application PROPERTIES AUTOMOC ON)
target_include_directories(justconnect_application PUBLIC "${REPO}")
target_link_libraries(justconnect_application PUBLIC Qt6::Core Qt6::Network Qt6::Concurrent)
