include_guard(GLOBAL)
find_package(Qt6 REQUIRED COMPONENTS Core Network Concurrent)

add_library(justconnect_application STATIC
    "${REPO}/application/coreengine.h"
    "${REPO}/application/authmethodsquery.cpp"
    "${REPO}/application/networkprotection.cpp"
    "${REPO}/application/campuscapture.cpp"
    "${REPO}/application/applicationlogger.cpp"
    "${REPO}/application/commandlineoptions.cpp"
    "${REPO}/application/applicationshutdown.cpp"
    "${REPO}/application/connectionsession.cpp"
    "${REPO}/application/savedconnectionservice.cpp"
    "${REPO}/application/connectionoptions.cpp"
    "${REPO}/application/connectioncredentialvault.cpp"
    "${REPO}/application/settingsmigrator.cpp"
    "${REPO}/application/systemproxysession.cpp"
    "${REPO}/application/coexistencenetworkaccess.cpp"
    "${REPO}/application/networkpolicysession.cpp"
    "${REPO}/application/defaultsettings.cpp"
    "${REPO}/core/connectionsessionstate.cpp")
set_target_properties(justconnect_application PROPERTIES AUTOMOC ON)
target_include_directories(justconnect_application PUBLIC "${REPO}")
target_link_libraries(justconnect_application PUBLIC Qt6::Core Qt6::Network Qt6::Concurrent)
set(bundled_connection "connections/fudan.ini")
qt_add_resources(justconnect_application bundled_connection
    PREFIX "/justconnect"
    BASE "${REPO}/application"
    FILES "${REPO}/application/${bundled_connection}")
target_compile_definitions(justconnect_application PRIVATE JC_BUNDLED_CONNECTION=":/justconnect/${bundled_connection}")
