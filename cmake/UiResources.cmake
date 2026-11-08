include_guard(GLOBAL)

add_library(justconnect_ui_resources OBJECT "${CMAKE_CURRENT_LIST_DIR}/../resource.qrc")
set_target_properties(justconnect_ui_resources PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC ON)
target_link_libraries(justconnect_ui_resources PRIVATE Qt6::Core)
