add_library(SingleApplication STATIC
    singleapplication.cpp
    singleapplication_p.cpp
)
add_library(SingleApplication::SingleApplication ALIAS SingleApplication)
set_target_properties(SingleApplication PROPERTIES AUTOMOC ON)
target_link_libraries(SingleApplication PUBLIC Qt6::Widgets Qt6::Network)
target_include_directories(SingleApplication PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
if(WIN32)
    target_link_libraries(SingleApplication PRIVATE advapi32)
endif()

target_compile_definitions(SingleApplication PRIVATE
    QT_NO_CAST_TO_ASCII
    QT_NO_CAST_FROM_ASCII
    QT_NO_URL_CAST_FROM_STRING
    QT_NO_CAST_FROM_BYTEARRAY
    QT_USE_QSTRINGBUILDER
    QT_NO_NARROWING_CONVERSIONS_IN_CONNECT
    QT_NO_KEYWORDS
    QT_NO_FOREACH
)
