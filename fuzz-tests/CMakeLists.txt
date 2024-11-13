# cifuzz:build-template:begin
# add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
# target_include_directories({{ .FuzzTestName }} PRIVATE
#     ../src
#     ../lib
# )
# target_link_libraries({{ .FuzzTestName }} PRIVATE lib_iso15765)
# cifuzz:build-template:end

add_compile_options(-fsanitize=address,undefined)
add_link_options(-fsanitize=address,undefined)

add_fuzz_test(fuzz_iqueue_init 
    fuzz_iqueue_init.cpp 
    TEST_FRAMEWORK 
    GTEST
)

target_include_directories(fuzz_iqueue_init
    PRIVATE
    ../src
    ../lib
)

target_link_libraries(fuzz_iqueue_init
    lib_iso15765 
    GTest::gtest
)
