# cifuzz:build-template:begin
# add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
# target_include_directories({{ .FuzzTestName }} PRIVATE
#     ../src
#     ../lib
# )
# target_link_libraries({{ .FuzzTestName }} PRIVATE lib_iso15765)
# cifuzz:build-template:end

foreach(TestType IN ITEMS
    fuzz_iqueue_init
    fuzz_iso15765
)

    add_fuzz_test(${TestType} 
        ${TestType}.cpp 
        TEST_FRAMEWORK 
        GTEST
    )

    target_include_directories(${TestType}
        PRIVATE
        ../src
        ../lib
    )

    target_link_libraries(${TestType}
        lib_iso15765 
        GTest::gtest
    )

endforeach(TestType )