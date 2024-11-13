# cifuzz:build-template:begin
# add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
# target_include_directories({{ .FuzzTestName }} PRIVATE
#     ../src
#     ../lib
# )
# target_link_libraries({{ .FuzzTestName }} PRIVATE lib_iso15765)
# cifuzz:build-template:end
