all:
	@echo -ne available targets:\\n\
    check - check code formatting\\n\
    format - apply code formatting\\n\
    init - set core.hooksPath to .githooks\\n\

init:
	git config --local core.hooksPath .githooks

check:
	./run_clang_format.py --clang-format-binary /usr/bin/clang-format-19 --check core apps tools unit_tests

format:
	./run_clang_format.py --clang-format-binary /usr/bin/clang-format-19 core apps tools unit_tests
