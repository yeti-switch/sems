all:
	@echo -ne available targets:\\n\
    check - check code formatting\\n\
    format - apply code formatting\\n\
    init - set core.hooksPath to .githooks\\n\

init:
	git config --local core.hooksPath .githooks

check:
	./run_clang_format.py --clang-format-binary /usr/bin/clang-format-19 --check -x .git,build,debian,doc

format:
	./run_clang_format.py --clang-format-binary /usr/bin/clang-format-19 -x .git,build,debian,doc
