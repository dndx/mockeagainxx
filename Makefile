CC=gcc
COPTS=-O -g -Wall -Werror -std=gnu99 -Wl,--no-as-needed -lrt
ifneq ($(MAKECMDGOALS),test)
	COPTS+= -DNDEBUG
endif
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TESTENV=LD_PRELOAD=$(ROOT_DIR)/mockeagainxx.so MOCKEAGAIN_VERBOSE=1
ALL_TESTS=$(shell find t -name "[0-9]*.c")
VALGRIND:=0

.PHONY: all test clean

all: mockeagainxx.so

%.so: %.c
	$(CC) $(COPTS) -fPIC -shared $< -o $@ -ldl || \
	$(CC) $(COPTS) -fPIC -shared $< -o $@

test: all $(ALL_TESTS)
	# 000
	export $(TESTENV); \
	$(CC) $(COPTS) -o ./t/runner ./t/000-mock-writes.c ./t/runner.c ./t/test_case.c \
	|| exit 1; \
	MOCKEAGAIN=w python ./t/echo_server.py ./t/runner $(VALGRIND) \
	&& echo "Test case 000-mock-writes.c passed" || exit 1;
	# 001
	export $(TESTENV); \
	$(CC) $(COPTS) -o ./t/runner ./t/001-mock-reads.c ./t/runner.c ./t/test_case.c \
	|| exit 1; \
	MOCKEAGAIN=r python ./t/echo_server.py ./t/runner $(VALGRIND) \
	&& echo "Test case 001-mock-reads.c passed" || exit 1;
	# 002
	export $(TESTENV); \
	$(CC) $(COPTS) -o ./t/runner ./t/002-pattern-matching.c ./t/runner.c ./t/test_case.c \
	|| exit 1; \
	MOCKEAGAIN=w MOCKEAGAIN_WRITE_TIMEOUT_PATTERN=tte python ./t/echo_server.py ./t/runner $(VALGRIND) \
	&& echo "Test case 002-pattern-matching.c passed" || exit 1;
	# 003
	export $(TESTENV); \
	$(CC) $(COPTS) -o ./t/runner ./t/003-disabled.c ./t/runner.c ./t/test_case.c \
	|| exit 1; \
	python ./t/echo_server.py ./t/runner $(VALGRIND) \
	&& echo "Test case 003-disabled.c passed" || exit 1;
	# 004
	export $(TESTENV); \
	$(CC) $(COPTS) -o ./t/runner ./t/004-setnonblocking.c ./t/runner.c ./t/test_case.c \
	|| exit 1; \
	MOCKEAGAIN=w python ./t/echo_server.py ./t/runner $(VALGRIND) \
	&& echo "Test case 004-setnonblocking.c passed" || exit 1;

clean:
	rm -rf *.so *.o *.lo t/runner

