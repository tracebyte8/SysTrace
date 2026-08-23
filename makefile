CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude

NAME = linux_syscall_monitor

# =========================
# MAIN MONITOR SOURCES
# =========================

SRC = \
	src/main.c \
	src/tracer.c \
	src/syscall.c \
	src/memory.c \
	src/file_monitor.c \
	src/process_monitor.c \
	src/memory_monitor.c \
	src/network_monitor.c \
	src/fd_tables.c \
	src/alert.c \
	src/rules.c \
	src/stat.c \
	src/dataset.c \
	src/namespace.c \
	src/set_root.c \
	dashboard/index.c

OBJS = $(SRC:.c=.o)


# =========================
# BASIC TEST PROGRAM
# =========================

TEST_SRC = src/test.c
TEST_BIN = basic_target


# =========================
# SECURITY TEST PROGRAMS
# =========================

TESTS_SRC := $(wildcard tests/*.c)
TESTS_BIN := $(patsubst tests/%.c,tests/bin/%,$(TESTS_SRC))


# =========================
# DEFAULT BUILD
# =========================

all: $(NAME) $(TEST_BIN) $(TESTS_BIN)


# =========================
# BUILD MAIN MONITOR
# =========================

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)


# =========================
# BUILD BASIC TEST
# =========================

$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $<


# =========================
# COMPILE .C -> .O
# =========================

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


# =========================
# BUILD SECURITY TESTS
# =========================

tests/bin/%: tests/%.c
	@mkdir -p tests/bin
	$(CC) $(CFLAGS) -o $@ $<


# =========================
# RUN BASIC TEST
# =========================

run: $(NAME) $(TEST_BIN)
	@echo "======================================"
	@echo "      LINUX SYSCALL MONITOR"
	@echo "======================================"
	@echo ""
	@echo "== Tracing basic_target =="
	@echo ""
	./$(NAME) ./$(TEST_BIN)


# =========================
# RUN ALL SECURITY TESTS
# =========================

run-tests: all
	@echo "======================================"
	@echo "      LINUX SYSCALL MONITOR TESTS"
	@echo "======================================"

	@for bin in $(TESTS_BIN); do \
		name=$$(basename $$bin); \
		case $$name in \
			mal_*) label=1 ;; \
			benign_*) label=0 ;; \
			*) label=-1 ;; \
		esac; \
		echo ""; \
		echo "======================================"; \
		echo "== Tracing $$name (expected label=$$label) =="; \
		echo "======================================"; \
		LABEL=$$label ./$(NAME) $$bin; \
	done


# =========================
# CLEAN
# =========================

clean:
	rm -f $(OBJS)
	rm -f $(NAME)
	rm -f $(TEST_BIN)
	rm -f report.html
	rm -rf tests/bin


# =========================
# CLEAN + BUILD
# =========================

re: clean all


# =========================
# PHONY TARGETS
# =========================

.PHONY: all run run-tests clean re