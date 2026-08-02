CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude

NAME = linux_syscall_monitor

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
	src/report.c \
	src/rules.c

OBJS = $(SRC:.c=.o)

TARGET = src/test.c

all: $(NAME) basic_target

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS)

basic_target: $(TARGET)
	$(CC) $(CFLAGS) -o basic_target $(TARGET)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(NAME) basic_target
	./$(NAME) ./basic_target

clean:
	rm -f $(OBJS) $(NAME) basic_target report.html

re: clean all

.PHONY: all clean re run