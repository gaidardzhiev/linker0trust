CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -pedantic -O2
BIN=linker

all: $(BIN)

$(BIN): linker.c
	$(CC) $(CFLAGS) -o $@ $<

test: clean all
	$(CC) -no-pie -static -o test.o test.c
	./$(BIN) test.o out.elf
	chmod +x out.elf
	@echo
	@echo "running injected binary..."
	./out.elf

clean:
	rm -f $(BIN) out.elf test.o

.PHONY: all clean test
