CC=gcc
BIN=linker

all: $(BIN)

$(BIN): linker.c
	$(CC) -o $@ $<

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
