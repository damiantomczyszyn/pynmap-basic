CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=

TARGET  := connect_scan
SOURCES := connect_scan.c

.PHONY: all clean debug asan run-example

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

# Build z symbolami i bez optymalizacji — do chodzenia po kodzie w gdb
debug: CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O0 -g3
debug: clean $(TARGET)

# AddressSanitizer: pokazuje wycieki i błędy dostępu do pamięci,
# czyli całą klasę problemów, których wersja w Pythonie nie ma
asan: CFLAGS := -std=c11 -Wall -Wextra -O1 -g -fsanitize=address,undefined
asan: LDFLAGS := -fsanitize=address,undefined
asan: clean $(TARGET)

run-example: $(TARGET)
	./$(TARGET) 127.0.0.1 1-1024 --open

clean:
	rm -f $(TARGET) *.o
