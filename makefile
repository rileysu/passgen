src = $(wildcard src/*.c)
headers = $(wildcard src/*.h)
out = bin/passgen.out

CFLAGS = -lgcrypt

all: $(out)

$(out):
	$(CC) $(CFLAGS) $(src) -Isrc -o $@

clean:
	rm -f $(out)
