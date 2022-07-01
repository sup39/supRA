VERSION = 0.1.0-beta.2
CFLAGS = -Os $(and $(LUA_ROOT),-I$(LUA_ROOT)) $(MYCFLAGS)
LDFLAGS = $(and $(LUA_ROOT),-L$(LUA_ROOT)) -llua -lm $(MYLDFLAGS)

IFACE = eth0
CONFILE = config.lua

.PHONY: run clean
all: bin/supRA
run: bin/supRA
	@sudo $^ $(IFACE) $(CONFILE)
clean:
	find . -name "*.o" | xargs rm -f

bin/supRA: src/supRA.o src/ra.o src/options.o | bin
	$(CC) -o $@ $^ $(LDFLAGS)

bin:
	mkdir -p $@
