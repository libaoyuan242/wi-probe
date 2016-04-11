RTAP = radiotap

LIB = libosdep.a

CFLAGS += -fPIC
OBJS = osdep.o linux.o radiotap/radiotap.o common.o network.o file.o

all:
	@echo Building for Linux
	@$(MAKE) .os.Linux

.os.Linux: $(OBJS)
	$(AR) cr $(LIB) $(OBJS)
	ranlib $(LIB)

install: all

clean:
	rm -f $(LIB) *.o .os.*
	$(MAKE) -C radiotap clean
