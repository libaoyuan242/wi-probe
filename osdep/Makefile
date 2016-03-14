AC_ROOT	= ../..
include $(AC_ROOT)/common.mak

RTAP		= radiotap
LIB		= libosdep.a

CFLAGS		+= -fPIC
OBJS		= osdep.o linux.o radiotap/radiotap.o common.o network.o file.o

all:
	@echo Building for Linux
	@$(MAKE) .os.Linux

.os.Linux: $(OBJS)
	$(AR) cru $(LIB) $(OBJS)
	$(RANLIB) $(LIB)
	touch $(@)

install: all

uninstall:

clean:
	rm -f $(LIB) *.o .os.*
	$(MAKE) -C $(RTAP) clean
