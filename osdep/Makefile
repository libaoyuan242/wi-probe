<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
=======
>>>>>>> 405fe8d... Removed dependency on common.mak
=======
>>>>>>> 405fe8d... Removed dependency on common.mak
#AC_ROOT	= ../..
#include $(AC_ROOT)/common.mak

RTAP		= radiotap
>>>>>>> 405fe8d... Removed dependency on common.mak
LIB		= libosdep.a

CFLAGS		+= -fPIC
OBJS		= osdep.o linux.o radiotap/radiotap.o common.o network.o file.o

all:
	@echo Building for Linux
	@$(MAKE) .os.Linux

.os.Linux: $(OBJS)
	$(AR) cru $(LIB) $(OBJS)
	ranlib $(LIB)
	touch $(@)

install: all

uninstall:

clean:
	rm -f $(LIB) *.o .os.*
	$(MAKE) -C radiotap clean
