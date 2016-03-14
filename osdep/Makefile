AC_ROOT	= ../..
include $(AC_ROOT)/common.mak

RTAP		= radiotap
LIB		= libosdep.a
CFLAGS		+= $(PIC)
OBJS		= osdep.o linux.o radiotap/radiotap.o common.o network.o file.o

all:
	@echo Building for $(OSNAME)
	@$(MAKE) .os.$(OSNAME)

.os.Linux: $(OBJS)
	$(AR) cru $(LIB) $(OBJS)
	$(RANLIB) $(LIB)
	touch $(@)

install: all

uninstall:

clean:
	$(MAKE) -C $(RTAP) clean
	rm -f $(LIB) *.o .os.*
