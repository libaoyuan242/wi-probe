#include ./common.mak
BINFILES = probe

OBJS_AR	= probe.o osdep/radiotap/radiotap.o

OSD			:= osdep
LIBS		:= -L$(OSD) -l$(OSD) $(LIBS)
LIBOSD		:= $(OSD)/lib$(OSD).a
CFLAGS		:= -Wall

all:	$(BINFILES)

$(LIBOSD):
	$(MAKE) -lm -C $(OSD)

probe:	$(OBJS_AR) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_AR) -o $(@) $(LIBS) -lm

clean:
	$(MAKE) -C $(OSD) clean
	-rm -f $(BINFILES) *.o

install: all
	$(MAKE) -C $(OSD) install
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(BINFILES) $(DESTDIR)$(bindir)

uninstall:
	$(MAKE) -C $(OSD) uninstall
	-rm -rf $(DESTDIR)
