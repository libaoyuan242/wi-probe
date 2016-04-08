BINFILES = wi-probe

OBJS_AR	= wi-probe.o osdep/radiotap/radiotap.o

OSD			:= osdep
LIBS		:= -L$(OSD) -l$(OSD) $(LIBS)
LIBOSD		:= $(OSD)/lib$(OSD).a
OPTFLAGS	= -D_FILE_OFFSET_BITS=64
CFLAGS		?= -g -W -Wall -O3
CFLAGS		+= $(OPTFLAGS) $(COMMON_CFLAGS)
CFLAGS		+= -Wno-unused-but-set-variable -Wno-array-bounds
bindir      := /usr/local/bin

all:	$(BINFILES)

$(LIBOSD):
	$(MAKE) -lm -C $(OSD)

wi-probe:	$(OBJS_AR) $(LIBOSD)
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
