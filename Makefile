NAME = evmqtt
VERSION = 0.5

SRCDIR = src
OBJDIR = obj
EXSRCDIR = examples
INCDIR = include
BINDIR = bin

DIRS = $(BINDIR) $(OBJDIR)


CFLAGS += -std=gnu99 -pedantic -Wall -Werror -Wextra -I$(INCDIR)

ifeq (1,$(DEBUG))
CFLAGS += -g
else
CFLAGS += -O2
endif

LDFLAGS += -levent -levent_openssl -lssl -lcrypto -lpcre

LIBCFLAGS := $(CFLAGS) -fPIC
LIBLDFLAGS := $(LDFLAGS) -shared

EXLDFLAGS := $(LDFLAGS) -levtssl -L$(BINDIR)/ -l$(NAME)

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
LIBHEADERS = $(wildcard $(INCDIR)/$(NAME)/*.h)
LIBBIN = $(BINDIR)/lib$(NAME).so

EXSOURCES = $(wildcard $(EXSRCDIR)/*.c)
EXBINS = $(patsubst $(EXSRCDIR)/%.c,$(BINDIR)/%,$(wildcard $(EXSRCDIR)/*.c))

HEADERS = $(wildcard $(SRCDIR)/*.h) $(wildcard $(EXSRCDIR)/*.h) $(LIBHEADERS)

.PHONY: all clean default lib examples debug install uninstall

default: clean lib

all: lib examples

lib: $(LIBBIN)

examples: $(EXBINS)

debug:
	$(MAKE) DEBUG=1

$(LIBBIN): % : %.$(VERSION)
	cd $(BINDIR) ; ln -sf $(patsubst $(BINDIR)/%,%,$^) $(patsubst $(BINDIR)/%,%,$@)


$(LIBBIN).$(VERSION): $(OBJECTS) | $(BINDIR)
	$(CC) $(LIBLDFLAGS) $^ -o $@
	chmod 755 $@

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(LIBCFLAGS) -c $< -o $@

$(EXBINS): $(BINDIR)/% : $(EXSRCDIR)/%.c | $(BINDIR) $(LIBBIN)
	$(CC) $(CFLAGS) $(EXLDFLAGS) $< -o $@

$(DIRS):
	mkdir -p $@


VALGRINDCALLFILE = valgrindcall
valgrind: $(VALGRINDCALLFILE)
	tools/startvalgrind $(VALGRINDCALLFILE) $(CALL)

format: $(SOURCES) $(EXSOURCES) $(HEADERS)
	tools/format $^

tab_format: $(SOURCES) $(EXSOURCES) $(HEADERS)
	tools/tab_format $^

ROOT ?= /
usr ?= usr/local

usrdir = $(ROOT)$(usr)
LIBINSTALLDIR = $(usrdir)lib/
HEADERINSTALLDIR = $(usrdir)include/$(NAME)/
EXAMPLESINSTALLDIR = $(usrdir)bin/

INSTALL_BIN_CMD=install -m 0755

install_lib: $(LIBBIN).$(VERSION)
	mkdir -p $(LIBINSTALLDIR)
	$(INSTALL_BIN_CMD) $^ $(LIBINSTALLDIR)
	cd $(LIBINSTALLDIR) ; ln -fs $(patsubst $(BINDIR)/%,%,$(LIBBIN).$(VERSION)) $(patsubst $(BINDIR)/%,%,$(LIBBIN))

install_headers: $(HEADERS)
	mkdir -p $(HEADERINSTALLDIR)
	install $(HEADERS) $(HEADERINSTALLDIR)

install_examples: $(EXBINS)
	mkdir -p $(EXAMPLESINSTALLDIR)
	$(INSTALL_BIN_CMD) $^ $(EXAMPLESINSTALLDIR)

install: install_lib install_headers install_examples

uninstall_lib:
	rm -f $(patsubst $(BINDIR)/%,$(LIBINSTALLDIR)/%*,$(LIBBIN))

uninstall_headers:
	echo $(HEADERS)
	rm -f $(patsubst $(INCDIR)/$(NAME)/%,$(HEADERINSTALLDIR)/%,$(HEADERS))
	#TODO remove $(HEADERINSTALLDIR) if empty

uninstall_examples:
	rm -f $(patsubst $(BINDIR)/%,$(EXAMPLESINSTALLDIR)/%,$(EXBINS))

uninstall: uninstall_lib uninstall_headers uninstall_examples

clean::
	rm -rf $(DIRS)
