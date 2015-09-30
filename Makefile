LUASRC = $(wildcard src/lua/*.lua)
LUAOBJ = $(LUASRC:.lua=.o)
CSRC   = $(wildcard src/c/*.c)
COBJ   = $(CSRC:.c=.o)

LUAJIT   := deps/luajit.vsn
SYSCALL  := deps/syscall.vsn
PFLUA    := deps/pflua.vsn

LUAJIT_CFLAGS := -include $(CURDIR)/gcc-preinclude.h

all: $(LUAJIT) $(SYSCALL) $(PFLUA)
	@echo "Building snabbswitch"
	cd src && $(MAKE)

install: all
	install -D src/snabb ${PREFIX}/usr/local/bin/snabb

$(LUAJIT):
	@if [ ! -f deps/luajit/Makefile ]; then \
	    echo "Initializing LuaJIT submodule.."; \
	    git submodule update --init deps/luajit; \
	fi
	@echo 'Building LuaJIT'
	@(cd deps/luajit && \
	 $(MAKE) PREFIX=`pwd`/usr/local \
	         CFLAGS="$(LUAJIT_CFLAGS)" && \
	 $(MAKE) DESTDIR=`pwd` install && \
         (git describe 2>/dev/null || echo release) > ../luajit.vsn)
	(cd deps/luajit/usr/local/bin; ln -fs luajit-2.1.0-alpha luajit)

$(PFLUA): $(LUAJIT)
	@if [ ! -f deps/pflua/src/pf.lua ]; then \
	    echo "Initializing pflua submodule.."; \
	    git submodule update --init deps/pflua; \
	fi
#       pflua has no tags at time of writing, so use raw commit id
	@(cd deps/pflua && (git rev-parse HEAD 2>/dev/null || echo release) > ../pflua.vsn)

$(SYSCALL): $(PFLUA)
	@if [ ! -f deps/ljsyscall/syscall.lua ]; then \
	    echo "Initializing ljsyscall submodule.."; \
	    git submodule update --init deps/ljsyscall; \
	fi
	@echo 'Copying ljsyscall components'
	@mkdir -p src/syscall/linux
	@cp -p deps/ljsyscall/syscall.lua   src/
	@cp -p deps/ljsyscall/syscall/*.lua src/syscall/
	@cp -p  deps/ljsyscall/syscall/linux/*.lua src/syscall/linux/
	@cp -pr deps/ljsyscall/syscall/linux/x64   src/syscall/linux/
	@cp -pr deps/ljsyscall/syscall/shared      src/syscall/
	@(cd deps/ljsyscall; (git describe 2>/dev/null || echo release) > ../ljsyscall.vsn)

clean:
	(cd deps/luajit && $(MAKE) clean)
	(cd src; $(MAKE) clean; rm -rf syscall.lua syscall)
	(rm deps/*.vsn)

PACKAGE:=snabbswitch
DIST_BINARY:=snabb
BUILDDIR:=$(shell pwd)

dist: DISTDIR:=$(BUILDDIR)/$(PACKAGE)-$(shell git describe --tags)
dist: all
	mkdir "$(DISTDIR)"
	git clone "$(BUILDDIR)" "$(DISTDIR)/$(PACKAGE)"
	git clone "$(BUILDDIR)/deps/luajit" "$(DISTDIR)/$(PACKAGE)/deps/luajit"
	git clone "$(BUILDDIR)/deps/ljsyscall" "$(DISTDIR)/$(PACKAGE)/deps/ljsyscall"
	git clone "$(BUILDDIR)/deps/pflua" "$(DISTDIR)/$(PACKAGE)/deps/pflua"
	rm -rf "$(DISTDIR)/$(PACKAGE)/.git"
	rm -rf "$(DISTDIR)/$(PACKAGE)/deps/luajit/.git"
	rm -rf "$(DISTDIR)/$(PACKAGE)/deps/ljsyscall/.git"
	rm -rf "$(DISTDIR)/$(PACKAGE)/deps/pflua/.git"
	cp "$(BUILDDIR)/src/$(DIST_BINARY)" "$(DISTDIR)/"
	cd "$(DISTDIR)/.." && tar cJvf "`basename '$(DISTDIR)'`.tar.xz" "`basename '$(DISTDIR)'`"
	rm -rf "$(DISTDIR)"
	@echo Dist tarball created: "$(DISTDIR).tar.xz"

.SERIAL: all
