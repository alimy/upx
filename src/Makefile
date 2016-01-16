# UPX Makefile (GNU make) - works with unix/win32/djgpp2
#
# usage:
#   `make target=linux'             # linux
#   `make target=djggp2'            # djggp2 2.03
#   `make target=vc6'               # Visual C++ 6.0
#   `make target=cygwin'            # cygwin 1.3.x
#   `make target=mingw32'           # mingw32
#   `make target=no-cygwin'         # mingw32 as included in cygwin 1.3.x
#   `make target=cross-m68k-linux'  # m68k-linux cross compiler
#   `make target=cross-mingw32'     # i386-mingw32msvc cross compiler
#   `make target=cross-mint'        # m68k-atari-mint cross compiler
#


# configuration section

ifeq ($(strip $(UCLDIR)),)
# change this to reflect where the UCL library is
UCLDIR = $(HOME)/local/src/ucl-0.92
endif

DEBUG = 0


# -------------------------------------------------------
# You should not have to change anything below this line.
# -------------------------------------------------------

SHELL = /bin/sh


.SUFFIXES:
.SUFFIXES: .a .c .cpp .exe .lib .o .obj .rc .res .ttp


srcdir = .
top_srcdir = ..

VPATH = $(srcdir)


# auto-detect the target unless given on the commandline
target = djgpp2
ifneq ($(strip $(wildcard /usr/include/linux)),)
target = linux
endif
ifneq ($(strip $(wildcard /platform/sun4?/kernel/unix)),)
target = sparc
endif


# util var for use in the rules - basename of the current target
override T = $(basename $@)


# /***********************************************************************
# // object files
# ************************************************************************/

# these use exceptions & RTTI
OBJECTS1 = \
	compress$o except$o file$o lefile$o \
	filter$o ui$o msg$o work$o \
	packer$o packhead$o packmast$o \
	p_com$o p_djgpp2$o p_exe$o p_sys$o p_tmt$o p_tos$o \
	p_unix$o p_w32pe$o p_wcle$o

# no exceptions or RTTI
OBJECTS2 = \
	filteri$o help$o main$o mygetopt$o util$o linker$o \
	c_init$o c_file$o c_none$o c_screen$o \
	s_object$o s_djgpp2$o s_vcsa$o s_win32$o

# pure C sources
OBJECTS3 =

OBJECTS = $(OBJECTS1) $(OBJECTS2) $(OBJECTS3)
RESOURCES =
LIBS =


# /***********************************************************************
# // compiler settings
# ************************************************************************/

# default to a gcc unix-type compiler
CC = gcc
CXX = $(CC)
CXXLD = $(CXX)
DEFS =
INCLUDES = -I. -I$(srcdir)
CFLAGS_OUTPUT = -o $@
CXXFLAGS_OUTPUT = $(CFLAGS_OUTPUT)

LINK_EXE = $(CXXLD) $(LDFLAGS) -o $@ $^ $(LDLIBS)
STUBEDIT_EXE =
STUBIFY_EXE =
CHMOD_EXE =

o = .o
a = .a
e = .exe


###
### gcc defaults
###

##CFLAGS_WERROR = -Werror
CFLAGS_WERROR =
CFLAGS_W  = $(CFLAGS_WERROR)
CFLAGS_W += -Wall -W -Wcast-align -Wcast-qual -Wmissing-declarations -Wmissing-prototypes -Wshadow -Wwrite-strings
CFLAGS_M  =
##CFLAGS_M += -fno-builtin
##CFLAGS_M += -malign-functions=0 -malign-jumps=0 -malign-loops=0
##CFLAGS_O  = -Os -fstrict-aliasing
##CFLAGS_O  = -O2 -fstrict-aliasing
CFLAGS_O  = -O2 -fno-strict-aliasing

CFLAGS    = $(CFLAGS_W) $(CFLAGS_M) $(CFLAGS_O)
CXXFLAGS  = $(CFLAGS) -Wsynth -fconserve-space
CXXFLAGS1 = $(CXXFLAGS)
##CXXFLAGS1 += -fasynchronous-exceptions
CXXFLAGS2 = $(CXXFLAGS) -fno-exceptions -fno-rtti

ifeq ($(DEBUG),1)
DEFS += -DDEBUG
## DEFS += -DTESTING
endif

ifeq ($(DEBUG),1)
LDFLAGS = -g
else
LDFLAGS = -s
endif
LDFLAGS += -Wl,-Map,$T.map
LDLIBS =
LIBDIRS =
DOS_LDLIBS =
DOS_LIBDIRS =


###
### compression library
###

UCLDIR:=$(strip $(subst \,/,$(UCLDIR)))
NRVDIR:=$(strip $(subst \,/,$(NRVDIR)))
u = ucl
U = UCL
upx_exe = upx$e
include $(srcdir)/Makefile.inc
ifneq ($(strip $(wildcard $(NRVDIR)/include/nrv)),)
  u = nrv
  U = NRV
  upx_exe = upx_$u$e
  include $(srcdir)/Makefile.inc
endif

tmp := -Wl,--rpath,
LDRPATH := $(addprefix $(tmp),$(LIBDIRS))
LIBDIRS += .
LDLIBDIRS := $(addprefix -L,$(LIBDIRS))

##LDFLAGS += $(LDRPATH)
LDFLAGS += $(LDLIBDIRS)


###
### linux/i386
###

ifeq ($(target),linux)
arch := $(shell uname -m | sed -e 's/^i[3456789]86$$/i386/')
e =
DEFS += '-DUPX_CONFIG_H="config_h/linux.h"'
ifeq ($(arch),i386)
  CC += -march=i386 -mcpu=i586
  ##CFLAGS_M += -mno-schedule-prologue
endif
CFLAGS_WERROR = -Werror
LDLIBS += -lmcheck

ifeq (1,2) 	# checkergcc
  CC = checkergcc
  CXX = checkerg++
else
ifeq ($(DEBUG),1)
  ##CFLAGS += -O0 -gstabs+3
  ##CFLAGS += -O0 -gdwarf-2
  CFLAGS += -O0 -g
else
  ##LDFLAGS += -static
  STUBEDIT_EXE = objcopy -S -R .comment -R .note $@
  ifeq ($(arch),i386)
    STUBIFY_EXE = perl $(srcdir)/stub/scripts/brandelf.pl $@
  endif
endif
CHMOD_EXE = chmod 755 $@
endif

endif	# linux


###
### linux cross compilers
###

ifeq ($(target),cross-m68k-linux)
e =
DEFS += '-DUPX_CONFIG_H="config_h/linux.h"'
CC = m68k-linux-gcc
endif	# cross-m68k-linux


###
### djgpp2
###

ifeq ($(target),djgpp2)
CC += -march=i386 -mcpu=i586
##CFLAGS_M += -mno-schedule-prologue
CFLAGS_WERROR = -Werror
STUBEDIT_EXE = stubedit $@ bufsize=0xfc00
ifneq ($(strip $(wildcard $(DJDIR)/bin/mfxdjstubify.exe)),)
ifneq ($(strip $(wildcard $(DJDIR)/bin/cwsdstub.exe)),)
STUBIFY_EXE = mfxdjstubify -v -s $(DJDIR)/bin/cwsdstub.exe $(upx_exe)
endif
endif
endif	# djgpp2


###
### cygwin / mingw32
###

ifeq ($(target),cygwin)
CC += -march=i386 -mcpu=i586
##CFLAGS_M += -mno-schedule-prologue
endif

ifeq ($(target),mingw32)
CC += -march=i386 -mcpu=i586
##CFLAGS_M += -mno-schedule-prologue
endif

# mingw32 as included in cygwin
ifeq ($(target),no-cygwin)
CC = gcc -mno-cygwin
CC += -march=i386 -mcpu=i586
##CFLAGS_M += -mno-schedule-prologue
endif

# mingw32 cross compiler
ifeq ($(target),cross-mingw32)
CC = i386-mingw32msvc-gcc
CC = i586-mingw32msvc-gcc
CC += -march=i386 -mcpu=i586
##CFLAGS_M += -mno-schedule-prologue
CHMOD_EXE =
endif


###
### Microsoft 32-bit C/C++ Compiler 12.00 (aka Visual C++ 6)
###

ifeq ($(target),vc6)
o = .obj
a = .lib
RESOURCES = upx.res
CC = cl -nologo
CFLAGS = -W4 -WX
CXXFLAGS1 = $(CFLAGS) -GR -GX -EHa
CXXFLAGS2 = $(CFLAGS)
LDFLAGS =
LINK_LDFLAGS = /link /map:$T.map

ifneq ($(strip $(DOS_LIBDIRS)),)
LIB := $(DOS_LIBDIRS);$(LIB)
endif
export LIB

ifeq (1,2)
  # statically link libc.lib
  CC += -ML
  LDLIBS = $(u)_s.lib setargv.obj
else
  # link against msvcrt.dll
  CC += -MD
  LDLIBS = $(DOS_LDLIBS) setargv.obj
endif
ifeq ($(DEBUG),1)
  CFLAGS += -Od -ZI
  LINK_LDFLAGS += /debug
else
  CFLAGS += -O2 -GF
  LINK_LDFLAGS += /release
endif

##LINK_LDFLAGS += /verbose
LINK_EXE = $(CXXLD) $(LDFLAGS) -Fe$@ $^ $(LDLIBS) $(LINK_LDFLAGS)

endif	# vc6


###
### atari
###

ifeq ($(target),cross-mint)
CC = m68k-atari-mint-gcc
CC += -m68000
CHMOD_EXE =
e = .ttp
endif


###
### sparc
###

ifeq ($(target),sparc)
e =
DEFS += '-DUPX_CONFIG_H="config_h/sparc.h"'
INCLUDES += -I/home/ethmola/local/include

ifeq (1,2) # native compiler
  CFLAGS = -O0 -g
  CXXFLAGS1 =
  CXXFLAGS2 =
  DEFS += -DUSE_STDNAMESPACE
else # gcc
  CFLAGS += -O0 -gstabs+
endif

ifeq (1,2) # purify
  DEFS += -D__PURIFY__
  LDFLAGS = -g -L/home/ethmola/local/lib
  LINK_EXE = purify $(CXXLD) $(LDFLAGS) -o $@ $^ $(LDLIBS)
else
  LDFLAGS += -g -L/home/ethmola/local/lib
  LINK_EXE = $(CXXLD) $(LDFLAGS) -o $@ $^ $(LDLIBS)
endif

endif	# sparc


###
### Borland C++ 5.5 (DOES NOT WORK - INCOMPLETE C++ IMPLEMENTATION)
###

ifeq ($(target),bcc)
o = .obj
a = .lib
CC = bcc32
CFLAGS = -w -w-par
CXXFLAGS1 = $(CFLAGS)
CXXFLAGS2 = $(CFLAGS)
CFLAGS_OUTPUT = -o$@
LDFLAGS =
LDLIBS = $(DOS_LDLIBS)

ifneq ($(strip $(DOS_LIBDIRS)),)
LIB := $(DOS_LIBDIRS);$(LIB)
endif
export LIB

ifeq ($(DEBUG),1)
  CFLAGS += -Od -d
else
  CFLAGS += -O2 -d
endif

LINK_EXE = $(CXXLD) $(LDFLAGS) -e$@ $^ $(LDLIBS)

endif	# bcc


###
### malloc debuggers and memory checkers
###

ifeq (1,2)
  LDLIBS += -lefence
endif

ifeq (1,2)
  CFLAGS += -DWITH_DMALLOC
  LDLIBS += -ldmalloc
endif

ifeq (1,2)
  CFLAGS += -DWITH_GC -DLINUX_THREADS -D_REENTRANT
  LDLIBS += -lgc -lpthread
  # only needed when using -static:
  ##LDFLAGS += -Wl,-defsym,_DYNAMIC=0
endif

ifeq (1,2)
  CFLAGS += -DWITH_MSS
  LDLIBS += -lmss
endif


###
### extra flags
###

DEFS      += $(EXTRA_DEFS)
CFLAGS    += $(EXTRA_CFLAGS)
CXXFLAGS1 += $(EXTRA_CXXFLAGS1)
CXXFLAGS2 += $(EXTRA_CXXFLAGS2)
LDFLAGS   += $(EXTRA_LDFLAGS)
LDLIBS    += $(EXTRA_LDLIBS)


# /***********************************************************************
# // main targets
# ************************************************************************/

all: $(upx_exe)

.PHONY: all unupx mostlyclean clean distclean maintainer-clean untabify tags

$(upx_exe): $(OBJECTS) $(RESOURCES) $(LIBS)
	$(LINK_EXE)
	$(STUBEDIT_EXE)
	$(STUBIFY_EXE)
	$(CHMOD_EXE)


unupx:
	$(MAKE) target=vc6 unupx.dll

unupx.dll: $(OBJECTS) $(LIBS)
	$(LINK_DLL)


mostlyclean:
	-rm -f *.d *.err *.i *.log *.map *~ gdb-trans*

clean: mostlyclean
	-rm -f *.a *.lib *.o *.obj *.res tags TAGS ID
	-rm -f *.idb *.pdb
	-rm -f upx upx.exe upx.ttp upx_nrv upx_nrv.exe upx_nrv.ttp upx_ucl upx_ucl.exe upx_ucl.ttp
	-rm -rf .deps

distclean: clean

maintainer-clean: distclean


untabify:
	mfxtu -d4 -t *.h *.cpp *.ch
	mfxtu -d8 -t stub/[ln]*.asm stub/*.ash stub/*.[cs]

tags TAGS:
	ctags *.h *.cpp *.ch

ID:
	mkid *.h *.cpp *.ch


# /***********************************************************************
# // rules
# ************************************************************************/

%$o : %.c
	$(CC) $(DEFS) $(INCLUDES) $(CFLAGS) $(CFLAGS_OUTPUT) -c $<

%$o : %.cpp
	$(CXX) $(DEFS) $(INCLUDES) $(CXXFLAGS1) $(CXXFLAGS_OUTPUT) -c $<

ifneq ($(strip $(OBJECTS2)),)
$(OBJECTS2): %$o : %.cpp
	$(CXX) $(DEFS) $(INCLUDES) $(CXXFLAGS2) $(CXXFLAGS_OUTPUT) -c $<
endif

%.res : %.rc
	rc -l 0x409 -fo$@ $<


# /***********************************************************************
# // dependencies
# ************************************************************************/

# FIXME: use automated dependencies

main$o:     mygetopt.h version.h
filter$o:   filter.h
filteri$o:  filter.h fcto_ml.ch fcto_ml2.ch
help$o:     version.h
msg$o:      ui.h
lefile$o:   lefile.h
linker$o:   linker.h
mygetopt$o: mygetopt.h
packer$o:   packer.h filter.h linker.h ui.h version.h
packhead$o: packer.h
packmast$o: packmast.h packer.h lefile.h \
		p_com.h p_djgpp2.h p_exe.h p_sys.h p_tmt.h p_tos.h \
		p_unix.h p_vxd.h p_w32pe.h p_wcle.h
ui$o:       packer.h ui.h
work$o:     packer.h ui.h packmast.h

p_com$o:    packer.h p_com.h           stub/l_com.h
p_djgpp2$o: packer.h p_djgpp2.h stub/stubify.h \
		stub/l_djgpp2.h
p_exe$o:    packer.h p_exe.h           stub/l_exe.h
p_sys$o:    packer.h p_sys.h p_com.h   stub/l_sys.h
p_tmt$o:    packer.h p_tmt.h \
		stub/l_tmt.h
p_tos$o:    packer.h p_tos.h \
		stub/l_t_n2b.h stub/l_t_n2bs.h \
		stub/l_t_n2d.h stub/l_t_n2ds.h
p_unix$o:   packer.h p_unix.h \
		stub/l_lx_n2b.h stub/l_lx_n2d.h
p_w32pe$o:  packer.h p_w32pe.h \
		stub/l_w32pe.h
p_wcle$o:   packer.h p_wcle.h lefile.h \
		stub/l_wcle.h

# vi:nowrap
