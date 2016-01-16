#
# UPX Makefile (GNU make) - works with unix/win32/djgpp2
#
# usage:
#   `make target=linux'             # linux
#   `make target=dos32-djggp2'      # dos32 - djggp2
#   `make target=win32-cygwin'      # win32 - cygwin
#   `make target=win32-mingw32'     # win32 - mingw32
#   `make target=win32-rsxnt'       # win32 - rsxnt
#   `make target=win32-bc'          # win32 - Borland C++
#   `make target=win32-dm'          # win32 - Digital Mars C++
#   `make target=win32-ic'          # win32 - Intel C++
#   `make target=win32-vc'          # win32 - Visual C++
#   `make target=win32-wc'          # win32 - Watcom C++
#   `make target=cross-amd64-linux' # x86_64-linux cross compiler
#   `make target=cross-mingw32'     # i586-mingw32msvc cross compiler
#   `make target=cross-mint'        # m68k-atari-mint cross compiler
#   `make target=gcc'               # generic gcc
#
# you can also set the `UPX_MAKE_TARGET' environment variable.
#


# configuration section

ifeq ($(strip $(UCLDIR)),)
# change this to reflect where the UCL library is
UCLDIR = $(HOME)/local/src/ucl-1.02
endif

## you can set the default target here
##target =

DEBUG = 0

srcdir = .
top_srcdir = ..


##### You should not have to change anything below this line. #####


# /***********************************************************************
# // object files
# ************************************************************************/

# these use exceptions & RTTI
OBJECTS1 = \
	compress$o except$o file$o lefile$o \
	filter$o mem$o ui$o msg$o stdcxx$o work$o \
	packer$o packhead$o packmast$o \
	p_com$o p_djgpp2$o p_exe$o p_sys$o p_tmt$o p_tos$o \
	p_unix$o p_w32pe$o p_wcle$o

# no exceptions or RTTI
OBJECTS2 = \
	filteri$o help$o linker$o main$o mygetopt$o snprintf$o util$o \
	c_init$o c_file$o c_none$o c_screen$o \
	s_object$o s_djgpp2$o s_vcsa$o s_win32$o

# pure C sources
OBJECTS3 =

OBJECTS = $(OBJECTS1) $(OBJECTS2) $(OBJECTS3)
LIBS =
RESOURCES =


# /***********************************************************************
# // main
# ************************************************************************/

override WITH_ZLIB =

include $(srcdir)/Makefile.bld


# /***********************************************************************
# // dependencies
# ************************************************************************/

# FIXME: use automated dependencies - see Makedefs.dep
#####include $(srcdir)/Makedefs.dep

main$o:     mygetopt.h version.h
compress$o: compress.ch
filter$o:   filter.h
filteri$o:  filter.h fcto.ch fcto2.ch
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
		stub/l_t_n2d.h stub/l_t_n2ds.h \
		stub/l_t_n2e.h stub/l_t_n2es.h
p_unix$o:   packer.h p_unix.h \
		stub/l_lx_n2b.h stub/l_lx_n2d.h stub/l_lx_n2e.h
p_w32pe$o:  packer.h p_w32pe.h \
		stub/l_w32pe.h
p_wcle$o:   packer.h p_wcle.h lefile.h \
		stub/l_wcle.h

# vi:nowrap
