#
# UPX stub Makefile (GNU make)
#
# see http://wildsau.idv.uni-linz.ac.at/mfx/download/upx/tools/
# for required support tools
#

ifeq ($(strip $(UCLDIR)),)
# change this to reflect where the UCL library is
UCLDIR = $(HOME)/local/src/ucl-0.92
endif


# -------------------------------------------------------
# You should not have to change anything below this line.
# -------------------------------------------------------

SHELL = /bin/sh

top_srcdir = ../..
srcdir = .


# These are the files we want to create.
STUBS = \
	l_com.h \
	l_djgpp2.h stubify.h \
	l_exe.h \
	l_lx_n2b.h l_lx_n2d.h \
	l_sys.h \
	l_t_n2b.h l_t_n2bs.h l_t_n2d.h l_t_n2ds.h \
	l_tmt.h \
	l_wcle.h \
	l_w32pe.h


# /***********************************************************************
# // source directories
# ************************************************************************/

UCL_UPX  = $(UCLDIR)/upx
UCL_I386 = $(UCLDIR)/upx/i386
UCL_M68K = $(UCLDIR)/upx/m68k

.SUFFIXES:
.SUFFIXES: .asm .ash .asx .asy .bin .c .h .s

vpath %.ash $(UCL_I386)
vpath %.ash $(UCL_M68K)


# /***********************************************************************
# // tools
# ************************************************************************/

NASM     = /usr/topics/asm/nasm-20000903/nasm -O2 -w+macro-params -w+orphan-labels
NASM     = nasm -w+macro-params -w+orphan-labels
NASM    += -i$(srcdir)/

APP      = perl -w $(srcdir)/scripts/app.pl
BIN2H    = perl -w $(srcdir)/scripts/bin2h.pl
BRANDELF = perl -w $(srcdir)/scripts/brandelf.pl
O2BIN    = perl -w $(srcdir)/scripts/o2bin.pl
STRIPELF = perl -w $(srcdir)/scripts/stripelf.pl
VERSION  = perl -w $(srcdir)/scripts/version.pl

# Compiler for the Linux/386 stubs.
ifeq (1,2)
  CC_LINUX_I386 = gcc272 -m386 -O2
else
  # gcc 2.95.3 seems to produce the smallest code
  # (specifying -mcpu=i586 inhibits use of 'leave', which costs 2 bytes per subr)
  CC_LINUX_I386 = gcc -march=i386 -mcpu=i386 -Os -fno-strict-aliasing
endif
CC_LINUX_I386 += -malign-functions=0 -malign-jumps=0 -malign-loops=0
CC_LINUX_I386 += -Werror
CC_LINUX_I386 += -Wall -W -Wcast-align -Wcast-qual -Wwrite-strings
CC_LINUX_I386 += -funsigned-char
###CC_LINUX_I386 += -fwritable-strings -save-temps

# Preprocessor for a68k assembler.
CPP_M68K  = gcc -I$(UCL_UPX) -E -x assembler-with-cpp -Wall -Wp,-P,-C,-traditional,-nostdinc


# /***********************************************************************
# // main targets
# ************************************************************************/

.PHONY: default all stubs mostlyclean clean distclean maintainer-clean ident strings

default:
	@echo "UPX info: type 'make all' if you have all the needed build tools."

all: stubs

stubs: $(STUBS)

mostlyclean:
	-rm -f *~ *.bin *.bkp *.i *.lst *.map stubify.exe

clean: mostlyclean
	-rm -f *.o *.asx *.asy

distclean: clean

# This command is intended for maintainers to use; it deletes files
# that may require special tools to rebuild.
maintainer-clean: distclean
	-rm -f $(STUBS)

ident: all
	ident *.bin

strings: all
	strings *.bin


# /***********************************************************************
# // rules
# ************************************************************************/

version.asy: ../version.h
	$(VERSION) --nasm $< > $@

.asm.asx:
	$(APP) $< $@

.ash.asy:
	$(APP) $< $@


stubify.h: stub.asm
	djasm $< stubify.exe
	$(BIN2H) stubify.exe stubify_stub $@ -q

l_com.h: l_com.asx
	$(NASM) -f bin -o l_com.bin $<
	$(BIN2H) l_com.bin nrv2b_loader $@

l_djgpp2.h: l_djgpp2.asx
	$(NASM) -f bin -o l_djgpp2.bin $<
	$(BIN2H) l_djgpp2.bin nrv_loader $@

l_exe.h: l_exe.asx
	$(NASM) -f bin -o l_exe.bin $<
	$(BIN2H) l_exe.bin nrv_loader $@

l_lx_n2b.h: l_linux.c l_xe_n2b.o
	$(CC_LINUX_I386) -DNRV2B -s -o l_lx_n2b.o -c $<
	ld -s -Map l_lx_n2b.map -o l_lx_n2b.bin l_xe_n2b.o l_lx_n2b.o
	objcopy -S -R .comment -R .note l_lx_n2b.bin
	$(STRIPELF) l_lx_n2b.bin
	$(BRANDELF) l_lx_n2b.bin
	$(BIN2H) l_lx_n2b.bin linux_i386_nrv2b_loader $@

l_xe_n2b.o: l_linuxe.asm
	$(NASM) -i$(UCL_I386)/ -f elf -dNRV2B -o $@ $<

l_lx_n2d.h: l_linux.c l_xe_n2d.o
	$(CC_LINUX_I386) -DNRV2D -s -o l_lx_n2d.o -c $<
	ld -s -Map l_lx_n2d.map -o l_lx_n2d.bin l_xe_n2d.o l_lx_n2d.o
	objcopy -S -R .comment -R .note l_lx_n2d.bin
	$(STRIPELF) l_lx_n2d.bin
	$(BRANDELF) l_lx_n2d.bin
	$(BIN2H) l_lx_n2d.bin linux_i386_nrv2d_loader $@

l_xe_n2d.o: l_linuxe.asm
	$(NASM) -i$(UCL_I386)/ -f elf -dNRV2D -o $@ $<

l_sys.h: l_sys.asx
	$(NASM) -f bin -o l_sys.bin $<
	$(BIN2H) l_sys.bin nrv2b_loader $@

l_tmt.h: l_tmt.asx
	$(NASM) -f bin -o l_tmt.bin $<
	$(BIN2H) l_tmt.bin nrv_loader $@

l_t_n2b.h: l_tos.s
	$(CPP_M68K) -D__A68K__ -DNRV2B -o l_t_n2b.i $<
	a68k -q -x l_t_n2b.i
	$(O2BIN) l_t_n2b.o l_t_n2b.bin 'UPX1' 'UPX9'
	$(BIN2H) l_t_n2b.bin nrv2b_loader $@

l_t_n2bs.h: l_tos.s
	$(CPP_M68K) -D__A68K__ -DNRV2B -DSMALL -o l_t_n2bs.i $<
	a68k -q -x l_t_n2bs.i
	$(O2BIN) l_t_n2bs.o l_t_n2bs.bin 'UPX1' 'UPX9'
	$(BIN2H) l_t_n2bs.bin nrv2b_loader_small $@

l_t_n2d.h: l_tos.s
	$(CPP_M68K) -D__A68K__ -DNRV2D -o l_t_n2d.i $<
	a68k -q -x l_t_n2d.i
	$(O2BIN) l_t_n2d.o l_t_n2d.bin 'UPX1' 'UPX9'
	$(BIN2H) l_t_n2d.bin nrv2d_loader $@

l_t_n2ds.h: l_tos.s
	$(CPP_M68K) -D__A68K__ -DNRV2D -DSMALL -o l_t_n2ds.i $<
	a68k -q -x l_t_n2ds.i
	$(O2BIN) l_t_n2ds.o l_t_n2ds.bin 'UPX1' 'UPX9'
	$(BIN2H) l_t_n2ds.bin nrv2d_loader_small $@

l_vxd.h: l_vxd.asm
	$(NASM) -f bin -o l_vxd.bin $<
	$(BIN2H) l_vxd.bin nrv_loader $@

l_wcle.h: l_wcle.asx
	$(NASM) -f bin -o l_wcle.bin $<
	$(BIN2H) l_wcle.bin nrv_loader $@

l_w32pe.h: l_w32pe.asx
	$(NASM) -f bin -o l_w32pe.bin $<
	$(BIN2H) l_w32pe.bin nrv_loader $@


# /***********************************************************************
# // dependencies
# ************************************************************************/

DEPS1 = header.ash macros.ash version.asy ident.ash ident_n.ash ident_s.ash
DEPS2 = header.asy macros.asy

$(STUBS):       $(srcdir)/scripts/bin2h.pl

ident.ash:	version.asy
ident.asy:	version.asy
ident_n.ash:	version.asy
ident_n.asy:	version.asy
ident_s.ash:	version.asy
ident_s.asy:	version.asy

l_com.h:        n2b_d16.asy  $(DEPS2)
l_djgpp2.h:     n2b_d32.asy  n2d_d32.asy  $(DEPS2)
l_exe.h:        n2b_d8e.asy  n2d_d8e.asy  $(DEPS2)
l_lx_n2b.h:     n2b_d32.ash  $(DEPS1)
l_xe_n2b.o:     n2b_d32.ash  $(DEPS1)
l_lx_n2d.h:     n2d_d32.ash  $(DEPS1)
l_xe_n2d.o:     n2d_d32.ash  $(DEPS1)
l_sys.h:        n2b_d16.asy  $(DEPS2)
l_t_n2b.h:      n2b_d.ash    bits.ash  $(DEPS1)
l_t_n2bs.h:     n2b_d.ash    bits.ash  $(DEPS1)
l_t_n2d.h:      n2d_d.ash    bits.ash  $(DEPS1)
l_t_n2ds.h:     n2d_d.ash    bits.ash  $(DEPS1)
l_tmt.h:        n2b_d32.asy  n2d_d32.asy  $(DEPS2)
l_vxd.h:        n2b_d32.asy  n2d_d32.asy  $(DEPS2)
l_wcle.h:       n2b_d32.asy  n2d_d32.asy  $(DEPS2)
l_w32pe.h:      n2b_d32.asy  n2d_d32.asy  $(DEPS2)

# vi:nowrap
