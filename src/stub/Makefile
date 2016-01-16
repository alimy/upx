#
# UPX stub Makefile (GNU make)
#
# see http://upx.sourceforge.net/download/tools/
# for required build tools
#

ifeq ($(strip $(UCLDIR)),)
# change this to reflect where the UCL library is
UCLDIR = $(HOME)/local/src/ucl-1.01
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
	l_lx_n2b.h l_lx_n2d.h l_lx_n2e.h \
	l_sys.h \
	l_t_n2b.h l_t_n2bs.h l_t_n2d.h l_t_n2ds.h l_t_n2e.h l_t_n2es.h \
	l_tmt.h \
	l_wcle.h \
	l_w32pe.h


# util var for use in the rules - basename of the current target
override T = $(basename $@)


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

NASM     = nasm -O2 -w+macro-params -w+orphan-labels
NASM    += -i$(srcdir)/

APP_I386 = perl -w $(srcdir)/scripts/app_i386.pl
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
  CC_LINUX_I386 = gcc-2.95 -march=i386 -mcpu=i386 -Os -fno-strict-aliasing
endif
CC_LINUX_I386 += -malign-functions=0 -malign-jumps=0 -malign-loops=0
CC_LINUX_I386 += -Werror
CC_LINUX_I386 += -Wall -W -Wcast-align -Wcast-qual -Wwrite-strings
CC_LINUX_I386 += -funsigned-char
###CC_LINUX_I386 += -fwritable-strings -save-temps

# Preprocessor for the a68k 68000-assembler.
CPP_M68K = gcc -I$(UCL_UPX) -E -x assembler-with-cpp -Wall -Wp,-P,-C,-traditional,-nostdinc -D__A68K__
ASM_M68K = a68k -q -x


# /***********************************************************************
# // main targets
# ************************************************************************/

.PHONY: default all stubs mostlyclean clean distclean maintainer-clean ident strings

default:
	@echo "UPX info: type 'make all' if you have all the required build tools."

all: stubs

stubs: $(STUBS)


mostlyclean:
	-rm -f *~ *.bin *.bkp *.i *.lst *.map stubify.exe
	-rm -f *.o *.asx *.asy

clean: mostlyclean
ifneq ($(strip $(wildcard stamp-h)),)
	-rm -f l_*.h $(STUBS)
endif

distclean: mostlyclean
	@-rm -f stamp-h

maintainer-clean: mostlyclean
	-rm -f l_*.h $(STUBS)
	@-rm -f stamp-h


ident: all
	ident *.bin

strings: all
	strings *.bin


# /***********************************************************************
# // rules
# ************************************************************************/

version.asy: ../version.h
	$(VERSION) --nasm $< > $@

%.asx : %.asm
	$(APP_I386) $< $@

%.asy : %.ash
	$(APP_I386) $< $@


stubify.h: stub.asm
	djasm $< stubify.exe
	$(BIN2H) stubify.exe stubify_stub $@ -q

l_com.h: l_com.asx
	$(NASM) -f bin -o $T.bin $<
	$(BIN2H) $T.bin nrv2b_loader $@

l_djgpp2.h: l_djgpp2.asx
	$(NASM) -f bin -o $T.bin $<
	$(BIN2H) $T.bin nrv_loader $@

l_exe.h: l_exe.asx
	$(NASM) -f bin -o $T.bin $<
	$(BIN2H) $T.bin nrv_loader $@

l_sys.h: l_sys.asx
	$(NASM) -f bin -o $T.bin $<
	$(BIN2H) $T.bin nrv2b_loader $@

l_tmt.h: l_tmt.asx
	$(NASM) -f bin -o $T.bin $<
	$(BIN2H) $T.bin nrv_loader $@

l_vxd.h: l_vxd.asx
	$(NASM) -f bin -o $T.bin $<
	$(BIN2H) $T.bin nrv_loader $@

l_wcle.h: l_wcle.asx
	$(NASM) -f bin -o $T.bin $<
	$(BIN2H) $T.bin nrv_loader $@

l_w32pe.h: l_w32pe.asx
	$(NASM) -f bin -o $T.bin $<
	$(BIN2H) $T.bin nrv_loader $@


# /***********************************************************************
# // atari/tos rules
# ************************************************************************/

l_t_n2b.h: l_tos.s
	$(CPP_M68K) -DNRV2B -o $T.i $<
	$(ASM_M68K) $T.i
	$(O2BIN) $T.o $T.bin 'UPX1' 'UPX9'
	$(BIN2H) $T.bin nrv2b_loader $@

l_t_n2bs.h: l_tos.s
	$(CPP_M68K) -DNRV2B -DSMALL -o $T.i $<
	$(ASM_M68K) $T.i
	$(O2BIN) $T.o $T.bin 'UPX1' 'UPX9'
	$(BIN2H) $T.bin nrv2b_loader_small $@

l_t_n2d.h: l_tos.s
	$(CPP_M68K) -DNRV2D -o $T.i $<
	$(ASM_M68K) $T.i
	$(O2BIN) $T.o $T.bin 'UPX1' 'UPX9'
	$(BIN2H) $T.bin nrv2d_loader $@

l_t_n2ds.h: l_tos.s
	$(CPP_M68K) -DNRV2D -DSMALL -o $T.i $<
	$(ASM_M68K) $T.i
	$(O2BIN) $T.o $T.bin 'UPX1' 'UPX9'
	$(BIN2H) $T.bin nrv2d_loader_small $@

l_t_n2e.h: l_tos.s
	$(CPP_M68K) -DNRV2E -o $T.i $<
	$(ASM_M68K) $T.i
	$(O2BIN) $T.o $T.bin 'UPX1' 'UPX9'
	$(BIN2H) $T.bin nrv2e_loader $@

l_t_n2es.h: l_tos.s
	$(CPP_M68K) -DNRV2E -DSMALL -o $T.i $<
	$(ASM_M68K) $T.i
	$(O2BIN) $T.o $T.bin 'UPX1' 'UPX9'
	$(BIN2H) $T.bin nrv2e_loader_small $@


# /***********************************************************************
# // linux rules
# ************************************************************************/

l_lx_n2b.h: l_linux.c l_xe_n2b.o
	$(CC_LINUX_I386) -DNRV2B -s -o $T.o -c $<
	ld -s -Map $T.map -o $T.bin l_xe_n2b.o $T.o
	objcopy -S -R .comment -R .note $T.bin
	$(STRIPELF) $T.bin
	$(BRANDELF) $T.bin
	$(BIN2H) $T.bin linux_i386_nrv2b_loader $@

l_xe_n2b.o: l_linuxe.asm
	$(NASM) -i$(UCL_I386)/ -f elf -dNRV2B -o $@ $<

l_lx_n2d.h: l_linux.c l_xe_n2d.o
	$(CC_LINUX_I386) -DNRV2D -s -o $T.o -c $<
	ld -s -Map $T.map -o $T.bin l_xe_n2d.o $T.o
	objcopy -S -R .comment -R .note $T.bin
	$(STRIPELF) $T.bin
	$(BRANDELF) $T.bin
	$(BIN2H) $T.bin linux_i386_nrv2d_loader $@

l_xe_n2d.o: l_linuxe.asm
	$(NASM) -i$(UCL_I386)/ -f elf -dNRV2D -o $@ $<

l_lx_n2e.h: l_linux.c l_xe_n2e.o
	$(CC_LINUX_I386) -DNRV2E -s -o $T.o -c $<
	ld -s -Map $T.map -o $T.bin l_xe_n2e.o $T.o
	objcopy -S -R .comment -R .note $T.bin
	$(STRIPELF) $T.bin
	$(BRANDELF) $T.bin
	$(BIN2H) $T.bin linux_i386_nrv2e_loader $@

l_xe_n2e.o: l_linuxe.asm
	$(NASM) -i$(UCL_I386)/ -f elf -dNRV2E -o $@ $<


# /***********************************************************************
# // dependencies
# ************************************************************************/

DEPS1 = header.ash macros.ash version.asy ident.ash ident_n.ash ident_s.ash
DEPS2 = header.asy macros.asy

$(STUBS):       $(srcdir)/scripts/bin2h.pl

ident.ash:      version.asy
ident.asy:      version.asy
ident_n.ash:    version.asy
ident_n.asy:    version.asy
ident_s.ash:    version.asy
ident_s.asy:    version.asy

l_com.h:        n2b_d16.asy  $(DEPS2)
l_djgpp2.h:     n2b_d32.asy  n2d_d32.asy  n2e_d32.asy  $(DEPS2)
l_exe.h:        n2b_d8e.asy  n2d_d8e.asy  n2e_d8e.asy  $(DEPS2)
l_lx_n2b.h:     n2b_d32.ash  $(DEPS1)
l_xe_n2b.o:     n2b_d32.ash  $(DEPS1)
l_lx_n2d.h:     n2d_d32.ash  $(DEPS1)
l_xe_n2d.o:     n2d_d32.ash  $(DEPS1)
l_lx_n2e.h:     n2e_d32.ash  $(DEPS1)
l_xe_n2e.o:     n2e_d32.ash  $(DEPS1)
l_sys.h:        n2b_d16.asy  $(DEPS2)
l_t_n2b.h:      n2b_d.ash    bits.ash  $(DEPS1)
l_t_n2bs.h:     n2b_d.ash    bits.ash  $(DEPS1)
l_t_n2d.h:      n2d_d.ash    bits.ash  $(DEPS1)
l_t_n2ds.h:     n2d_d.ash    bits.ash  $(DEPS1)
l_t_n2e.h:      n2e_d.ash    bits.ash  $(DEPS1)
l_t_n2es.h:     n2e_d.ash    bits.ash  $(DEPS1)
l_tmt.h:        n2b_d32.asy  n2d_d32.asy  n2e_d32.asy  $(DEPS2)
l_vxd.h:        n2b_d32.asy  n2d_d32.asy  n2e_d32.asy  $(DEPS2)
l_wcle.h:       n2b_d32.asy  n2d_d32.asy  n2e_d32.asy  $(DEPS2)
l_w32pe.h:      n2b_d32.asy  n2d_d32.asy  n2e_d32.asy  $(DEPS2)

.NOEXPORT:

# vi:nowrap
