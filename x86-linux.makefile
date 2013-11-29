#!/bin/false
#
# generic makefile
#

# Miscellaneous defines:
MFNAME=x86-linux.makefile
UNAMER=`uname -r`
UNAMES=`uname -s`
UNAMEM=`uname -m`
PROJDIR=.

# varies by platform (default is Linux):
CXX_LNX_BASE = g++ -fPIC -Wall 
CC_LNX_BASE = gcc -fPIC -Wall 
CC_OPTS_LNX_BASE = -DUNIX -DLINUX -DOS_UNIX -DOS_LINUX -D_REENTRANT -DUSE_PTHREADS -DLUNA_LITTLE_ENDIAN 
LD_LNX_BASE = g++ -fPIC -lpthread -ldl

CXX_LNX_32 = $(CXX_LNX_BASE) -m32
CC_LNX_32 = $(CC_LNX_BASE) -m32
CC_OPTS_LNX_32 = $(CC_OPTS_LNX_BASE)
LD_LNX_32 = $(LD_LNX_BASE) -m32

CXX_LNX_64 = $(CXX_LNX_BASE) -m64
CC_LNX_64 = $(CC_LNX_BASE) -m64
CC_OPTS_LNX_64 = $(CC_OPTS_LNX_BASE) -DLUNA_LP64_CORRECT
LD_LNX_64 = $(LD_LNX_BASE) -m64


# varies by platform (SunOS):
CXX_SUN_BASE = CC -KPIC -mt
CC_SUN_BASE = cc -xCC -KPIC -mt
CC_OPTS_SUN_BASE = -DUNIX -DSOLARIS -DOS_UNIX -DOS_SOLARIS -D_REENTRANT -DUSE_PTHREADS -DLUNA_BIG_ENDIAN 
LD_SUN_BASE = CC -KPIC -mt -lposix4 -lpthread

CXX_SUN_32 = $(CXX_SUN_BASE)
CC_SUN_32 = $(CC_SUN_BASE)
CC_OPTS_SUN_32 = $(CC_OPTS_SUN_BASE)
LD_SUN_32 = $(LD_SUN_BASE)

CXX_SUN_64 = $(CXX_SUN_BASE) -xarch=v9 -xregs=no%appl
CC_SUN_64 = $(CC_SUN_BASE) -xarch=v9 -xregs=no%appl
CC_OPTS_SUN_64 = $(CC_OPTS_SUN_BASE) -DLUNA_LP64_CORRECT
LD_SUN_64 = $(LD_SUN_BASE) -xarch=v9 -xregs=no%appl


# varies by platform (AIX):
CXX_AIX = xlC_r
CC_AIX = xlc_r
CC_OPTS_AIX = -DUNIX -DAIX -DOS_UNIX -DOS_AIX -D_REENTRANT -DUSE_PTHREADS -DLUNA_BIG_ENDIAN 
LD_AIX = xlC_r


# varies by platform (HP-UX):
CXX_HP = aCC
CC_HP = cc
CC_OPTS_HP = -DUNIX -DHPUX -DOS_UNIX -DOS_HPUX -DOS_HPUX_11_00 -D_REENTRANT -DUSE_PTHREADS -DLUNA_BIG_ENDIAN 
LD_HP = aCC -lpthread


# CC, CFLAGS, LD:
CFLAGS_INC = -I. -I./source 

CFLAGS_LOCAL = 
CFLAGS_DEBUG = -DDEBUG_disabled
CFLAGS = -I. $(CFLAGS_INC) $(CFLAGS_LOCAL) $(CFLAGS_DEBUG) $(CC_OPTS)

BUILD_32 = build32
BUILD_64 = build64
BUILD = $(BUILD_32)

# obj-m definition:
obj-m = $(BUILD)/ckdemo


# obj-m definition:
vkd-objs = $(BUILD)/c_bridge.o \
  $(BUILD)/ChrystokiConfiguration.o \
  $(BUILD)/ckbridge.o \
  $(BUILD)/Ckodesc.o \
  $(BUILD)/console.o \
  $(BUILD)/DynamicLibrary.o \
  $(BUILD)/editor.o \
  $(BUILD)/template.o \
  $(BUILD)/Utils.o \
  $(BUILD)/Ckdemo.o 


# SUFFIXES:
.SUFFIXES: .h .c .cpp .o


# default target:
default all:
	@if [ ! -d ./$(BUILD_32) ]; then mkdir -p ./$(BUILD_32) ; fi
	@if [ ! -d ./$(BUILD_64) ]; then mkdir -p ./$(BUILD_64) ; fi
	@if [ "$(UNAMES)" = "SunOS" ]; then make -f $(MFNAME) default-local PROJDIR=`pwd`/../.. CXX="$(CXX_SUN_64)" CC="$(CC_SUN_64)" CC_OPTS="$(CC_OPTS_SUN_64)" LD="$(LD_SUN_64)" BUILD="$(BUILD_64)" ; fi
	@if [ "$(UNAMES)" = "SunOS" ]; then make -f $(MFNAME) default-local PROJDIR=`pwd`/../.. CXX="$(CXX_SUN_32)" CC="$(CC_SUN_32)" CC_OPTS="$(CC_OPTS_SUN_32)" LD="$(LD_SUN_32)" BUILD="$(BUILD_32)" ; fi
	@if [ "$(UNAMES)" = "AIX" ];   then make -f $(MFNAME) default-local PROJDIR=`pwd`/../.. CXX="$(CXX_AIX)" CC="$(CC_AIX)" CC_OPTS="$(CC_OPTS_AIX)" LD="$(LD_AIX)" ; fi
	@if [ "$(UNAMES)" = "HP-UX" ]; then make -f $(MFNAME) default-local PROJDIR=`pwd`/../.. CXX="$(CXX_HP)"  CC="$(CC_HP)"  CC_OPTS="$(CC_OPTS_HP)"  LD="$(LD_HP)"  ; fi
	@if [ "$(UNAMES)" = "Linux" -a "$(UNAMEM)" = "x86_64" ]; then make -f $(MFNAME) default-local PROJDIR=`pwd`/../.. CXX="$(CXX_LNX_64)" CC="$(CC_LNX_64)" CC_OPTS="$(CC_OPTS_LNX_64)" LD="$(LD_LNX_64)" BUILD="$(BUILD_64)" ; fi
	@if [ "$(UNAMES)" = "Linux" ]; then make -f $(MFNAME) default-local PROJDIR=`pwd`/../.. CXX="$(CXX_LNX_32)" CC="$(CC_LNX_32)" CC_OPTS="$(CC_OPTS_LNX_32)" LD="$(LD_LNX_32)" BUILD="$(BUILD_32)" ; fi
	@echo


# clean target:
clean cleanbin:
	@make -f $(MFNAME) clean-local BUILD="$(BUILD_64)"
	@make -f $(MFNAME) clean-local BUILD="$(BUILD_32)"
	@echo


# default-local target:
default-local: $(vkd-objs)
	$(LD) -o $(obj-m) $(vkd-objs)
	file $(obj-m)
	@echo


# clean-local target:
clean-local:
	rm -f $(obj-m)
	rm -f $(vkd-objs)
	@echo


# compile .o file from .cpp file
.cpp.o:
	$(CXX) $(CFLAGS) -c -o $@ $<
	file $@
	@echo


# compile .o file from .c file
.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<
	file $@
	@echo

$(BUILD)/c_bridge.o: source/c_bridge.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/ChrystokiConfiguration.o: source/ChrystokiConfiguration.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/ckbridge.o: source/ckbridge.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/Ckodesc.o: source/Ckodesc.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/console.o: source/console.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/DynamicLibrary.o: source/DynamicLibrary.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/editor.o: source/editor.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/template.o: source/template.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/Utils.o: source/Utils.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/Ckdemo.o: Ckdemo.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

$(BUILD)/GeneralFunctions.o: GeneralFunctions.cpp
	$(CXX) $(CFLAGS) -c -o $@ $<

# header file dependencies:
$(BUILD)/c_bridge.o: source/*.h
$(BUILD)/ChrystokiConfiguration.o: source/*.h
$(BUILD)/ckbridge.o: source/*.h
$(BUILD)/Ckodesc.o: source/*.h
$(BUILD)/console.o: source/*.h
$(BUILD)/DynamicLibrary.o: source/*.h
$(BUILD)/editor.o: source/*.h
$(BUILD)/template.o: source/*.h
$(BUILD)/Utils.o: source/*.h
$(BUILD)/Ckdemo.o: source/*.h  GeneralFunctions.h
$(BUILD)/GeneralFunctions.o: source/*.h  GeneralFunctions.h

#eof
