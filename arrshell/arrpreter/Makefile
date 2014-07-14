#makefile for the arrshell pin module


CXXFLAGS        = -O2 -std=c++11 -Wall -fPIC -fno-stack-protector -fomit-frame-pointer -fno-strict-aliasing #-Werror
PIN_DIR         = ../pin
XTIER_DIR       = ../../x-tier
QEMU_DIR        = ../../qemu

LIBINJECT_DIR   = ../../libinject/

INCLUDEDIRS = -I$(XTIER_DIR) -I$(QEMU_DIR) -I$(PIN_DIR)/source/tools/InstLib -I$(PIN_DIR)/source/include/pin -I$(PIN_DIR)/source/include/pin/gen -I$(PIN_DIR)/extras/components/include -I$(PIN_DIR)/extras/xed2-intel64/include $(shell pkg-config QtCore --cflags)

LINKDIRS = -L$(PIN_DIR)/intel64/lib -L$(PIN_DIR)/intel64/lib-ext -L$(PIN_DIR)/extras/xed2-intel64/lib  -L$(PIN_DIR)/intel64/runtime/libelf
#LINKLIBS = $(shell pkg-config QtCore --libs) -lpin -lxed -ldwarf -lelf -ldl
LINKLIBS = $(shell pkg-config QtCore --libs) -lpin -lelf -ldwarf -L$(LIBINJECT_DIR) -linject -Wl,-rpath $(LIBINJECT_DIR)

SHAREDLIBFLAGS = -shared -Wl,--hash-style=sysv -Wl,-Bsymbolic -Wl,--version-script=$(PIN_DIR)/source/include/pin/pintool.ver

ARRPRETER_CONF = -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -DTARGET_IA32E -DHOST_IA32E -DTARGET_LINUX



all: arrpreter.so

injection_arrpreter.o: $(XTIER_DIR)/X-TIER_base-userland.c $(XTIER_DIR)/X-TIER.c
	$(CXX) $(CXXFLAGS) -o $@ -c $<

arrpreter.o: arrpreter.cpp
	$(CXX) $(CXXFLAGS) $(ARRPRETER_CONF) $(INCLUDEDIRS) -o $@ -c $^

arrpreter.so: injection_arrpreter.o arrpreter.o
	$(CXX) $(CXXFLAGS) $(SHAREDLIBFLAGS) $(LINKDIRS) $^ $(LINKLIBS) -o $@

clean:
	rm -f *.so *.o

.PHONY: all clean
