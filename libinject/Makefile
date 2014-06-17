
CXXFLAGS = -g -O1 -std=c++11 -fPIC

XTIER_DIR       = ../x-tier
QEMU_DIR        = ../qemu

INCLUDEDIRS = -I$(XTIER_DIR) -I$(QEMU_DIR) $(shell pkg-config QtCore --cflags)
LINKLIBS = $(shell pkg-config QtCore --libs)
LINKINJECT = -L. -linject -Wl,-rpath .



all: inject-test

inject-test: inject-test.o libinject.so
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LINKINJECT) -o $@

libinject.so: libinject.o x-tier-userspace.o
	$(CXX) -shared $(CXXFLAGS) $(LDFLAGS) $^ $(LINKLIBS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDEDIRS) -o $@ -c $<

x-tier-userspace.o: $(XTIER_DIR)/X-TIER_base-userland.c $(XTIER_DIR)/X-TIER.c
	$(CXX) $(CXXFLAGS) $(INCLUDEDIRS) -o $@ -c $<


clean:
	rm -f *.o *.so inject-test

run: inject-test
	./$<

.PHONY: all clean run
