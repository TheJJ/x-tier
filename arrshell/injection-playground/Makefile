
CXXFLAGS = -g -O1 -std=c++11

XTIER_DIR       = ../../x-tier
QEMU_DIR        = ../../qemu

INCLUDEDIRS = -I$(XTIER_DIR) -I$(QEMU_DIR) $(shell pkg-config QtCore --cflags)
LINKLIBS = $(shell pkg-config QtCore --libs)



all: inject-test

inject-test: inject-test.o x-tier-userspace.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LINKLIBS) -o $@

inject-test.o: inject-test.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDEDIRS) -o $@ -c $<

x-tier-userspace.o: $(XTIER_DIR)/X-TIER_base-userland.c $(XTIER_DIR)/X-TIER.c
	$(CXX) $(CXXFLAGS) $(INCLUDEDIRS) -o $@ -c $<

clean:
	rm -f *.o inject-test

run: inject-test
	./$<

.PHONY: all clean run
