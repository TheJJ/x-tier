
CXXFLAGS = -g -O0 -std=c++11 -Wall -Werror -fPIC

XTIER_DIR       = ../x-tier
LIBINJECT_DIR   = ../libinject

INCLUDEDIRS = -I$(XTIER_DIR) -I$(LIBINJECT_DIR)
LINKLIBS =
LINKINJECT = -L$(LIBINJECT_DIR) -linject -Wl,-rpath $(LIBINJECT_DIR)



all: lolredirect target-test

target-test: target.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

lolredirect: lolredirect.o util.o syscall_redirector.o syscall_utils.o state_tracker.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LINKINJECT) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDEDIRS) -o $@ -c $<

run: lolredirect
	./$<

clean:
	rm -f *.o *.so lolredirect

.PHONY: all clean run
