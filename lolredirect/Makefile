
CXXFLAGS = -g -O1 -std=c++11 -fPIC

XTIER_DIR       = ../x-tier
LIBINJECT_DIR   = ../libinject

INCLUDEDIRS = -I$(XTIER_DIR)
LINKLIBS =
LINKINJECT = -L$(LIBINJECT_DIR) -linject -Wl,-rpath $(LIBINJECT_DIR)



all: lolredirect target-test

target-test: target.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LINKINJECT) -o $@

lolredirect: lolredirect.o $(LIBINJECT_DIR)/libinject.so
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< $(LINKLIBS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDEDIRS) -o $@ -c $<

clean:
	rm -f *.o *.so lolredirect

.PHONY: all clean run
