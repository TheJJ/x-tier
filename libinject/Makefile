
CXXFLAGS = -g -O1 -std=c++11 -fPIC

QEMU_DIR        = ../qemu

INCLUDEDIRS = -I$(QEMU_DIR)
LINKLIBS =
LINKINJECT = -L. -linject -Wl,-rpath .


PARSER_PATH = parser/linux

all: inject-test

inject-test: inject-test.o libinject.so
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LINKINJECT) -o $@

libinject.so: libinject.o strings.o error.o helpers.o
	$(CXX) -shared $(CXXFLAGS) $(LDFLAGS) $^ $(LINKLIBS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDEDIRS) -o $@ -c $<

xparser.so:
	$(MAKE) -C $(PARSER_PATH)

clean:
	$(MAKE) -C $(PARSER_PATH) clean
	rm -f *.o *.so inject-test

run: inject-test
	./$<

.PHONY: all clean run
