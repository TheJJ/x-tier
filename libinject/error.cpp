#include "error.h"

#include <cstdarg>
#include <cstdlib>
#include <cstring>

#include "strings.h"

namespace util {

Error::Error(const char *fmt, ...) {
	va_list vl;
	va_start(vl, fmt);
	this->buf = vformat(fmt, vl);
	va_end(vl);
}

Error::Error(Error const &other) {
	buf = copy(other.buf);
}

Error &Error::operator=(Error const &other) {
	delete[] buf;
	buf = copy(other.buf);
	return *this;
}

Error::Error(Error &&other) {
	buf = other.buf;
	other.buf = nullptr;
}


Error::~Error() {
	delete[] buf;
}

const char *Error::str() {
	return buf;
}

}
