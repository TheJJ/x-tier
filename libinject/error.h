#ifndef _LIBINJECT_ERROR_H_
#define _LIBINJECT_ERROR_H_

#include <cstdarg>
#include <cstdio>

namespace util {

/**
Exception type
*/
class Error {
public:
	Error(const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
	~Error();
	Error(Error const &copy);
	Error &operator=(Error const &copy);
	Error(Error &&other);

	const char *str();

private:
	char *buf;
};

}

#endif //_LIBINJECT_ERROR_H_
