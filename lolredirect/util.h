#ifndef _LOLREDIRECT_UTIL_H_
#define _LOLREDIRECT_UTIL_H_

#include <string>

namespace util {

/**
 * copy memory to/from redirected process.
 */
int tmemcpy(struct syscall_mod *trap, char *dest, const char *src, ssize_t len, bool to_other);

/**
 * copy strings from redirected process.
 */
int tstrncpy(struct syscall_mod *trap, char *dest, const char *addr, ssize_t len);

/**
 * string comparison with prefix only.
 */
int strpcmp(const char *search, const char *prefix);

/**
 * create an absolute path from the current working directory and a new path.
 */
std::string abspath(std::string cwd, std::string path);

/**
 * normalize a path containing /A/../B/ to /B/ etc.
 */
std::string normpath(std::string path);

/**
 * check if the given path is an absolute path.
 */
bool is_abspath(std::string path);


} //namespace util

#endif //_LOLREDIRECT_UTIL_H_
