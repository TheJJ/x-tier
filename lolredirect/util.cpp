#include "lolredirect.h"
#include "util.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/uio.h>

struct syscall_mod;

namespace util {

/**
 * traced to tracer memory copy.
 * copy len bytes from trapped process at address addr to destination dest
 */
int tmemcpy(struct syscall_mod *trap, char *dest, const char *src, ssize_t len, bool to_other) {
	struct iovec local[1], remote[1];

	//bytes to copy:
	local[0].iov_len = len;
	remote[0].iov_len = len;

	int n;
	if (to_other) {
		local[0].iov_base  = (void *)src;
		remote[0].iov_base = (void *)dest;
		n = process_vm_writev(trap->pid, local, 1, remote, 1, 0);
	}
	else {
		local[0].iov_base  = (void *)dest;
		remote[0].iov_base = (void *)src;
		n = process_vm_readv(trap->pid, local, 1, remote, 1, 0);
	}

	if (n == len) {
		return 0;
	}

	if (n >= 0) {
		printf("tmemcpy: short read (%d < %ld) @%p\n", n, len, src);
		return -1;
	}

	switch (errno) {
	case ENOSYS:
		printf("process_vm_readv syscall unsupported!\n");
		return -1;
	case ESRCH:
		return -1; //process is gone
	case EFAULT:
	case EIO:
	case EPERM:
		return -1; //address space is inaccessible
	default:
		printf("unhandled error in tmemcpy!\n");
		return -1;
	}
}


/**
 * traced to tracer string copy
 * copies a string at addr of max length len of trapped process to our memory at dest
 */
int tstrncpy(struct syscall_mod *trap, char *dest, const char *addr, ssize_t len) {
	constexpr int max_chunk_len = 256;
	int n, nread = 0;

	struct iovec local[1], remote[1];

	local[0].iov_base = dest;
	remote[0].iov_base = (void*)addr;

	while (len > 0) {
		int end_in_page;
		int chunk_len;

		chunk_len = len;
		if (chunk_len > max_chunk_len) {
			chunk_len = max_chunk_len;
		}

		// honor page boundaries,
		// EFAULT otherwise while the \0 is in previous page
		end_in_page = (((size_t)addr + chunk_len) & (4096 - 1));
		n = chunk_len - end_in_page;

		if (chunk_len > end_in_page) {
			chunk_len -= end_in_page;
		}

		local[0].iov_len = remote[0].iov_len = chunk_len;

		n = process_vm_readv(trap->pid, local, 1, remote, 1, 0);

		if (n > 0) {
			if (memchr(local[0].iov_base, '\0', n)) {
				return strlen(dest);
			}

			local[0].iov_base   = (void *)(((char *)local[0].iov_base)  + n);
			remote[0].iov_base  = (void *)(((char *)remote[0].iov_base) + n);
			len                -= n;
			nread              += n;
			continue;
		}

		switch (errno) {
		case ENOSYS:
			printf("process_vm_readv syscall unsupported!\n");
			return -1;
		case ESRCH:
			return -1; // the process is gone
		case EFAULT:
		case EIO:
		case EPERM:
			// address space is inaccessible
			if (nread) {
				printf("read too less: %d < %ld @%p", nread, nread + len, addr);
			}
			return -1;
		default:
			printf("unhandled error in tstrncpy!\n");
			return -1;
		}
	}
	return 0;
}


std::string abspath(std::string cwd, std::string path) {
	if (path.length() > 0) {
		if (is_abspath(path)) {
			return path;
		}
		else { //path is relative
			return normpath(cwd + "/" + path);
		}
	}
	else {
		return cwd;
	}
}


std::string normpath(std::string path) {
	char        sep    = '/';
	char        dot    = '.';
	const char *dotdot = "..";

	size_t len = path.length();

	if (len == 0) {
		return "";
	}

	bool initial_slash = path[0] == sep;

	int slash_count = 0;
	for (size_t i = 0; i < len; i++) {
		if (path[i] == sep) {
			slash_count += 1;
		}
	}

	char *buf = new char[len + 1];
	strncpy(buf, path.c_str(), len + 1);
	buf[len] = '\0';

	int    tok_count     = 0;
	char  *tok_pos, *tok, *str;
	char **comps         = new char*[slash_count];
	char **new_comps     = new char*[slash_count];
	int   *new_comp_lens = new int[slash_count];

	//tokenize at /
	for (str = buf; tok_count < slash_count; str = nullptr, tok_count++) {
		tok = strtok_r(str, &sep, &tok_pos);

		if (tok == nullptr) {
			break;
		}

		comps[tok_count] = tok;
	}

	int new_comps_pos = 0;
	int new_comps_len = 0;
	int prev_len = 0;

	//gather all path components: drop empty parts, the . and cancel out ..
	for (int i = 0; i < tok_count; i++) {
		int comp_len = strlen(comps[i]);
		new_comp_lens[new_comps_pos] = comp_len;

		if (comp_len == 0) {
			continue;
		}
		else if (comp_len == 1 and comps[i][0] == dot) {
			continue;
		}
		else if (0 == strcmp(comps[i], dotdot)) {
			new_comps_pos -= 1;
			new_comps_len -= prev_len;

			if (new_comps_pos < 0) {
				new_comps_pos = 0;
			}
			if (new_comps_len < 0) {
				new_comps_len = 0;
			}
		}
		else {
			new_comps[new_comps_pos] = comps[i];
			new_comps_pos += 1;
			new_comps_len += comp_len;
			prev_len = comp_len;
		}
	}

	//new path buffer, slash + components + component_count(for slashes)
	char *new_path = new char[1 + new_comps_len + new_comps_pos];

	char *path_insert_pos = new_path;

	if (initial_slash) {
		path_insert_pos[0] = sep;
		path_insert_pos += 1;
	}

	//create the new path with / as separators
	for (int i = 0; i < new_comps_pos; i++) {
		if (i > 0) {
			path_insert_pos[0] = sep;
			path_insert_pos += 1;
		}
		memcpy(path_insert_pos, new_comps[i], new_comp_lens[i]);
		path_insert_pos += new_comp_lens[i];
	}
	path_insert_pos[0] = '\0';

	std::string result{new_path};

	delete[] comps;
	delete[] buf;
	delete[] new_comps;
	delete[] new_path;
	delete[] new_comp_lens;

	return result;
}


bool is_abspath(std::string path) {
	if (path.length() > 0) {
		if (path[0] == '/') {
			return true;
		}
	}
	return false;
}


} //namespace util
