#include "lolredirect.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/uio.h>


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

} //namespace util
