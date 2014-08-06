#include "lolredirect.h"

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "syscall_redirector.h"
#include "state_tracker.h"
#include "util.h"
#include "x-inject.h"


bool syscall_redirect(struct syscall_mod *trap) {
	bool success = true;

	switch (trap->syscall_id) {
	case SYS_getuid: //TODO
		break;

	case SYS_getdents:
		success = on_getdents(trap);
		break;

	case SYS_open:
		success = on_open(trap, false);
		break;

	case SYS_openat:
		success = on_open(trap, true);
		break;

	case SYS_close:
		success = on_close(trap);
		break;

	case SYS_stat:
		success = on_stat(trap, false);
		break;

	case SYS_fstat:
		success = on_stat(trap, true);
		break;

	case SYS_lstat: //TODO, link stat
		break;

	case SYS_read:
		success = on_read(trap);
		break;

	case SYS_write: //TODO
		break;

	case SYS_lseek:
		success = on_lseek(trap);
		break;

	case SYS_fcntl:
		success = on_fcntl(trap);
		break;

	case SYS_fadvise64: //ignore file access pattern hint
		trap->set_return(0);
		break;

	case SYS_chdir:
		success = on_chdir(trap, false);
		break;

	case SYS_fchdir:
		success = on_chdir(trap, true);
		break;
	}

	return success;
}


/**
 * open: syscall 2
 */
bool on_open(struct syscall_mod *trap, bool openat) {
	int n = 0;
	int base_arg_id = 0;

	if (openat) {
		base_arg_id += 1;
	}

	char path[max_path_len];
	n = util::tstrncpy(trap, path, (const char *)trap->get_arg(base_arg_id++), max_path_len);
	int flags = (int)trap->get_arg(base_arg_id++);
	int mode  = (int)trap->get_arg(base_arg_id++);

	if (n < 0) {
		PRINT_ERROR("failed copying path string\n");
		return false;
	}

	if (openat) {
		if (not util::is_abspath(path)) {
			int fd = (int)trap->get_arg(0);

			auto search = trap->pstate->files.find(fd);
			if (search == trap->pstate->files.end()) {
				trap->set_return(-EBADF);
				return true;
			}

			std::string path_s = util::abspath(search->second.path, path);
			strncpy(path, path_s.c_str(), max_path_len);
		}
	}
	else if (not util::is_abspath(path)) {
		std::string path_s = util::abspath(trap->pstate->cwd, path);
		strncpy(path, path_s.c_str(), max_path_len);
	}

	//TODO: library that creates inject files
	struct injection *injection = new_injection("/tmp/open.inject");

	injection_load_code(injection);

	add_string_argument(injection, path);
	add_int_argument(injection, flags);
	add_int_argument(injection, mode);

	injection = consolidate(injection);

	PRINT_DEBUG("Trying to open file '%s' (flags 0x%x, mode 0x%x) within the guest...\n", path, flags, mode);
	struct received_data recv_data;
	inject_module(injection, &recv_data);

	free_injection(injection);

	if (recv_data.return_value >= 0) {
		PRINT_DEBUG("open successful: '%s'\n", path);

		struct file_state fd;
		fd.fd = (int)trap->pstate->next_free_fd;
		fd.path = path;
		fd.flags = flags;
		fd.mode = mode;
		fd.pos = 0;
		fd.close_on_exec = 0;
		fd.getdents = false;

		trap->pstate->files[fd.fd] = fd;

		trap->set_return(fd.fd);
		PRINT_DEBUG("virtual fd = '%d'\n", fd.fd);
		trap->pstate->next_free_fd += 1;
	}
	else {
		PRINT_DEBUG("Could not open file '%s'\n", path);
		trap->set_return(recv_data.return_value);
	}
	return true;
}


/**
 * read: syscall 0
 */
bool on_read(struct syscall_mod *trap) {
	int   fd       = (int)trap->get_arg(0);
	char *buf      = (char *)trap->get_arg(1);
	int   buf_size = (int)trap->get_arg(2);

	PRINT_DEBUG("read fd %d to 0x%lx and with size %d\n", fd, (long)buf, buf_size);

	struct received_data recv_data;
	struct injection *injection = NULL;

	// take the corresponding file_state from our stored file state dict
	auto search = trap->pstate->files.find(fd);
	if (search == trap->pstate->files.end()) {
		PRINT_ERROR("File Descriptor %d unkown!\n", fd);
		trap->set_return(-EBADF);
		return true;
	}

	struct file_state *fs = &trap->pstate->files[fd];

	injection = new_injection("/tmp/read.inject");
	injection_load_code(injection);

	add_string_argument(injection, fs->path.c_str());
	add_int_argument(injection, fs->flags);
	add_int_argument(injection, fs->pos);
	add_int_argument(injection, buf_size);

	injection = consolidate(injection);

	PRINT_DEBUG("Trying to read %d bytes from file '%s'...\n", buf_size, fs->path.c_str());

	inject_module(injection, &recv_data);

	PRINT_DEBUG("read() returned %d when reading file '%s'\n", buf_size, fs->path.c_str());

	if (recv_data.return_value > buf_size) {
		throw util::Error("read %ld bytes, but buffer is only %d big! aborting", recv_data.return_value, buf_size);
	}
	else if (recv_data.return_value >= 0) {
		int n = util::tmemcpy(trap, buf, recv_data.data, recv_data.return_value, true);

		if (n < 0) {
			free_injection(injection);
			throw util::Error("failed storing read data to child process!");
		}

		fs->pos += recv_data.return_value;
		trap->set_return(recv_data.return_value);
	}

	free_injection(injection);

	return true;
}


/**
 * close: syscall 3
 */
bool on_close(struct syscall_mod *trap) {
	int fd = (int)trap->get_arg(0);

	if (trap->pstate->files.find(fd) != trap->pstate->files.end()) {
		trap->pstate->files.erase(fd);
		trap->set_return(0);
		return true;
	}
	else {
		trap->set_return(-EBADF);
		return true;
	}
}



/**
 * getdents: syscall 78
 */
bool on_getdents(struct syscall_mod *trap) {
	int                  fd    = (int)trap->get_arg(0);
	struct linux_dirent *dirp  = (struct linux_dirent *)trap->get_arg(1);
	int                  count = (int)trap->get_arg(2);

	struct received_data recv_data;
	struct injection *injection = NULL;
	int n = 0;

	auto search = trap->pstate->files.find(fd);
	if (search == trap->pstate->files.end()) {
		PRINT_ERROR("File Descriptor %d unkown!\n", fd);
		trap->set_return(-EBADF);
		return true;
	}

	struct file_state *fs = &trap->pstate->files[fd];

	// We only inject on the first getdents call
	if (!fs->getdents) {
		injection = new_injection("/tmp/getdents.inject");
		injection_load_code(injection);
		add_string_argument(injection, fs->path.c_str());
		injection = consolidate(injection);

		PRINT_DEBUG("Trying to get directory contents of '%s'...\n", fs->path.c_str());
		inject_module(injection, &recv_data);

		free_injection(injection);

		if (recv_data.length < count) {
			// the passed buffer dirp is larger than the data we received
			n = util::tmemcpy(trap, (char *)dirp, recv_data.data, recv_data.length, true);
			if (n < 0) {
				throw util::Error("failed storing getdents data to redirected process");
			}

			fs->getdents = recv_data.length;
			trap->set_return(recv_data.return_value);
		}
		else {
			PRINT_WARNING("Data returned is larger than the size of the buffer! Next getdents call will do nothing! (TODO)\n");
			n = util::tmemcpy(trap, (char *)dirp, recv_data.data, count, true);
			if (n < 0) {
				throw util::Error("failed storing getdents data to redirected process");
			}
			fs->getdents = count;
			trap->set_return(count);
		}
	}
	else {
		//TODO: handle subsequent getdents calls
		// 0 = end of directory
		trap->set_return(0);
		fs->getdents = 0;
	}

	return true;
}


/**
 * stat: syscall 4, fstat: syscall 5
 */
bool on_stat(struct syscall_mod *trap, bool do_fdlookup) {
	char *stat_result_ptr = (char *)trap->get_arg(1);

	struct received_data recv_data;
	struct injection *injection = new_injection("/tmp/stat.inject");
	injection_load_code(injection);

	const char *stat_path = NULL;

	int n;

	if (not do_fdlookup) {
		char stat_path_buf[max_path_len];
		n = util::tstrncpy(trap, stat_path_buf, (const char *)trap->get_arg(0), max_path_len);

		if (n < 0) {
			throw util::Error("failed copying path string!\n");
		}

		PRINT_DEBUG("requested to stat filename '%s'\n", stat_path_buf);

		if (not util::is_abspath(stat_path_buf)) {
			std::string path_s = util::abspath(trap->pstate->cwd, stat_path_buf);
			strncpy(stat_path_buf, path_s.c_str(), max_path_len);
		}

		stat_path = stat_path_buf;
	}
	else {
		int stat_fd = (int)trap->get_arg(0);

		auto search = trap->pstate->files.find(stat_fd);
		if (search == trap->pstate->files.end()) {
			trap->set_return(-EBADF);
			return true;
		}
		stat_path = search->second.path.c_str();
		PRINT_DEBUG("Looked up: fd %d => '%s'\n", stat_fd, stat_path);
	}

	add_string_argument(injection, stat_path);
	injection = consolidate(injection);

	PRINT_DEBUG("Trying to stat file '%s' -> %p...\n", stat_path, stat_result_ptr);
	inject_module(injection, &recv_data);

	struct stat *received_stat = (struct stat *)recv_data.data;

	if (recv_data.return_value == 0) {
		size_t file_size = received_stat->st_size;
		PRINT_DEBUG("file '%s' size: %zu\n", stat_path, file_size);
	}
	else if (recv_data.return_value < 0) {
		goto out;
	}

	if (recv_data.length != sizeof(struct stat)) {
		free_injection(injection);
		throw util::Error("recieved wrong struct stat size!");
	}

	PRINT_DEBUG("recv_data %p\n", &recv_data);

	// store stat data to other process
	n = util::tmemcpy(trap, stat_result_ptr, recv_data.data, sizeof(struct stat), true);
	if (n < 0) {
		free_injection(injection);
		throw util::Error("failed storing stat result!");
	}

	//0 on success, < 0 on fail
out:
	trap->set_return(recv_data.return_value);
	free_injection(injection);

	return true;
}

/**
 * lseek: syscall 8
 */
bool on_lseek(struct syscall_mod *trap) {
	int  fd       = (int)trap->get_arg(0);
	long position = (long)trap->get_arg(1);
	int  whence   = (int)trap->get_arg(2);

	struct file_state *fs;

	if (trap->pstate->files.find(fd) == trap->pstate->files.end()) {
		PRINT_ERROR("File Descriptor %d unkown!\n", fd);
		trap->set_return(-EBADF);
		return true;
	}

	fs = &trap->pstate->files[fd];

	switch (whence) {
	case SEEK_SET:
		fs->pos = position;
		trap->set_return(position);
		break;
	case SEEK_CUR:
		fs->pos += position;
		trap->set_return(fs->pos);
		break;
	}

	return true;
}

bool on_fcntl(struct syscall_mod *trap) {
	int fd        = (int)trap->get_arg(0);
	int operation = (int)trap->get_arg(1);

	if (trap->pstate->files.find(fd) == trap->pstate->files.end()) {
		PRINT_ERROR("File Descriptor %d unkown!\n", fd);
		trap->set_return(-EBADF);
		return true;
	}

	int syscall_return_val = 0;

	//see include/uapi/asm-generic/fcntl.h
	switch (operation) {

	case F_DUPFD:
		PRINT_DEBUG("duplicating fd %d\n", fd);
		//create fd copy.

		trap->pstate->files[trap->pstate->next_free_fd] = trap->pstate->files[fd];
		trap->set_return(trap->pstate->next_free_fd);
		trap->pstate->next_free_fd += 1;
		break;

	case F_GETFL:
		PRINT_DEBUG("getting open flags for fd %d\n", fd);
		syscall_return_val = trap->pstate->files[fd].flags;
		break;

	case F_GETFD:
		PRINT_DEBUG("getting fd flags (close_on_exec) for fd %d\n", fd);
		syscall_return_val = trap->pstate->files[fd].close_on_exec;
		break;

	case F_SETFD: {
		int new_coe = (int)trap->get_arg(2);
		PRINT_DEBUG("setting fd flags (close_on_exec) for fd %d to %d\n", fd, new_coe);
		trap->pstate->files[fd].close_on_exec = new_coe;
		break;
	}
	default:
		PRINT_ERROR("unknown/uninplemented fcntl operation %d!\n", operation);
		syscall_return_val = -EINVAL;
	}

	trap->set_return(syscall_return_val);
	return true;
}

/**
 * chdir: syscall 80, fchdir: syscall 81
 *
 * change working dir of current process
 */
bool on_chdir(struct syscall_mod *trap, bool do_fdlookup) {
	std::string new_work_dir;

	if (do_fdlookup) {
		int fd = (int)trap->get_arg(0);
		PRINT_DEBUG("chdir to fd %d\n", fd);

		auto search = trap->pstate->files.find(fd);
		if (search == trap->pstate->files.end()) {
			trap->set_return(-EBADF);
			return true;
		}
		new_work_dir = search->second.path;
		PRINT_DEBUG("Looked up: fd %d => '%s'\n", fd, new_work_dir.c_str());
	}
	else {
		char path_buf[max_path_len];
		int n = util::tstrncpy(trap, path_buf, (const char *)trap->get_arg(0), max_path_len);

		if (n < 0) {
			throw util::Error("failed copying chdir string!\n");
		}

		PRINT_DEBUG("chdir to '%s'\n", path_buf);
		new_work_dir = path_buf;
	}

	trap->pstate->cwd = util::abspath(trap->pstate->cwd, new_work_dir);

	trap->set_return(0);
	return true;
}

/**
 * chdir: syscall 79
 *
 * return working dir of current process
 */
bool on_getcwd(struct syscall_mod *trap) {
	char   *cwd_result_ptr = (char *)trap->get_arg(0);
	size_t  max_buf_len    = (size_t)trap->get_arg(1);

	size_t cwd_full_len = trap->pstate->cwd.length() + 1; // \0 included

	if (cwd_full_len > max_buf_len) {
		trap->set_return(-ERANGE);
		return true;
	}

	int n = util::tmemcpy(trap, cwd_result_ptr, trap->pstate->cwd.c_str(), cwd_full_len, true);

	if (n < 0) {
		throw util::Error("failed copying cwd result string!\n");
	}

	trap->set_return((uint64_t)cwd_result_ptr);
	return true;
}
