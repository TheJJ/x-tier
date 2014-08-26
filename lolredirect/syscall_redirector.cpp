#include "lolredirect.h"

#include <algorithm>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "syscall_redirector.h"
#include "state_tracker.h"
#include "util.h"
#include "x-inject.h"


bool syscall_redirect(syscall_mod *trap) {
	bool success = true;

	switch (trap->syscall_id) {
	case SYS_getuid:
	case SYS_getgid:
	case SYS_geteuid:
	case SYS_getegid:
	case SYS_getresgid:
	case SYS_getresuid:
		trap->set_return(0);
		break;

	case SYS_uname:
		success = on_uname(trap);
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
		success = on_stat(trap, false, false, false);
		break;

	case SYS_fstat:
		success = on_stat(trap, true, false, false);
		break;

	case SYS_newfstatat:
		success = on_stat(trap, true, true, false);
		break;

	case SYS_lstat:
		success = on_stat(trap, false, false, true);
		break;

	case SYS_read:
		success = on_read(trap);
		break;

	case SYS_write:
		success = on_write(trap);
		break;

	case SYS_lseek:
		success = on_lseek(trap);
		break;

	case SYS_fcntl:
		success = on_fcntl(trap);
		break;

	case SYS_fadvise64:
		// ignore file access pattern hint:
		trap->set_return(0);
		break;

	case SYS_chdir:
		success = on_chdir(trap, false);
		break;

	case SYS_fchdir:
		success = on_chdir(trap, true);
		break;

	case SYS_getcwd:
		success = on_getcwd(trap);
		break;

	case SYS_dup:
		success = on_dup(trap, 1);
		break;

	case SYS_dup2:
		success = on_dup(trap, 2);
		break;

	case SYS_dup3:
		success = on_dup(trap, 3);
		break;
	}

	return success;
}


/**
 * open: syscall 2
 */
bool on_open(syscall_mod *trap, bool openat) {
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

			std::string basepath;
			if (fd == AT_FDCWD) {
				PRINT_DEBUG("openat CWD\n");
				basepath = trap->pstate->cwd;
			} else {
				auto search = trap->pstate->files.find(fd);
				if (search == trap->pstate->files.end()) {
					trap->set_return(-EBADF);
					return true;
				}
				basepath = search->second->path;
			}

			std::string path_s = util::abspath(basepath, path);
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

		int fd_id = (int)trap->pstate->next_free_fd;
		struct file_state *fd = new file_state{
			{fd_id},
			path,
			flags,
			mode,
			0,
			0,
			false
		};

		trap->pstate->files[fd_id] = fd;

		trap->set_return(fd_id);
		PRINT_DEBUG("virtual fd = '%d'\n", fd_id);
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
bool on_read(syscall_mod *trap) {
	int   fd       = (int)trap->get_arg(0);
	char *buf      = (char *)trap->get_arg(1);
	int   buf_size = (int)trap->get_arg(2);

	PRINT_DEBUG("read fd %d to 0x%lx and with size %d\n", fd, (long)buf, buf_size);

	struct received_data recv_data;
	struct injection *injection = NULL;

	// take the corresponding file_state from our stored file state dict
	auto search = trap->pstate->files.find(fd);
	if (search == trap->pstate->files.end()) {
		PRINT_ERROR("File Descriptor %d unknown!\n", fd);
		trap->set_return(-EBADF);
		return true;
	}

	struct file_state *fs = search->second;

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
bool on_close(syscall_mod *trap) {
	int fd = (int)trap->get_arg(0);

	if (trap->pstate->close_fd(fd)) {
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
bool on_getdents(syscall_mod *trap) {
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

	struct file_state *fs = trap->pstate->files[fd];

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
bool on_stat(syscall_mod *trap, bool do_fdlookup, bool do_at, bool do_lstat) {
	char *stat_result_ptr;

	struct received_data recv_data;
	struct injection *injection;

	const char *stat_path = NULL;
	const char *stat_type_str = NULL;
	char stat_path_buf[max_path_len];
	char statat_path_buf[max_path_len];

	int n;

	if (do_lstat) {
		injection = new_injection("/tmp/lstat.inject");
		stat_type_str = "lstat";
	}
	else {
		injection = new_injection("/tmp/stat.inject");
		stat_type_str = "stat";
	}
	injection_load_code(injection);

	if (do_fdlookup) {
		int stat_fd = (int)trap->get_arg(0);
		bool base_fdcwd = false;

		// newfstatat requested
		// -> fd is basepath, unless it's AT_FDCWD
		if (do_at) {
			if (stat_fd == AT_FDCWD) {
				PRINT_DEBUG("AT_CWD requested!\n");
				base_fdcwd = true;
			}
		}

		// look up the fd filename. it could be the prefix when do_at
		if (not base_fdcwd) {
			auto search = trap->pstate->files.find(stat_fd);
			if (search == trap->pstate->files.end()) {
				trap->set_return(-EBADF);
				return true;
			}
			stat_path = search->second->path.c_str();
			PRINT_DEBUG("Looked up: fd %d => '%s'\n", stat_fd, stat_path);
		}

		// the fd is actually just a prefix. arg 1 has the real filename.
		if (do_at) {
			// as arg0 is the fd, arg1 the filename -> arg2 resultptr
			stat_result_ptr = (char *)trap->get_arg(2);

			n = util::tstrncpy(trap, statat_path_buf, (const char *)trap->get_arg(1), max_path_len);
			if (n < 0) {
				throw util::Error("failed copying statat path string!\n");
			}

			// prefix impossible with relative path
			if (util::is_abspath(statat_path_buf)) {
				stat_path = statat_path_buf;
			}
			else {
				std::string path_s;
				if (base_fdcwd) {
					// prefix the cwd
					path_s = util::abspath(trap->pstate->cwd, statat_path_buf);
				}
				else {
					// prefix the fd as basedir
					path_s = util::abspath(stat_path, statat_path_buf);
				}
				strncpy(stat_path_buf, path_s.c_str(), max_path_len);
				stat_path = stat_path_buf;
			}
		} else {
			stat_result_ptr = (char *)trap->get_arg(1);
		}
	}
	else {
		stat_result_ptr = (char *)trap->get_arg(1);

		n = util::tstrncpy(trap, stat_path_buf, (const char *)trap->get_arg(0), max_path_len);
		if (n < 0) {
			throw util::Error("failed copying path string!\n");
		}

		PRINT_DEBUG("requested to %s filename '%s'\n", stat_type_str, stat_path_buf);

		if (not util::is_abspath(stat_path_buf)) {
			std::string path_s = util::abspath(trap->pstate->cwd, stat_path_buf);
			strncpy(stat_path_buf, path_s.c_str(), max_path_len);
		}

		stat_path = stat_path_buf;
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
bool on_lseek(syscall_mod *trap) {
	int  fd       = (int)trap->get_arg(0);
	long position = (long)trap->get_arg(1);
	int  whence   = (int)trap->get_arg(2);

	struct file_state *fs;

	if (trap->pstate->files.find(fd) == trap->pstate->files.end()) {
		PRINT_ERROR("File Descriptor %d unkown!\n", fd);
		trap->set_return(-EBADF);
		return true;
	}

	fs = trap->pstate->files[fd];

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

bool on_fcntl(syscall_mod *trap) {
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

	case F_DUPFD: {
		PRINT_DEBUG("duplicating fd %d\n", fd);
		//create fd copy.

		struct file_state *newstate = new file_state{};
		memcpy(newstate, trap->pstate->files[fd], sizeof(file_state));
		newstate->fd_ids.clear();
		newstate->fd_ids.insert(trap->pstate->next_free_fd);

		trap->pstate->files[trap->pstate->next_free_fd] = newstate;
		trap->set_return(trap->pstate->next_free_fd);
		trap->pstate->next_free_fd += 1;
		break;
	}
	case F_GETFL:
		PRINT_DEBUG("getting open flags for fd %d\n", fd);
		syscall_return_val = trap->pstate->files[fd]->flags;
		break;

	case F_GETFD:
		PRINT_DEBUG("getting fd flags (close_on_exec) for fd %d\n", fd);
		syscall_return_val = trap->pstate->files[fd]->close_on_exec;
		break;

	case F_SETFD: {
		int new_coe = (int)trap->get_arg(2);
		PRINT_DEBUG("setting fd flags (close_on_exec) for fd %d to %d\n", fd, new_coe);
		trap->pstate->files[fd]->close_on_exec = new_coe;
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
bool on_chdir(syscall_mod *trap, bool do_fdlookup) {
	std::string new_work_dir;

	if (do_fdlookup) {
		int fd = (int)trap->get_arg(0);
		PRINT_DEBUG("chdir to fd %d\n", fd);

		auto search = trap->pstate->files.find(fd);
		if (search == trap->pstate->files.end()) {
			trap->set_return(-EBADF);
			return true;
		}
		new_work_dir = search->second->path;
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
bool on_getcwd(syscall_mod *trap) {
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

bool on_uname(syscall_mod *trap) {
	char *result_ptr = (char *)trap->get_arg(0);
	int n;

	struct received_data recv_data;
	struct injection *injection = new_injection("/tmp/uname.inject");
	injection_load_code(injection);
	injection = consolidate(injection);

	PRINT_DEBUG("querying uname...\n");
	inject_module(injection, &recv_data);

	if (recv_data.return_value < 0) {
		return recv_data.return_value;
	}

	if (recv_data.length != sizeof(struct utsname)) {
		free_injection(injection);
		throw util::Error("recieved wrong struct size!");
	}

	// store data to other process
	n = util::tmemcpy(trap, result_ptr, recv_data.data, sizeof(struct utsname), true);
	if (n < 0) {
		free_injection(injection);
		throw util::Error("failed storing result!");
	}

	trap->set_return(recv_data.return_value);
	free_injection(injection);
	return true;
}

bool on_dup(syscall_mod *trap, int dupn) {
	int oldfd = trap->get_arg(0);
	int newfd = -1;
	//int newflags = -1;

	if (dupn >= 2) {
		newfd = trap->get_arg(1);

		if (oldfd == newfd) {
			return newfd;
		}
	}
	else {
		newfd = trap->pstate->next_free_fd;
		trap->pstate->next_free_fd += 1;
	}

	if (dupn == 3) {
		//newflags = trap->get_arg(2);
		if (oldfd == newfd) {
			trap->set_return(-EINVAL);
			return true;
		}

		// TODO: implement dup3, but we don't handle the clo_exec flag anyway..
	}

	auto searchold = trap->pstate->files.find(oldfd);
	if (searchold == trap->pstate->files.end()) {
		trap->set_return(-EBADF);
		return true;
	}

	// try to close the new fd, returns false if unsuccessful
	trap->pstate->close_fd(newfd);

	// add the duped fd to the reference list
	file_state *file_state_old = searchold->second;
	file_state_old->fd_ids.insert(newfd);

	// assign the pointer to the same file state object!
	trap->pstate->files[newfd] = file_state_old;

	trap->set_return(newfd);
	return true;
}

bool on_readlink(syscall_mod *trap, bool do_at) {
	throw util::Error("readlink redirection not implemented yet!");
}

bool on_getxattr(syscall_mod *trap) {
	throw util::Error("getxattr redirection not implemented yet!");
}

bool on_lgetxattr(syscall_mod *trap) {
	throw util::Error("lgetxattr redirection not implemented yet!");
}

bool on_clock_gettime(syscall_mod *trap) {
	throw util::Error("clock_gettime redirection not implemented yet!");
}

bool on_clock_getres(syscall_mod *trap) {
	throw util::Error("clock_getres redirection not implemented yet!");
}

bool on_statfs(syscall_mod *trap) {
	throw util::Error("statfs redirection not implemented yet!");
}

// ##################
// syscalls with write access
// ##################

bool on_write(syscall_mod *trap) {
	int   fd       = (int)trap->get_arg(0);
	char *buf      = (char *)trap->get_arg(1);
	int   buf_size = (int)trap->get_arg(2);

	PRINT_DEBUG("write to fd %d from buf 0x%lx size %d\n", fd, (long)buf, buf_size);

	struct received_data recv_data;
	struct injection *injection = NULL;

	// take the corresponding file_state from our stored file state dict
	auto search = trap->pstate->files.find(fd);
	if (search == trap->pstate->files.end()) {
		PRINT_ERROR("File Descriptor %d unknown!\n", fd);
		trap->set_return(-EBADF);
		return true;
	}
	struct file_state *fs = search->second;

	constexpr size_t write_chunk_size = 2048;
	char writebuf[write_chunk_size];
	int total_written = 0;
	int written = 0;
	int write_chunk = 0;

	PRINT_DEBUG("Trying to write %d bytes to file '%s'...\n", buf_size, fs->path.c_str());

	do {
		size_t bytes_left = buf_size - total_written;
		int write_bytes = std::min(bytes_left, write_chunk_size);
		buf += written; // slide src buffer beginning
		int n = util::tmemcpy(trap, writebuf, buf, write_bytes, false);
		if (n < 0) {
			throw util::Error("failed fetching write buffer from tracked process!");
		}

		// create the injection for each write call.. we can't 'unconsolidate' currently.
		injection = new_injection("/tmp/write.inject");
		injection_load_code(injection);

		add_string_argument(injection, fs->path.c_str());
		add_int_argument(injection, fs->flags);
		add_int_argument(injection, fs->pos);
		add_struct_argument(injection, writebuf, write_bytes);
		add_int_argument(injection, write_bytes);
		injection = consolidate(injection);

		PRINT_DEBUG("Writing chunk %d, size %d\n", write_chunk, write_bytes);
		inject_module(injection, &recv_data);

		written = recv_data.return_value;
		total_written += written;

		free_injection(injection);

		write_chunk += 1;
	} while (written > 0 && total_written < buf_size);


	int64_t ret;
	if (written < 0) {
		ret = written;
	} else {
		ret = total_written;
	}

	PRINT_DEBUG("write(%s) returned %ld\n", fs->path.c_str(), ret);
	trap->set_return(ret);
	return true;
}

bool on_unlink(syscall_mod *trap) {
	throw util::Error("unlink redirection not implemented yet!");
}

bool on_unlinkat(syscall_mod *trap) {
	throw util::Error("unlink redirection not implemented yet!");
}
