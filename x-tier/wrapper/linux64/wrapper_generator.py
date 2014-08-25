#!/usr/bin/env python3

#
# generate wrapper c code.


import argparse
import re
from string import Template

hypercall_id      = 42
hypercall_command = 42

# 64-bit call convention:
arg_reg = {
    0: "rdi",
    1: "rsi",
    2: "rdx",
    3: "rcx",
    4: "r8",
    5: "r9",
}
# 6... n: on stack from right to left



class FuncArgument:
    def __init__(self, name, data_len):
        self.name = name
        self.data_len = data_len

    def move_value(self, param_id, arg_id):
        """
        returns ["asm instruction" // comment, ...]
        """

        if arg_id > 5:
            raise Exception("stack arguments unsupported")

        ret = list()
        #TODO: maybe the register needs to be null'd when writing less than 8 bytes!
        ret.append('"mov %%%d, %%%%%s"  // arg %d' % (param_id, arg_reg[arg_id], arg_id))

        return ret

    def prepare_arg(self):
        raise NotImplementedError("implement in subclass")

    def get_func_arg(self):
        raise NotImplementedError("implement in subclass")


class NumberArgument(FuncArgument):
    def __init__(self, name):
        super().__init__(name, 8)

    def prepare_arg(self):
        return ""

    def get_func_arg(self):
        if self.data_len == 8:
            return "int64_t %s" % self.name
        else:
            raise Exception("other than int64_t non-ptr arguments not supported")


class CharArrayArgument(FuncArgument):
    """
    allocates stack memory of given length
    """

    def __init__(self, name, length):
        super().__init__(name, 8)
        self.length = length

    def copy_to_stack(self, name, length):
        return Template("""
	esp_offset += ${length};
	char *${name}_stack_buffer = (char *)(((char *)kernel_esp) - ${length});
	for (i = 0; i < ${length}; i++) {
		${name}_stack_buffer[i] = ${name}[i];
	}
""").substitute(name=name, length=length)

    def prepare_arg(self):
        return Template("""
	// === ${arg_repr}
${stackcpy}
""").substitute(arg_repr=repr(self), stackcpy=self.copy_to_stack(self.name, self.length))

    def get_func_arg(self):
        return "const char *%s" % self.name

    def __repr__(self):
        return "argument: char %s[%s]" % (self.name, self.length)


class StringArgument(CharArrayArgument):
    """
    same as chararray, but nullterminated.
    also generates length calculation snippet.
    """

    def __init__(self, name):
        super().__init__(name, 0)

    def determine_length(self, name):
        return Template(
"""int ${name}_length = 1; // including \\0
	char *${name}_len_tmp = (char *)${name};

	while ((*${name}_len_tmp) != '\\0') {
		${name}_length  += 1;
		${name}_len_tmp += 1;
	}
""").substitute(name=name)

    def prepare_arg(self):
        return Template("""
	// === argument: char *${name}
	${get_length}
	${stackcpy}
	// ====
""").substitute(
    name       = self.name,
    get_length = self.determine_length(self.name),
    stackcpy   = self.copy_to_stack(self.name, "%s_length" % self.name)
)

    def __repr__(self):
        return "argument: char *%s" % (self.name)


class Wrapper:

    templ = Template("""
#include "../../../tmp/sysmap.h"  // kernel symbol names
${header_include}

// variables to be patches by injection shellcode, in .text section
unsigned long kernel_esp     __attribute__ ((section (".text"))) = 0;
unsigned long target_address __attribute__ ((section (".text"))) = 0;

long ${func_name}(${func_args}) {
	unsigned long esp_offset = 0;   // kernel stack allocation size
	unsigned long return_value = 0; // function call return value

	int i = 0;

${args_prepare}

	// store the prepared arguments to registers
	// then ask the hypervisor to perform the external function call.
	__asm__ volatile(
		"mov $$" SYMADDR_STR(${target_func_name}) ", %%rbx;" // RBX gets jump target

		${args_to_regs}

		"mov  %0, %%rax;"      // store original kernel_stack into rax
		"sub  %1, %%rax;"      // decrease stack ptr by allocation amount
		"push %%rbp;"          // save EBP
		"mov  %%rsp, %%rbp;"   // save stack pointer
		"mov  %%rax, %%rsp;"   // set stack pointer
		"mov  $$42, %%rax;"    // select `command` as interrupt handler in RAX
		"int  $$42;"           // send interrupt, hypercall happens here
		"mov  %%rbp, %%rsp;"   // restore RSP
		"pop  %%rbp;"          // restore RBP

		"mov  %%rax, %5;"      // save return value
		:
		:
		"r"(kernel_esp),
		"r"(esp_offset),
		${argument_regs}
		"m"(open_ret)          // return value
		:
		"rax", "rbx", ${argument_regs_clobbered});

	// Return to caller
	return open_ret;
}
""")

    def __init__(self, name, dest_name, args):
        self.name = name  # function name
        self.dest_name = dest_name # external function name to call
        self.args = args

    def get_code(self):
        param_id = 2 # we already got 2 asm params in the template

        to_regs        = list()
        reg_args       = list()
        prepare_args   = list()
        clobbered_regs = list()
        function_args  = list()

        for idx, arg in enumerate(self.args):
            function_args.append(arg.get_func_arg())
            prepare_args.append(arg.prepare_arg())
            to_regs.extend(arg.move_value(param_id, idx))

            reg_args.append(arg.name)
            clobbered_regs.append(arg_reg[idx])
            param_id += 1


        function_args  = ", ".join(function_args)
        prepare_args   = "".join(prepare_args)
        reg_args       = "".join(['"m"(%s), ' % a for a in reg_args])
        clobbered_regs = ", ".join(['"%s"'    % a for a in clobbered_regs])
        to_regs        = "\n\t\t".join(to_regs)
        headers        = "#include <stdint.h>" if "int64_t" in function_args else ""

        c = self.templ.substitute(
            header_include          = headers,
            func_name               = self.name,
            func_args               = function_args,
            args_prepare            = prepare_args,
            target_func_name        = self.dest_name,
            args_to_regs            = to_regs,
            argument_regs           = reg_args,
            argument_regs_clobbered = clobbered_regs,
        )

        return c

def parse_func_args(args):
    ret = list()

    for arg in args:
        arg_parts = arg.split(" ")

        ptrcnt = arg_parts[-1].count("*")
        arg_parts[-2] += "*" * ptrcnt

        atype = " ".join(arg_parts[:-1])
        aname = arg_parts[-1][ptrcnt:]

        if "*" in aname:
            raise Exception("* in argument name: %s" % aname)

        ret.append((atype, aname))

    return ret

def create_args(args):
    # input: [(type, name), ..]
    # output: [FuncArgument, ..]

    ret = list()

    for atype, aname in args:
        if atype.count("*") > 1:
            raise Exception("more than single ptrs not supported yet!")

        if all([w in atype for w in ("char", "*")]):
            # char ptr arg

            length_known = re.search(r"<(\w+)>", atype)
            if length_known:
                # length is known, stored in variable
                ret.append(CharArrayArgument(aname, length_known.group(1)))
            else:
                # \0 terminated.
                ret.append(StringArgument(aname))
        else:
            array = re.search(r"\[(\d+)\]", atype)
            if array:
                ret.append(CharArrayArgument(aname, array.group(1)))
            else:
                # regular number argument
                ret.append(NumberArgument(aname))

    return ret

def main(args):
    wrapper_args = create_args(parse_func_args(args.argument))
    w = Wrapper(args.function_name, args.jump_name, wrapper_args)
    print(w.get_code())


if __name__ == "__main__":
    p = argparse.ArgumentParser(description='x-tier wrapper generator. generates stealty external function calling wrappers.')
    p.add_argument("function_name", help="generated function name")
    p.add_argument("jump_name", help="external function name to be called")
    p.add_argument("argument", nargs="*", help="arguments for the external function call. add [len] or <lenvar> to type to define buffer sizes.")

    args = p.parse_args()
    main(args)
