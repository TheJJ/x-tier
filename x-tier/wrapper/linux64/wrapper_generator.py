#!/usr/bin/env python3

#
# generate wrapper c code.


import argparse
import re
from string import Template
import sys

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
        ret.append('"mov %%%d, %%%%%s;"  // arg %d' % (param_id, arg_reg[arg_id], arg_id))

        return ret

    def mod_espoffset(self, size):
        return "esp_offset += %s;" % size

    def memcpy(self, dest, src, size):
        return Template(
"""for (i = 0; i < ${size}; i++) {
		${dest}[i] = ${src}[i];
	}""").substitute(dest=dest, src=src, size=size)

    def stackbuffer(self, name, length):
        return "char *%s_stack_buffer = (char *)(((char *)kernel_esp) - (esp_offset + %s));" % (name, length)

    def prepare_arg(self):
        raise NotImplementedError("implement in subclass")

    def copy_back_arg(self):
        raise NotImplementedError("implement in subclass")

    def get_func_arg(self):
        raise NotImplementedError("implement in subclass")

    def get_asm_arg(self):
        raise NotImplementedError("implement in subclass")


class NumberArgument(FuncArgument):
    def __init__(self, name):
        super().__init__(name, 8)

    def prepare_arg(self):
        return ""

    def copy_back_arg(self):
        return ""

    def get_func_arg(self):
        if self.data_len == 8:
            return "int64_t %s" % self.name
        else:
            raise Exception("other than int64_t non-ptr arguments not supported")

    def get_asm_arg(self):
        return self.name


class CharArrayArgument(FuncArgument):
    """
    allocates stack memory of given length
    """

    def __init__(self, name, length, inout):
        super().__init__(name, 8)
        self.length = length

        if inout not in ("in", "out"):
            raise Exception("buffers have to be declared in or out: %s was not." % self.name)
        self.inout  = inout

    def copy_to_stack(self, name, length):
        return Template("""
	${stackbuffer}
	${memcpy}
""").substitute(
    stackbuffer = self.stackbuffer(name, length),
    memcpy      = self.memcpy(self.get_asm_arg(), name, length),
)

    def prepare_arg(self):
        if self.inout == "in":
            return Template("""
	// === ${arg_repr}
${stackcpy}
${esp_mod}
""").substitute(
    arg_repr = repr(self),
    esp_mod  = self.mod_espoffset(self.length),
    stackcpy = self.copy_to_stack(self.name, self.length),
)

        elif self.inout == "out":
            return Template("""
	${stackbuffer}
	${esp_mod} // reserve space for ${name}
            """).substitute(
                stackbuffer = self.stackbuffer(self.name, self.length),
                esp_mod     = self.mod_espoffset(self.length),
                name        = self.name,
            )

    def copy_back_arg(self):
        if self.inout == "in":
            return ""
        elif self.inout == "out":
            # TODO: currently copies the WHOLE buffer back,
            #       the external function might have filled less than that.
            return Template("""
	${memcpy}
""").substitute(
    memcpy=self.memcpy(self.name, self.get_asm_arg(), self.length)
)

    def get_func_arg(self):
        return "char *%s" % self.name

    def get_asm_arg(self):
        return "%s_stack_buffer" % self.name

    def __repr__(self):
        return "argument: char %s[%s]" % (self.name, self.length)


class StringArgument(CharArrayArgument):
    """
    same as chararray, but nullterminated.
    also generates length calculation snippet.
    """

    def __init__(self, name, inout):
        super().__init__(name, 0, inout)

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
        if self.inout == "out":
            return ""
        elif self.inout == "in":
            return Template("""
	// === argument: char *${name}
	${get_length}
	${stackcpy}
	${esp_mod}
	// ====
""").substitute(
    name       = self.name,
    get_length = self.determine_length(self.name),
    stackcpy   = self.copy_to_stack(self.name, "%s_length" % self.name),
    esp_mod    = self.mod_espoffset("%s_length" % self.name),
)

    def copy_back_arg(self):
        if self.inout == "in":
            return ""
        elif self.inout == "out":
            return Template("""
	${get_length}
	${memcpy}
""").substitute(
    get_length = self.determine_length(self.get_asm_arg()),
    memcpy     = self.memcpy(self.name, self.get_asm_arg(), "%s_length" % self.get_asm_arg())
)


    def __repr__(self):
        return "argument: char *%s" % (self.name)


class Wrapper:

    templ = Template("""
#include "../../../tmp/sysmap.h"  // kernel symbol names
${header_include}
${comment}
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
		"mov  $$42, %%rax;"     // select `command` as interrupt handler in RAX
		"int  $$42;"            // send interrupt, hypercall happens here
		"mov  %%rbp, %%rsp;"   // restore RSP
		"pop  %%rbp;"          // restore RBP

		"mov  %%rax, %${retarg_id};"      // save return value
		:
		:
		"r"(kernel_esp),
		"r"(esp_offset),
		${argument_regs}
		"m"(return_value)
		:
		"rax", "rbx", ${argument_regs_clobbered}
	);

${args_copyback}

	// return to caller
	return return_value;
}
""")

    def __init__(self, name, dest_name, args, headers):
        self.name      = name      # function name
        self.dest_name = dest_name # external function name to call
        self.args      = args
        self.headers   = set(headers) if headers else set()

    def get_code(self, opt_comment=""):
        param_id = 2 # we already got 2 asm params in the template

        to_regs        = list()
        reg_args       = list()
        prepare_args   = list()
        clobbered_regs = list()
        function_args  = list()
        copy_back_args = list()

        for idx, arg in enumerate(self.args):
            function_args.append(arg.get_func_arg())
            prepare_args.append(arg.prepare_arg())
            to_regs.extend(arg.move_value(param_id, idx))
            copy_back_args.append(arg.copy_back_arg())

            reg_args.append(arg.get_asm_arg())
            clobbered_regs.append(arg_reg[idx])
            param_id += 1

        function_args  = ", ".join(function_args)
        prepare_args   = "".join(prepare_args)
        reg_args       = " ".join(['"m"(%s),' % a for a in reg_args])
        clobbered_regs = ", ".join(['"%s"'    % a for a in clobbered_regs])
        to_regs        = "\n\t\t".join(to_regs)
        args_copyback  = "".join(copy_back_args)

        if "int64_t" in function_args:
            self.headers.add("<stdint.h>")
        headers        = "".join(["#include %s\n" % h for h in self.headers])

        c = self.templ.substitute(
            header_include          = headers,
            func_name               = self.name,
            func_args               = function_args,
            args_prepare            = prepare_args,
            target_func_name        = self.dest_name,
            args_to_regs            = to_regs,
            argument_regs           = reg_args,
            argument_regs_clobbered = clobbered_regs,
            args_copyback           = args_copyback,
            retarg_id               = param_id,
            comment                 = opt_comment,
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

        atypel = atype.split(" ")
        if all([w in atypel for w in ("in", "out")]):
            raise Exception("both in and out defined")
        elif "in" in atypel:
            inout = "in"
        elif "out" in atypel:
            inout = "out"
        else:
            inout = ""

        length_var = re.search(r"\[([\w\(\) ]+|\d+)\]", atype)

        if all([w in atype for w in ("char", "*")]):
            # char ptr arg

            if length_var:
                # length is known, stored in variable
                ret.append(CharArrayArgument(aname, length_var.group(1), inout))
            else:
                if inout == "out":
                    raise Exception("output strings are not possible, you probably wanna use a buffer!")
                # \0 terminated.
                ret.append(StringArgument(aname, inout))
        else:
            if length_var:
                ret.append(CharArrayArgument(aname, length_var.group(1), inout))
            else:
                # regular number argument
                ret.append(NumberArgument(aname))

    return ret

def main(args):
    wrapper_args = create_args(parse_func_args(args.argument))
    w = Wrapper(args.function_name, args.jump_name, wrapper_args, args.header)
    print(w.get_code(
        "/**\n * generated with: %s\n */\n" % (' '.join(["'%s'" % a for a in sys.argv]))
    ))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description='x-tier wrapper generator. generates stealty external function calling wrappers.')
    p.add_argument("-i", "--header", action='append', help="add the given header to the include list")
    p.add_argument("function_name", help="generated function name")
    p.add_argument("jump_name", help="external function name to be called")
    p.add_argument("argument", nargs="*", help="arguments for the external function call. add [len] or <lenvar> to type to define buffer sizes.")

    args = p.parse_args()
    main(args)
