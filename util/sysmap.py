#!/usr/bin/env python3
#
# linux system map conversion script.
#
#USAGE
#   ./sysmap.py <infile> <outfile>
#
# `infile` can be any system.map file or /proc/kallsyms which will be processed to
# a usable C header file, stored to `outfile`.
#


from sys import argv
import re
import argparse

#prefix used for prepending all symbol names.
prefix = "lnx_"

string_prefix = "str_"


#use only symbols of type d,r,t, see man 1 nm for that.
pat = re.compile(r"([0-9a-fA-F]*)\s([%s])\s([_a-zA-Z0-9]*)" % ("rRdDtT"))


p = argparse.ArgumentParser(description="converts nm-formatted system maps to c headers")
p.add_argument("input_filename")
p.add_argument("output_filename")
p.add_argument("-c", "--create-funcs", default=False, action="store_true")
p.add_argument("-t", "--append-ul", default=False, action="store_true")

args = p.parse_args()


numentries = 0
allentries = set()

print("starting conversion of system map")
with open(args.input_filename, "r") as infile:
    with open(args.output_filename, "w") as outfile:
        outfile.write("""#ifndef _SYSMAP_H_
#define _SYSMAP_H_

#define SYMADDR_STR(s) _SYSMAP_MACROSTR(s)
#define _SYSMAP_MACROSTR(x) #x


""")

        for line in infile:
            match = pat.match(line)
            if match:
                address = match.group(1)
                stype = match.group(2).lower()
                cname = match.group(3)

                #eliminate duplicates
                if cname not in allentries:
                    allentries.add(cname)
                else:
                    continue

                output = "#define %s%s" % (prefix, cname)

                if args.append_ul:
                    addr_ul = "0x%sUL" % address
                else:
                    addr_ul = "0x%s" % address

                if args.create_funcs and stype == "t":
                    #create function
                    output += " ((void (*)())%s)\n" % (addr_ul)
                else:
                    output += " %s\n" % (addr_ul)

                outfile.write(output)


            numentries += 1
            print("\rprocessed " + str(numentries) + " entries", end="")

        outfile.write("\n\n#endif")
        print("\nfinished processing system map!")
