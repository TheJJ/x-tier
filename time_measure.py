#!/usr/bin/python3

import argparse
import subprocess
import sys
import time


if __name__ == "__main__":
    p = argparse.ArgumentParser(description='x-tier time measurement utility')
    p.add_argument("-c", "--count", type=int, default=1, help="repeat the measurement by a given count")
    p.add_argument("-o", "--out", default="-", help="stdout file")
    p.add_argument("-e", "--err", default="-", help="stderr file")
    p.add_argument("argument", nargs="+", help="call to execute.")

    args = p.parse_args()

    sys.stderr.write("starting time measurement of %s\n" % args.argument)

    if args.count > 1:
        sys.stderr.write("-> repeating measurement %d times\n" % args.count)
    elif args.count < 0:
        raise Exception("uhm, a negative repeat count... %d" % args.count)

    out_dest = None
    if args.out != "-":
        outfile = open(args.out, "wb")
        out_dest = subprocess.PIPE
    else:
        out_file = sys.stdout

    err_dest = None
    if args.err != "-":
        errfile = open(args.err, "wb")
        err_dest = subprocess.PIPE
    else:
        errfile = sys.stderr

    duration = 0

    for i in range(args.count):
        if out_dest or err_dest:
            with subprocess.Popen(args.argument, stdout=out_dest, stderr=err_dest) as p:
                start_t = time.perf_counter()
                (stdoutdata, stderrdata) = p.communicate()
                duration += time.perf_counter() - start_t

                if out_dest:
                    outfile.write(stdoutdata)
                if err_dest:
                    errfile.write(stderrdata)
        else:
            start_t = time.perf_counter()
            subprocess.call(args.argument)
            duration += time.perf_counter() - start_t



    if out_dest:
        outfile.close()
    if err_dest:
        errfile.close()

    if args.count > 1:
        sys.stderr.write("total execution time:\n%f\n" % duration)
    sys.stderr.write("execution time: (%d run%s)\n" % (args.count, "" if args.count == 1 else "s"))
    sys.stderr.write("%f s\n" % (duration / args.count))
