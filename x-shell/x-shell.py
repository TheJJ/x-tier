#!/usr/bin/env python3

import argparse
import os
import shlex
from string import Template
import subprocess
import sys
import threading

#qemu invokation for the testing vm
vm_invokation = Template("".join([
    "qemu/x86_64-softmmu/qemu-system-x86_64",
    "-machine type=q35,accel=kvm",
    "-drive file=$diskfile,if=virtio",
    "-m 1024",
    "-netdev user,id=user.0,hostfwd=tcp:127.0.0.1:9001-:22,hostfwd=tcp:127.0.0.1:9002-:1337",
    "-device virtio-net-pci,netdev=user.0",
    "-smp 4",
    "-balloon virtio",
    "-virtfs local,path=data/,security_model=none,mount_tag=datadir",
    "-vga vmware",
    "-monitor telnet:127.0.0.1:8999,server"
]))

class XShell:
    def __init__(self):
        self.emulator = None

    def unload_modules(self):
        #if is_loaded kvm-intel:
        #    rmmod kvm-intel
        #if is_loaded kvm:
        #    rmmod kvm
        pass

    def load_modules(self):
        #load kvm modules if necessary

        #if is_not_loaded kvm:
        #    insmod linux/arch/x86/kvm/kvm.ko
        #if is_not_loaded kvm-intel:
        #    insmod linux/arch/x86/kvm/kvm-intel.ko
        pass

    def run_emu(self, diskimg):
        qemu_args = shlex.split(vm_invokation.substitute(diskfile=diskimg))
        self.emulator = ChildProcess(qemu_args)
        self.emulator.start()
        self.emulator.join()


class ChildProcess(threading.Thread):
    def __init__(self, args):
        super().__init__()
        self.invokation = args
        self.proc = None

    def run(self):
        self.proc = subprocess.Popen(self.invokation)
        self.proc.communicate()
        self.proc.wait()

    def kill(self, signal):
        self.proc.send_signal(signal)


def start(args):
    shell = XShell()
    shell.run_emu(args.diskimage)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='xshell vmi introspection')
    sp = parser.add_subparsers(dest='module', help="available xshell program subsystems")

    run_parser = sp.add_parser("run", help="run xshell")
    run_parser.add_argument('-d', '--diskimage', required=True, help="specifies the disk image booted by the emulator")
    run_parser.set_defaults(action=start)

    args = parser.parse_args()

    if args.module == None:
        parser.print_help()
    else:
        args.action(args)
