import os
import subprocess
import re

def process_define(syscalls, text):
    name, types = None, None
    if text.startswith('SYSCALL_DEFINE('):
        m = re.search(r'^SYSCALL_DEFINE\(([^)]+)\)\(([^)]+)\)$', text)
        if not m:
            print("Unable to parse:", text)
            return
        name, args = m.groups()
        types = [s.strip().rsplit(" ", 1)[0] for s in args.split(",")]
    else:
        m = re.search(r'^SYSCALL_DEFINE(\d)\(([^,]+)\s*(?:,\s*([^)]+))?\)$', text)
        if not m:
            print("Unable to parse:", text)
            return
        nargs, name, argstr = m.groups()
        if argstr is not None:
            argspec = [s.strip() for s in argstr.split(",")]
            types = argspec[0:len(argspec):2]
        else:
            types = []
    syscalls[name] = types

def get_sys_call_types(linux):
    syscalls = {}
    find = subprocess.Popen(["find"] +
                             [os.path.join(linux, d) for d in
                              "arch/x86 fs include ipc kernel mm net security".split()] +
                            ["-name", "*.c", "-print"],
                            stdout = subprocess.PIPE)
    for f in find.stdout:
        fh = open(f.strip())
        in_syscall = False
        text = ''
        for line in fh:
            line = line.strip()
            if not in_syscall and 'SYSCALL_DEFINE' in line:
                text = ''
                in_syscall = True
            if in_syscall:
                text += line
                if line.endswith(')'):
                    in_syscall = False
                    process_define(syscalls, text)
                else:
                    text += " "
    return syscalls


def parse_type(t):
    if re.search(r'^(const\s*)?char\s*(__user\s*)?\*\s*$', t):
        return "ARG_STR"
    if t.endswith('*'):
        return "ARG_PTR"
    return "ARG_INT"

def write_output(syscalls_h, types, numbers):
    out = open(syscalls_h, 'w')
    bracket='{'
    out.write(f"#define MAX_SYSCALL_NUM {max(numbers.keys())}\nstruct syscall_entry syscalls[] = {bracket}\n")
    for num in sorted(numbers.keys()):
        name = numbers[num]
        if name in types:
            args = types[name]
        else:
            args = ["void*"] * 6
        out.write(f"  [{num}] = {bracket}\n")
        out.write(f"    .name  = \"{name}\",\n")
        out.write(f"    .nargs = {len(args)},\n")
        out.write("    .args  = {\n")
        out.write(", ".join([parse_type(t) for t in args] + ["-1"] * (6 - len(args))))
        out.write("\n}},\n")
    out.write("};\n")
    out.close()

def do_syscall_numbers(file_path):
    syscalls = {}
    f = open(file_path)
    data = f.readlines()[10:374]
    for line in data:
        if line.startswith('#'):
            continue
        else:
            number, _, name = line.split('\t')[:3]
            syscalls[int(number)] = name.strip()
    f.close()
    return syscalls


linux_path = '../linux-6.0.2'
sys_call_file_path = 'arch/x86/entry/syscalls/syscall_64.tbl'
sys_call_data = do_syscall_numbers(os.path.join(linux_path, sys_call_file_path))
syscall_types = get_sys_call_types(linux_path)
write_output('syscallents.h', syscall_types, sys_call_data)
