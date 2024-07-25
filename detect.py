#!/usr/bin/env python

import os
import pickle
import networkx as nx
from collections import deque

from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, Application,
                             ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.syscall import (SYSCALL_NAMES, SYSCALL_PROTOTYPES,
                            FILENAME_ARGUMENTS, SOCKET_SYSCALL_NAMES)
from ptrace.func_call import FunctionCallOptions
from sys import stderr, exit
from optparse import OptionParser
from logging import getLogger, error
from ptrace.error import PTRACE_ERRORS, writeError
from ptrace.ctypes_tools import formatAddress
from ptrace.tools import signal_to_exitcode
import sys
import re
from time import time

class SyscallTracer(Application):

    def __init__(self):
        self.degree_data = {}
        self.final_graph_data = {} 
        self.initial_func = None
        self.initial_graph = None
        self.in_nodes = None
        self.out_nodes = None
        self.actual_out_node = None
        self.out_funcs = []
        self.path_data = {}
        self.valid_sys_call_dict = None
        self.ignore_sys_calls_list = set(['brk', 'arch_prctl', 'set_tid_address', 'set_robust_list', 'rseq', 'uname', 'prlimit64', 'readlink', 'getrandom', 'mprotect', 'fstat', 'fstatfs', 'newfstatat'])

        Application.__init__(self)

        self.parseOptions()
        self.load_graph_data()
        self.setupLog()

    def load_graph_data(self):
        """
        Loads the graph data into memory for proccessing..
        """
        file_path = f'{self.program[0]}.pkl'
        if not os.path.exists(file_path):
            print(f'Pickle Graph Data File is missing..')
            sys.exit(0)
        data = None
        with open(file_path, 'rb') as f:
            data = pickle.load(f)
        for func_name, graph in data:
            self.final_graph_data[func_name] = nx.DiGraph(graph)
            in_nodes, out_nodes = self.get_degree_nodes(self.final_graph_data[func_name])
            self.degree_data[func_name] = {'in_node': in_nodes[0], 'out_node': out_nodes[0]}

        self.initial_func = [key for key in self.final_graph_data.keys() if key.startswith('main')][0]
        self.initial_graph = self.final_graph_data[self.initial_func]
        self.in_nodes, self.out_nodes = self.get_degree_nodes(self.initial_graph)
        self.actual_out_node = self.out_nodes[0]
        self.out_funcs = [self.initial_func] 

        self.valid_sys_call_dict = self.get_sys_call_distributed()

    def get_degree_nodes(self, graph_data):
        """
        Returns source and sink among all nodes given graph data
        """
        in_d, out_d = [], []
        self_loop_data = set(nx.nodes_with_selfloops(graph_data))
        for node in graph_data.nodes():
            n_out_d = graph_data.out_degree(node)
            n_in_d = graph_data.in_degree(node)
            if (not n_in_d) or ((n_in_d == 1) and (node in self_loop_data)):
                in_d.append(node)
            if (not n_out_d) or ((n_out_d == 1) and (node in self_loop_data)):
                out_d.append(node)
        return in_d, out_d

    def get_previous_called_node(self, data, name):
        """
        Code which helps in backtracking when encountered with the final node of a function.
        """
        node_data, func_names = data['nodes'], data['func']
        req_index, node_value, func_value = None, None, None
        for index, f_name in enumerate(func_names):
            if f_name == name:
                req_index = index - 1
                node_value, func_value = node_data[index-1], func_names[index-1]
                break
        if req_index is None:
            req_index = len(func_names) - 1
            if req_index != -1:
                node_value, func_value = node_data[req_index], func_names[req_index]
                return node_value, func_value, node_data[:req_index], func_names[:req_index]
            else:
                return None, None, [], []
        else:
            return node_value, func_value, node_data[:index-1], func_names[:index-1]

    def get_sys_call_distributed(self):
        """
        Traverses the graphs and returns the valid syscall data accordingly.
        """
        queue = deque()
        current_valid_sys_call_nodes = set()
        valid_sys_calls_data = {}
        visited_nodes = set()
        for node, func in zip(self.in_nodes, self.out_funcs):
            queue.append((node, func, self.final_graph_data[func], self.final_graph_data[func].successors(node)))
        while queue:
            current_node, func_name, graph_data, children = queue[0]
            graph_degree_data = self.degree_data[func_name]
            _, current_graph_out_node = graph_degree_data['in_node'], graph_degree_data['out_node']
            if current_node not in visited_nodes:
                if current_node == current_graph_out_node:
                    # If its out_node of a function need to backtrack accoridngly..
                    if current_node != self.actual_out_node:
                        p_node, p_name, p_node_data, p_func_data = self.get_previous_called_node(self.path_data[current_node], func_name)
                        self.path_data[p_node] = {}
                        self.path_data[p_node]['nodes'] = p_node_data 
                        self.path_data[p_node]['func'] = p_func_data
                        if p_node is not None:
                            p_graph = self.final_graph_data[p_name]
                            p_succ = p_graph.successors(p_node)
                            queue.append((p_node, p_name, p_graph, p_succ))
                            visited_nodes.add(current_node)
                            queue.popleft()
                    else:
                        valid_sys_calls_data['exit_group_syscall'] = None
                        queue.popleft()
                else:
                    try:
                        child = next(children)
                        label_data = graph_data[current_node][child]['label']
                        # Found a system call
                        if label_data.endswith('syscall'):
                            check_ = valid_sys_calls_data.get(label_data, None)
                            if check_ is None:
                                valid_sys_calls_data[label_data] = {}
                            valid_sys_calls_data[label_data][func_name] = valid_sys_calls_data.get(label_data, {}).get(func_name, set()) | set([child])
                            current_valid_sys_call_nodes.add(child)
                            if self.path_data.get(child, None) is None:
                                self.path_data[child] = {}
                            self.path_data[child]['nodes'] = self.path_data.get(current_node, {}).get('nodes', []) + [current_node, child]
                            self.path_data[child]['func'] = self.path_data.get(current_node, {}).get('func', []) + [func_name, func_name]
                        elif (label_data == 'ep'):
                            queue.append((child, func_name, graph_data, graph_data.successors(child)))
                            if self.path_data.get(child, None) is None:
                                self.path_data[child] = {}
                            self.path_data[child]['nodes'] = self.path_data.get(current_node, {}).get('nodes', []) + [current_node, child]
                            self.path_data[child]['func'] = self.path_data.get(current_node, {}).get('func', []) + [func_name, func_name]
                        else:
                            # Edge value is a valid function so traverse that function graph accordingly.
                            func_graph_data = self.final_graph_data[label_data]
                            in_nodes, _ = self.get_degree_nodes(func_graph_data)
                            for in_node in in_nodes:
                                queue.append((in_node, label_data, func_graph_data, func_graph_data.successors(in_node)))
                                if self.path_data.get(in_node, None) is None:
                                    self.path_data[in_node] = {}
                                self.path_data[in_node]['nodes'] = self.path_data.get(current_node, {}).get('nodes', []) + [child]
                                self.path_data[in_node]['func'] = self.path_data.get(current_node, {}).get('func', []) + [func_name]
                    except StopIteration as s:
                        visited_nodes.add(current_node)
                        queue.popleft()
                    except Exception as e:
                        print(e)
            else:
                queue.popleft()
        # Removing junk other than systemcall to preserve memory
        for key in list(self.path_data.keys()):
            if key not in current_valid_sys_call_nodes:
                del self.path_data[key]
        return valid_sys_calls_data

    def setupLog(self):
        if self.options.output:
            fd = open(self.options.output, 'w')
            self._output = fd
        else:
            fd = stderr
            self._output = None
        self._setupLog(fd)

    def parseOptions(self):
        parser = OptionParser(
            usage="%prog [options] -- program [arg1 arg2 ...]")
        self.createCommonOptions(parser)
        parser.add_option("--enter", help="Show system call enter and exit",
                          action="store_true", default=False)
        parser.add_option("--profiler", help="Use profiler",
                          action="store_true", default=False)
        parser.add_option("--type", help="Display arguments type and result type (default: no)",
                          action="store_true", default=False)
        parser.add_option("--name", help="Display argument name (default: no)",
                          action="store_true", default=False)
        parser.add_option("--string-length", "-s", help="String max length (default: 300)",
                          type="int", default=300)
        parser.add_option("--array-count", help="Maximum number of array items (default: 20)",
                          type="int", default=20)
        parser.add_option("--raw-socketcall", help="Raw socketcall form",
                          action="store_true", default=False)
        parser.add_option("--output", "-o", help="Write output to specified log file",
                          type="str")
        parser.add_option("--ignore-regex", help="Regex used to filter syscall names (e.g. --ignore='^(gettimeofday|futex|f?stat)')",
                          type="str")
        parser.add_option("--address", help="Display structure address",
                          action="store_true", default=False)
        parser.add_option("--syscalls", '-e', help="Comma separated list of shown system calls (other will be skipped)",
                          type="str", default=None)
        parser.add_option("--socket", help="Show only socket functions",
                          action="store_true", default=False)
        parser.add_option("--filename", help="Show only syscall using filename",
                          action="store_true", default=False)
        parser.add_option("--show-pid",
                          help="Prefix line with process identifier",
                          action="store_true", default=False)
        parser.add_option("--list-syscalls",
                          help="Display system calls and exit",
                          action="store_true", default=False)
        parser.add_option("-i", "--show-ip",
                          help="print instruction pointer at time of syscall",
                          action="store_true", default=False)

        self.createLogOptions(parser)

        self.options, self.program = parser.parse_args()
        if self.options.list_syscalls:
            syscalls = list(SYSCALL_NAMES.items())
            syscalls.sort(key=lambda data: data[0])
            for num, name in syscalls:
                print("% 3s: %s" % (num, name))
            exit(0)

        if self.options.pid is None and not self.program:
            parser.print_help()
            exit(1)

        # Create "only" filter
        only = set()
        if self.options.syscalls:
            # split by "," and remove spaces
            for item in self.options.syscalls.split(","):
                item = item.strip()
                if not item or item in only:
                    continue
                ok = True
                valid_names = list(SYSCALL_NAMES.values())
                for name in only:
                    if name not in valid_names:
                        print("ERROR: unknown syscall %r" % name, file=stderr)
                        ok = False
                if not ok:
                    print(file=stderr)
                    print(
                        "Use --list-syscalls options to get system calls list", file=stderr)
                    exit(1)
                # remove duplicates
                only.add(item)
        if self.options.filename:
            for syscall, format in SYSCALL_PROTOTYPES.items():
                restype, arguments = format
                if any(argname in FILENAME_ARGUMENTS for argtype, argname in arguments):
                    only.add(syscall)
        if self.options.socket:
            only |= SOCKET_SYSCALL_NAMES
        self.only = only
        if self.options.ignore_regex:
            try:
                self.ignore_regex = re.compile(self.options.ignore_regex)
            except Exception as err:
                print("Invalid regular expression! %s" % err)
                print("(regex: %r)" % self.options.ignore_regex)
                exit(1)
        else:
            self.ignore_regex = None

        if self.options.fork:
            self.options.show_pid = True

        self.processOptions()

    def ignoreSyscall(self, syscall):
        name = syscall.name
        if self.only and (name not in self.only):
            return True
        if self.ignore_regex and self.ignore_regex.match(name):
            return True
        return False

    def displaySyscall(self, syscall):
        # print(f'Encountered {syscall.name}')
        if syscall.name in self.ignore_sys_calls_list:
            pass
        else:
            to_check = f'{syscall.name}_syscall'
            valid_sys_calls = set(self.valid_sys_call_dict.keys())
            # print(f'Valid sys calls are {valid_sys_calls}')
            if to_check not in valid_sys_calls:
                print('Attack detected exiting...')
                sys.exit(0)
            else:
                if to_check.startswith('exit'):
                    print('No attack detected. Terminating program..')
                    sys.exit(0)
                else:
                    node_data = self.valid_sys_call_dict[to_check]
                    self.out_funcs = list(node_data.keys())
                    self.in_nodes = node_data[self.out_funcs[0]]
                    self.out_funcs = self.out_funcs*len(self.in_nodes)
                for key in list(self.path_data.keys()):
                    if key not in self.in_nodes:
                        del self.path_data[key]
            self.valid_sys_call_dict = self.get_sys_call_distributed()


    def syscallTrace(self, process):
        # First query to break at next syscall
        self.prepareProcess(process)
        exitcode = 0
        while True:
            # No more process? Exit
            if not self.debugger:
                break

            # Wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
            except ProcessExit as event:
                self.processExited(event)
                if event.exitcode is not None:
                    exitcode = event.exitcode
                continue
            except ProcessSignal as event:
                event.display()
                event.process.syscall(event.signum)
                exitcode = signal_to_exitcode(event.signum)
                continue
            except NewProcessEvent as event:
                self.newProcess(event)
                continue
            except ProcessExecution as event:
                self.processExecution(event)
                continue

            # Process syscall enter or exit
            self.syscall(event.process)
        return exitcode

    def syscall(self, process):
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        if syscall and (syscall.result is not None or self.options.enter):
            self.displaySyscall(syscall)

        # Break at next syscall
        process.syscall()

    def processExited(self, event):
        # Display syscall which has not exited
        state = event.process.syscall_state
        if (state.next_event == "exit") \
                and (not self.options.enter) \
                and state.syscall:
            self.displaySyscall(state.syscall)

        # Display exit message
        error("*** %s ***" % event)

    def prepareProcess(self, process):
        process.syscall()
        process.syscall_state.ignore_callback = self.ignoreSyscall

    def newProcess(self, event):
        process = event.process
        error("*** New process %s ***" % process.pid)
        self.prepareProcess(process)
        process.parent.syscall()

    def processExecution(self, event):
        process = event.process
        error("*** Process %s execution ***" % process.pid)
        process.syscall()

    def runDebugger(self):
        # Create debugger and traced process
        self.setupDebugger()
        process = self.createProcess()
        if not process:
            return

        self.syscall_options = FunctionCallOptions(
            write_types=self.options.type,
            write_argname=self.options.name,
            string_max_length=self.options.string_length,
            replace_socketcall=not self.options.raw_socketcall,
            write_address=self.options.address,
            max_array_count=self.options.array_count,
        )
        self.syscall_options.instr_pointer = self.options.show_ip

        return self.syscallTrace(process)

    def main(self):
        if self.options.profiler:
            from ptrace.profiler import runProfiler
            exitcode = runProfiler(getLogger(), self._main)
        else:
            exitcode = self._main()
        if self._output is not None:
            self._output.close()
        sys.exit(exitcode)

    def _main(self):
        self.debugger = PtraceDebugger()
        exitcode = 0
        try:
            exitcode = self.runDebugger()
        except ProcessExit as event:
            self.processExited(event)
            if event.exitcode is not None:
                exitcode = event.exitcode
        except PtraceError as err:
            error("ptrace() error: %s" % err)
            if err.errno is not None:
                exitcode = err.errno
        except KeyboardInterrupt:
            error("Interrupted.")
            exitcode = 1
        except PTRACE_ERRORS as err:
            writeError(getLogger(), err, "Debugger error")
            exitcode = 1
        self.debugger.quit()
        return exitcode

    def createChild(self, program):
        if not os.path.exists(program[0]):
            print('Missing binary file...')
            sys.exit(0)
        pid = Application.createChild(self, program)
        error("execve(%s, %s, [/* 40 vars */]) = %s" % (
            program[0], program, pid))
        return pid


if __name__ == "__main__":
    SyscallTracer().main()
