#!/usr/bin/env python3

import os
import sys
import mmap
import ctypes
import subprocess
import tempfile
import readline
import cmd


def string_to_bytes(string, charset='latin-1'):
  if(isinstance(string, bytes) and not isinstance(string, str)):
    return (string)
  else:
    return bytes(string, charset)

def execute_shellcode(shellcode_str):

  print(f"shellocde_str={shellcode_str}")

  shellcode_bytes = string_to_bytes(shellcode_str)

  print(f"shellcode_bytes={shellcode_bytes}")

  # Allocate memory with a RWX private anonymous mmap
  exec_mem = mmap.mmap(-1, len(shellcode_bytes),
                       prot = mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                       flags = mmap.MAP_ANONYMOUS | mmap.MAP_PRIVATE)

  print(f"memory address={exec_mem}")

  # Copy shellcode from bytes object to executable memory
  exec_mem.write(shellcode_bytes)

  # Cast to the memory to a C function object
  ctypes_buffer = ctypes.c_int.from_buffer(exec_mem)
  function = ctypes.CFUNCTYPE( ctypes.c_int64 )(ctypes.addressof(ctypes_buffer))
  function._avoid_gc_for_mmap = exec_mem

  print(f"function={function}")

  # Return pointer to shell code function in executable memory
  return function

class NasmException(Exception):
    def __init__(self, retcode, msg):
        self.retcode = retcode
        self.msg = msg.strip()
        Exception.__init__(self, msg.strip())

def parse_nasm_err(errstr):
    return errstr.split(' ', 1)[1]

def assemble_to_file(asmfile, binfile):
    proc = subprocess.Popen(["nasm", "-fbin", "-o", binfile, asmfile],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buf_out, buf_err = proc.communicate()
    buf_err = buf_err.decode()
    if proc.returncode != 0:
        raise NasmException(proc.returncode, parse_nasm_err(buf_err))


def parse_disassembly(disas):
    cur_opcodes = ''
    cur_disas = ''
    s = ''
    for line in disas.splitlines():
        line = line.strip()
        if len(line) > 0:
            # break out the elements of the line
            elems = line.split(None, 2)
            if len(elems) == 3:
                # starts a new instruction, append previous and clear our state
                if len(cur_opcodes) > 0:
                    s += "%-24s %s\n" % (cur_opcodes, cur_disas)
                cur_opcodes = ''
                # offset, opcodes, disas-text
                cur_disas = elems[2]
                cur_opcodes = elems[1]
            elif len(elems) == 1 and elems[0][0] == '-':
                # continuation
                cur_opcodes += elems[0][1:]
    # append last instruction
    if len(cur_opcodes) > 0:
        s += "%-24s %s" % (cur_opcodes, cur_disas)
    return s

def reduce_disassembly(disas):
    cur_opcodes = ''
    for line in disas.splitlines():
      cur_opcodes += line.split(" ", 1)[0]
    print(f"cur_opcodes={cur_opcodes}")
    fmt_opcodes = bytes.fromhex(cur_opcodes)
    fm2_opcodes = string_to_bytes(cur_opcodes)
    print(f"fm_opcodes ={fm_opcodes}")
    print(f"fm2_opcodes={fm2_opcodes}")
    return fmt_opcodes


def disassemble_file(binfile, bits):
    proc = subprocess.Popen(["ndisasm", "-b%u"%(bits), binfile],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buf_out, buf_err = proc.communicate()
    buf_out = buf_out.decode();
    buf_err = buf_err.decode();
    if proc.returncode != 0:
        raise NasmException(proc.returncode, buf_err)
    else:
        return parse_disassembly(buf_out)

def disassemble(machine_code, bits):
    binfile = None
    binfd = None
    try:
        binfd, binfile = tempfile.mkstemp()
        os.write(binfd, machine_code)
        os.close(binfd)
        print(disassemble_file(binfile, bits))
    finally:
        if binfile:
            os.unlink(binfile)
        
def assemble(asm, bits):
    asmfile = None 
    asmfd = None
    binfile = None
    try:
        asmfd, asmfile = tempfile.mkstemp()
        os.write(asmfd, b"[BITS %u]\n_start:\n"%(bits))
        os.write(asmfd, asm.encode())
        os.write(asmfd, b"\n")
        os.close(asmfd)

        binfile = asmfile + ".bin"
        assemble_to_file(asmfile, binfile)
        disasm_res = disassemble_file(binfile, bits)
    finally:
        if asmfile:
            os.unlink(asmfile)
        if binfile and os.path.exists(binfile): 
            os.unlink(binfile)
    return disasm_res

class NasmShell(cmd.Cmd):
    def __init__(self, bits=32):
        cmd.Cmd.__init__(self)
        self.bits = bits 
        self.disas_mode = False
        self.exec_mode = False
        self.disas_prompt = "ndisasm> "
        self.assemble_prompt = "nasm> "
        self.exec_prompt = "nasm (exec)> "
        self.prompt = self.assemble_prompt
        if self.bits not in [32, 64]:
            raise NasmException(0, 'must be 32 or 64 bits')

    def do_bits(self, bits):
        '''bits [32,64].\nUsed to set the architecture.\nWhen run without argument, prints the current architecture.'''
        if not bits or len(bits) == 0:
            print('%u' % (self.bits))
        else:
            if bits not in ['32','64']:
                print('error: must be either 32 or 64')
            else:
                self.bits = int(bits)   

    def do_disas(self, *args):
        '''set disassemble mode. Input following should be hexidecimal characters.'''
        self.disas_mode = True 
        self.prompt = self.disas_prompt
        print("disas mode")

    def do_ds(self, *args):
        '''an alias for disassemble mode'''
        self.do_disas(self)

    def do_assemble(self, *args):
        '''set assemble mode. Input following should be instructions.'''
        self.disas_mode = False
        self.prompt = self.assemble_prompt
        print("assemble mode")

    def do_as(self, *args):
        '''an alias for assemble mode'''
        self.do_assemble(self)

    def do_exec(self, *args):
        '''set assemble and exec mode'''
        self.disas_mode = False
        self.exec_mode = True
        self.prompt = self.exec_prompt
        print("assemble (exec) mode")

    def do_test(self, *args):
      self.args = "\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\x13\x00\x00\x00\xba\x06\x00\x00\x00\x0f\x05\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05\x48\x65\x6c\x6c\x6f\x0a"
      execute_shellcode(self.args)()

    def do_quit(self, *args):
        '''quit the program'''
        return True
    
    def do_exit(self, *args):
        '''an alias for quit'''
        return self.do_quit(self, args)

    def default(self, line):
        print(f"DEBUG: line={line}")
        if line == 'EOF':
            return True
        else:
            try:
                if self.disas_mode:
                    disassemble(bytes.fromhex(''.join(line.split())), self.bits)
                else:
                    raw = assemble(line.replace(';','\n'), self.bits)
                    print(raw)
                    if self.exec_mode:
                        print("attempting to execute shellcode")
                        execute_shellcode(reduce_disassembly(raw))()
            except NasmException as ne:
                print(ne)
            except TypeError as te:
                print (te)
            #except ValueError as ve:
                #print ("An even number of hexidecimal digits must appear in byte/opcode")
             #   print(f"ValueError: {ve}")

bits = 32
if len(sys.argv) > 1:
    bits = int(sys.argv[1])
shell = NasmShell(bits)
shell.cmdloop()

# prompt should go below this...
print("")
