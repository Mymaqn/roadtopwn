from pwn import *

context.arch = "amd64" #Specify x86-64 architecture

context.terminal = ["konsole","-e"] #Specify that I am using Konsole terminal

#Auto-executing gdbscript for every run
gdbscript = '''
b *main
c
'''

binary = "./ret2win" #Binary name

io = gdb.debug(binary,gdbscript=gdbscript)

io.interactive()
