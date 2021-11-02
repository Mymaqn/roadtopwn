# Challenge 1 - Ret2win

## The Basics
Let's first cover some of the need to know information of assembly and how a program works, regarding the stack, before we jump into the exploitation. I promise I'll try to keep this as super short as I can

### General information
When executing a program the bytes inside of a binary file is interpreted as instructions by the CPU. 

For now all that we need to know is that you can use a disassembler to interpret the bytes to CPU instructions so you actually have a slight chance of reading them.

Example of Cutter on a program's main function:
# INSERT IMAGE HERE
This might look severely overwhelming at first but let's break it down

The CPU has registers which it can store and manipulate values from/to.
There are 2 types of registers we need to be aware of:
1. General purpose registers
2. Special purpose registers

Of these types of registers, all we need to worry about for now, are the general purpose registers and a single special purpose register.

#### General purpose registers
General purpose registers are used exactly for what it sounds like. General purpose.
These registers are used to pass variables to functions, interrupts to the kernel, tell us where the stack is etc..

In x86-64, which we are focusing on, there are in total 16 general purpose registers which can be addressed in full or by the lower 32,16 and 8 bits:
| 64-bit Register | 32-bit Register | 16-bit Register | 8-bit Register |
| --------------- | --------------- | --------------- | -------------- |
|rax|eax|ax|al|
|rbx|ebx|bx|bl|
|rcx|ecx|cx|cl|
|rdx|edx|dx|dl|
|rsi|esi|si|sil|
|rdi|edi|di|dil|
|rbp|ebp|bp|bpl|
|rsp|esp|sp|spl|
|r8|r8d|r8w|r8b|
|r9|r9d|r9w|r9b|
|r10|r10d|r10w|r10b|
|r11|r11d|r11w|r11b|
|r12|r12d|r12w|r12b|
|r13|r13d|r13w|r13b|
|r14|r14d|r14w|r14b|
|r15|r15d|r15w|r15b

This looks terrifying to remember, but is actually not that hard when it comes down to it as you mostly will be working with the following registers in the following way:

Setting these:
* rax
* rbx
* rcx
* rdx
* rsi
* rdi

Keeping track of these:
* rsp
* rbp




