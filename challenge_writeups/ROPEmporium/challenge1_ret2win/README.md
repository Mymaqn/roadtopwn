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

Whilst everything else are just addressing into the lower bits of these registers. As shown in this little infographic:

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━rax━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                               ┏━━━━━━━━━━━━━━eax━━━━━━━━━━━━━┫
┃                               ┃               ┏━━━━━━ax━━━━━━┫
┃                               ┃               ┃       ┏━━al━━┫
0000000000000000000000000000000000000000000000000000000000000000
```

### The stack
The stack is funny in a way, since it counterintuitively grows downwards. This is important to keep in mind as stack buffer overflow ROP would not be possible in the same way if the stack grew upwards.

The stack is just a memory area the process has allocated, at the begining of execution, which contains important values, like our variables, or where to return to after a function call.

rsp and rbp mentioned in the general purpose register section are used to keep track of where in memory the stack is located

rsp points to the current memory address of the stack

rbp is the base pointer and points to the base address of the stackframe, which is a frame of the stack, set up for the function we are currently in

The CPU can use the instructions push and pop to manipulate the stack.
* Push - Pushes a value onto the stack
* Pop - Pops a value off the stack

This works by the method of LIFO (Last in first out). Which means that the most recent value pushed onto the stack is also going to be the first value to be popped off the stack.

#### Example:

Stack:
|StackAddress|Value|rsp|
|------------|-----|---|
|0x7fffff00|0x41|<---|

Registers:
|Register|Value|
|--------|-----|
|rax|0x51|
|rsi|0x61|

Execute instruction
```push rax```

Stack:
|StackAddress|Value|rsp|
|------------|-----|---|
|0x7ffffef8|0x51|<---|
|0x7fffff00|0x41||

Registers:
|Register|Value|
|--------|-----|
|rax|0x51|
|rsi|0x61|

Execute instruction
```pop rsi```

Stack:
|StackAddress|Value|rsp|
|------------|-----|---|
|0x7fffff00|0x41|<---|

Registers:
|Register|Value|
|--------|-----|
|rax|0x51|
|rsi|0x51|





