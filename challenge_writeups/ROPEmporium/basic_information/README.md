# Challenge 1 - Ret2win

## The Basics
Let's first cover some of the need to know information of assembly and how a program works, regarding the stack, before we jump into the exploitation. I promise I'll try to keep this as short as I can, but this should hopefully cover all the information needed to get started.

### General information
When executing a program the bytes inside of a binary file is interpreted as instructions by the CPU. 

For now all that we need to know is that you can use a disassembler to interpret the bytes into CPU instructions so you actually have a slight chance of reading them.

Example of the disassembler Cutter on a program's main function:
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


As can be seen we effectively used the stack to change the value of the rsi register to the value of the rax register by using the stack.

### The most important register RIP
As mentioned there is one special purpose register we need to cover, which is RIP.

RIP is the instruction pointer and points at the next instruction we will execute. If we can control RIP we can control what we execute next in the program.

For the purpose of this example we will be using the mov instruction. Mov moves the value of the 2nd register mention into the first register mentioned so eg:
```mov rax, rdi```
would move the value of the rdi register into the rax register.

Example:
Registers:
|Register|Value|
|--------|-----|
|rax|0x51|
|rsi|0x20|
|rdx|0x00|
|rdi|0x30|

|Address|instruction|RIP|
|-------|-----------|---|
|0x40400|mov rdi, rax|<--|
|0x40403|mov rsi, rax||
|0x40406|mov rdx, rdi||

Step one instruction

Registers:
|Register|Value|
|--------|-----|
|rax|0x51|
|rsi|0x20|
|rdx|0x00|
|rdi|0x51|

|Address|instruction|RIP|
|-------|-----------|---|
|0x40400|mov rdi, rax||
|0x40403|mov rsi, rax|<--|
|0x40406|mov rdx, rdi||


Step one instruction

Registers:
|Register|Value|
|--------|-----|
|rax|0x51|
|rsi|0x51|
|rdx|0x00|
|rdi|0x51|

|Address|instruction|RIP|
|-------|-----------|---|
|0x40400|mov rdi, rax||
|0x40403|mov rsi, rax||
|0x40406|mov rdx, rdi|<--|

etc.

The instruction pointer moves one instruction forward per step and executes the instruction. Then moves another instruction forward. Rinse and repeat and you got program execution.

We therefore need to control RIP to be able to control execution flow of the program.


### The ret instruction

So how do we control RIP? Well one way is through the ret instruction.

The ret instruction basically takes the top value of the stack and puts it into RIP. Does that sound familiar?

If it does. It's because it works exactly like the pop instruction but just for RIP. The ret instruction is basically just a pop rip instruction with another flavor text.

## So what do we use this for?
### Buffer overflow

Now I've filled you with a bunch of information about CPU registers, instructions etc. but how does this all factor into us exploiting the binary?

In the case of ROPEmporium all the challenges are stack based buffer overflows. But what is a buffer overflow exactly?

When you create a variable in eg. C you specify a size for that variable. The compiler then creates a stack frame for your function, which is able to contain the size of that variable.

A buffer overflow is when you are able to write more data into the variable, than the compiler expected, which in turn overflows into other stack values further down on the stack.

A pointer to a return address, which the program should return to, after it is done executing the function, is stored on the stack as well.

If we are able to overflow from our variable onto the return address we have ROP!

### What is ROP?
ROP is controlling the return address to use already existing instructions inside the binary to take full control of the binary.

ROP usually works with the help of gadgets, which are instruction pairs which could look like this:

```
pop rax
ret
```

Since the stack is under our control because of the buffer overflow, we can control the stack value which is put into rax along with the next address the binary should return to, which could in turn be another gadget.

This should be all the theory needed to get started! Jump into challenge1_ret2win once you feel ready to start the practical bit!


